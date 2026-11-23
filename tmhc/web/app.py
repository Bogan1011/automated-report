"""Upload website for health-check evidence.

    python -m tmhc web                      # uses ~/healthcheck/config.yaml
    python -m tmhc web --set-password NAME  # create/change a login

The site writes each client into the watcher's inbox (same folder layout as
copying by hand), so the background watcher builds the report. It never
talks to the internet; the zip password lives in config.yaml on the server.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import re
from collections import OrderedDict
import secrets
import shutil
import time
import zipfile
from pathlib import Path
from typing import Optional

import yaml
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import checklist as cl
from ..engine.evaluate import load_rules
from ..sources import screenshots
from ..cli import make_checklist
from ..watch import (DEFAULT_CONFIG, _load_state, client_status, find_evidence, load_config)

HERE = Path(__file__).resolve().parent
MAX_UPLOAD = 1024 * 1024 * 1024        # 1 GB per file
SESSION_HOURS = 12
COOKIE = "tmhc_session"
EVIDENCE_EXT = {".docx", ".zip", ".csv", ".cmpolicy", ".xml"}
# products with a rule pack: tab id -> (product name, rule pack). More as packs are added.
PRODUCT_INFO = OrderedDict([
    ("SEP", {"name": "Standard Endpoint Protection", "rules": "apexone_sep"}),
    ("SWP", {"name": "Server & Workload Protection", "rules": "swp"}),
    ("CECP", {"name": "Cloud Email and Collaboration Protection", "rules": "cecp"}),
])
PRODUCTS = [v["name"] for v in PRODUCT_INFO.values()]
BUILD_RE = re.compile(r"\d+\.\d+\.\d+(\.\d+)?")
# latest-build settings per product: (form/profile key, label, example)
BUILD_FIELDS = {
    "SEP": [("latest_agent_build", "Latest Apex One agent build", "14.0.20958")],
    "SWP": [("latest_dsa_windows", "Latest Windows agent build", "20.0.3.29020"),
            ("latest_dsa_linux", "Latest Linux agent build", "20.0.3.28120")],
    "CECP": [],                     # SaaS - no agents
}


def product_short(prof_or_name) -> str:
    """'SEP' / 'SWP' / 'CECP' from a profile dict or a product name."""
    if isinstance(prof_or_name, dict):
        rules = str((prof_or_name.get("options") or {}).get("rules", ""))
        for k, v in PRODUCT_INFO.items():
            if rules == v["rules"]:
                return k
        prof_or_name = prof_or_name.get("product", "")
    for k, v in PRODUCT_INFO.items():
        if str(prof_or_name).strip().lower() in (v["name"].lower(), k.lower()):
            return k
    if re.search(r"\b(cas|cloud app security|email and collaboration)\b", str(prof_or_name), re.I):
        return "CECP"                       # the product's former name
    return "SEP"


def _check_builds(form: dict, short: str) -> Optional[str]:
    for key, label, ex in BUILD_FIELDS[short]:
        if not BUILD_RE.fullmatch(form.get(key, "").strip()):
            return (f"Enter {label[0].lower() + label[1:]} (e.g. {ex}). Save it in Settings so it is filled in "
                    "for every client.")
    return None


# --------------------------------------------------------------------------
# config + auth
# --------------------------------------------------------------------------
def _hash(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return f"pbkdf2${salt}${dk.hex()}"


def _check(password: str, stored: str) -> bool:
    try:
        _, salt, _ = stored.split("$")
    except ValueError:
        return False
    return hmac.compare_digest(_hash(password, salt), stored)


def _save_config(path: Path, cfg: dict) -> None:
    data = dict(cfg)
    data["inbox"] = str(data["inbox"])
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    header = "".join(l for l in text.splitlines(True) if l.startswith("#")) or "# Health-check settings\n"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def set_password(config_path: Path, user: str, password: str) -> None:
    cfg = load_config(config_path)
    web = cfg.setdefault("web", {})
    web.setdefault("secret", secrets.token_hex(32))
    web.setdefault("users", {})[user] = _hash(password)
    _save_config(config_path, cfg)


def _sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _make_cookie(secret: str, user: str) -> str:
    exp = int(time.time()) + SESSION_HOURS * 3600
    payload = f"{user}|{exp}"
    return f"{payload}|{_sign(secret, payload)}"


def _read_cookie(secret: str, value: str) -> Optional[str]:
    try:
        user, exp, sig = value.rsplit("|", 2)
    except (ValueError, AttributeError):
        return None
    if not hmac.compare_digest(sig, _sign(secret, f"{user}|{exp}")) or int(exp) < time.time():
        return None
    return user


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def safe_name(name: str) -> str:
    """Client name -> folder name: no path tricks, nothing Windows dislikes."""
    name = re.sub(r"[^\w .&()\-,]", "", name, flags=re.UNICODE).strip(" .")
    name = re.sub(r"\s+", " ", name)
    return name[:90]


def _client_dir(cfg: dict, name: str) -> Path:
    inbox: Path = cfg["inbox"]
    folder = (inbox / name).resolve()
    if folder.parent != inbox.resolve() or not folder.is_dir() or name.startswith((".", "_")):
        raise HTTPException(404, "client not found")
    return folder


async def _save_upload(up: UploadFile, dest: Path) -> int:
    size = 0
    with dest.open("wb") as fh:
        while chunk := await up.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD:
                fh.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"{up.filename} is larger than 1 GB")
            fh.write(chunk)
    return size


def _check_evidence(folder: Path, zip_password: str, short: str = "SEP") -> list[str]:
    """Quick look at what was uploaded, so problems show up immediately."""
    notes: list[str] = []
    ev = find_evidence(folder)
    if ev.get("screenshots_docx"):
        try:
            with zipfile.ZipFile(folder / ev["screenshots_docx"]) as z:
                n = sum(1 for m in z.namelist() if m.startswith("word/media/"))
            notes.append(f"ok: screenshots file has {n} pictures")
        except zipfile.BadZipFile:
            notes.append("problem: the screenshots file is not a valid Word .docx")
    else:
        notes.append("note: no screenshots file - only exports will be used")
    if ev.get("logs") and ev["logs"] != ".":
        try:
            with zipfile.ZipFile(folder / ev["logs"]) as z:
                names = z.namelist()
                enc = [i for i in z.infolist() if i.flag_bits & 0x1]
                if enc:
                    z.read(enc[0], pwd=zip_password.encode() if zip_password else None)
            notes.append(f"ok: logs zip opened ({len(names)} files)")
            base = [Path(n).name.lower() for n in names]
            if short == "CECP":
                csvs = [n for n in names if n.lower().endswith(".csv")]
                pdfs = [n for n in names if n.lower().endswith(".pdf")]
                notes.append(f"ok: detection log found ({Path(csvs[0]).name})" if csvs else
                             "warning: no detection log CSV (result.csv) - the detection charts will be missing")
                notes.append(f"ok: monthly report PDF found ({Path(pdfs[0]).name[:60]})" if pdfs else
                             "note: no monthly report PDF - total items scanned and the scan panel will be missing")
            elif short == "SWP":
                xml = [n for n in names if n.lower().endswith(".xml")]
                notes.append("ok: Computers.csv found" if any(b.startswith("computers") and b.endswith(".csv")
                                                             for b in base) else
                             "warning: no Computers.csv - agent counts and module states will be missing")
                notes.append(f"ok: {len(xml)} policy .xml export(s) found" if xml else
                             "warning: no policy .xml export - only screenshots will be used for policy rows")
                for label, key in (("Intrusion Prevention events", "intrusion_prevention"),
                                   ("Log Inspection events", "log_inspection")):
                    notes.append(f"ok: {label} found" if any(key in b for b in base) else
                                 f"note: no {label} CSV - that presentation slide is left out")
            else:
                pol = [n for n in names if n.lower().endswith(".cmpolicy")]
                agents = [n for n in names if "agent list" in n.lower()]
                notes.append(f"ok: policy export found ({Path(pol[0]).stem[:70]})" if pol else
                             "warning: no .cmpolicy policy export in the zip - policy rows will be 'Not captured'")
                notes.append("ok: Apex One agent list found" if agents else
                             "warning: no 'Apex One Security Agent List' CSV - agent counts will be missing")
        except RuntimeError:
            notes.append("problem: the logs zip did not open with the server's zip password (Settings)")
        except zipfile.BadZipFile:
            notes.append("problem: the logs file is not a valid zip")
    elif not ev.get("logs"):
        notes.append("warning: no logs zip - policy rows and agent counts will be missing")
    return notes


def _profile_from_form(form: dict, cfg: dict, ev: dict, old: Optional[dict] = None) -> dict:
    d = cfg.get("defaults") or {}
    prof = dict(old or {})
    short = product_short(form.get("product") or (old or {}).get("product") or "SEP")
    prof.update({
        "client_name": form["client_name"].strip(),
        "product": PRODUCT_INFO[short]["name"],
        "quarter": form.get("quarter", "").strip() or "auto",
        "check_date": form.get("check_date", "").strip() or "auto",
        "report_date": form.get("report_date", "").strip() or dt.date.today().isoformat(),
        "prepared_by": form.get("prepared_by", "").strip(),
        "approved_by": form.get("approved_by", "").strip(),
        "account_owner": form.get("account_owner", "").strip(),
        "location": form.get("location", "").strip() or "Remotely",
        "customer_attendance": form.get("customer_attendance", "").strip() or "Console Access",
        "trend_attendance": form.get("trend_attendance", "").strip() or form.get("prepared_by", "").strip(),
    })
    for key, _, _ in BUILD_FIELDS[short]:
        prof[key] = form.get(key, "").strip() or d.get(key, "")
    evidence = dict(prof.get("evidence") or {})
    evidence.update(ev)
    evidence["zip_password"] = d.get("zip_password", "")
    evidence.setdefault("checklist", "checklist.xlsx")
    prof["evidence"] = evidence
    prof["options"] = dict(old.get("options") if old and old.get("options") else (cfg.get("options") or {"reader": "ocr"}))
    prof["options"]["rules"] = PRODUCT_INFO[short]["rules"]
    return prof


def _write_profile(folder: Path, prof: dict) -> None:
    header = "# Written by the health-check website. Editing on the website rebuilds the report.\n"
    (folder / "profile.yaml").write_text(header + yaml.safe_dump(prof, sort_keys=False, allow_unicode=True),
                                         encoding="utf-8")


def _read_profile(folder: Path) -> dict:
    p = folder / "profile.yaml"
    return (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.exists() else {}


def _outputs(folder: Path) -> dict:
    out = folder / "output"
    reports = sorted(out.glob("*.docx"), key=lambda p: p.stat().st_mtime) if out.is_dir() else []
    report = reports[-1] if reports else None
    review = report.with_name(report.stem + "_review.xlsx") if report else None
    decks = sorted(out.glob("*.pptx"), key=lambda p: p.stat().st_mtime) if out.is_dir() else []
    return {"report": report, "review": review if review and review.exists() else None,
            "presentation": decks[-1] if decks else None,
            "checklist": folder / "checklist.xlsx" if (folder / "checklist.xlsx").exists() else None}


def _fmt_time(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%d %b %Y %H:%M")


# --------------------------------------------------------------------------
# app
# --------------------------------------------------------------------------
def create_app(config_path: Path = DEFAULT_CONFIG) -> FastAPI:
    app = FastAPI(title="Health Check Reports", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals["now_year"] = dt.date.today().year

    def cfg() -> dict:
        return load_config(config_path)

    def user_of(request: Request) -> Optional[str]:
        c = cfg()
        web = c.get("web") or {}
        if not web.get("secret") or not web.get("users"):
            return None
        u = _read_cookie(web["secret"], request.cookies.get(COOKIE, ""))
        return u if u in web["users"] else None

    def render(request: Request, template: str, **ctx):
        ctx.setdefault("user", user_of(request))
        return templates.TemplateResponse(request, template, ctx)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if request.method == "POST":
            # same-origin check (cookie is SameSite=Strict as well)
            origin = request.headers.get("origin") or request.headers.get("referer") or ""
            host = request.headers.get("host", "")
            if origin and re.sub(r"^https?://", "", origin).split("/")[0] != host:
                return HTMLResponse("Cross-site request refused", status_code=403)
        if path.startswith("/static") or path in ("/login", "/favicon.ico"):
            return await call_next(request)
        if not user_of(request):
            return RedirectResponse("/login", status_code=303)
        resp = await call_next(request)
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------------- login ------------------------------------------------
    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        configured = bool((cfg().get("web") or {}).get("users"))
        return render(request, "login.html", configured=configured, error=None)

    @app.post("/login")
    def login(request: Request, username: str = Form(...), password: str = Form(...)):
        c = cfg()
        web = c.get("web") or {}
        stored = (web.get("users") or {}).get(username.strip())
        if not stored or not _check(password, stored):
            time.sleep(1.0)                            # slow down guessing
            return render(request, "login.html", configured=True, error="Wrong user name or password")
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(COOKIE, _make_cookie(web["secret"], username.strip()), httponly=True,
                        samesite="strict", max_age=SESSION_HOURS * 3600)
        return resp

    @app.post("/logout")
    def logout():
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(COOKIE)
        return resp

    # ---------------- client list ------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, tab: str = "SEP"):
        c = cfg()
        tab = tab.upper() if tab.upper() in PRODUCT_INFO else "SEP"
        state = _load_state(c["inbox"])
        rows = []
        counts = {k: 0 for k in PRODUCT_INFO}
        for folder in sorted((p for p in c["inbox"].iterdir() if p.is_dir() and not p.name.startswith((".", "_"))),
                             key=lambda p: p.stat().st_mtime, reverse=True):
            prof = _read_profile(folder)
            short = product_short(prof)
            counts[short] += 1
            if short != tab:
                continue
            st = client_status(folder, state)
            rows.append({"name": folder.name, "client": prof.get("client_name", folder.name),
                         "prepared_by": prof.get("prepared_by", ""), "check_date": prof.get("check_date", ""),
                         "status": st["status"], "detail": st["detail"],
                         "updated": _fmt_time(folder.stat().st_mtime), "outputs": _outputs(folder)})
        busy = any(r["status"] in ("queued", "building") for r in rows)
        return render(request, "index.html", rows=rows, busy=busy, tab=tab, tabs=PRODUCT_INFO, counts=counts)

    # ---------------- new client --------------------------------------------
    @app.get("/new", response_class=HTMLResponse)
    def new_page(request: Request, product: str = "SEP"):
        c = cfg()
        d = c.get("defaults") or {}
        short = product_short(product)
        form = {"product": PRODUCT_INFO[short]["name"], "prepared_by": d.get("prepared_by", ""),
                "approved_by": d.get("approved_by", ""), "account_owner": d.get("account_owner", ""),
                "location": d.get("location", "Remotely"),
                "customer_attendance": d.get("customer_attendance", "Console Access"),
                "trend_attendance": d.get("trend_attendance", d.get("prepared_by", "")),
                "report_date": dt.date.today().isoformat()}
        for fields in BUILD_FIELDS.values():
            for key, _, _ in fields:
                form[key] = d.get(key, "")
        return render(request, "new.html", form=form, products=PRODUCTS, error=None, build_fields=BUILD_FIELDS,
                      short=short, info=PRODUCT_INFO, has_zip_password=bool(d.get("zip_password")))

    @app.post("/new")
    async def new_client(request: Request, screenshots_docx: Optional[UploadFile] = File(None),
                         logs_zip: Optional[UploadFile] = File(None),
                         extra: list[UploadFile] = File(default=[])):
        c = cfg()
        form = {k: v for k, v in (await request.form()).items() if isinstance(v, str)}
        name = safe_name(form.get("client_name", ""))
        d = c.get("defaults") or {}

        short = product_short(form.get("product", "SEP"))

        def fail(msg: str):
            return render(request, "new.html", form=form, products=PRODUCTS, error=msg, build_fields=BUILD_FIELDS,
                          short=short, info=PRODUCT_INFO, has_zip_password=bool(d.get("zip_password")))

        if not name:
            return fail("Enter the client name.")
        err = _check_builds(form, short)
        if err:
            return fail(err)
        if (c["inbox"] / name).exists():
            return fail(f"A client folder '{name}' already exists - open it from the list to replace its evidence.")
        uploads = [u for u in [screenshots_docx, logs_zip, *extra] if u is not None and u.filename]
        if not uploads:
            return fail("Upload at least the screenshots Word file or the logs zip.")
        for u in uploads:
            if Path(u.filename).suffix.lower() not in EVIDENCE_EXT:
                return fail(f"{u.filename}: only .docx, .zip, .csv, .cmpolicy and .xml files are accepted.")
        if screenshots_docx and screenshots_docx.filename and not screenshots_docx.filename.lower().endswith(".docx"):
            return fail("The screenshots file must be a Word .docx file.")
        if logs_zip and logs_zip.filename and not logs_zip.filename.lower().endswith(".zip"):
            return fail("The logs file must be a .zip file.")

        staging = c["inbox"] / f".incoming-{secrets.token_hex(4)}"
        staging.mkdir()
        try:
            for u in uploads:
                await _save_upload(u, staging / Path(u.filename).name)
            ev = find_evidence(staging)
            _write_profile(staging, _profile_from_form(form, c, ev))
            notes = _check_evidence(staging, d.get("zip_password", ""), short)
            try:            # checklist straight away, so blanks can be filled while it builds
                make_checklist(staging / "profile.yaml", sync=True, quiet=True)
            except (SystemExit, Exception) as exc:
                notes.append(f"note: checklist will be created after the first build ({str(exc).strip()[:120]})")
            (staging / ".upload_check.json").write_text(json.dumps(notes), encoding="utf-8")
            staging.rename(c["inbox"] / name)          # appears to the watcher all at once
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return RedirectResponse(f"/client/{name}", status_code=303)

    # ---------------- one client --------------------------------------------
    @app.get("/client/{name}", response_class=HTMLResponse)
    def client_page(request: Request, name: str):
        c = cfg()
        folder = _client_dir(c, name)
        prof = _read_profile(folder)
        st = client_status(folder)
        status_txt = (folder / "STATUS.txt").read_text(encoding="utf-8") if (folder / "STATUS.txt").exists() else ""
        checks = json.loads((folder / ".upload_check.json").read_text()) if (folder / ".upload_check.json").exists() else []
        files = [{"name": p.name, "size": f"{p.stat().st_size / 1048576:.1f} MB", "at": _fmt_time(p.stat().st_mtime)}
                 for p in sorted(folder.iterdir())
                 if p.is_file() and Path(p.name).suffix.lower() in EVIDENCE_EXT and not p.name.startswith(("~$", "."))]
        pending = [k for k in _not_captured(folder)]
        return render(request, "client.html", name=name, prof=prof, st=st, status_txt=status_txt,
                      pending=len(pending),
                      checks=checks, files=files, outputs=_outputs(folder), products=PRODUCTS,
                      build_fields=BUILD_FIELDS, short=product_short(prof), info=PRODUCT_INFO,
                      has_zip_password=bool((c.get("defaults") or {}).get("zip_password")))

    @app.post("/client/{name}/details")
    async def save_details(request: Request, name: str):
        c = cfg()
        folder = _client_dir(c, name)
        form = {k: v for k, v in (await request.form()).items() if isinstance(v, str)}
        if not form.get("client_name", "").strip():
            raise HTTPException(400, "client name is required")
        old = _read_profile(folder)
        prof = _profile_from_form(form, c, find_evidence(folder), old)
        _write_profile(folder, prof)
        return RedirectResponse(f"/client/{name}", status_code=303)

    @app.post("/client/{name}/evidence")
    async def replace_evidence(request: Request, name: str, files: list[UploadFile] = File(...)):
        c = cfg()
        folder = _client_dir(c, name)
        ups = [u for u in files if u.filename]
        for u in ups:
            ext = Path(u.filename).suffix.lower()
            if ext not in EVIDENCE_EXT:
                raise HTTPException(400, f"{u.filename}: only .docx, .zip, .csv, .cmpolicy")
        for u in ups:
            ext = Path(u.filename).suffix.lower()
            if ext in (".docx", ".zip"):              # one screenshots file and one zip per client
                for old in folder.glob(f"*{ext}"):
                    if not old.name.startswith("~$"):
                        old.unlink()
            tmp = folder / f".upload-{secrets.token_hex(4)}{ext}"
            await _save_upload(u, tmp)
            tmp.replace(folder / Path(u.filename).name)
        prof = _read_profile(folder)
        prof.setdefault("evidence", {}).update(find_evidence(folder))
        _write_profile(folder, prof)
        notes = _check_evidence(folder, (c.get("defaults") or {}).get("zip_password", ""), product_short(_read_profile(folder)))
        (folder / ".upload_check.json").write_text(json.dumps(notes), encoding="utf-8")
        return RedirectResponse(f"/client/{name}", status_code=303)

    @app.post("/client/{name}/rebuild")
    def rebuild(name: str):
        folder = _client_dir(cfg(), name)
        prof = folder / "profile.yaml"
        if prof.exists():
            os.utime(prof, None)                       # watcher sees a change and rebuilds
        return RedirectResponse(f"/client/{name}", status_code=303)

    @app.post("/client/{name}/archive")
    def archive(name: str):
        c = cfg()
        folder = _client_dir(c, name)
        dest_root = c["inbox"] / "_archive"
        dest_root.mkdir(exist_ok=True)
        dest = dest_root / f"{name} {dt.datetime.now():%Y%m%d-%H%M%S}"
        folder.rename(dest)
        return RedirectResponse("/", status_code=303)

    @app.get("/client/{name}/download/{kind}")
    def download(name: str, kind: str):
        folder = _client_dir(cfg(), name)
        path = _outputs(folder).get(kind)
        if kind not in ("report", "review", "checklist", "presentation") or path is None or not path.exists():
            raise HTTPException(404, "not available yet")
        media = {".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                 ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation"}.get(
            path.suffix, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        return FileResponse(path, media_type=media, filename=path.name)

    # ---------------- checklist in the browser ------------------------------
    def _checklist_rows(folder: Path) -> list[dict]:
        from openpyxl import load_workbook
        path = folder / "checklist.xlsx"
        if not path.exists():
            return []
        prof = _read_profile(folder)
        rules = load_rules((prof.get("options") or {}).get("rules", "apexone_sep"))
        cat = screenshots.field_catalogue(rules)
        ws = load_workbook(path)[cl.SHEET]
        rows = []
        for r in ws.iter_rows(min_row=2, values_only=True):
            if not r[0]:
                continue
            typ = cat.get(r[0], {}).get("type", "text")
            choices = cl.BOOL_CHOICES if typ == "bool" else (cl.DESKTOP_SERVER_CHOICES if typ == "desktop_server" else None)
            spec = cat.get(r[0], {})
            suggest = [x for x in dict.fromkeys([*spec.get("suggest", []), "Enabled", "Disabled",
                                                  "Not Configured", "N/A"]) if x]
            rows.append({"key": r[0], "section": r[1] or "", "setting": r[2] or "", "recommended": r[3] or "",
                         "deployed": "" if r[4] is None else str(r[4]), "notes": r[5] or "", "where": r[6] or "",
                         "prefilled": (r[7] if len(r) > 7 else None) or "", "type": typ, "choices": choices,
                         "suggest": suggest})
        return rows

    def _not_captured(folder: Path) -> list[str]:
        p = folder / ".not_captured.json"
        try:
            return [x["key"] for x in json.loads(p.read_text(encoding="utf-8"))]
        except (OSError, ValueError, KeyError, TypeError):
            return []

    @app.get("/client/{name}/checklist", response_class=HTMLResponse)
    def checklist_page(request: Request, name: str):
        folder = _client_dir(cfg(), name)
        rows = _checklist_rows(folder)
        missing = set(_not_captured(folder))
        # rows still "Not captured" in the last build come first
        first = [r for r in rows if r["key"] in missing and not r["deployed"]]
        rest = [r for r in rows if r not in first]
        blanks = sum(1 for r in rows if not r["deployed"])
        return render(request, "checklist.html", name=name, first=first, rest=rest, blanks=blanks,
                      built=(folder / ".not_captured.json").exists(), st=client_status(folder),
                      prof=_read_profile(folder))

    @app.post("/client/{name}/checklist")
    async def checklist_save(request: Request, name: str):
        from openpyxl import load_workbook
        folder = _client_dir(cfg(), name)
        path = folder / "checklist.xlsx"
        if not path.exists():
            raise HTTPException(404, "checklist not created yet")
        form = await request.form()
        wb = load_workbook(path)
        ws = wb[cl.SHEET]
        changed = 0
        for row in ws.iter_rows(min_row=2):
            key = row[cl.COL_KEY - 1].value
            field = f"v::{key}"
            if key and field in form:
                new = str(form[field]).strip()
                cur = row[cl.COL_DEPLOYED - 1].value
                if (str(cur).strip() if cur is not None else "") != new:
                    row[cl.COL_DEPLOYED - 1].value = new or None
                    changed += 1
        if changed:
            tmp = folder / ".checklist-saving.xlsx"
            wb.save(tmp)
            tmp.replace(path)
        return RedirectResponse(f"/client/{name}?saved={changed}", status_code=303)

    # ---------------- settings ----------------------------------------------
    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request, saved: int = 0, checked: int = 0):
        c = cfg()
        return render(request, "settings.html", d=c.get("defaults") or {}, o=c.get("options") or {},
                      products=PRODUCTS, saved=saved, checked=checked, build_fields=BUILD_FIELDS, info=PRODUCT_INFO,
                      lb=(c.get("defaults") or {}).get("latest_builds") or {}, users=sorted((c.get("web") or {}).get("users", {})))

    @app.post("/settings")
    async def settings_save(request: Request):
        c = cfg()
        form = {k: v for k, v in (await request.form()).items() if isinstance(v, str)}
        d = c.setdefault("defaults", {})
        for k in ("product", "prepared_by", "approved_by", "account_owner", "location",
                  "customer_attendance", "trend_attendance"):
            if k in form:
                d[k] = form[k].strip()
        recheck = False
        for fields in BUILD_FIELDS.values():
            for key, label, ex in fields:
                build = form.get(key, "").strip()
                if build and not BUILD_RE.fullmatch(build):
                    raise HTTPException(400, f"{label} must look like {ex}")
                if form.get(f"auto_{key}") == "1":         # follow Trend Micro again
                    if d.get(f"{key}_manual"):
                        d[f"{key}_manual"] = False
                        recheck = True
                elif key in form and build != d.get(key, ""):
                    d[key] = build
                    d[key + "_updated"] = dt.date.today().isoformat() if build else ""
                    d[f"{key}_manual"] = True                # typed by the analyst: keep it
        if form.get("zip_password"):                   # blank = keep the current one
            d["zip_password"] = form["zip_password"]
        if form.get("clear_zip_password") == "1":
            d["zip_password"] = ""
        if form.get("new_password"):
            if len(form["new_password"]) < 8:
                raise HTTPException(400, "password must be at least 8 characters")
            c["web"]["users"][user_of(request)] = _hash(form["new_password"])
        _save_config(config_path, c)
        if recheck:
            _refresh_builds()
        return RedirectResponse("/settings?saved=1", status_code=303)

    def _refresh_builds() -> None:
        from .. import latest_builds
        latest_builds.request_check(config_path)     # done by the tmhc-builds job (internet access)

    @app.post("/settings/check-builds")
    def check_builds():
        _refresh_builds()
        return RedirectResponse("/settings?checked=1", status_code=303)

    return app


def main(argv=None) -> None:
    import argparse
    import getpass

    ap = argparse.ArgumentParser(prog="tmhc web")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--host", default=None, help="default from config web.host, else 0.0.0.0")
    ap.add_argument("--port", type=int, default=None, help="default from config web.port, else 8090")
    ap.add_argument("--set-password", metavar="USER", help="create or change a login, then exit")
    a = ap.parse_args(argv)
    if a.set_password:
        pw = os.environ.get("TMHC_WEB_PASSWORD") or getpass.getpass(f"Password for {a.set_password}: ")
        if len(pw) < 8:
            raise SystemExit("password must be at least 8 characters")
        set_password(a.config, a.set_password, pw)
        print(f"login '{a.set_password}' saved")
        return
    cfg = load_config(a.config)
    web = cfg.get("web") or {}
    if not web.get("users"):
        raise SystemExit(f"no login yet - run: python -m tmhc web --set-password <name>")
    import uvicorn
    uvicorn.run(create_app(a.config), host=a.host or web.get("host", "0.0.0.0"),
                port=a.port or int(web.get("port", 8090)), log_level="info",
                proxy_headers=False, server_header=False)
