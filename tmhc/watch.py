"""Watch an inbox folder and build reports automatically.

    python -m tmhc watch                       # uses ~/healthcheck/config.yaml
    python -m tmhc watch --config /path/config.yaml --once

Layout of the inbox (one folder per client, one sub-folder per report):

    inbox/
      Acme Industries/                    <- the client
        SEP Q4 2026/                      <- one health check (product + quarter)
          Acme_SEP_SS.docx                <- screenshots (any .docx name)
          Acme_SEP_Logs.zip               <- exports     (any .zip name)
          profile.yaml                    <- created automatically, edit if needed
          checklist.xlsx                  <- created after the first run; fill blanks
          output/                         <- the report, presentation and review workbook
          STATUS.txt                      <- what happened, and what to do next
        SEP Q1 2027/
        CECP Q4 2026/

Evidence dropped straight into a client folder (or a new folder named after
the client) is moved into its own "<product> <quarter>" sub-folder once the
copy has finished - so older single-level folders are reorganised too.

A folder is processed once its files have stopped changing (copying
finished). It is processed again whenever the screenshots, exports,
profile or checklist change - so filling the checklist and saving it is
enough to get an updated report.

Everything happens on this machine.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import time
import traceback
from pathlib import Path

import yaml

from . import checklist
from .cli import build, make_checklist
from .engine.evaluate import NOT_CAPTURED, load_rules, status_counts
from .models import Source
from .sources import screenshots

DEFAULT_CONFIG = Path.home() / "healthcheck" / "config.yaml"
STATE_FILE = ".tmhc_state.json"
PROGRESS_FILE = ".progress.json"      # {"pct": 0-100, "stage": "...", "started": iso} while building
GO_FILE = ".go"                       # written by the website: build now, no settle wait
RULES_SHORT = {"apexone_sep": "SEP", "swp": "SWP", "cecp": "CECP"}

DEFAULT_CONFIG_TEXT = """\
# Health-check watcher settings
inbox: {inbox}
poll_seconds: 20          # how often to look for new or changed folders
settle_seconds: 30        # wait until files have not changed for this long

# Used for every new client folder (each folder gets its own profile.yaml,
# which you can edit afterwards).
defaults:
  product: Standard Endpoint Protection
  prepared_by: Your Name
  approved_by: Approver Name
  account_owner: Account Owner
  location: Remotely
  customer_attendance: Console Access
  trend_attendance: Your Name
  zip_password: ""        # the password your log zips usually use
  # Latest agent builds. Filled automatically from Trend Micro's release notes
  # once a day (see tmhc/latest_builds.py); a value set on the website's
  # Settings page is kept as a manual override.
  latest_agent_build: "14.0.21067"     # Standard Endpoint Protection (Oct 2026 release)
  latest_dsa_windows: "20.0.3.31610"   # Server & Workload Protection, Windows
  latest_dsa_linux: "20.0.3.31610"     # Server & Workload Protection, Linux

options:
  rules: apexone_sep
  reader: ocr             # ocr | ocr+local | none   (all local; see README)
  stale_pattern_releases: 12
  min_confidence: 0.6
"""


def _log(msg: str) -> None:
    print(f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)


def load_config(path: Path) -> dict:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        inbox = path.parent / "inbox"
        path.write_text(DEFAULT_CONFIG_TEXT.format(inbox=inbox), encoding="utf-8")
        _log(f"wrote default config {path} - edit your names there")
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cfg["inbox"] = Path(str(cfg.get("inbox") or path.parent / "inbox")).expanduser()
    cfg["inbox"].mkdir(parents=True, exist_ok=True)
    return cfg


# --------------------------------------------------------------------------
# evidence discovery
# --------------------------------------------------------------------------
def _is_ours(p: Path) -> bool:
    return p.name.startswith(("~$", ".")) or "output" in p.parts[-2:-1]


def find_evidence(folder: Path) -> dict:
    docs = [p for p in folder.glob("*.docx") if not _is_ours(p)]
    zips = [p for p in folder.glob("*.zip") if not _is_ours(p)]
    pols = list(folder.glob("*.cmpolicy")) + list(folder.glob("*.xml"))
    csvs = list(folder.glob("*.csv"))
    ev = {}
    if docs:
        ev["screenshots_docx"] = max(docs, key=lambda p: p.stat().st_size).name
    if zips:
        ev["logs"] = max(zips, key=lambda p: p.stat().st_size).name
    elif pols or csvs:
        ev["logs"] = "."          # exports dropped loose in the folder
    return ev


def fingerprint(folder: Path) -> dict:
    fp = {}
    for p in sorted(folder.iterdir()):
        if p.is_file() and not p.name.startswith((".", "~$")) and p.name != "STATUS.txt":
            st = p.stat()
            fp[p.name] = [st.st_size, int(st.st_mtime)]
    return fp


def newest_change(fp: dict) -> float:
    return max((v[1] for v in fp.values()), default=0)


# --------------------------------------------------------------------------
# clients and their reports
# --------------------------------------------------------------------------
def safe_name(name: str) -> str:
    """Client / report name -> folder name: no path tricks, nothing Windows dislikes."""
    import re
    name = re.sub(r"[^\w .&()\-,]", "", str(name), flags=re.UNICODE).strip(" .")
    name = re.sub(r"\s+", " ", name)
    return name[:90]


def _visible_dirs(folder: Path) -> list[Path]:
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir()
                  if p.is_dir() and not p.name.startswith((".", "_")) and p.name != "output")


def iter_clients(inbox: Path) -> list[Path]:
    return _visible_dirs(inbox)


def iter_jobs(inbox: Path) -> list[Path]:
    """Every report folder: inbox/<client>/<report>."""
    return [job for client in iter_clients(inbox) for job in _visible_dirs(client)]


def job_key(folder: Path) -> str:
    return f"{folder.parent.name}/{folder.name}"


def short_of(prof: dict) -> str:
    rules = str((prof.get("options") or {}).get("rules", "apexone_sep"))
    if rules in RULES_SHORT:
        return RULES_SHORT[rules]
    try:
        from .cli import pack_short
        return pack_short(load_rules(rules))
    except Exception:
        return "SEP"


def quarter_of(prof: dict) -> str:
    """The quarter a report belongs to: as entered, else from the check date, else the report date."""
    q = str(prof.get("quarter") or "")
    if q and q != "auto":
        return q
    for k in ("check_date", "report_date"):
        try:
            return _quarter(dt.date.fromisoformat(str(prof.get(k))))
        except ValueError:
            continue
    return _quarter(dt.date.today())


def unique_dir(parent: Path, name: str) -> Path:
    cand, i = parent / name, 2
    while cand.exists():
        cand, i = parent / f"{name} ({i})", i + 1
    return cand


def _loose_items(folder: Path) -> list[Path]:
    """What makes a folder a report rather than a client: evidence or a profile right inside it."""
    return [p for p in folder.iterdir()
            if (p.is_file() and p.name != "client.yaml") or p.name in ("output", ".logs_cache")]


def migrate_loose(cfg: dict, state: dict, settle: float = 0) -> list[tuple[str, str]]:
    """Move reports that sit directly in a top-level folder into <client>/<product> <quarter>/."""
    inbox: Path = cfg["inbox"]
    moved = []
    for d in iter_clients(inbox):
        if not (find_evidence(d) or (d / "profile.yaml").exists()):
            continue
        fp = fingerprint(d)
        if settle and not (d / GO_FILE).exists() and time.time() - newest_change(fp) < settle:
            continue                                   # still copying
        if (d / ".building").exists():
            continue
        prof_path = ensure_profile(d, cfg) if find_evidence(d) else d / "profile.yaml"
        prof = yaml.safe_load(prof_path.read_text(encoding="utf-8")) or {}
        client = safe_name(prof.get("client_name") or d.name) or d.name
        job = safe_name(f"{short_of(prof)} {quarter_of(prof)}")
        subdirs = _visible_dirs(d)
        if not subdirs:                                # the whole folder is one report
            if client == d.name:
                tmp = inbox / f".moving-{d.name}"
                d.rename(tmp)
                (inbox / client).mkdir()
                dest = unique_dir(inbox / client, job)
                tmp.rename(dest)
            else:
                (inbox / client).mkdir(exist_ok=True)
                dest = unique_dir(inbox / client, job)
                d.rename(dest)
        else:                                          # a client folder with loose new evidence
            dest = unique_dir(d, job)
            dest.mkdir()
            for item in _loose_items(d):
                item.rename(dest / item.name)
        old = d.name
        if old in state:
            state[job_key(dest)] = state.pop(old)
        moved.append((old, job_key(dest)))
        _log(f"[{old}] moved to {job_key(dest)}")
    if moved:
        _save_state(inbox, state)
    return moved


class Progress:
    """Writes <report>/.progress.json for the website (percent done + current step)."""

    def __init__(self, folder: Path):
        self.path = folder / PROGRESS_FILE
        self.pct, self.stage, self.t = -1, "", 0.0
        self.started = dt.datetime.now().isoformat(timespec="seconds")

    def __call__(self, pct: float, stage: str) -> None:
        pct = max(self.pct, min(100, int(pct)))       # never goes backwards
        now = time.time()
        if pct == self.pct and stage == self.stage and now - self.t < 3:
            return
        self.pct, self.stage, self.t = pct, stage, now
        tmp = self.path.with_name(PROGRESS_FILE + ".tmp")
        tmp.write_text(json.dumps({"pct": pct, "stage": stage, "started": self.started,
                                   "at": dt.datetime.now().isoformat(timespec="seconds")}), encoding="utf-8")
        tmp.replace(self.path)


def read_progress(folder: Path) -> dict:
    try:
        return json.loads((folder / PROGRESS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# --------------------------------------------------------------------------
# profile
# --------------------------------------------------------------------------
def _quarter(d: dt.date) -> str:
    return f"Q{(d.month - 1) // 3 + 1} {d.year}"


def ensure_profile(folder: Path, cfg: dict) -> Path:
    prof_path = folder / "profile.yaml"
    ev = find_evidence(folder)
    if prof_path.exists():
        prof = yaml.safe_load(prof_path.read_text(encoding="utf-8")) or {}
        changed = False
        for k, v in ev.items():                   # keep evidence names in step with the folder
            if prof.setdefault("evidence", {}).get(k) != v:
                prof["evidence"][k] = v
                changed = True
        if changed:
            prof_path.write_text(yaml.safe_dump(prof, sort_keys=False, allow_unicode=True), encoding="utf-8")
        return prof_path

    d = dict(cfg.get("defaults") or {})
    today = dt.date.today()
    prof = {
        "client_name": folder.name.replace("_", " ").strip(),
        "product": d.get("product", "Standard Endpoint Protection"),
        "quarter": "auto",
        "check_date": "auto",          # read from the screenshots' taskbar clock
        "report_date": today.isoformat(),
        "prepared_by": d.get("prepared_by", ""),
        "approved_by": d.get("approved_by", ""),
        "account_owner": d.get("account_owner", ""),
        "location": d.get("location", "Remotely"),
        "customer_attendance": d.get("customer_attendance", "Console Access"),
        "trend_attendance": d.get("trend_attendance", d.get("prepared_by", "")),
        "latest_agent_build": d.get("latest_agent_build", ""),
        "evidence": {**ev, "zip_password": d.get("zip_password", ""), "checklist": "checklist.xlsx"},
        "options": dict(cfg.get("options") or {"reader": "ocr"}),
    }
    header = ("# Created automatically from config.yaml. Edit freely - saving this file\n"
              "# re-runs the report. client_name is taken from the folder name: put the\n"
              "# full legal name here (e.g. '... Private Limited').\n")
    prof_path.write_text(header + yaml.safe_dump(prof, sort_keys=False, allow_unicode=True), encoding="utf-8")
    _log(f"[{folder.name}] created profile.yaml")
    return prof_path


def resolve_auto_fields(prof_path: Path) -> None:
    """Fill 'auto' dates from what the screenshots show (after OCR has run)."""
    prof = yaml.safe_load(prof_path.read_text(encoding="utf-8")) or {}
    cache = prof_path.parent / "screenshot_cache.json"
    guess = ""
    if cache.exists():
        guess = json.loads(cache.read_text(encoding="utf-8")).get("check_date_guess", "")
    changed = False
    if str(prof.get("check_date")) == "auto":
        prof["check_date"] = guess or dt.date.today().isoformat()
        changed = True
    if str(prof.get("quarter")) == "auto":
        try:
            d = dt.date.fromisoformat(str(prof["check_date"]))
        except ValueError:
            d = dt.date.today()
        prof["quarter"] = _quarter(d)
        changed = True
    if changed:
        text = prof_path.read_text(encoding="utf-8")
        header = "".join(l for l in text.splitlines(True) if l.startswith("#"))
        prof_path.write_text(header + yaml.safe_dump(prof, sort_keys=False, allow_unicode=True),
                             encoding="utf-8")


# --------------------------------------------------------------------------
# one folder
# --------------------------------------------------------------------------
def process(folder: Path, cfg: dict, progress=None) -> str:
    started = time.time()
    tick = progress or (lambda pct, stage: None)
    ev = find_evidence(folder)
    if not ev:
        return "waiting for evidence (.docx screenshots and/or .zip exports)"
    tick(2, "Starting")
    prof_path = ensure_profile(folder, cfg)

    # OCR first so the check date can be filled from the screenshots
    prof = yaml.safe_load(prof_path.read_text(encoding="utf-8"))
    if str(prof.get("check_date")) == "auto" and ev.get("screenshots_docx"):
        from .sources import ocr
        if str((prof.get("options") or {}).get("reader", "ocr")).startswith("ocr"):
            ocr.run(folder / ev["screenshots_docx"], folder / "screenshot_cache.json",
                    (prof.get("options") or {}).get("rules", "apexone_sep"),
                    progress=lambda m: _log(f"[{job_key(folder)}] {m}"),
                    tick=lambda i, n: tick(10 + 60 * i / max(n, 1), f"Reading screenshots ({i} of {n})"))
    resolve_auto_fields(prof_path)

    hc = build(prof_path, progress=tick)
    tick(97, "Updating the checklist")
    make_checklist(prof_path, sync=True, quiet=True)      # new settings added, answers kept

    # what the website should ask for: every row still "Not captured", once per setting
    seen, pending = set(), []
    for r in hc.rows_server + hc.rows_policy:
        if r.deployed == NOT_CAPTURED and r.key and r.key not in seen:
            seen.add(r.key)
            pending.append({"key": r.key, "section": r.section, "setting": r.group or r.component,
                            "recommended": r.recommended})
    (folder / ".not_captured.json").write_text(json.dumps(pending, indent=1), encoding="utf-8")

    counts = status_counts(hc)
    missing = sorted({r.key for r in hc.rows_server + hc.rows_policy if r.deployed == NOT_CAPTURED})
    from_shots = sum(1 for f in hc.facts.values() if f.source == Source.SCREENSHOT)
    outputs = sorted((folder / "output").glob("*.docx"))
    lines = [
        f"Report built {dt.datetime.now():%d %b %Y %H:%M} in {time.time() - started:.0f}s",
        f"Report:  output/{outputs[-1].name if outputs else '?'}",
        f"Review:  output/{outputs[-1].stem + '_review.xlsx' if outputs else '?'}",
        "",
        f"Client: {hc.client_name}   Policy: {hc.policy_name or '-'}   Check date: {hc.check_date}",
        f"Rows: {counts['good']} good, {counts['concern']} concern, {counts['critical']} critical, "
        f"{counts['info']} info, {counts['unknown']} not captured",
        f"Gaps: {len(hc.gaps_server)} server, {len(hc.gaps_policy)} policy",
        f"Values read from screenshots: {from_shots}",
        "",
    ]
    if missing:
        lines += [f"{len(missing)} settings were not captured. Fill them in the checklist (website:",
                  "'Fill checklist', or checklist.xlsx in this folder) and save - the report rebuilds.",
                  "Also check the screenshot readings in the review workbook (Source = Screenshot).", ""]
    else:
        lines += ["Every setting was captured. Spot-check screenshot readings in the review workbook.", ""]
    if hc.warnings:
        lines += ["Notes:"] + [f"  - {w}" for w in hc.warnings if not w.startswith("No data")][:15]
    (folder / "STATUS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return f"done: {counts['unknown']} not captured, {len(hc.gaps_server) + len(hc.gaps_policy)} gaps"


# --------------------------------------------------------------------------
# loop
# --------------------------------------------------------------------------
def _load_state(inbox: Path) -> dict:
    p = inbox / STATE_FILE
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(inbox: Path, state: dict) -> None:
    (inbox / STATE_FILE).write_text(json.dumps(state, indent=1), encoding="utf-8")


def scan_once(cfg: dict, state: dict, force_settle: bool = False) -> bool:
    inbox: Path = cfg["inbox"]
    settle = 0 if force_settle else int(cfg.get("settle_seconds", 30))
    migrate_loose(cfg, state, settle)
    did = False
    for folder in iter_jobs(inbox):
        key = job_key(folder)
        go = (folder / GO_FILE).exists()
        fp = fingerprint(folder)
        if not find_evidence(folder):
            continue
        if state.get(key, {}).get("fp") == fp and not go:
            continue
        if not go and time.time() - newest_change(fp) < settle:
            continue                                  # still copying / saving
        (folder / GO_FILE).unlink(missing_ok=True)
        _log(f"[{key}] building report...")
        marker = folder / ".building"
        marker.write_text(dt.datetime.now().isoformat(), encoding="utf-8")
        prog = Progress(folder)
        prog(1, "Starting")
        try:
            result = process(folder, cfg, progress=prog)
        except SystemExit as exc:                     # friendly errors from the CLI
            result = f"stopped: {str(exc).strip()}"
            (folder / "STATUS.txt").write_text(f"Could not build the report:\n\n{str(exc).strip()}\n"
                                               "\nFix the above and save any file in this folder to retry.\n",
                                               encoding="utf-8")
        except Exception as exc:
            result = f"error: {exc}"
            (folder / "STATUS.txt").write_text("Could not build the report:\n\n" + traceback.format_exc(),
                                               encoding="utf-8")
        finally:
            marker.unlink(missing_ok=True)
            (folder / PROGRESS_FILE).unlink(missing_ok=True)
        _log(f"[{key}] {result}")
        state[key] = {"fp": fingerprint(folder), "at": dt.datetime.now().isoformat(), "result": result}
        _save_state(inbox, state)
        did = True
    return did


def _wait(cfg: dict, seconds: int) -> None:
    """Sleep, but wake up at once when the website asks for a build."""
    inbox: Path = cfg["inbox"]
    end = time.time() + seconds
    while time.time() < end:
        if any(inbox.glob(f"*/*/{GO_FILE}")) or any(inbox.glob(f"*/{GO_FILE}")):
            return
        time.sleep(1)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="tmhc watch")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--once", action="store_true", help="process what is there now, then exit")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    state = _load_state(cfg["inbox"])
    _log(f"watching {cfg['inbox']} (every {cfg.get('poll_seconds', 20)}s)")
    if a.once:
        scan_once(cfg, state, force_settle=True)
        return
    for pattern in ("*/.building", "*/*/.building", f"*/*/{PROGRESS_FILE}"):   # left over from a crash/restart
        for stale in cfg["inbox"].glob(pattern):
            stale.unlink(missing_ok=True)
    while True:
        try:
            cfg = load_config(a.config)               # pick up settings changed on the website
            state = _load_state(cfg["inbox"])
            scan_once(cfg, state)
        except Exception as exc:                      # never let the service die
            _log(f"scan error: {exc}")
        _wait(cfg, int(cfg.get("poll_seconds", 20)))


# --------------------------------------------------------------------------
# status for the website
# --------------------------------------------------------------------------
def client_status(folder: Path, state: dict | None = None) -> dict:
    """waiting | queued | building | done | error, plus a one-line detail and (building) pct."""
    if state is None:
        state = _load_state(folder.parent.parent)
    if (folder / ".building").exists():
        pr = read_progress(folder)
        return {"status": "building", "detail": pr.get("stage") or "Building the report...",
                "pct": int(pr.get("pct", 1)), "started": pr.get("started", "")}
    if not find_evidence(folder):
        return {"status": "waiting", "detail": "Upload the screenshots and/or logs", "pct": 0}
    entry = state.get(job_key(folder)) or {}
    if entry.get("fp") == fingerprint(folder) and not (folder / GO_FILE).exists():
        result = entry.get("result", "")
        status = "done" if result.startswith("done") else "error"
        return {"status": status, "detail": result, "at": entry.get("at", ""), "pct": 100 if status == "done" else 0}
    return {"status": "queued", "detail": "Queued - starts in a few seconds", "pct": 0}
