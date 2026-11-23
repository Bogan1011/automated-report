"""Watch an inbox folder and build reports automatically.

    python -m tmhc watch                       # uses ~/healthcheck/config.yaml
    python -m tmhc watch --config /path/config.yaml --once

Layout of the inbox (one folder per client):

    inbox/
      Acme Industries/
        Acme_SEP_SS.docx     <- screenshots (any .docx name)
        Acme_SEP_Logs.zip            <- exports     (any .zip name)
        profile.yaml                    <- created automatically, edit if needed
        checklist.xlsx                  <- created after the first run; fill blanks
        output/                         <- the report and review workbook
        STATUS.txt                      <- what happened, and what to do next

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
  latest_agent_build: ""  # Trend's current Apex One agent build, e.g. 14.0.20958

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
def process(folder: Path, cfg: dict) -> str:
    started = time.time()
    ev = find_evidence(folder)
    if not ev:
        return "waiting for evidence (.docx screenshots and/or .zip exports)"
    prof_path = ensure_profile(folder, cfg)

    # OCR first so the check date can be filled from the screenshots
    prof = yaml.safe_load(prof_path.read_text(encoding="utf-8"))
    if str(prof.get("check_date")) == "auto" and ev.get("screenshots_docx"):
        from .sources import ocr
        if str((prof.get("options") or {}).get("reader", "ocr")).startswith("ocr"):
            ocr.run(folder / ev["screenshots_docx"], folder / "screenshot_cache.json",
                    (prof.get("options") or {}).get("rules", "apexone_sep"),
                    progress=lambda m: _log(f"[{folder.name}] {m}"))
    resolve_auto_fields(prof_path)

    hc = build(prof_path)
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
    did = False
    for folder in sorted(p for p in inbox.iterdir() if p.is_dir() and not p.name.startswith((".", "_"))):
        fp = fingerprint(folder)
        if not find_evidence(folder):
            continue
        if state.get(folder.name, {}).get("fp") == fp:
            continue
        if time.time() - newest_change(fp) < settle:
            continue                                  # still copying / saving
        _log(f"[{folder.name}] building report...")
        marker = folder / ".building"
        marker.write_text(dt.datetime.now().isoformat(), encoding="utf-8")
        try:
            result = process(folder, cfg)
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
        _log(f"[{folder.name}] {result}")
        state[folder.name] = {"fp": fingerprint(folder), "at": dt.datetime.now().isoformat(), "result": result}
        _save_state(inbox, state)
        did = True
    return did


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
    for stale in cfg["inbox"].glob("*/.building"):     # left over from a crash/restart
        stale.unlink(missing_ok=True)
    while True:
        try:
            cfg = load_config(a.config)               # pick up settings changed on the website
            state = _load_state(cfg["inbox"])
            scan_once(cfg, state)
        except Exception as exc:                      # never let the service die
            _log(f"scan error: {exc}")
        time.sleep(int(cfg.get("poll_seconds", 20)))


# --------------------------------------------------------------------------
# status for the website
# --------------------------------------------------------------------------
def client_status(folder: Path, state: dict | None = None) -> dict:
    """waiting | queued | building | done | error, plus a one-line detail."""
    if state is None:
        state = _load_state(folder.parent)
    if (folder / ".building").exists():
        return {"status": "building", "detail": "Building the report..."}
    if not find_evidence(folder):
        return {"status": "waiting", "detail": "Upload the screenshots and/or logs"}
    entry = state.get(folder.name) or {}
    if entry.get("fp") == fingerprint(folder):
        result = entry.get("result", "")
        status = "done" if result.startswith("done") else "error"
        return {"status": status, "detail": result, "at": entry.get("at", "")}
    return {"status": "queued", "detail": "Queued - starts when the upload has settled"}
