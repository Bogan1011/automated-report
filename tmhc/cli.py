"""Command-line entry point.

    python -m tmhc init       clients/acme/profile.yaml   # write a starter profile
    python -m tmhc checklist  clients/acme/profile.yaml   # Excel checklist (no AI)
    python -m tmhc run        clients/acme/profile.yaml   # build the report
    python -m tmhc run        clients/acme/profile.yaml --dry-run    # what would be read
    python -m tmhc run        clients/acme/profile.yaml --offline    # cache/checklist only

Everything runs on this machine. Screenshots are read by a local model
(Ollama) or not at all; the cloud reader exists but is refused unless the
profile sets ``allow_cloud: true``.
"""
from __future__ import annotations

import argparse
import datetime as dt
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

import yaml

from . import checklist
from .engine.evaluate import evaluate, load_rules, status_counts
from .models import Fact, HealthCheck, Source
from .render.docx_report import DEFAULT_TEMPLATE, render
from .render.review import write_review
from .sources import agentlist, ocr, policy, screenshots, v1logs

STARTER_PROFILE = """\
# Client profile for one health check. Paths are relative to this file.
client_name: Acme Industries Private Limited
product: Standard Endpoint Protection
quarter: Q4 2026
check_date: 2026-10-07        # day of the Teams session (YYYY-MM-DD)
report_date: 2026-10-28       # printed on the cover (YYYY-MM-DD)
prepared_by: Your Name
approved_by: Approver Name
account_owner: Account Owner
location: Remotely
customer_attendance: Console Access
trend_attendance: Your Name

evidence:
  screenshots_docx: evidence/Acme_SEP_SS.docx   # Word file of console screenshots
  logs: evidence/Acme_SEP_Logs.zip              # folder or zip of CSV / .cmpolicy exports
  zip_password: ""                              # if the zip is protected
  checklist: checklist.xlsx                     # created by `python -m tmhc checklist`

options:
  rules: apexone_sep
  stale_pattern_releases: 12       # ~7 days of smart-scan pattern releases
  min_confidence: 0.6              # ignore screenshot readings below this
  skip_covered: true               # don't read screenshots for settings the exports prove

  # How screenshots are read. Nothing leaves this machine unless you choose 'cloud'.
  #   ocr       - text recognition + checkbox detection (default; fast, no AI, no GPU)
  #   ocr+local - ocr first, then a local AI model (Ollama) for what ocr missed
  #   none      - don't read screenshots; use the checklist only
  #   local     - local AI model only
  #   cloud     - Anthropic API; ALSO needs allow_cloud: true
  reader: ocr
  local_model: qwen2.5vl:7b        # qwen2.5vl:3b for smaller GPUs
  ollama_host: http://127.0.0.1:11434
  allow_cloud: false

# Values you confirmed in the session but have no screenshot, export or
# checklist entry for. They override everything else.
manual_facts: {}
#  global.scan_cookies: {value: false, display: Disabled}
"""


def _date(value) -> dt.date | None:
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        return None


def _require(path: Path, profile_key: str) -> None:
    if not path.exists():
        here = path.parent
        nearby = sorted(p.name for p in here.iterdir()) if here.is_dir() else []
        hint = f"\n  files in {here}: {', '.join(nearby) or '(none)'}" if here.is_dir() else \
               f"\n  folder {here} does not exist"
        raise SystemExit(f"\nFile not found: {path}\n  check `{profile_key}` in profile.yaml{hint}")


def _unpack_logs(path: Path, password: str) -> tuple[Path, Path | None]:
    _require(path, "evidence: logs")
    if path.is_dir():
        return path, None
    tmp = Path(tempfile.mkdtemp(prefix="tmhc_logs_"))
    with zipfile.ZipFile(path) as z:
        for member in z.infolist():
            target = (tmp / member.filename).resolve()
            if not str(target).startswith(str(tmp.resolve())):
                raise SystemExit(f"refusing unsafe path in zip: {member.filename}")
        try:
            z.extractall(tmp, pwd=password.encode() if password else None)
        except RuntimeError as exc:
            shutil.rmtree(tmp, ignore_errors=True)
            raise SystemExit(f"\nCannot open {path.name}: {exc}\n  check `evidence: zip_password` "
                             "in profile.yaml") from None
    return tmp, tmp


def _load_profile(profile_path: Path) -> tuple[dict, Path, dict, dict]:
    prof = yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}
    return prof, profile_path.parent, prof.get("options", {}) or {}, prof.get("evidence", {}) or {}


def _new_healthcheck(prof: dict) -> tuple[HealthCheck, dt.date]:
    check = _date(prof.get("check_date"))
    report = _date(prof.get("report_date")) or dt.date.today()
    hc = HealthCheck(
        client_name=prof.get("client_name", ""),
        quarter=(f"Q{(check.month - 1) // 3 + 1} {check.year}" if check and str(prof.get("quarter")) in ("auto", "", "None")
                 else str(prof.get("quarter", ""))),
        prepared_by=prof.get("prepared_by", ""), approved_by=prof.get("approved_by", ""),
        account_owner=prof.get("account_owner", ""), location=prof.get("location", "Remotely"),
        attendees_customer=prof.get("customer_attendance", "Console Access"),
        attendees_trend=prof.get("trend_attendance", ""),
        check_date=check.isoformat() if check else "",
        check_date_display=check.strftime("%d-%m-%Y") if check else "",
        report_date=report.strftime("%d/%m/%Y"),
    )
    return hc, report


def _load_exports(hc: HealthCheck, base: Path, ev: dict, opts: dict, say=print) -> None:
    """Policy export, agent list and log exports - all local file parsing."""
    if not ev.get("logs"):
        say("no logs/exports configured - every setting will need a screenshot or checklist entry")
        return
    logs_dir, cleanup = _unpack_logs(base / ev["logs"], str(ev.get("zip_password") or ""))
    try:
        pols = sorted(logs_dir.rglob("*.cmpolicy"))
        for i, pf in enumerate(pols):
            facts, pol = policy.extract(pf)
            if i == 0:
                hc.add_facts(facts)
                hc.policy_name = pol.name
                say(f"policy export: {pol.name} ({len(facts)} settings)")
            else:
                hc.warnings.append(f"Additional policy export {pf.name} ignored - one policy per report")
        agents = next(iter(sorted(logs_dir.rglob("*Agent List*.csv"))), None)
        if agents:
            facts, metrics = agentlist.extract(agents, int(opts.get("stale_pattern_releases", 12)))
            hc.add_facts(facts)
            hc.metrics.update(metrics)
            say(f"agent list: {metrics['deployed_agents']} agents "
                f"({metrics['online']} online / {metrics['offline']} offline)")
        facts, metrics = v1logs.extract_dir(logs_dir)
        hc.add_facts(facts)
        hc.metrics.update(metrics)
        say(f"log exports: {len(facts)} files read")
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


def make_checklist(profile_path: Path, force: bool = False) -> Path:
    prof, base, opts, ev = _load_profile(profile_path)
    rules = load_rules(opts.get("rules", "apexone_sep"))
    hc, _ = _new_healthcheck(prof)
    _load_exports(hc, base, ev, opts)
    out = base / ev.get("checklist", "checklist.xlsx")
    if out.exists() and not force:
        sys.exit(f"{out} already exists - it may hold your answers. Use --force to overwrite.")
    covered = {k for k, f in hc.facts.items() if f.source != Source.SCREENSHOT}
    # Pre-fill anything a local screenshot reading already found, for confirmation.
    cache = screenshots.ShotCache(base / "screenshot_cache.json")
    prefill = {f.key: f for f in cache.facts(float(opts.get("min_confidence", 0.6)))}
    path = checklist.write(out, screenshots.field_catalogue(rules), covered,
                           client=hc.client_name, prefill=prefill)
    print(f"checklist: {path}  - fill the yellow 'Deployed' column, then run the report")
    return path


def build(profile_path: Path, out_dir: Path | None = None, offline: bool = False,
          dry_run: bool = False, template: Path | None = None) -> HealthCheck:
    prof, base, opts, ev = _load_profile(profile_path)
    rules = load_rules(opts.get("rules", "apexone_sep"))
    hc, report = _new_healthcheck(prof)
    say = print

    _load_exports(hc, base, ev, opts, say)

    # ---- screenshots -------------------------------------------------------
    out_dir = out_dir or (base / "output")
    cache_path = base / "screenshot_cache.json"
    reader_kind = str(opts.get("reader", "ocr")).lower()
    min_conf = float(opts.get("min_confidence", 0.6))
    shots_docx = base / ev["screenshots_docx"] if ev.get("screenshots_docx") else None
    if shots_docx and reader_kind != "none" and not offline:
        _require(shots_docx, "evidence: screenshots_docx")
        if reader_kind.startswith("ocr"):
            if dry_run:
                say(f"would OCR every screenshot in {shots_docx.name}")
            else:
                ocr.run(shots_docx, cache_path, opts.get("rules", "apexone_sep"), progress=say)
        model_kind = reader_kind.split("+")[-1] if "+" in reader_kind else (
            reader_kind if reader_kind in ("local", "cloud") else None)
        if model_kind:
            covered = {k for k, f in hc.facts.items() if f.source != Source.SCREENSHOT}
            covered |= {f.key for f in screenshots.ShotCache(cache_path).facts(min_conf)}
            screenshots.run(shots_docx, rules, cache_path, covered_keys=covered,
                            reader=screenshots.make_reader(dict(opts, reader=model_kind)),
                            skip_covered=True, dry_run=dry_run, progress=say)
        if dry_run:
            return hc
    cache_facts = screenshots.ShotCache(cache_path).facts(min_conf)
    if cache_facts:
        hc.add_facts(cache_facts)
        say(f"screenshots: {len(cache_facts)} readings from cache")

    # ---- checklist + analyst entries ---------------------------------------
    cl_path = base / ev.get("checklist", "checklist.xlsx")
    cl_facts = checklist.read(cl_path, screenshots.field_catalogue(rules))
    if cl_facts:
        hc.add_facts(cl_facts)
        say(f"checklist: {len(cl_facts)} values from {cl_path.name}")
    for key, spec in (prof.get("manual_facts") or {}).items():
        spec = spec if isinstance(spec, dict) else {"value": spec, "display": str(spec)}
        hc.add_fact(Fact(key=key, value=spec.get("value"),
                         display=str(spec.get("display", spec.get("value"))),
                         source=Source.MANUAL, evidence=spec.get("note", "entered in client profile")))

    # ---- evaluate + render --------------------------------------------------
    evaluate(hc, rules)
    first = hc.client_name.split()[0] if hc.client_name else "Client"
    stem = f"{first}_SEP_Health_Check_Report_{report.strftime('%b_%Y')}"
    docx_out = render(hc, out_dir / f"{stem}.docx", template or DEFAULT_TEMPLATE,
                      product=prof.get("product", "Standard Endpoint Protection"))
    review_out = write_review(hc, out_dir / f"{stem}_review.xlsx")
    counts = status_counts(hc)
    say(f"\nrows: {counts}")
    if counts.get("unknown"):
        say(f"  {counts['unknown']} settings not captured - see the 'Not captured' sheet, "
            f"or run `python -m tmhc checklist {profile_path}` to fill them in")
    say(f"gaps: {len(hc.gaps_server)} server, {len(hc.gaps_policy)} policy")
    say(f"report: {docx_out}")
    say(f"review: {review_out}")
    return hc


def main(argv=None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["watch"]:
        from .watch import main as watch_main
        return watch_main(argv[1:])
    ap = argparse.ArgumentParser(prog="tmhc", description="Trend Micro health-check report generator")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init", help="write a starter client profile")
    p_init.add_argument("profile", type=Path)
    p_cl = sub.add_parser("checklist", help="create the Excel checklist of settings to fill in")
    p_cl.add_argument("profile", type=Path)
    p_cl.add_argument("--force", action="store_true", help="overwrite an existing checklist")
    p_run = sub.add_parser("run", help="build the report for a client profile")
    p_run.add_argument("profile", type=Path)
    p_run.add_argument("--out", type=Path, help="output folder (default: <profile dir>/output)")
    p_run.add_argument("--offline", action="store_true",
                       help="don't read any new screenshots; use cache, checklist and exports only")
    p_run.add_argument("--dry-run", action="store_true", help="list screenshots that would be read, then stop")
    p_run.add_argument("--template", type=Path, help="alternative Word template")
    sub.add_parser("watch", help="watch an inbox folder and build reports automatically (see tmhc/watch.py)")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "init":
            if a.profile.exists():
                sys.exit(f"{a.profile} already exists")
            a.profile.parent.mkdir(parents=True, exist_ok=True)
            (a.profile.parent / "evidence").mkdir(exist_ok=True)
            a.profile.write_text(STARTER_PROFILE, encoding="utf-8")
            print(f"wrote {a.profile} - put the screenshot .docx and logs zip in "
                  f"{a.profile.parent / 'evidence'}")
        elif a.cmd == "checklist":
            make_checklist(a.profile, force=a.force)
        elif a.cmd == "run":
            build(a.profile, a.out, offline=a.offline, dry_run=a.dry_run, template=a.template)
    except (screenshots.CloudNotAllowed, screenshots.LocalModelUnavailable) as exc:
        sys.exit(f"\n{exc}")


if __name__ == "__main__":
    main()
