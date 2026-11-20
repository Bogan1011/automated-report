"""Command-line entry point.

    python -m tmhc init  clients/acme/profile.yaml      # write a starter profile
    python -m tmhc run   clients/acme/profile.yaml      # build the report
    python -m tmhc run   clients/acme/profile.yaml --dry-run   # show what would be read
    python -m tmhc run   clients/acme/profile.yaml --offline   # cache + exports only, no API
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

from .engine.evaluate import load_rules, evaluate, status_counts
from .models import Fact, HealthCheck, Source
from .render.docx_report import DEFAULT_TEMPLATE, render
from .render.review import write_review
from .sources import agentlist, policy, screenshots, v1logs

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

options:
  rules: apexone_sep               # rule pack in tmhc/rules/
  stale_pattern_releases: 12       # ~7 days of smart-scan pattern releases
  min_confidence: 0.6              # ignore screenshot readings below this
  model: claude-sonnet-5-5         # vision model for screenshots
  skip_covered: true               # don't read screenshots for settings the .cmpolicy proves

# Values you confirmed in the session but have no screenshot or export for.
# They override everything else and are labelled "Analyst entry" in the
# review workbook.
manual_facts: {}
#  global.scan_cookies: {value: false, display: Disabled}
#  global.pattern_alert_icon: {value: false, display: Disabled}
"""


def _date(value) -> dt.date | None:
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        return None


def _unpack_logs(path: Path, password: str) -> tuple[Path, Path | None]:
    if path.is_dir():
        return path, None
    tmp = Path(tempfile.mkdtemp(prefix="tmhc_logs_"))
    with zipfile.ZipFile(path) as z:
        for member in z.infolist():
            target = (tmp / member.filename).resolve()
            if not str(target).startswith(str(tmp.resolve())):
                raise SystemExit(f"refusing unsafe path in zip: {member.filename}")
        z.extractall(tmp, pwd=password.encode() if password else None)
    return tmp, tmp


def build(profile_path: Path, out_dir: Path | None = None, offline: bool = False,
          dry_run: bool = False, template: Path | None = None) -> HealthCheck:
    prof = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    base = profile_path.parent
    opts = prof.get("options", {}) or {}
    ev = prof.get("evidence", {}) or {}
    rules = load_rules(opts.get("rules", "apexone_sep"))

    check = _date(prof.get("check_date"))
    report = _date(prof.get("report_date")) or dt.date.today()
    hc = HealthCheck(
        client_name=prof.get("client_name", ""), quarter=str(prof.get("quarter", "")),
        prepared_by=prof.get("prepared_by", ""), approved_by=prof.get("approved_by", ""),
        account_owner=prof.get("account_owner", ""), location=prof.get("location", "Remotely"),
        attendees_customer=prof.get("customer_attendance", "Console Access"),
        attendees_trend=prof.get("trend_attendance", ""),
        check_date=check.isoformat() if check else "",
        check_date_display=check.strftime("%d-%m-%Y") if check else "",
        report_date=report.strftime("%d/%m/%Y"),
    )
    say = print

    # ---- structured exports ------------------------------------------------
    cleanup = None
    if ev.get("logs"):
        logs_dir, cleanup = _unpack_logs(base / ev["logs"], str(ev.get("zip_password") or ""))
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

    # ---- screenshots -------------------------------------------------------
    out_dir = out_dir or (base / "output")
    cache_path = base / "screenshot_cache.json"
    if ev.get("screenshots_docx"):
        docx_path = base / ev["screenshots_docx"]
        covered = {k for k, f in hc.facts.items() if f.source != Source.SCREENSHOT}
        if offline:
            cache = screenshots.ShotCache(cache_path)
            facts = cache.facts(float(opts.get("min_confidence", 0.6)))
            say(f"screenshots: offline, {len(facts)} readings from cache")
        else:
            facts, cache = screenshots.run(
                docx_path, rules, cache_path, covered_keys=covered,
                model=opts.get("model", screenshots.DEFAULT_MODEL),
                skip_covered=bool(opts.get("skip_covered", True)), dry_run=dry_run, progress=say)
            facts = cache.facts(float(opts.get("min_confidence", 0.6)))
        hc.add_facts(facts)
        if dry_run:
            return hc

    # ---- analyst entries ----------------------------------------------------
    for key, spec in (prof.get("manual_facts") or {}).items():
        spec = spec if isinstance(spec, dict) else {"value": spec, "display": str(spec)}
        hc.add_fact(Fact(key=key, value=spec.get("value"), display=str(spec.get("display", spec.get("value"))),
                         source=Source.MANUAL, evidence=spec.get("note", "entered in client profile")))

    # ---- evaluate + render --------------------------------------------------
    evaluate(hc, rules)
    stem = f"{hc.client_name.split()[0] if hc.client_name else 'Client'}_SEP_Health_Check_Report_{report.strftime('%b_%Y')}"
    docx_out = render(hc, out_dir / f"{stem}.docx", template or DEFAULT_TEMPLATE,
                      product=prof.get("product", "Standard Endpoint Protection"))
    review_out = write_review(hc, out_dir / f"{stem}_review.xlsx")
    counts = status_counts(hc)
    say(f"\nrows: {counts}")
    say(f"gaps: {len(hc.gaps_server)} server, {len(hc.gaps_policy)} policy")
    say(f"report: {docx_out}")
    say(f"review: {review_out}")
    if cleanup:
        shutil.rmtree(cleanup, ignore_errors=True)
    return hc


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="tmhc", description="Trend Micro health-check report generator")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init", help="write a starter client profile")
    p_init.add_argument("profile", type=Path)
    p_run = sub.add_parser("run", help="build the report for a client profile")
    p_run.add_argument("profile", type=Path)
    p_run.add_argument("--out", type=Path, help="output folder (default: <profile dir>/output)")
    p_run.add_argument("--offline", action="store_true", help="use the screenshot cache only, no API calls")
    p_run.add_argument("--dry-run", action="store_true", help="list screenshots that would be read, then stop")
    p_run.add_argument("--template", type=Path, help="alternative Word template")
    a = ap.parse_args(argv)

    if a.cmd == "init":
        if a.profile.exists():
            sys.exit(f"{a.profile} already exists")
        a.profile.parent.mkdir(parents=True, exist_ok=True)
        a.profile.write_text(STARTER_PROFILE, encoding="utf-8")
        print(f"wrote {a.profile}")
    elif a.cmd == "run":
        build(a.profile, a.out, offline=a.offline, dry_run=a.dry_run, template=a.template)


if __name__ == "__main__":
    main()
