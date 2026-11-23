"""Look up Trend Micro's latest agent builds on Trend's own public pages.

* Standard Endpoint Protection (Vision One SEP / Apex One as a Service):
  the monthly hotfix readme on files.trendmicro.com lists
  "Security Agent version: 14.0.NNNNN".
* Server & Workload Protection (Deep Security Agent 20 LTS):
  the agent release notes on help.deepsecurity.trendmicro.com list
  "Build number: 20.0.3-NNNNN" (Windows and Linux ship the same build).

A small scheduled job (systemd timer tmhc-builds, every 5 minutes) runs
`tmhc builds`: it checks Trend once a day, or straight away when the website's
"Check Trend Micro now" button left a request file. It is the only part of
the server allowed to reach the internet; the website and the report builder
stay offline. A value the analyst typed in Settings is marked manual and is never
overwritten until "use Trend's latest automatically" is ticked again.

Only these public pages are requested - no client data leaves the server.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import urllib.request
from pathlib import Path
from typing import Callable, Optional

import yaml

SEP_README = "https://files.trendmicro.com/documentation/readme/ApexSaaS/ApexOne_SaaS_{ym}_Readme.html"
DSA_NOTES = "https://help.deepsecurity.trendmicro.com/release-notes-dsa.html"
KEYS = {"latest_agent_build": "SEP", "latest_dsa_windows": "SWP Windows", "latest_dsa_linux": "SWP Linux"}
CHECK_EVERY = dt.timedelta(hours=24)

Fetch = Callable[[str], Optional[str]]


def _fetch(url: str) -> Optional[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (tmhc health-check report tool)"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            if r.status != 200:
                return None
            return r.read().decode("utf-8", "ignore")
    except Exception:
        return None


def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def latest_sep(fetch: Fetch = _fetch, today: Optional[dt.date] = None, months: int = 14) -> Optional[tuple[str, str]]:
    """Newest Apex One SaaS / SEP Security Agent build -> ('14.0.21067', source url)."""
    today = today or dt.date.today()
    best = None
    y, m = today.year, today.month
    found_pages = 0
    for _ in range(months):
        url = SEP_README.format(ym=f"{y}{m:02d}")
        html = fetch(url)
        if html:
            text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))
            for b in re.findall(r"Security Agent version\s*:\s*14\.0\.(?:0\.)?(\d{4,6})", text, re.I):
                v = f"14.0.{b}"
                if best is None or _vkey(v) > _vkey(best[0]):
                    best = (v, url)
            found_pages += 1
            if found_pages >= 2 and best:          # the two newest readmes are enough
                break
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return best


def latest_swp(fetch: Fetch = _fetch) -> Optional[tuple[str, str, str]]:
    """Newest Deep Security Agent 20 build -> (windows, linux, source url)."""
    html = fetch(DSA_NOTES)
    if not html:
        return None
    text = re.sub(r"<[^>]+>", " ", html)
    builds = [f"{a}.{b}" for a, b in re.findall(r"Build number:\s*(20\.\d+\.\d+)[-.](\d{3,6})", text)]
    if not builds:
        builds = [f"{a}.{b}" for a, b in re.findall(r"Deep Security Agent\s*-\s*(20\.\d+\.\d+)-(\d{3,6})", text)]
    if not builds:
        return None
    # the page has a Linux and a Windows part; take each part's newest if they can be told apart
    idx = [m.start() for m in re.finditer(r"\bWindows\b", text)]
    newest = max(builds, key=_vkey)
    win = lin = newest
    split = re.search(r"(?:Deep Security Agent (?:for )?Windows|Windows agent release notes|Windows\s+Deep Security Agent)",
                      text, re.I)
    if split and idx:
        first, second = text[:split.start()], text[split.start():]
        lb = [f"{a}.{b}" for a, b in re.findall(r"(20\.\d+\.\d+)-(\d{3,6})", first)]
        wb = [f"{a}.{b}" for a, b in re.findall(r"(20\.\d+\.\d+)-(\d{3,6})", second)]
        if lb and wb:
            lin, win = max(lb, key=_vkey), max(wb, key=_vkey)
    return win, lin, DSA_NOTES


def check(fetch: Fetch = _fetch, today: Optional[dt.date] = None) -> dict:
    """{'latest_agent_build': ('14.0.21067', url), 'latest_dsa_windows': (...), ...} for what was found."""
    out: dict = {}
    sep = latest_sep(fetch, today)
    if sep:
        out["latest_agent_build"] = sep
    swp = latest_swp(fetch)
    if swp:
        win, lin, url = swp
        out["latest_dsa_windows"] = (win, url)
        out["latest_dsa_linux"] = (lin, url)
    return out


def _save(path: Path, cfg: dict) -> None:
    data = dict(cfg)
    data["inbox"] = str(data.get("inbox", ""))
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    header = "".join(l for l in text.splitlines(True) if l.startswith("#")) or "# Health-check settings\n"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)


def due(cfg: dict, now: Optional[dt.datetime] = None) -> bool:
    info = (cfg.get("defaults") or {}).get("latest_builds") or {}
    last = info.get("checked")
    if not last:
        return True
    try:
        return (now or dt.datetime.now()) - dt.datetime.fromisoformat(str(last)) >= CHECK_EVERY
    except ValueError:
        return True


def refresh(config_path: Path, force: bool = False, fetch: Fetch = _fetch, log=print) -> dict:
    """Update the default latest builds from Trend Micro (skips values set manually)."""
    config_path = Path(config_path)
    cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    if not force and not due(cfg):
        return {}
    found = check(fetch)
    d = cfg.setdefault("defaults", {})
    info = d.setdefault("latest_builds", {})
    info["checked"] = dt.datetime.now().replace(microsecond=0).isoformat()
    info["error"] = "" if found else "Trend Micro pages could not be reached - kept the current values"
    changed = {}
    for key, (value, url) in found.items():
        info.setdefault("sources", {})[key] = url
        if d.get(f"{key}_manual"):
            continue
        if value != d.get(key):
            changed[key] = (d.get(key, ""), value)
            d[key] = value
            d[f"{key}_updated"] = dt.date.today().isoformat()
    _save(config_path, cfg)
    for key, (old, new) in changed.items():
        log(f"latest {KEYS[key]} build from Trend Micro: {new} (was {old or 'not set'})")
    if not found:
        log(info["error"])
    return changed


REQUEST_FILE = ".check_builds"


def request_check(config_path: Path) -> None:
    """Ask the scheduled job to check now (the website itself has no internet access)."""
    (Path(config_path).parent / REQUEST_FILE).write_text(dt.datetime.now().isoformat(), encoding="utf-8")


def run_scheduled(config_path: Path, force: bool = False, fetch: Fetch = _fetch, log=print) -> dict:
    flag = Path(config_path).parent / REQUEST_FILE
    requested = flag.exists()
    changed = refresh(config_path, force=force or requested, fetch=fetch, log=log)
    if requested:
        flag.unlink(missing_ok=True)
    return changed


def main(argv=None) -> None:
    import argparse
    from .watch import DEFAULT_CONFIG
    ap = argparse.ArgumentParser(prog="tmhc builds", description="update the latest agent builds from Trend Micro")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--force", action="store_true", help="check now even if checked within the last day")
    a = ap.parse_args(argv)
    if not a.config.exists():
        raise SystemExit(f"{a.config} not found")
    run_scheduled(a.config, force=a.force)
    d = (yaml.safe_load(a.config.read_text(encoding="utf-8")) or {}).get("defaults") or {}
    for key, label in KEYS.items():
        print(f"  {label:12s} {d.get(key, '') or 'not set':14s} {'(manual)' if d.get(key + '_manual') else ''}")
