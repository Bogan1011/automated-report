"""Derive deployment metrics from the Apex One Security Agent List export.

Every count quoted in the executive summary and in the server-side gap
table (deployed agents, online/offline split, agent build spread,
endpoints awaiting a restart, agents running stale patterns, agents on a
server OS) is computed here, so the analyst never transcribes a number
from a console screenshot.
"""
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from ..models import Fact, Source

# Smart Scan Agent Pattern versions are published roughly twice a day, so
# "N releases behind" is the offline proxy for pattern age. 12 releases
# therefore approximates one week. Override in the client profile if your
# console reports a different cadence.
DEFAULT_STALE_RELEASES = 12


def _version_key(v: str) -> tuple:
    try:
        return tuple(int(x) for x in str(v).split("."))
    except (ValueError, AttributeError):
        return (-1,)


def _is_server(platform: str) -> bool:
    return "server" in (platform or "").lower()


class AgentInventory:
    """Parsed Apex One agent list."""

    def __init__(self, path: str | Path, stale_releases: int = DEFAULT_STALE_RELEASES):
        self.path = Path(path)
        self.stale_releases = stale_releases
        with self.path.open(encoding="utf-8-sig", newline="") as fh:
            self.rows: list[dict] = [r for r in csv.DictReader(fh) if any(r.values())]

    # -- basic counts ------------------------------------------------------
    @property
    def total(self) -> int:
        return len(self.rows)

    @property
    def connection(self) -> Counter:
        return Counter(r.get("Connection Status", "").strip() for r in self.rows)

    @property
    def builds(self) -> Counter:
        return Counter(r.get("Agent Program", "").strip() for r in self.rows)

    @property
    def latest_build(self) -> str:
        valid = [b for b in self.builds if b]
        return max(valid, key=_version_key) if valid else ""

    @property
    def outdated_agents(self) -> int:
        return self.total - self.builds.get(self.latest_build, 0)

    @property
    def restart_required(self) -> int:
        return sum(
            1 for r in self.rows
            if "yes" in (r.get("Restart Required", "") or "").strip().lower()
        )

    @property
    def server_agents(self) -> int:
        return sum(1 for r in self.rows if _is_server(r.get("Platform", "")))

    @property
    def scan_methods(self) -> Counter:
        return Counter(r.get("Scan Method", "").strip() for r in self.rows)

    # -- pattern freshness -------------------------------------------------
    @property
    def latest_pattern(self) -> str:
        pats = [r.get("Smart Scan Agent Pattern", "").strip() for r in self.rows]
        valid = [p for p in pats if p and p.replace(".", "").isdigit()]
        return max(valid, key=_version_key) if valid else ""

    def stale_pattern_agents(self) -> int:
        """Agents whose smart-scan pattern is more than `stale_releases` behind."""
        latest = self.latest_pattern
        if not latest:
            return 0
        lk = _version_key(latest)
        major, minor = lk[0], lk[1] if len(lk) > 1 else 0
        cutoff = (major, minor - self.stale_releases)
        n = 0
        for r in self.rows:
            p = (r.get("Smart Scan Agent Pattern") or "").strip()
            k = _version_key(p)
            if k == (-1,) or len(k) < 2:
                n += 1
                continue
            if (k[0], k[1]) < cutoff:
                n += 1
        return n

    def builds_behind(self, n: int = 3) -> int:
        """Agents more than `n` distinct builds behind the newest one (the report's N-3 check)."""
        ordered = sorted((b for b in self.builds if b), key=_version_key, reverse=True)
        if len(ordered) <= n:
            return 0
        cutoff = _version_key(ordered[n])
        return sum(c for b, c in self.builds.items() if b and _version_key(b) < cutoff)

    def build_breakdown(self) -> str:
        """The multi-line build spread used in the overview table."""
        return "\n".join(
            f"{b} - {c}" for b, c in
            sorted(self.builds.items(), key=lambda kv: _version_key(kv[0]), reverse=True)
            if b
        )


def extract(path: str | Path,
            stale_releases: int = DEFAULT_STALE_RELEASES) -> tuple[list[Fact], dict[str, Any]]:
    """Return facts plus a metrics dict for the summary text."""
    inv = AgentInventory(path, stale_releases)
    ev = inv.path.name
    out: list[Fact] = []

    def add(key: str, value: Any, display: str) -> None:
        out.append(Fact(key=key, value=value, display=display,
                        source=Source.AGENT_LIST, evidence=ev))

    online = inv.connection.get("Online", 0)
    offline = inv.connection.get("Offline", 0)

    add("inventory.deployed_agents", inv.total, f"Deployed - {inv.total}")
    add("inventory.online_offline", (online, offline), f"Online - {online}\nOffline - {offline}")
    add("inventory.agent_build", inv.builds, inv.build_breakdown())
    add("inventory.latest_build", inv.latest_build, inv.latest_build)
    add("inventory.outdated_agents", inv.outdated_agents, str(inv.outdated_agents))
    add("inventory.builds_behind_n3", inv.builds_behind(3), str(inv.builds_behind(3)))
    add("inventory.restart_required", inv.restart_required, str(inv.restart_required))
    add("inventory.server_agents", inv.server_agents, str(inv.server_agents))
    add("inventory.stale_pattern_agents", inv.stale_pattern_agents(),
        str(inv.stale_pattern_agents()))
    scan_methods = inv.scan_methods
    dominant = scan_methods.most_common(1)[0][0] if scan_methods else ""
    add("inventory.scan_method", dominant,
        dominant if len(scan_methods) == 1
        else ", ".join(f"{k}: {v}" for k, v in scan_methods.most_common()))

    metrics = {
        "deployed_agents": inv.total,
        "online": online,
        "offline": offline,
        "latest_build": inv.latest_build,
        "outdated_agents": inv.outdated_agents,
        "restart_required": inv.restart_required,
        "builds_behind_n3": inv.builds_behind(3),
        "server_agents": inv.server_agents,
        "stale_pattern_agents": inv.stale_pattern_agents(),
        "latest_pattern": inv.latest_pattern,
        "build_breakdown": inv.build_breakdown(),
    }
    return out, metrics
