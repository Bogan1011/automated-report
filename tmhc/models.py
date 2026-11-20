"""Core data model for the Trend Micro health-check pipeline.

Everything that is learned about a customer environment becomes a `Fact`.
Facts come from several sources of differing trustworthiness; the engine
merges them by precedence so that a deterministic export always beats a
value read off a screenshot.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Status(str, Enum):
    """The five status levels used in the report's legend table."""

    GOOD = "good"
    CONCERN = "concern"
    CRITICAL = "critical"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def icon_name(self) -> str:
        return f"status_{self.value}.png"


class Source(str, Enum):
    """Where a fact came from, in order of trustworthiness."""

    POLICY_EXPORT = "policy_export"   # .cmpolicy JSON - authoritative
    AGENT_LIST = "agent_list"         # Apex One agent inventory CSV
    V1_LOGS = "v1_logs"               # Vision One log exports
    EXCLUSION_CSV = "exclusion_csv"   # scan-exclusion CSV exports
    SCREENSHOT = "screenshot"         # vision model reading a console capture
    MANUAL = "manual"                 # analyst override in client profile

    @property
    def precedence(self) -> int:
        return _PRECEDENCE[self]


# Higher wins. A manual override from the analyst always wins; a screenshot
# reading is the weakest signal and never overwrites a structured export.
_PRECEDENCE = {
    Source.MANUAL: 100,
    Source.POLICY_EXPORT: 90,
    Source.AGENT_LIST: 80,
    Source.EXCLUSION_CSV: 70,
    Source.V1_LOGS: 60,
    Source.SCREENSHOT: 10,
}


@dataclass
class Fact:
    """A single observed configuration value.

    `key` is a dotted path from the rule pack, e.g.
    ``policy.realtime.files_to_scan`` or ``global.firewall.enabled``.
    `display` is the human-readable string that lands in the report's
    "Deployed" column; `value` is the normalised machine form used for
    comparison.
    """

    key: str
    value: Any
    display: str
    source: Source
    confidence: float = 1.0
    evidence: Optional[str] = None  # screenshot filename, CSV name, JSON path

    def beats(self, other: "Fact") -> bool:
        if self.source.precedence != other.source.precedence:
            return self.source.precedence > other.source.precedence
        return self.confidence > other.confidence


@dataclass
class ReportRow:
    """One rendered row of a health-check table."""

    section: str
    component: str
    recommended: str
    deployed: str
    status: Status
    key: Optional[str] = None
    source: Optional[Source] = None
    evidence: Optional[str] = None
    indent: int = 0
    group: Optional[str] = None  # left-hand merged label, e.g. "Target"


@dataclass
class Gap:
    """A finding destined for the remediation tables."""

    text: str
    severity: Status = Status.CONCERN
    key: Optional[str] = None
    scope: str = "server"  # "server" or "policy"


@dataclass
class HealthCheck:
    """Everything needed to render one report."""

    client_name: str = ""
    report_date: str = ""
    quarter: str = ""
    prepared_by: str = ""
    approved_by: str = ""
    attendees_customer: str = "Console Access"
    attendees_trend: str = ""
    location: str = "Remotely"
    check_date: str = ""           # ISO, used for comparisons (licence expiry)
    check_date_display: str = ""   # as printed in the report, e.g. 07-10-2026
    account_owner: str = ""
    facts: dict[str, Fact] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    policy_name: str = ""
    rows_server: list[ReportRow] = field(default_factory=list)
    rows_policy: list[ReportRow] = field(default_factory=list)
    gaps_server: list[Gap] = field(default_factory=list)
    gaps_policy: list[Gap] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_fact(self, fact: Fact) -> None:
        """Insert a fact, respecting source precedence."""
        existing = self.facts.get(fact.key)
        if existing is None or fact.beats(existing):
            if existing is not None and existing.display != fact.display:
                self.warnings.append(
                    f"{fact.key}: {fact.source.value} reported "
                    f"{fact.display!r}, overriding {existing.source.value} "
                    f"value {existing.display!r}"
                )
            self.facts[fact.key] = fact

    def add_facts(self, facts: list[Fact]) -> None:
        for f in facts:
            self.add_fact(f)

    def get(self, key: str) -> Optional[Fact]:
        return self.facts.get(key)
