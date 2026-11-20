"""Analyst review workbook: where every value in the report came from."""
from __future__ import annotations

from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from ..models import HealthCheck, Source, Status
from ..engine.evaluate import NOT_CAPTURED, status_counts

FILL = {
    Status.GOOD: "E2F0D9", Status.CONCERN: "FCE4D6", Status.CRITICAL: "F8CBAD",
    Status.INFO: "DDEBF7", Status.UNKNOWN: "EDEDED",
}
SOURCE_LABEL = {
    Source.POLICY_EXPORT: "Policy export (.cmpolicy)",
    Source.AGENT_LIST: "Agent list CSV",
    Source.V1_LOGS: "Vision One log export",
    Source.EXCLUSION_CSV: "Exclusion CSV",
    Source.SCREENSHOT: "Screenshot (vision)",
    Source.MANUAL: "Analyst entry",
}
# Where to find a setting in the console, by key prefix - used for the
# "Not captured" sheet so the next session knows which page to screenshot.
WHERE = [
    ("global.", "Apex One console > Agents > Global Agent Settings (or Updates / Administration pages)"),
    ("admin.", "Vision One > Standard Endpoint Protection > Administration"),
    ("license.", "Vision One > License Information"),
    ("policy.", "Standard Endpoint Protection > Policies > (policy) - or export the policy (.cmpolicy)"),
]


def _where(key: str) -> str:
    for prefix, text in WHERE:
        if key.startswith(prefix):
            return text
    return ""


def _sheet(wb, title, headers, rows, widths):
    ws = wb.create_sheet(title)
    ws.append(headers)
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="C0504D")
    for r in rows:
        ws.append(r)
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    return ws


def write_review(hc: HealthCheck, path: str | Path) -> Path:
    wb = Workbook()
    wb.remove(wb.active)

    counts = status_counts(hc)
    summary = [
        ("Client", hc.client_name), ("Policy", hc.policy_name), ("Check date", hc.check_date),
        *[(f"Rows - {k}", v) for k, v in counts.items()],
        ("Server gaps", len(hc.gaps_server)), ("Policy gaps", len(hc.gaps_policy)),
        ("Rows not captured", sum(1 for r in hc.rows_server + hc.rows_policy if r.deployed == NOT_CAPTURED)),
    ]
    _sheet(wb, "Summary", ["Item", "Value"], summary, [28, 60])

    rows = []
    for table, items in (("Server", hc.rows_server), ("Policy", hc.rows_policy)):
        for r in items:
            if r.group == "__heading__":
                continue
            rows.append([table, r.section, r.group or r.component, r.recommended, r.deployed,
                         r.status.value, SOURCE_LABEL.get(r.source, "") if r.source else "",
                         r.evidence or "", r.key or ""])
    ws = _sheet(wb, "Rows",
                ["Table", "Section", "Component", "Trend recommended", "Deployed", "Status",
                 "Source", "Evidence", "Fact key"],
                rows, [9, 30, 34, 50, 34, 10, 22, 50, 40])
    for row in ws.iter_rows(min_row=2):
        st = Status(row[5].value)
        row[5].fill = PatternFill("solid", fgColor=FILL[st])

    missing = []
    seen = set()
    for r in hc.rows_server + hc.rows_policy:
        if r.deployed == NOT_CAPTURED and r.key not in seen:
            seen.add(r.key)
            missing.append([r.key, r.group or r.component, r.recommended, _where(r.key or "")])
    _sheet(wb, "Not captured", ["Fact key", "Setting", "Trend recommended", "Where to capture it"],
           missing, [40, 45, 50, 70])

    gaps = [["Server", g.severity.value, g.text] for g in hc.gaps_server] + \
           [["Policy", g.severity.value, g.text] for g in hc.gaps_policy]
    _sheet(wb, "Gaps", ["Table", "Severity", "Gap and remediation"], gaps, [10, 12, 120])

    _sheet(wb, "Warnings", ["Message"], [[w] for w in hc.warnings if not w.startswith("No data")],
           [140])

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out)
    return out
