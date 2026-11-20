"""Render a HealthCheck into the Word template."""
from __future__ import annotations

import copy
import datetime as dt
import re
from pathlib import Path
from typing import Optional

import docx
from docx.oxml.ns import qn
from docx.shared import Inches
from docx.table import _Cell

from ..models import Gap, HealthCheck, ReportRow, Status
from .docx_utils import (clear_drawings, enable_update_fields, find_table_with,
                         replace_everywhere, set_cell_text, set_vmerge)

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "assets"
DEFAULT_TEMPLATE = HERE / "templates" / "sep_report_template.docx"
ICON_WIDTH = Inches(0.17)


# --------------------------------------------------------------------------
# executive summary text
# --------------------------------------------------------------------------
def _pretty_date(value) -> str:
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y"):
        try:
            return dt.datetime.strptime(str(value), fmt).strftime("%d %B %Y")
        except ValueError:
            continue
    return str(value)


def _headline(text: str) -> str:
    """First clause of a gap sentence, for the executive summary bullets."""
    cut = re.split(r",? recommended|\. It is recommended|\. Recommend|, Recommend", text, maxsplit=1)[0]
    return cut.rstrip(" .") + "."


def executive_findings(hc: HealthCheck) -> list[str]:
    m = hc.metrics
    out: list[str] = []
    lic_name = hc.get("license.name")
    expiry = hc.get("license.expiry")
    seats = hc.get("license.seats")
    if expiry:
        name = lic_name.display if lic_name else "Endpoint Security"
        seat_txt = f" with seat count of **{seats.display}**" if seats else ""
        out.append(f"Your **{name}** license is valid till **{_pretty_date(expiry.value)}**{seat_txt}.")
    if m.get("offline"):
        out.append(f"**{m['offline']}** agents are offline.")
    if m.get("outdated_agents"):
        out.append(f"**{m['outdated_agents']}** Agents have outdated Program versions. "
                   f"The Latest Version is **{m.get('latest_build')}**.")
    if m.get("restart_required"):
        out.append(f"**{m['restart_required']}** endpoint required restart for update.")
    if m.get("stale_pattern_agents"):
        out.append(f"**{m['stale_pattern_agents']}** Agents have outdated patterns older than 7 days.")
    mac = hc.get("inventory.mac_agents")
    if mac:
        out.append(f"Apex One (Mac) agents are also managed - {mac.display}.")
    for g in hc.gaps_server:
        if (g.key or "").startswith(("global.", "admin.")):
            out.append(_headline(g.text))
    if hc.gaps_policy:
        out.append(f"The “**{hc.policy_name}**” policy is not configured as per Trend Micro "
                   f"Best Practices ({len(hc.gaps_policy)} gaps).")
    return out


# --------------------------------------------------------------------------
# table filling
# --------------------------------------------------------------------------
def _tcs(tr):
    return tr.findall(qn("w:tc"))


def _put_icon(tc, table, status: Status) -> None:
    clear_drawings(tc)
    set_cell_text(tc, "")
    cell = _Cell(tc, table)
    run = cell.paragraphs[0].add_run()
    run.add_picture(str(ASSETS / status.icon_name), width=ICON_WIDTH)


def fill_settings_table(doc, token: str, rows: list[ReportRow]) -> None:
    table = find_table_with(doc, token)
    if table is None:
        raise ValueError(f"template has no table tagged {token}")
    tbl = table._tbl
    trs = tbl.findall(qn("w:tr"))
    heading_proto, data_proto = trs[1], trs[2]
    anchor = data_proto
    prev_group: Optional[str] = None

    for row in rows:
        if row.group == "__heading__":
            tr = copy.deepcopy(heading_proto)
            set_cell_text(_tcs(tr)[0], row.component)
            prev_group = None
        else:
            tr = copy.deepcopy(data_proto)
            cells = _tcs(tr)
            first, rec, dep, stat = cells[0], cells[-3], cells[-2], cells[-1]
            if row.group:
                if row.group == prev_group:
                    set_cell_text(first, "")
                    set_vmerge(first, "continue")
                else:
                    set_cell_text(first, row.group)
                    set_vmerge(first, "restart")
            else:
                set_cell_text(first, row.component)
                set_vmerge(first, None)
            prev_group = row.group
            set_cell_text(rec, row.recommended)
            set_cell_text(dep, row.deployed)
            anchor.addnext(tr)
            anchor = tr
            _put_icon(stat, table, row.status)
            continue
        anchor.addnext(tr)
        anchor = tr

    tbl.remove(heading_proto)
    tbl.remove(data_proto)


def fill_gap_table(doc, token: str, gaps: list[Gap]) -> None:
    table = find_table_with(doc, token)
    if table is None:
        raise ValueError(f"template has no table tagged {token}")
    tbl = table._tbl
    proto = tbl.findall(qn("w:tr"))[1]
    anchor = proto
    items = gaps or [Gap(text="No gaps identified - configuration meets Trend Micro best practice.")]
    for g in items:
        tr = copy.deepcopy(proto)
        set_cell_text(_tcs(tr)[-1], g.text)
        anchor.addnext(tr)
        anchor = tr
    tbl.remove(proto)


def fill_exec_summary(doc, product: str, findings: list[str]) -> None:
    table = find_table_with(doc, "{{EXEC_FINDING}}")
    if table is None:
        return
    tr = table._tbl.findall(qn("w:tr"))[1]
    cells = _tcs(tr)
    set_cell_text(cells[0], product)
    set_cell_text(cells[-1], "\n".join(findings) if findings else "No findings.")


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
def render(hc: HealthCheck, out_path: str | Path, template: str | Path = DEFAULT_TEMPLATE,
           product: str = "Standard Endpoint Protection") -> Path:
    doc = docx.Document(str(template))

    fill_exec_summary(doc, product, executive_findings(hc))
    fill_settings_table(doc, "{{SERVER_TABLE}}", hc.rows_server)
    fill_settings_table(doc, "{{POLICY_TABLE}}", hc.rows_policy)
    fill_gap_table(doc, "{{SERVER_GAPS}}", hc.gaps_server)
    fill_gap_table(doc, "{{POLICY_GAPS}}", hc.gaps_policy)

    mapping = {
        "{{client_name}}": hc.client_name,
        "{{policy_name}}": hc.policy_name or "Endpoint Policy",
        "{{quarter}}": hc.quarter,
        "{{report_date}}": hc.report_date,
        "{{check_date}}": hc.check_date_display or hc.check_date,
        "{{prepared_by}}": hc.prepared_by,
        "{{approved_by}}": hc.approved_by,
        "{{account_owner}}": hc.account_owner,
        "{{location}}": hc.location,
        "{{customer_attendance}}": hc.attendees_customer,
        "{{trend_attendance}}": hc.attendees_trend or hc.prepared_by,
    }
    roots = [doc.element.body]
    for s in doc.sections:
        for part in (s.header, s.footer, s.first_page_header, s.first_page_footer,
                     s.even_page_header, s.even_page_footer):
            try:
                roots.append(part._element)
            except Exception:
                pass
    replace_everywhere(roots, mapping)

    leftover = [m for m in set(re.findall(r"\{\{[a-zA-Z_]+\}\}", doc.element.xml))]
    if leftover:
        hc.warnings.append(f"template placeholders left unfilled: {sorted(leftover)}")

    cp = doc.core_properties
    cp.title = f"Technical Health Check - {product} - {hc.client_name}"
    cp.author = hc.prepared_by
    enable_update_fields(doc)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out))
    return out
