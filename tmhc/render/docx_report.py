"""Render a HealthCheck into the Word template."""
from __future__ import annotations

import copy
import datetime as dt
import re
from pathlib import Path
from typing import Optional

import docx
from docx.oxml.ns import qn
from docx.shared import Emu, Inches
from docx.table import _Cell

from ..models import Gap, HealthCheck, ReportRow, Status
from .docx_utils import (clear_drawings, enable_update_fields, find_table_with,
                         replace_everywhere, set_cell_text, set_vmerge)

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "assets"
DEFAULT_TEMPLATE = HERE / "templates" / "sep_report_template.docx"
ICON_WIDTH = Emu(180975)   # same size as in the analysts' reports


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


def _ordinal(d: dt.date) -> str:
    n = d.day
    suf = "th" if 11 <= n % 100 <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n:02d}{suf} {d.strftime('%b %Y')}"


def swp_findings(hc: HealthCheck) -> list[str]:
    """Executive-summary bullets for Server & Workload Protection, in the manual reports' order."""
    m = hc.metrics
    f = hc.get
    out: list[str] = []
    name, seats = f("license.name"), f("license.seats")
    if m.get("license_valid_us"):
        lic = (name.display if name else "Server & Workload Protection").replace("™", "").replace(" - ", " \u2013 ")
        units = f" with **{seats.display}** units" if seats else ""
        out.append(f"**{lic}** license{units} is valid till **{m['license_valid_us']}.**")
    total, outdated = m.get("deployed_agents"), m.get("outdated_agents")
    if outdated:
        who = "**All** computers are" if outdated == total else f"**{outdated}** computers are"
        out.append(f"{who} running on the older software version.")
    if m.get("critical") or m.get("warning"):
        out.append(f"**{m.get('managed', 0)}** computers are in the managed state, **{m.get('warning', 0)}** computers "
                   f"are in the warning state, and **{m.get('critical', 0)}** computers are in the critical state.")
    if m.get("out_of_date") or m.get("update_unknown"):
        parts = []
        if m.get("out_of_date"):
            parts.append(f"**{m['out_of_date']}** computers are **out-of-date**")
        if m.get("update_unknown"):
            parts.append(f"**{m['update_unknown']}** computers are **unknown**")
        out.append("In component update, " + " and ".join(parts) + ".")
    missing = []
    t = f("swp.task.malware_scan")
    if t is not None and not t.value:
        missing.append("**Scan computers for malware**")
    t = f("swp.task.recommendation_scan")
    if t is not None and not t.value:
        missing.append("**Scan computer for recommendation**")
    if missing:
        out.append(f"In schedule task, {' and '.join(missing)} {'are' if len(missing) > 1 else 'is'} not configured.")
    siem = f("swp.siem")
    if siem is not None and not siem.value:
        out.append("**SIEM** is not configured")
    if m.get("without_policy"):
        out.append(f"**{m['without_policy']}** Computers are without policy.")
    out.extend(x for x in hc.summaries if x not in out)
    if hc.gaps_policy:
        names = m.get("policy_names") or []
        if names:
            joined = " and ".join(f"**{n}**" for n in names)
            out.append(f"{joined} Polic{'ies are' if len(names) > 1 else 'y is'} not configured as per Trend Micro "
                       f"Best Practices.")
    return out


def executive_findings(hc: HealthCheck, short: str = "SEP") -> list[str]:
    if short == "SWP":
        return swp_findings(hc)
    return _sep_findings(hc)


def _sep_findings(hc: HealthCheck) -> list[str]:
    """Short bullets with bold key terms, in the order used in the manual reports."""
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
    out.extend(hc.summaries)
    if hc.gaps_policy:
        out.append(f"The **\u201c{hc.policy_name} Policy\u201d** policy is not configured as per Trend Micro "
                   f"Best Practices.")
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
    trs = tbl.findall(qn("w:tr"))
    heading_proto = None
    if len(trs) > 2 and "{{GAP_HEADING}}" in "".join(t.text or "" for t in trs[1].iter(qn("w:t"))):
        heading_proto, proto = trs[1], trs[2]       # SWP: "In Both ... Policy" sub-headings
    else:
        proto = trs[1]
    anchor = proto
    items = gaps or [Gap(text="No gaps identified - configuration meets Trend Micro best practice.")]
    for g in items:
        if g.heading:
            if heading_proto is None:
                continue
            tr = copy.deepcopy(heading_proto)
            set_cell_text(_tcs(tr)[0], g.text)
        else:
            tr = copy.deepcopy(proto)
            set_cell_text(_tcs(tr)[-1], g.text)
        anchor.addnext(tr)
        anchor = tr
    tbl.remove(proto)
    if heading_proto is not None:
        tbl.remove(heading_proto)


def fill_exec_summary(doc, product: str, findings: list[str]) -> None:
    table = find_table_with(doc, "{{EXEC_FINDING}}")
    if table is None:
        return
    tr = table._tbl.findall(qn("w:tr"))[1]
    cells = _tcs(tr)
    set_cell_text(cells[0], product)
    set_cell_text(cells[-1], "\n".join(findings) if findings else "No findings.")


# --------------------------------------------------------------------------
# row-for-row templates ({{=key}} / {{?key|key}} tokens)
# --------------------------------------------------------------------------
_SEVERITY = [Status.CRITICAL, Status.CONCERN, Status.UNKNOWN, Status.INFO, Status.GOOD]
BOLD_VALUE_PREFIXES = ("policy.priv.", "policy.svc.")
BOLD_LABEL_SUFFIXES = (".actions",)          # "**Virus:** Clean" (SWP remediation actions)
_TOKEN = re.compile(r"^\{\{([=?])([A-Za-z0-9_.|]+)\}\}$")


def _cell_text(tc) -> str:
    return "".join(t.text or "" for t in tc.iter(qn("w:t"))).strip()


def fill_token_tables(doc, hc: HealthCheck) -> int:
    """Fill the analyst-designed tables cell by cell; returns cells filled."""
    from ..engine.evaluate import NOT_CAPTURED
    lookup: dict[str, tuple[str, Status]] = {}
    for r in hc.rows_server + hc.rows_policy:
        if r.key and r.group != "__heading__" and r.key not in lookup:
            lookup[r.key] = (r.deployed, r.status)

    def value(key: str) -> tuple[str, Status]:
        if key in lookup:
            return lookup[key]
        f = hc.get(key)
        if f is not None:                       # a fact without a rule: show it, no judgement
            return f.display, Status.INFO
        hc.warnings.append(f"No data for {key} (template row)")
        return NOT_CAPTURED, Status.UNKNOWN

    filled = 0
    for table in doc.tables:
        for tc in table._tbl.iter(qn("w:tc")):
            m = _TOKEN.match(_cell_text(tc))
            if not m:
                continue
            kind, keys = m.group(1), m.group(2).split("|")
            if kind == "=":
                text = value(keys[0])[0]
                if keys[0].startswith(BOLD_VALUE_PREFIXES) and ":" in text:
                    # house style: "Postpone Scheduled Scan : **Disabled**"
                    text = "\n".join(re.sub(r"^(.*:\s*)(\S.*)$", r"\1**\2**", ln) for ln in text.split("\n"))
                elif keys[0].endswith(BOLD_LABEL_SUFFIXES):
                    text = "\n".join(re.sub(r"^([^:*]+:)\s*(\S.*)$", r"**\1** \2", ln) for ln in text.split("\n"))
                set_cell_text(tc, text)
            else:
                worst = min((value(k)[1] for k in keys), key=_SEVERITY.index)
                _put_icon(tc, table, worst)
            filled += 1
    return filled


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------
EXEC_LABEL = {"SWP": "Vision one Server and workload security"}


def _replace_picture_after(doc, marker: str, png: bytes) -> bool:
    """Swap the image in the first paragraph with a picture after the one containing `marker`."""
    paras = doc.paragraphs
    for i, p in enumerate(paras):
        if marker.lower() not in p.text.lower():
            continue
        for q in paras[i + 1:i + 5]:
            blips = q._p.findall(".//" + qn("a:blip"))
            if blips:
                rid = blips[0].get(qn("r:embed"))
                part = doc.part.related_parts[rid]
                part._blob = png
                return True
    return False


def render(hc: HealthCheck, out_path: str | Path, template: str | Path = DEFAULT_TEMPLATE,
           product: str = "Standard Endpoint Protection", short: str = "SEP") -> Path:
    doc = docx.Document(str(template))

    fill_exec_summary(doc, EXEC_LABEL.get(short, product), executive_findings(hc, short))
    if find_table_with(doc, "{{SERVER_TABLE}}") is not None:     # older generated-table templates
        fill_settings_table(doc, "{{SERVER_TABLE}}", hc.rows_server)
        fill_settings_table(doc, "{{POLICY_TABLE}}", hc.rows_policy)
    else:
        fill_token_tables(doc, hc)
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
    chk = None
    try:
        chk = dt.date.fromisoformat(hc.check_date) if hc.check_date else None
    except ValueError:
        pass
    mapping["{{check_date_long}}"] = _ordinal(chk) if chk else (hc.check_date_display or hc.check_date)
    if short == "SWP":
        risky = hc.metrics.get("risky_extensions") or []
        mapping["{{m.risky_ext_text}}"] = (
            "Kindly remove " + ", ".join("." + e for e in risky) + " extension from the exclusion."
            if risky else "No executable or archive file extensions were found in the scan exclusion lists.")
        try:
            from .charts import computer_status_png
            png = computer_status_png(hc.metrics)
            if png:
                _replace_picture_after(doc, "current installed Server & Workload Protection Agents", png)
        except Exception as exc:                         # keep the template's picture
            hc.warnings.append(f"computer status chart not drawn: {exc}")
        lic_ok = hc.get("swp.inventory.deployed")
        seats = hc.metrics.get("license_seats")
        status = "Good"
        try:
            if lic_ok is not None and int(lic_ok.value) > int(seats):
                status = "Concern"
        except (TypeError, ValueError):
            status = "Unknown"
        mapping["{{m.license_status}}"] = status
        mapping["{{m.license_status_line}}"] = f"Status {status}"
        seats_txt = seats if seats not in (None, "", "N/A") else "N/A"
        mapping["{{m.license_sentence}}"] = (
            f"The license purchased is for {seats_txt} and is valid till {hc.metrics['license_valid_long']}."
            if hc.metrics.get("license_valid_long") else f"The license purchased is for {seats_txt}.")
    for k, v in hc.metrics.items():
        if isinstance(v, (str, int, float)):
            mapping["{{m." + k + "}}"] = str(v)
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
    cp.subject = short
    cp.author = hc.prepared_by
    enable_update_fields(doc)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out))
    return out
