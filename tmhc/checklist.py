"""No-AI capture: an Excel checklist of the settings the exports don't cover.

Use this on machines that can't run a local vision model (a typical office
laptop), or whenever you would rather type values than screenshot them.

    python -m tmhc checklist clients/acme/profile.yaml
        -> clients/acme/checklist.xlsx   (fill the yellow "Deployed" column)
    python -m tmhc run clients/acme/profile.yaml
        -> picks the checklist up automatically

Only settings that the policy export and agent-list CSV do NOT already prove
are listed, so for an Apex One / SEP check it is about 40 rows - mostly
dropdowns - and can be filled live during the Teams session.

Nothing here uses the network.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.worksheet.datavalidation import DataValidation

from .models import Fact, Source

SHEET = "Checklist"
HEADERS = ["Key", "Section", "Setting", "Trend recommended", "Deployed", "Notes", "Where in console",
           "Prefilled"]
COL_KEY, COL_DEPLOYED, COL_NOTES, COL_PREFILLED = 1, 5, 6, 8

BOOL_CHOICES = ["Enabled", "Disabled", "Not Configured", "N/A"]
DESKTOP_SERVER_CHOICES = [
    "Windows Desktop: Enabled Windows Server: Enabled",
    "Windows Desktop: Enabled Windows Server: Disabled",
    "Windows Desktop: Disabled Windows Server: Enabled",
    "Windows Desktop: Disabled Windows Server: Disabled",
]
TRUE_WORDS = {"enabled", "enable", "yes", "y", "true", "on", "subscribed", "configured", "1"}

WHERE = [
    ("global.agent_update", "Apex One > Updates > Agents > Automatic Updates / Update Source"),
    ("global.ua_", "Apex One > Updates > Agents > Update Source"),
    ("global.smart_protection", "Apex One > Administration > Smart Protection"),
    ("global.wrs_frs", "Apex One > Administration > Smart Protection > Smart Protection Sources"),
    ("global.so_", "Apex One > Administration > Settings > Suspicious Object List"),
    ("global.", "Apex One > Agents > Global Agent Settings"),
    ("admin.schedule_update", "SEP > Administration > Updates > Scheduled Update"),
    ("admin.deployment_plan", "SEP > Administration > Updates > Scheduled Update"),
    ("admin.ad_sync", "SEP > Administration > Settings > Active Directory and Compliance Settings"),
    ("admin.syslog", "SEP > Administration > Settings > Syslog Settings"),
    ("admin.event_notifications", "SEP > Logs & Reports > Notifications > Event Notifications"),
    ("admin.inactive_agent_removal", "Vision One > Endpoint Inventory > Global Settings"),
    ("admin.so_sync", "SEP > Suspicious Object Sync > Distribution settings"),
    ("admin.policy_count", "SEP > Policies > Policy Management"),
    ("license.", "Vision One > Administration > License Information"),
    ("platform.", "Vision One console"),
    ("policy.", "SEP > Policies > (policy) - or export the policy (.cmpolicy) instead"),
]


def where(key: str) -> str:
    for prefix, text in WHERE:
        if key.startswith(prefix):
            return text
    return ""


def wanted_keys(catalogue: dict[str, dict], covered: Iterable[str]) -> list[str]:
    """Settings the analyst may need to supply: everything the exports did not prove."""
    covered = set(covered)
    # platform.* extras feed no report row; leave them out so the list is only what matters
    return [k for k in catalogue if k not in covered and not k.startswith(("inventory.", "logs.", "platform."))]


def read_values(path: str | Path) -> dict[str, dict]:
    """key -> {deployed, notes, prefilled} for an existing checklist."""
    p = Path(path)
    if not p.exists():
        return {}
    ws = load_workbook(p, data_only=True)[SHEET]
    out = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row or not row[COL_KEY - 1]:
            continue
        dep = row[COL_DEPLOYED - 1]
        if hasattr(dep, "strftime"):
            dep = dep.strftime("%Y-%m-%d")
        out[row[COL_KEY - 1]] = {
            "deployed": "" if dep is None else str(dep).strip(),
            "notes": row[COL_NOTES - 1] or "",
            "prefilled": (row[COL_PREFILLED - 1] if len(row) >= COL_PREFILLED else None) or "",
        }
    return out


def sync(path: str | Path, catalogue: dict[str, dict], covered: Iterable[str],
         client: str = "", prefill: dict[str, Fact] | None = None) -> bool:
    """Bring an existing checklist up to date without losing anything typed into it.

    Adds settings that are now missing, drops ones an export now proves, and
    fills still-blank rows with new screenshot readings. Writes only when
    something changed (so the watcher does not see a change every build).
    """
    existing = read_values(path)
    keys = wanted_keys(catalogue, covered)
    prefill = prefill or {}
    rows = {}
    for k in keys:
        cur = existing.get(k, {"deployed": "", "notes": "", "prefilled": ""})
        pre = prefill.get(k)
        if not cur["deployed"] and pre is not None:
            cur = {"deployed": pre.display, "notes": "read from screenshot - check", "prefilled": pre.display}
        rows[k] = cur
    same = list(existing) == keys and all(
        existing[k]["deployed"] == rows[k]["deployed"] and str(existing[k]["prefilled"]) == str(rows[k]["prefilled"])
        for k in keys)
    if same and Path(path).exists():
        return False
    write(path, catalogue, covered, client=client, existing=rows)
    return True


def write(path: str | Path, catalogue: dict[str, dict], covered: Iterable[str],
          client: str = "", prefill: dict[str, Fact] | None = None,
          existing: dict[str, dict] | None = None) -> Path:
    prefill = prefill or {}
    keys = wanted_keys(catalogue, covered)

    wb = Workbook()
    ws = wb.active
    ws.title = SHEET
    ws.append(HEADERS)
    head_fill = PatternFill("solid", fgColor="C0504D")
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = head_fill

    dv_bool = DataValidation(type="list", formula1='"' + ",".join(BOOL_CHOICES) + '"', allow_blank=True)
    dv_ds = DataValidation(type="list", formula1="=Lists!$A$1:$A$4", allow_blank=True)
    for dv in (dv_bool, dv_ds):
        dv.showErrorMessage = False   # dropdown is a suggestion; free text still allowed
        ws.add_data_validation(dv)

    yellow = PatternFill("solid", fgColor="FFF2CC")
    for k in keys:
        spec = catalogue[k]
        if existing is not None and k in existing:
            e = existing[k]
            dep, note, pref = e["deployed"], e["notes"], e["prefilled"]
        else:
            pre = prefill.get(k)
            dep = pre.display if pre else ""
            note = "read from screenshot - check" if pre else ""
            pref = pre.display if pre else ""
        ws.append([k, spec.get("section", ""), spec.get("setting", ""), spec.get("recommended", ""),
                   dep or None, note, where(k), pref or None])
        r = ws.max_row
        cell = ws.cell(row=r, column=COL_DEPLOYED)
        cell.fill = yellow
        typ = spec.get("type")
        if typ == "bool":
            dv_bool.add(cell)
        elif typ == "desktop_server":
            dv_ds.add(cell)
        elif typ == "date":
            ws.cell(row=r, column=COL_NOTES).value = (ws.cell(row=r, column=COL_NOTES).value or
                                                      "date as YYYY-MM-DD")
        elif typ == "int":
            ws.cell(row=r, column=COL_NOTES).value = ws.cell(row=r, column=COL_NOTES).value or "number"

    for i, w in enumerate([34, 30, 45, 45, 30, 24, 55, 10], 1):
        ws.column_dimensions[chr(64 + i)].width = w
    ws.column_dimensions["A"].hidden = True
    ws.column_dimensions["H"].hidden = True
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "E2"

    lists = wb.create_sheet("Lists")
    for i, v in enumerate(DESKTOP_SERVER_CHOICES, 1):
        lists.cell(row=i, column=1, value=v)
    lists.sheet_state = "hidden"

    info = wb.create_sheet("How to fill")
    for line in [
        f"Health-check checklist{(' - ' + client) if client else ''}",
        "",
        "Fill the yellow 'Deployed' column with what the console shows. Pick from the",
        "dropdown where there is one; otherwise type the value exactly as shown",
        "(e.g. '12 hours', 'Daily', 'Partially Enabled', '2028-04-09').",
        "Leave a row blank if you did not check it - it will show as 'Not captured'",
        "in the report instead of being guessed.",
        "Then save: the report rebuilds by itself (or run: python -m tmhc run <profile.yaml>).",
    ]:
        info.append([line])
    info.column_dimensions["A"].width = 90

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out)
    return out


def _value_for(display: str, typ: str) -> Any:
    low = display.strip().lower()
    if typ == "bool":
        # "Enabled (30 Days)", "Yes - subscribed" etc. count by their first word
        first = low.replace("-", " ").replace("(", " ").split()[0] if low.split() else ""
        return low in TRUE_WORDS or first in TRUE_WORDS
    if typ == "desktop_server":
        parts = low.replace("windows", "").split("server")
        desk = "enabled" in parts[0]
        srv = len(parts) > 1 and "enabled" in parts[1]
        return (desk, srv)
    if typ == "int":
        digits = "".join(ch for ch in display if ch.isdigit())
        return int(digits) if digits else display
    return display.strip()


def read(path: str | Path, catalogue: dict[str, dict]) -> list[Fact]:
    """Filled checklist -> analyst facts. Blank rows are skipped."""
    p = Path(path)
    if not p.exists():
        return []
    ws = load_workbook(p, data_only=True)[SHEET]
    facts = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        key, deployed = row[COL_KEY - 1], row[COL_DEPLOYED - 1]
        if not key or deployed is None or str(deployed).strip() == "":
            continue
        display = deployed.strftime("%Y-%m-%d") if hasattr(deployed, "strftime") else str(deployed).strip()
        prefilled = row[COL_PREFILLED - 1] if len(row) >= COL_PREFILLED else None
        if prefilled is not None and str(prefilled).strip() == display:
            continue          # untouched screenshot reading: keep it as screenshot evidence
        typ = catalogue.get(key, {}).get("type", "text")
        note = row[COL_NOTES - 1]
        value = _value_for(display, typ)
        if typ == "date":
            import datetime as _dt
            try:
                display = _dt.date.fromisoformat(display[:10]).strftime("%d %B %Y")
            except ValueError:
                pass
        evidence = (f"checklist (corrected screenshot reading {prefilled!r})" if prefilled
                    else f"checklist{(': ' + str(note)) if note else ''}")
        facts.append(Fact(key=key, value=value, display=display, source=Source.MANUAL, evidence=evidence))
    return facts
