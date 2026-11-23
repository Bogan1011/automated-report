"""Product Efficacy presentation (PowerPoint), built from the same data as the Word report.

The deck follows the analysts' Product Efficacy decks slide for slide:

    SEP  title, executive summary, agent version & platform, one or two
         slides per detection type (Virus/Malware, Spyware/Grayware, Web
         Reputation, Device Control, C&C Callback, Behaviour Monitoring),
         findings & recommendations, policy findings, thank you.
    SWP  title, executive summary, agent version & platform, security update
         status, Log Inspection (charts + rule table), Intrusion Prevention
         (charts + top CVE rule), findings & recommendations, policy findings
         (In Both / <policy> only), thank you.

Charts are native PowerPoint charts (editable, in the analysts' dark style);
detection slides are left out when the export for them is missing or empty.
The client logo is a grey placeholder on the title slide - right-click >
Change Picture to drop the real one in.
"""
from __future__ import annotations

import copy
import datetime as dt
import re
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Iterable, Optional

from lxml import etree
from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor
from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION, XL_LEGEND_POSITION
from pptx.enum.shapes import MSO_SHAPE_TYPE
from pptx.oxml.ns import qn
from pptx.table import _Cell
from pptx.util import Pt

from ..models import HealthCheck

TEMPLATES = Path(__file__).resolve().parent / "templates"
BG = "404040"
BAR = "146182"
PIE = {"Out-of-Date": "146182", "Up-to-Date": "ED7D31", "Unknown": "808080"}
PIE_CYCLE = ["146182", "ED7D31", "808080", "FFC000", "5B9BD5", "70AD47", "A5A5A5", "9E480E"]
WHITE = RGBColor(0xFF, 0xFF, 0xFF)


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def _short_date(hc: HealthCheck) -> str:
    try:
        d = dt.date.fromisoformat(hc.check_date)
    except (TypeError, ValueError):
        return hc.check_date_display or ""
    n = d.day
    suf = "th" if 11 <= n % 100 <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suf} {d.strftime('%b %Y')}"


def _join(items: list[str], bold: bool = True) -> str:
    items = [f"**{x}**" if bold else x for x in items]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _hosts_phrase(hosts: list[str], noun: str = "endpoints") -> str:
    """'the X endpoint' / 'X and Y endpoints' / 'multiple endpoints'."""
    if len(hosts) == 1:
        return f"the **{hosts[0]}** {noun.rstrip('s')}"
    if len(hosts) <= 3:
        return f"{_join(hosts)} {noun}"
    return f"multiple {noun}"


def _times(n: int) -> str:
    return "1 time" if n == 1 else f"{n} times"


def _trunc(s: str, n: int = 34) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


def _read_rows(path: Optional[Path]) -> list[dict]:
    if not path:
        return []
    from ..sources.v1logs import read_table
    try:
        return read_table(path)
    except Exception:
        return []


def _find(folder: Optional[Path], *patterns: str) -> Optional[Path]:
    if not folder or not folder.exists():
        return None
    for pat in patterns:
        hits = sorted(p for p in folder.rglob("*") if p.is_file() and re.search(pat, p.name, re.I))
        if hits:
            return hits[0]
    return None


# --------------------------------------------------------------------------
# slide cloning
# --------------------------------------------------------------------------
class Deck:
    def __init__(self, template: Path):
        self.prs = Presentation(str(template))
        kw = self.prs.core_properties.keywords or ""
        kinds = kw.split(":")[-1].split(",") if kw.startswith("tmhc-efficacy") else []
        self.protos = {k: s for k, s in zip(kinds, list(self.prs.slides))}
        self.proto_ids = [s.slide_id for s in self.prs.slides]
        self.out: list = []

    def new(self, kind: str):
        src = self.protos[kind]
        slide = self.prs.slides.add_slide(src.slide_layout)
        for ph in list(slide.placeholders):
            ph._element.getparent().remove(ph._element)
        for el in src.shapes._spTree.iterchildren():
            if el.tag in (qn("p:nvGrpSpPr"), qn("p:grpSpPr")):
                continue
            new_el = copy.deepcopy(el)
            # every relationship reference (pictures, SVG "graphics", links) must point at
            # a relationship of the new slide
            for node in new_el.iter():
                for attr in (qn("r:embed"), qn("r:link"), qn("r:id")):
                    rid = node.get(attr)
                    if rid and rid in src.part.rels:
                        rel = src.part.rels[rid]
                        if rel.is_external:
                            node.set(attr, slide.part.relate_to(rel.target_ref, rel.reltype, is_external=True))
                        else:
                            node.set(attr, slide.part.relate_to(rel._target, rel.reltype))
            slide.shapes._spTree.append(new_el)
        self.out.append(slide)
        return slide

    def finish(self, path: Path) -> Path:
        lst = self.prs.slides._sldIdLst
        for sld in list(lst):
            if int(sld.get("id")) in self.proto_ids:
                self.prs.part.drop_rel(sld.rId)
                lst.remove(sld)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.prs.save(str(path))
        return path


def _shape(slide, name: str):
    return next((s for s in slide.shapes if s.name == name), None)


def _title(slide, text: str) -> None:
    """Set the slide title; a vertical tab (\v) is a line break, as in the decks."""
    for s in slide.shapes:
        if s.is_placeholder and s.has_text_frame:
            p = s.text_frame.paragraphs[0]
            if not p.runs:
                p.add_run()
            first = p.runs[0]._r
            for r in list(p._p):
                if r is not first and r.tag in (qn("a:r"), qn("a:br")):
                    p._p.remove(r)
            parts = text.split("\v")
            first.find(qn("a:t")).text = parts[0]
            prev = first
            for part in parts[1:]:
                br = etree.SubElement(p._p, qn("a:br"))
                rpr = first.find(qn("a:rPr"))
                if rpr is not None:
                    br.append(copy.deepcopy(rpr))
                prev.addnext(br)
                prev = br
                if part:
                    r = copy.deepcopy(first)
                    r.find(qn("a:t")).text = part
                    prev.addnext(r)
                    prev = r
            for extra in list(s.text_frame.paragraphs)[1:]:
                extra._p.getparent().remove(extra._p)
            return


def _fill_para(p_el, text: str) -> None:
    """Write `text` (with **bold**) into an a:p, cloning its first run's look."""
    runs = p_el.findall(qn("a:r"))
    proto = copy.deepcopy(runs[0]) if runs else None
    for r in runs:
        p_el.remove(r)
    for fld in p_el.findall(qn("a:fld")):
        p_el.remove(fld)
    end = p_el.find(qn("a:endParaRPr"))
    parts = text.split("**")
    for i, seg in enumerate(parts):
        if not seg:
            continue
        r = copy.deepcopy(proto) if proto is not None else etree.SubElement(p_el, qn("a:r"))
        rpr = r.find(qn("a:rPr"))
        if rpr is None:
            rpr = etree.SubElement(r, qn("a:rPr"))
            r.insert(0, rpr)
        if i % 2:
            rpr.set("b", "1")
        elif "b" in rpr.attrib:
            del rpr.attrib["b"]
        t = r.find(qn("a:t"))
        if t is None:
            t = etree.SubElement(r, qn("a:t"))
        t.text = seg
        if end is not None:
            end.addprevious(r)
        else:
            p_el.append(r)


def _fill_box(shape, lines: list[str]) -> None:
    """Bullets: plain lines use the main bullet, lines starting with '- ' the sub bullet."""
    tf = shape.text_frame
    paras = [p._p for p in tf.paragraphs]
    main = next((p for p in paras if "{{MAIN}}" in "".join(t.text or "" for t in p.iter(qn("a:t")))), paras[0])
    sub = next((p for p in paras if "{{SUB}}" in "".join(t.text or "" for t in p.iter(qn("a:t")))), None)
    if sub is None:                       # derive the "o" sub-bullet from the main bullet
        sub = copy.deepcopy(main)
        ppr = sub.find(qn("a:pPr"))
        if ppr is not None:
            for el in ppr:
                if el.tag == qn("a:buFont"):
                    el.set("typeface", "Courier New")
                    for a in ("panose", "pitchFamily", "charset"):
                        el.attrib.pop(a, None)
                elif el.tag == qn("a:buChar"):
                    el.set("char", "o")
    protos = (copy.deepcopy(main), copy.deepcopy(sub))
    body = main.getparent()
    for p in paras:
        body.remove(p)
    for line in lines or [""]:
        is_sub = line.startswith("- ")
        p = copy.deepcopy(protos[1] if is_sub else protos[0])
        _fill_para(p, line[2:] if is_sub else line)
        body.append(p)


def _cell_text(cell, text: str) -> None:
    tf = cell.text_frame
    for p in list(tf.paragraphs)[1:]:
        p._p.getparent().remove(p._p)
    _fill_para(tf.paragraphs[0]._p, text)


def _cell_lines(cell, lines: list[str]) -> None:
    tf = cell.text_frame
    first = tf.paragraphs[0]._p
    for p in list(tf.paragraphs)[1:]:
        p._p.getparent().remove(p._p)
    proto = copy.deepcopy(first)
    _fill_para(first, lines[0] if lines else "")
    prev = first
    for line in lines[1:]:
        p = copy.deepcopy(proto)
        _fill_para(p, line)
        prev.addnext(p)
        prev = p


def _row_token(tr) -> str:
    txt = "".join(t.text or "" for t in tr.iter(qn("a:t")))
    m = re.search(r"\{\{ROW:(\w+)\}\}", txt)
    return m.group(1) if m else ""


def _table_rows(table, rows: list[tuple[str, list[str]]]) -> None:
    """Rebuild a table from its prototype rows: rows = [(style, [cell texts])]."""
    tbl = table._tbl
    protos = {}
    for tr in list(tbl.tr_lst):
        tok = _row_token(tr)
        if tok:
            protos[tok] = tr
    anchor = None
    for tr in tbl.tr_lst:
        if _row_token(tr):
            anchor = tr
            break
    if anchor is None:
        return
    anchor = anchor.getprevious()
    for style, cells in rows:
        proto = protos.get(style)
        if proto is None:
            proto = next(iter(protos.values()))
        tr = copy.deepcopy(proto)
        tcs = tr.findall(qn("a:tc"))
        for i, tc in enumerate(tcs):
            if tc.get("hMerge") or tc.get("vMerge"):
                continue
            c = _Cell(tc, table)
            if style.startswith("findings") and i == 0 and len(tcs) > 1:
                continue                                 # arrow bullet column
            idx = i - 1 if style.startswith("findings") and len(tcs) > 1 else i
            _cell_text(c, cells[idx] if idx < len(cells) else "")
        if anchor is None:
            tbl.insert(tbl.index(tbl.tr_lst[0]), tr)
        else:
            anchor.addnext(tr)
        anchor = tr
    for tr in protos.values():
        tbl.remove(tr)


# --------------------------------------------------------------------------
# charts
# --------------------------------------------------------------------------
def _dark(chart, title: str) -> None:
    cs = chart._chartSpace
    spPr = cs.find(qn("c:spPr"))
    if spPr is None:
        spPr = etree.SubElement(cs, qn("c:spPr"))
        cs.find(qn("c:chart")).addnext(spPr)
    for ch in list(spPr):
        spPr.remove(ch)
    fill = etree.SubElement(spPr, qn("a:solidFill"))
    etree.SubElement(fill, qn("a:srgbClr")).set("val", BG)
    ln = etree.SubElement(spPr, qn("a:ln"))
    etree.SubElement(ln, qn("a:noFill"))
    chart.font.color.rgb = WHITE
    chart.font.size = Pt(9)
    chart.has_title = True
    tf = chart.chart_title.text_frame
    tf.text = title
    r = tf.paragraphs[0].runs[0]
    r.font.bold, r.font.size, r.font.color.rgb = True, Pt(12), WHITE


def _replace_picture(slide, name: str):
    pic = _shape(slide, name)
    if pic is None:
        return None
    geom = (pic.left, pic.top, pic.width, pic.height)
    pic._element.getparent().remove(pic._element)
    return geom


def bar_chart(slide, placeholder: str, title: str, items: list[tuple[str, int]], n: int = 10):
    geom = _replace_picture(slide, placeholder)
    if geom is None or not items:
        return None
    items = items[:n]
    data = CategoryChartData()
    data.categories = [_trunc(k) for k, _ in reversed(items)]
    data.add_series("Count", [v for _, v in reversed(items)])
    gf = slide.shapes.add_chart(XL_CHART_TYPE.BAR_CLUSTERED, *geom, data)
    ch = gf.chart
    _dark(ch, title)
    ch.has_legend = False
    plot = ch.plots[0]
    plot.gap_width = 40
    plot.has_data_labels = True
    dl = plot.data_labels
    dl.font.bold, dl.font.size, dl.font.color.rgb = True, Pt(9), WHITE
    dl.position = XL_LABEL_POSITION.OUTSIDE_END
    ser = plot.series[0]
    ser.format.fill.solid()
    ser.format.fill.fore_color.rgb = RGBColor.from_string(BAR)
    va = ch.value_axis
    va.has_major_gridlines = True
    va.major_gridlines.format.line.color.rgb = RGBColor.from_string("595959")
    va.format.line.fill.background()
    va.tick_labels.font.color.rgb = WHITE
    ca = ch.category_axis
    ca.tick_labels.font.color.rgb = WHITE
    ca.format.line.color.rgb = RGBColor.from_string("595959")
    return ch


def pie_chart(slide, placeholder: str, title: str, items: list[tuple[str, int]], colors: dict | None = None):
    geom = _replace_picture(slide, placeholder)
    if geom is None or not items:
        return None
    data = CategoryChartData()
    data.categories = [k for k, _ in items]
    data.add_series(title, [v for _, v in items])
    gf = slide.shapes.add_chart(XL_CHART_TYPE.PIE, *geom, data)
    ch = gf.chart
    _dark(ch, title)
    ch.has_legend = True
    ch.legend.position = XL_LEGEND_POSITION.BOTTOM
    ch.legend.include_in_layout = False
    ch.legend.font.color.rgb = WHITE
    plot = ch.plots[0]
    plot.has_data_labels = True
    dl = plot.data_labels
    dl.show_percentage, dl.show_value, dl.number_format, dl.number_format_is_linked = True, False, "0%", False
    dl.font.color.rgb = WHITE
    dl.font.size = Pt(10)
    dl.position = XL_LABEL_POSITION.OUTSIDE_END
    for i, (k, _) in enumerate(items):
        pt = plot.series[0].points[i]
        pt.format.fill.solid()
        pt.format.fill.fore_color.rgb = RGBColor.from_string((colors or {}).get(k, PIE_CYCLE[i % len(PIE_CYCLE)]))
    return ch


# --------------------------------------------------------------------------
# shared slides
# --------------------------------------------------------------------------
def _title_slide(deck: Deck, product: str) -> None:
    s = deck.new("title")
    _title(s, f" Product Efficacy Check – \v{product}")


def _exec_slide(deck: Deck, label: str, findings: list[str]) -> None:
    s = deck.new("exec")
    for sh in s.shapes:
        if sh.has_table:
            t = sh.table
            _cell_text(t.cell(1, 0), label)
            _cell_lines(t.cell(1, 1), findings or ["No findings."])


def _paginate(items: list, budget: int, cost) -> list[list]:
    pages, cur, used = [], [], 0
    for it in items:
        c = cost(it)
        if cur and used + c > budget:
            pages.append(cur)
            cur, used = [], 0
        cur.append(it)
        used += c
    if cur:
        pages.append(cur)
    return pages


def _gap_cost(text: str) -> int:
    return 1 + len(text) // 105


def _findings_slides(deck: Deck, gaps) -> None:
    rows = [g.text for g in gaps if not g.heading]
    for page in _paginate(rows, 18, _gap_cost):
        s = deck.new("findings")
        _title(s, "Findings & Recommendations")
        for sh in s.shapes:
            if sh.has_table:
                _table_rows(sh.table, [("findings", [t]) for t in page])


def _policy_slides(deck: Deck, gaps, header: str, grouped: bool) -> None:
    items = [("heading" if g.heading else "findings", g.text) for g in gaps]
    if not items:
        return
    both = next((t for k, t in items if k == "heading" and t.startswith("In Both")), "")
    pages = _paginate(items, 16, lambda it: 1 if it[0] == "heading" else _gap_cost(it[1]))
    for i in range(len(pages) - 1):              # never end a slide with a lone sub-heading
        while pages[i] and pages[i][-1][0] == "heading":
            pages[i + 1].insert(0, pages[i].pop())
    for page in [p for p in pages if p]:
        s = deck.new("policy_findings")
        _title(s, "Findings & Recommendations")
        head = header
        if grouped and page[0][0] == "heading" and page[0][1].startswith("In Both"):
            head, page = f"{header} {page[0][1]}", page[1:]
        elif grouped and both:
            head = f"{header} {both}"
        rows = [("header", [head])] + [(k, [t]) for k, t in page]
        for sh in s.shapes:
            if sh.has_table:
                _table_rows(sh.table, rows)


def _text(slide, lines: list[str]) -> None:
    boxes = [sh for sh in slide.shapes if sh.has_text_frame and "{{MAIN}}" in sh.text_frame.text]
    if boxes:
        _fill_box(boxes[0], lines)


# --------------------------------------------------------------------------
# Server & Workload Protection
# --------------------------------------------------------------------------
def _top(rows: list[dict], col: str, n: int = 10) -> list[tuple[str, int]]:
    return Counter((r.get(col) or "").strip() for r in rows if (r.get(col) or "").strip()).most_common(n)


def _swp(deck: Deck, hc: HealthCheck, logs: Optional[Path], product: str) -> None:
    from .docx_report import swp_findings
    m = hc.metrics
    when = _short_date(hc)
    _title_slide(deck, product)
    _exec_slide(deck, "Vision one Server and workload security", swp_findings(hc))

    # agent version & platform
    s = deck.new("two_charts")
    _title(s, "Agent Version & Platform\v")
    bar_chart(s, "CHART_1", "Agent Version", m.get("agent_versions") or [])
    bar_chart(s, "CHART_2", "Agent Platform", m.get("platform_counts") or [])
    ver_gap = next((g.text for g in hc.gaps_server if g.key == "swp.inventory.agent_versions"), "")
    _text(s, [_bold_numbers(ver_gap)] if ver_gap else
          [f"All computers are running the latest version ({m.get('latest_dsa_windows')} for Windows, "
           f"{m.get('latest_dsa_linux')} for Linux)."])

    # security update status
    if m.get("deployed_agents"):
        s = deck.new("one_chart")
        _title(s, "Agent Security Update Status")
        items = [(k, m.get(v, 0)) for k, v in (("Out-of-Date", "out_of_date"), ("Up-to-Date", "up_to_date"),
                                               ("Unknown", "update_unknown")) if m.get(v)]
        pie_chart(s, "CHART_1", "Security Update Status", items, PIE)
        if m.get("out_of_date") or m.get("update_unknown"):
            _text(s, [f"**{m.get('out_of_date', 0)}** computers are outdated, and **{m.get('update_unknown', 0)}** "
                      "computers are in an unknown state in Security Update Status, recommended to check the "
                      "communication and perform a security update again. Apply security updates"])
        else:
            _text(s, ["All computers have up-to-date security updates."])

    # Log Inspection
    li = _read_rows(_find(logs, r"Log_Inspection_Events.*\.csv$", r"^LI .*\.csv$"))
    if li:
        s = deck.new("two_charts")
        _title(s, "Log Inspection Detections ")
        reasons = _top(li, "Reason", 7)
        bar_chart(s, "CHART_1", "Log Inspection Reason Triggered", reasons, 7)
        bar_chart(s, "CHART_2", "Top 10 Computer With Log Inspection Detection", _top(li, "Computer", 10))
        n = len(li)
        lines = [f"There were {'more than ' if n >= 5000 else ''}**{n}** detections of Log Inspection from the "
                 f"last 30 days on {when}."]
        for reason, cnt in reasons[:2]:
            hosts = [h for h, _ in _top([r for r in li if r.get("Reason") == reason], "Computer", 4)]
            where = f"{_join(hosts[:3])} computers" if len(hosts) <= 3 else "multiple computers"
            lines.append(f"**{reason}** - This rule was triggered **{cnt}** times on {where}.")
        _text(s, lines)
        _li_table_slide(deck, li)

    # Intrusion Prevention
    ips = _read_rows(_find(logs, r"Intrusion_Prevention_Events.*\.csv$", r"^IPS .*\.csv$"))
    if ips:
        s = deck.new("two_charts")
        _title(s, "Intrusion Prevention Detection\v")
        reasons = _top(ips, "Reason", 7)
        bar_chart(s, "CHART_1", "IPS Reason Detection", reasons, 7)
        bar_chart(s, "CHART_2", "Top 10 Computer With IPS Detection", _top(ips, "Computer", 10))
        top_reason, cnt = reasons[0]
        sub = [r for r in ips if r.get("Reason") == top_reason]
        hosts = [h for h, _ in _top(sub, "Computer", 4)]
        where = f"{_join(hosts[:3])} computers" if len(hosts) <= 3 else "multiple computers"
        lines = [f"There were total of **{len(ips)}** detections of Intrusion Prevention for last 30 days on {when}.",
                 f"**{top_reason}** - This rule was triggered **{cnt}** times on {where}.",
                 f"- **Action:** {', '.join(k for k, _ in _top(sub, 'Action', 3))}",
                 f"- **Top 5 Source IP:** {', '.join(k for k, _ in _top(sub, 'Source IP', 5))}",
                 f"- **Top 5 Destination IP:** {', '.join(k for k, _ in _top(sub, 'Destination IP', 5))}",
                 f"- **Direction:** {', '.join(k for k, _ in _top(sub, 'Direction', 2))}"]
        _text(s, lines)
        cves = [(k, v) for k, v in Counter(r.get("Reason", "") for r in ips).most_common() if "CVE-" in k]
        if cves:
            reason, cnt = cves[0]
            sub = [r for r in ips if r.get("Reason") == reason]
            s = deck.new("cve")
            _title(s, "Intrusion Prevention Detection")
            hosts = [h for h, _ in _top(sub, "Computer", 4)]
            where = f"{_join(hosts[:3])} computers" if len(hosts) <= 3 else "multiple computers"
            _text(s, [f"**{reason}** - This rule was triggered **{cnt}** times on {where}.",
                      f"- **Action:** {', '.join(k for k, _ in _top(sub, 'Action', 3))}",
                      f"- **Source IP:** {', '.join(k for k, _ in _top(sub, 'Source IP', 5))}",
                      f"- **Destination IP:** {', '.join(k for k, _ in _top(sub, 'Destination IP', 5))}",
                      f"- **Direction:** {', '.join(k for k, _ in _top(sub, 'Direction', 2))}"])
            pie_chart(s, "CHART_1", "Action", _top(ips, "Action", 6),
                      {"Reset": "ED7D31", "Detect Only: Reset": "146182"})

    _findings_slides(deck, hc.gaps_server)
    _policy_slides(deck, hc.gaps_policy, "Gap Description and Remediation:", grouped=True)
    deck.new("end")


def _bold_numbers(text: str) -> str:
    """'All agents ... 20.0.3.29020 ...' -> bold the subject and version numbers, as in the decks."""
    text = re.sub(r"\b(\d+(?:\.\d+){2,})\b", r"**\1**", text)
    return re.sub(r"^(All|\d+)\b", r"**\1**", text)


def _li_table_slide(deck: Deck, li: list[dict]) -> None:
    by_reason = OrderedDict()
    for reason, cnt in Counter(r.get("Reason", "") for r in li).most_common():
        descs = Counter(r.get("Description", "") for r in li if r.get("Reason") == reason).most_common(12)
        by_reason[reason] = (cnt, descs)
    rows = []
    for reason, (cnt, descs) in by_reason.items():
        rows.append(("group", [reason, str(cnt)]))
        rows += [("item", [d or "(no description)", str(n)]) for d, n in descs]
    cap = 40
    if len(rows) > cap - 1:                     # keep the slide readable: trim the longest groups
        rows = rows[: cap - 1]
    left, right = rows[:21], rows[21:]
    s = deck.new("li_tables")
    _title(s, "Log Inspection Detections ")
    tables = sorted([sh for sh in s.shapes if sh.has_table], key=lambda sh: sh.left)
    # the right-hand table borrows the group-row style from the left one
    if len(tables) == 2:
        group_proto = next((tr for tr in tables[0].table._tbl.tr_lst if _row_token(tr) == "group"), None)
        if group_proto is not None:
            first = tables[1].table._tbl.tr_lst[0]
            first.addprevious(copy.deepcopy(group_proto))
    total = ("total", ["Total", str(len(li))])
    if len(tables) == 2:
        _table_rows(tables[0].table, left)
        _table_rows(tables[1].table, right + [total])
    elif tables:
        _table_rows(tables[0].table, rows + [total])
    cats = []
    for reason in by_reason:
        for key, label in (("windows", "Microsoft Windows"), ("syslog", "Syslog"), ("active directory", "Active Directory"),
                           ("nginx", "Nginx Server"), ("apache", "Apache Server"), ("ssh", "SSH"),
                           ("mysql", "MySQL"), ("sql server", "SQL Server"), ("iis", "IIS")):
            if key in reason.lower() and label not in cats:
                cats.append(label)
    lines = []
    if cats:
        lines.append(f"Work internally on {_join(cats)} events.")
    lines.append("Regularly review and analyze these logs for any access granted events, especially those "
                 "pertaining to privileged accounts.")
    _text(s, lines)


# --------------------------------------------------------------------------
# Standard Endpoint Protection
# --------------------------------------------------------------------------
DETECTIONS = [
    # file prefix, title, item column, endpoint column, outcome column, noun
    ("VM ", "Virus/Malware Detection", "Virus/Malware", "Endpoint", "Action", "Virus/Malware"),
    ("SG ", "Spyware/Grayware Detection", "Spyware/Grayware", "Endpoint", "Action", "Spyware/Grayware"),
    ("WV ", "Web Reputation Detection", "URL", "Endpoint Host", "Action", "Web Violation"),
    ("DC ", "Device Control Detection", "Device Type", "Product Entity/Endpoint", "Permission", "Device Control"),
    ("C&C ", "C&C Calback Detection", "Callback Address", "Compromised Host", "Action", "C&C Callback"),
    ("BM ", "Behaviour Monitoring Detection", "Rule Name", "Endpoint", "Action", "Behaviour Monitoring"),
]
ACTION_WORDS = {"file cleaned": "Cleaned", "file quarantined": "Quarantined", "file passed": "Passed",
                "file deleted": "Deleted", "unable to upload file": "Unable to upload file",
                "block": "Blocked", "deny": "Denied", "terminate": "Terminated", "allow": "Allowed"}


def _outcome(word: str) -> str:
    w = (word or "").strip()
    if w.lower().startswith("action required"):
        return "Restart required"
    return ACTION_WORDS.get(w.lower(), w)


def _sep(deck: Deck, hc: HealthCheck, logs: Optional[Path], product: str) -> None:
    from .docx_report import executive_findings
    m = hc.metrics
    when = _short_date(hc)
    _title_slide(deck, product)
    _exec_slide(deck, product, executive_findings(hc, "SEP"))

    agents = _find(logs, r"Agent List.*\.csv$")
    if agents:
        import csv
        with agents.open(encoding="utf-8-sig", newline="") as fh:
            rows = [r for r in csv.DictReader(fh) if any(r.values())]
        s = deck.new("versions")
        _title(s, "Agent Version & Platform\v")
        bar_chart(s, "CHART_1", "Agent Program Version",
                  sorted(Counter(r.get("Agent Program", "") for r in rows if r.get("Agent Program")).items(),
                         key=lambda kv: [-int(x) for x in re.findall(r"\d+", kv[0])]), 10)
        plat = Counter((r.get("Platform") or "").strip() for r in rows if (r.get("Platform") or "").strip())
        for sh in s.shapes:
            if sh.has_table:
                _table_rows(sh.table, [("item", [_trunc(k, 32), str(v)]) for k, v in plat.most_common(10)]
                            + [("total", ["Total", str(len(rows))])])
        lines = [f"**{m.get('latest_build')}** is the latest agent Program versions recommended to upgrade all "
                 "the older agents to the latest version."]
        if m.get("server_agents"):
            lines.append(f"**{m['server_agents']}** Servers are using the Apex One Security agent, recommended to "
                         "use Server and Workload Security for better protection of the server.")
        _text(s, lines)

    for prefix, title, item_col, host_col, out_col, noun in DETECTIONS:
        path = _find(logs, "^" + re.escape(prefix))
        rows = _read_rows(path)
        if not rows:
            continue
        if prefix == "BM ":
            _bm_slides(deck, rows, when)
            continue
        s = deck.new("two_charts")
        _title(s, title)
        items = _top(rows, item_col, 10)
        bar_chart(s, "CHART_1", title, items, 8)
        bar_chart(s, "CHART_2", f"Endpoints in {title}" if prefix not in ("C&C ",) else "Endpoints Having C&C Detection",
                  _top(rows, host_col, 10))
        n = len(rows)
        verb = "There were" if prefix in ("VM ", "SG ", "WV ") else "There was a total of"
        period = "from the last 30 days" if prefix == "SG " else "from last 30 days" if prefix in ("VM ", "WV ") \
            else "for last 30 days"
        lines = [f"{verb} **{n}** detection{'s' if n != 1 else ''} of {noun} {period} on {when}."]
        outcomes_all = [k for k, _ in _top(rows, out_col, 6)]
        if prefix == "DC ":
            host, _ = _top(rows, host_col, 1)[0]
            perm = _top([r for r in rows if r.get(host_col) == host], out_col, 1)[0][0]
            lines.append(f"**{host}** was the endpoint that was triggered the most having Device control detection "
                         f"and was **{perm}** .")
        elif prefix == "C&C ":
            parts = [f"**{k}** callback address detected **{_times(v)}**" for k, v in items[:3]]
            acts = ", ".join(sorted({_outcome(x).lower() for x in outcomes_all}))
            lines.append(", and ".join(parts) + f" and connections were **{acts}**.")
            lines.append("Recommended to check these address, if it's a secure connection then add it to the "
                         "suspicious approve list otherwise block this address.")
        else:
            for name, cnt in items[:2]:
                sub = [r for r in rows if r.get(item_col) == name]
                hosts = [h for h, _ in _top(sub, host_col, 4)]
                acts = sorted({_outcome(r.get(out_col, "")) for r in sub} - {"Restart required"})
                acts_txt = " and ".join(a.lower() for a in acts) if acts else "detected"
                if prefix == "WV ":
                    lines.append(f"**{name}** This site is detected **{cnt}** times on {_hosts_phrase(hosts)}, "
                                 f"and the URLs were **{' and '.join(acts) or 'Blocked'}**.")
                else:
                    extra = " Action Required - Restart the endpoint to finish cleaning the security threat." if any(
                        _outcome(r.get(out_col, "")) == "Restart required" for r in sub) else ""
                    lines.append(f"**{name}** {noun} was detected **{cnt}** times on {_hosts_phrase(hosts)}, and "
                                 f"the files were **{acts_txt}**.{extra}")
        _text(s, lines)
        if prefix == "C&C ":
            continue
        # outcome slide
        s2 = deck.new("one_chart")
        _title(s2, title)
        pie_chart(s2, "CHART_1", "Action", _top(rows, out_col, 6))
        outs = []
        for o in outcomes_all:
            w = _outcome(o)
            if w not in outs and w != "Restart required":
                outs.append(w)
        lines = []
        if prefix in ("VM ", "SG "):
            lines.append(f"Files were **{_join(outs, bold=False)}** by Apex One.")
            restart = sorted({r.get(host_col, "") for r in rows
                              if _outcome(r.get(out_col, "")) == "Restart required" and r.get(host_col)})
            if restart:
                lines.append(f"{_join(restart)} endpoint{'s' if len(restart) > 1 else ''} require a restart to "
                             "complete the cleanup of detected security threats. It is recommended to restart "
                             f"{'those endpoints' if len(restart) > 1 else 'that endpoint'}.")
            worst = _top(rows, host_col, 1)[0][0]
            lines.append(f"Kindly check **{worst}** endpoint and remove infected files, as well as unwanted "
                         "malicious software if found any that may have been installed in your computer, run a "
                         "full-system scan with TrendAI apex one agent.")
            lines.append("Keep all agent Program versions & pattern versions up to Date.")
        elif prefix == "WV ":
            lines.append(f"All the web violation events were **{outs[0]}**." if len(outs) == 1 else
                         f"Web violation events were **{_join(outs, bold=False)}**.")
        elif prefix == "DC ":
            lines.append(f"All detections triggered have been **{outs[0]}**." if len(outs) == 1 else
                         f"Detections triggered have been **{_join(outs, bold=False)}**.")
        _text(s2, lines)

    _findings_slides(deck, hc.gaps_server)
    _policy_slides(deck, hc.gaps_policy,
                   f"Policy Gap Description and Remediation: {hc.policy_name or 'Endpoint'} Policy", grouped=False)
    deck.new("end")


def _bm_slides(deck: Deck, rows: list[dict], when: str) -> None:
    s = deck.new("two_charts")
    _title(s, "Behaviour Monitoring Detection")
    bar_chart(s, "CHART_1", "BM Detection By Policy", _top(rows, "Rule Name", 8), 8)
    bar_chart(s, "CHART_2", "BM Detection on Endpoints", _top(rows, "Endpoint", 10))
    lines = [f"There was a total of **{len(rows)}** detections of Behaviour Monitoring for last 30 days on {when}."]
    for name, cnt in _top(rows, "Rule Name", 2):
        sub = [r for r in rows if r.get("Rule Name") == name]
        hosts = [h for h, _ in _top(sub, "Endpoint", 4)]
        acts = sorted({_outcome(r.get("Action", "")) for r in sub})
        lines.append(f"**{cnt}** times **{name}** was triggered on {_hosts_phrase(hosts)}, and it was "
                     f"**{' and '.join(acts)}**.")
    _text(s, lines)

    actions = [a for a, _ in _top(rows, "Action", 6)]
    s2 = deck.new("bm_table")
    _title(s2, "Behaviour Monitoring Detection")
    table = next((sh.table for sh in s2.shapes if sh.has_table), None)
    if table is not None:
        _set_action_columns(table, actions)
        out = []
        groups = Counter((r.get("Rule Name", ""), r.get("Risk Level", "")) for r in rows)
        for (rule, risk), _ in groups.most_common():
            sub = [r for r in rows if r.get("Rule Name") == rule and r.get("Risk Level") == risk]
            cnt = Counter(r.get("Action", "") for r in sub)
            out.append(("group", [f"**{rule}** - {risk}"] + [str(cnt[a]) if cnt[a] else " " for a in actions]))
            for op, _ in _top(sub, "Operation", 6):
                c2 = Counter(r.get("Action", "") for r in sub if r.get("Operation") == op)
                out.append(("item", [op] + [str(c2[a]) if c2[a] else " " for a in actions]))
        tot = Counter(r.get("Action", "") for r in rows)
        out.append(("total", ["Total"] + [str(tot[a]) for a in actions]))
        _table_rows(table, out)
    ops = [o for o, _ in _top(rows, "Operation", 5)]
    acts = [_outcome(a) for a in actions]
    _text(s2, [f"The events which were triggered have been **{_join(acts, bold=False)}**.",
               f"The operations that were triggered such as **{_join(ops, bold=False)}** . Recommended  to check the "
               "process, if genuine then ignore it if not then take specific action accordingly."])


def _set_action_columns(table, actions: list[str]) -> None:
    """Grow / shrink the Action columns of the BM table to the actions seen."""
    tbl = table._tbl
    grid = tbl.tblGrid
    cols = grid.findall(qn("a:gridCol"))
    have = len(cols) - 1
    want = max(1, len(actions))
    total_w = sum(int(c.get("w")) for c in cols[1:])
    while have < want:
        grid.append(copy.deepcopy(cols[-1]))
        for tr in tbl.tr_lst:
            tr.append(copy.deepcopy(tr.findall(qn("a:tc"))[-1]))
        have += 1
    while have > want:
        grid.remove(grid.findall(qn("a:gridCol"))[-1])
        for tr in tbl.tr_lst:
            tr.remove(tr.findall(qn("a:tc"))[-1])
        have -= 1
    for c in grid.findall(qn("a:gridCol"))[1:]:
        c.set("w", str(total_w // want))
    trs = tbl.tr_lst
    head = trs[0].findall(qn("a:tc"))
    head[1].set("gridSpan", str(want))
    for tc in head[2:]:
        tc.set("hMerge", "1")
    for i, a in enumerate(actions):
        _cell_text(_Cell(trs[1].findall(qn("a:tc"))[i + 1], table), a)


# --------------------------------------------------------------------------
# Cloud Email and Collaboration Protection
# --------------------------------------------------------------------------
def _exec_slide_levels(deck: Deck, label: str, findings: list[str]) -> None:
    """Executive summary whose cell has a main ("Ø") and a sub ("o") bullet prototype;
    lines starting with a tab use the sub bullet."""
    s = deck.new("exec")
    for sh in s.shapes:
        if not sh.has_table:
            continue
        t = sh.table
        _cell_text(t.cell(1, 0), label)
        tf = t.cell(1, 1).text_frame
        paras = [p._p for p in tf.paragraphs]
        sub = next((p for p in paras if "{{EXEC_SUB}}" in "".join(x.text or "" for x in p.iter(qn("a:t")))), None)
        main = paras[0]
        protos = (copy.deepcopy(main), copy.deepcopy(sub if sub is not None else main))
        body = main.getparent()
        for p in paras:
            body.remove(p)
        for line in findings or ["No findings."]:
            p = copy.deepcopy(protos[1] if line.startswith("\t") else protos[0])
            _fill_para(p, line.lstrip("\t"))
            body.append(p)


def _picture_at(slide, placeholder: str, png: bytes) -> bool:
    import io
    geom = _replace_picture(slide, placeholder)
    if geom is None:
        return False
    slide.shapes.add_picture(io.BytesIO(png), *geom)
    return True


def _chart(slide, placeholder: str, title: str, items, vertical) -> None:
    if vertical is None:
        pie_chart(slide, placeholder, title, items)
    else:
        bar_chart(slide, placeholder, title, items)


def _grouped_findings_slides(deck: Deck, gaps) -> None:
    """One table: gap rows with sub-heading rows; a heading is repeated when its
    gaps continue on the next slide."""
    items = [("heading" if g.heading else "findings", g.text) for g in gaps]
    if not items:
        return
    pages = _paginate(items, 20, lambda it: 1 if it[0] == "heading" else _gap_cost(it[1]))
    for i in range(len(pages) - 1):               # never end a slide with a lone sub-heading
        while pages[i] and pages[i][-1][0] == "heading":
            pages[i + 1].insert(0, pages[i].pop())
    current = None
    for page in [p for p in pages if p]:
        if page[0][0] != "heading" and current:
            page = [("heading", current)] + page
        for k, t in page:
            if k == "heading":
                current = t
        s = deck.new("grouped_findings")
        _title(s, "Findings & Recommendations")
        for sh in s.shapes:
            if sh.has_table:
                _table_rows(sh.table, [(k, [t]) for k, t in page])


def _cecp(deck: Deck, hc: HealthCheck, logs: Optional[Path], product: str) -> None:
    from ..sources import cecp_exports
    from .docx_report import THREAT_ORDER, cecp_findings, threat_charts
    m = hc.metrics
    _title_slide(deck, product)
    if "static" in deck.protos:
        deck.new("static")
    _exec_slide_levels(deck, "TrendAI Cloud Email and Collaboration Protection", cecp_findings(hc))

    s = deck.new("totals")
    _title(s, "Total Scans and Detections")
    if m.get("_total_panel_png"):
        _picture_at(s, "CHART_1", m["_total_panel_png"])
    else:
        _replace_picture(s, "CHART_1")
    counts = sorted((m.get("threat_counts") or {}).items(), key=lambda kv: -kv[1])
    if counts:
        bar_chart(s, "CHART_2", f"Threat Detected in {m.get('month_name', '')}".strip(), counts)
    else:
        _replace_picture(s, "CHART_2")
    lines = []
    if m.get("period_from"):
        lines.append(f"We collected logs from {m['period_from']} to {m['period_to']}.")
    if m.get("total_scans"):
        lines.append(f"The total number of Items scanned (Files/Chats/Records/Emails) in the {m.get('month_abbr', '')} "
                     f"Month was **{m['total_scans_text']}** and  **{m.get('threats_total', 0)}** threats were detected.")
    _text(s, lines or ["No detection logs were provided."])

    threats = m.get("threats") or {}
    for ttype in [t for t in THREAT_ORDER if t in threats] + [t for t in threats if t not in THREAT_ORDER]:
        info = threats[ttype]
        charts = threat_charts(ttype, info)
        count = cecp_exports.count_sentence(ttype, info, m, short=True).replace(
            f" {ttype} ", f" **{ttype}** ", 1)
        action = cecp_exports.action_sentence(ttype, info)
        if not charts:
            continue
        first, rest = (charts[:2], charts[2:]) if len(charts) != 2 else (charts, [])
        kind = "two_charts" if len(first) == 2 else "one_chart"
        s = deck.new(kind)
        _title(s, f"{ttype} Detections:")
        for i, (title, items, vertical) in enumerate(first, 1):
            _chart(s, f"CHART_{i}", title, items, vertical)
        _text(s, [count] + ([action] if action and not rest else []))
        for title, items, vertical in rest:
            s = deck.new("one_chart")
            _title(s, f"{ttype} Detections:")
            _chart(s, "CHART_1", title, items, vertical)
            _text(s, [action] if action else [count])

    _grouped_findings_slides(deck, list(hc.gaps_server) + list(hc.gaps_policy))
    deck.new("end")


# --------------------------------------------------------------------------
def render_presentation(hc: HealthCheck, out_path: str | Path, short: str = "SEP",
                        logs_dir: Optional[Path] = None, product: str = "") -> Path:
    template = TEMPLATES / f"{short.lower()}_efficacy_template.pptx"
    if not template.exists():
        raise FileNotFoundError(f"no presentation template for {short}")
    deck = Deck(template)
    logs = Path(logs_dir) if logs_dir else None
    if short == "SWP":
        _swp(deck, hc, logs, product or "Server & Workload Protection")
    elif short == "CECP":
        _cecp(deck, hc, logs, product or "Cloud Email and Collaboration Protection")
    else:
        _sep(deck, hc, logs, product or "Standard Endpoint Protection")
    cp = deck.prs.core_properties
    cp.title = f"Product Efficacy Report - {product} - {hc.client_name}"
    cp.author = hc.prepared_by
    cp.keywords = ""
    return deck.finish(Path(out_path))
