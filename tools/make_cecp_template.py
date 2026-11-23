"""Build the CECP report template from an analyst's finished CECP report.

    python tools/make_cecp_template.py FINISHED_CECP_REPORT.docx \
        tmhc/render/templates/cecp_report_template.docx \
        --client "Acme Corporation Limited" --owner "Account Owner Name" \
        --by "Analyst Name" --quarter "Q4 2026" --report-date 18/11/2026 \
        --check-date "27 Oct 2026" --period-from "01 Sept 2026" --period-to "30 Sept 2026" \
        --forbid acme --forbid analyst

On top of tools/make_template.py (row-for-row settings tables, gap table,
client strings -> placeholders) this:

* keeps a sub-bullet ("o") paragraph in the executive summary cell;
* turns the first "<threat> Detections" block of the detections section
  into prototypes ({{THREAT_HEADING}} / {{THREAT_COUNT}} / {{THREAT_PIC}} /
  {{THREAT_ACTION}}) and removes the other blocks - the renderer writes one
  block per threat type found in the logs;
* swaps every chart / console picture of the detections section for a
  neutral placeholder (they show the client's users and senders);
* refuses to save if any --forbid word is still present anywhere.
"""
from __future__ import annotations

import argparse
import copy
import io
import re
import sys
import tempfile
import zipfile
from pathlib import Path

import docx
from docx.oxml.ns import qn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_template  # noqa: E402
from tmhc.render.docx_utils import _fill_paragraph  # noqa: E402

DEFAULT_POLICIES = {
    "Default Exchange Policy ATP": "m.exo_policy_name",
    "Default SharePoint Online Policy ATP (Monitor Only)": "m.spo_policy_name",
    "Default OneDrive Policy ATP(Monitor Only)": "m.odb_policy_name",
    "Default OneDrive Policy ATP (Monitor Only)": "m.odb_policy_name",
    "Default Microsoft Teams Policy ATP(Monitor Only)": "m.teams_policy_name",
    "Default Microsoft Teams Policy ATP (Monitor Only)": "m.teams_policy_name",
}


def _placeholder_png() -> bytes:
    from PIL import Image, ImageDraw
    im = Image.new("RGB", (750, 450), (64, 64, 64))
    ImageDraw.Draw(im).text((300, 215), "chart", fill=(200, 200, 200))
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def _ptext(p) -> str:
    return "".join(t.text or "" for t in p.iter(qn("w:t"))).strip()


def _set_text(p, text: str) -> None:
    _fill_paragraph(p, text, None)


def post_process(src: Path, tmpl: Path) -> None:
    orig = docx.Document(str(src))
    doc = docx.Document(str(tmpl))

    # ---- executive summary: keep a sub-bullet prototype -------------------------
    exec_tbl = next((t for t in doc.tables if "{{EXEC_FINDING}}" in t._tbl.xml), None)
    o_tbl = next((t for t in orig.tables
                  if make_template.header_text(t).startswith(("Product | Findings", "Products | Findings"))), None)
    if exec_tbl is not None and o_tbl is not None:
        o_cell = o_tbl._tbl.findall(qn("w:tr"))[1].findall(qn("w:tc"))[-1]
        paras = o_cell.findall(qn("w:p"))

        def num_id(p):
            el = p.find(".//" + qn("w:numId"))
            return el.get(qn("w:val")) if el is not None else None
        first = num_id(paras[0]) if paras else None
        sub = next((p for p in paras if num_id(p) not in (None, first)), None)
        if sub is not None:
            proto = copy.deepcopy(sub)
            _set_text(proto, "{{EXEC_SUB}}")
            cell = exec_tbl._tbl.findall(qn("w:tr"))[1].findall(qn("w:tc"))[-1]
            cell.findall(qn("w:p"))[-1].addnext(proto)

    # ---- detections section ------------------------------------------------------
    body = doc.element.body
    paras = [el for el in body.iterchildren() if el.tag == qn("w:p")]
    texts = [_ptext(p) for p in paras]

    def idx(pred, start=0):
        for i in range(start, len(paras)):
            if pred(texts[i]):
                return i
        return None

    i_logs = idx(lambda t: t.startswith("We collected logs from"))
    if i_logs is not None:
        _set_text(paras[i_logs], "We collected logs from {{m.period_from}} to {{m.period_to}}.")
    i_tot = idx(lambda t: t.startswith("The total number of Items scanned"))
    if i_tot is not None:
        _set_text(paras[i_tot], "The total number of Items scanned (Files/Chats/Records/Emails) in the "
                                "{{m.month_abbr}} Month is {{m.total_scans_text}}.")
    i_top = idx(lambda t: t.startswith("Top Detections by"))
    i_end = idx(lambda t: t == "Trend Vision One", (i_top or 0))
    if i_top is not None and i_end is not None:
        i_head = idx(lambda t: t.endswith("Detections"), i_top + 1)
        block = paras[i_head:i_end]
        count_p = block[1]
        pics = [p for p in block[2:] if p.find(".//" + qn("w:drawing")) is not None]
        i_action = next(i for i, p in enumerate(block[2:], start=2)
                        if p.find(".//" + qn("w:drawing")) is None and _ptext(p))
        action_p = block[i_action]
        _set_text(block[0], "{{THREAT_HEADING}}")
        _set_text(count_p, "{{THREAT_COUNT}}")
        pic = pics[0]
        for r in pic.findall(qn("w:r")):
            pic.remove(r)
        _set_text(pic, "{{THREAT_PIC}}")
        _set_text(action_p, "{{THREAT_ACTION}}")
        keep = {id(block[0]), id(count_p), id(pic), id(action_p)}
        # remove the rest of the blocks; keep the blank paragraph before the next heading
        for p in block[:-1]:
            if id(p) not in keep:
                body.remove(p)

    # ---- DLP rows under each policy table follow the DLP policy lists ----------------
    from tmhc.render.docx_utils import replace_everywhere
    replace_everywhere([body], {"Policy is not enabled for all users of Data Loss Prevention.": "{{m.dlp_exo_line}}",
                                "Policy is not enabled for Data Loss Prevention.": "{{m.dlp_collab_line}}"})

    # ---- placeholder pictures for the charts kept in the template -----------------
    blank = _placeholder_png()
    for el in body.iter(qn("a:blip")):
        rid = el.get(qn("r:embed"))
        part = doc.part.related_parts.get(rid)
        if part is None:
            continue
        p = el
        while p is not None and p.tag != qn("w:p"):
            p = p.getparent()
        prev = p.getprevious() if p is not None else None
        label = _ptext(prev) if prev is not None else ""
        if label.startswith(("The total number of Items scanned", "Over-all Threat Detection")):
            part._blob = blank
    doc.save(str(tmpl))


def forbid_scan(path: Path, words: list[str]) -> list[tuple[str, str]]:
    hits = []
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if not name.endswith((".xml", ".rels")):
                continue
            xml = z.read(name).decode("utf-8", "ignore")
            for w in words:
                if re.search(r"\b" + re.escape(w) + r"\b", xml, re.I):
                    hits.append((name, w))
    return hits


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--client", required=True)
    ap.add_argument("--owner", required=True)
    ap.add_argument("--by", required=True)
    ap.add_argument("--quarter", required=True)
    ap.add_argument("--report-date", required=True)
    ap.add_argument("--check-date", required=True, help='as printed, e.g. "27 Oct 2026"')
    ap.add_argument("--period-from", required=True)
    ap.add_argument("--period-to", required=True)
    ap.add_argument("--forbid", action="append", default=[], help="word that must not survive (repeatable)")
    a = ap.parse_args()
    rep = {a.client: "client_name", a.owner: "account_owner", a.by: "prepared_by", a.quarter: "quarter",
           a.report_date: "report_date", a.check_date: "check_date_short",
           a.period_from: "m.period_from", a.period_to: "m.period_to"}
    rep.update(DEFAULT_POLICIES)
    rep = dict(sorted(rep.items(), key=lambda kv: -len(kv[0])))
    import yaml
    row_map = yaml.safe_load((Path(__file__).parent / "cecp_row_map.yaml").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        mid = Path(tmp) / "t.docx"
        make_template.build(a.report, mid, rep, row_map)
        post_process(a.report, mid)
        hits = forbid_scan(mid, a.forbid + [a.client.split()[0], a.owner.split()[0], a.by.split()[0]])
        if hits:
            raise SystemExit(f"client strings still present, template not saved: {sorted(set(hits))}")
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_bytes(mid.read_bytes())
    print(f"template written: {a.out}")


if __name__ == "__main__":
    main()
