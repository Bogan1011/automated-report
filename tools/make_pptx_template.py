"""Turn a finished Product Efficacy deck into a reusable presentation template.

    python tools/make_pptx_template.py REFERENCE.pptx OUT.pptx --product swp
    python tools/make_pptx_template.py REFERENCE.pptx OUT.pptx --product sep

Keeps one prototype slide per slide kind (title, executive summary, chart
slides, tables, findings, end) in the analyst's exact design, and removes
every client detail:

* the client logo on the title slide becomes a grey "Client logo"
  placeholder (right-click > Change Picture in PowerPoint keeps its place);
* chart pictures become empty placeholders named CHART_1, CHART_2 ... - the
  generator draws native, editable charts in their place;
* text boxes keep one paragraph per bullet style ({{MAIN}} / {{SUB}});
* tables keep one prototype row per row style ({{ROW:...}} tokens).

The kinds are stored in the template's keywords so the generator knows
which slide is which.
"""
from __future__ import annotations

import argparse
import copy
import io
import sys
import zipfile
from pathlib import Path

from pptx import Presentation
from pptx.enum.shapes import MSO_SHAPE_TYPE

# reference slide number (1-based) -> kind
LAYOUTS = {
    "swp": {1: "title", 2: "exec", 3: "two_charts", 4: "one_chart", 6: "li_tables", 8: "cve",
            9: "findings", 11: "policy_findings", 12: "end"},
    "sep": {1: "title", 2: "exec", 3: "versions", 4: "two_charts", 5: "one_chart", 14: "bm_table",
            15: "findings", 17: "policy_findings", 19: "end"},
}
STATIC_TEXT = {"cve": {"TextBox 5"}}       # generic advice kept as written


def _png(w: int, h: int, text: str = "") -> bytes:
    from PIL import Image, ImageDraw
    im = Image.new("RGB", (max(1, w), max(1, h)), (215, 215, 215))
    if text:
        d = ImageDraw.Draw(im)
        d.rectangle([2, 2, w - 3, h - 3], outline=(150, 150, 150), width=3)
        d.text((w // 2 - 4 * len(text), h // 2 - 6), text, fill=(90, 90, 90))
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def _bullet(p) -> str:
    pPr = p._p.pPr
    if pPr is None:
        return ""
    for el in pPr:
        if el.tag.endswith("buChar"):
            return el.get("char", "")
    return ""


def _keep_protos(tf) -> None:
    """Keep the first main-bullet and first sub-bullet paragraph, tokenised."""
    paras = list(tf.paragraphs)
    main = next((p for p in paras if _bullet(p) not in ("o", "")), paras[0])
    sub = next((p for p in paras if _bullet(p) == "o"), None)
    for p in paras:
        if p is not main and p is not sub:
            p._p.getparent().remove(p._p)
    _set_runs(main, "{{MAIN}}")
    if sub is not None:
        _set_runs(sub, "{{SUB}}")


def _set_runs(p, text: str) -> None:
    runs = p.runs
    if not runs:
        p.add_run().text = text
        return
    runs[0].text = text
    for r in runs[1:]:
        r._r.getparent().remove(r._r)


def _set_cell(cell, text: str) -> None:
    tf = cell.text_frame
    for p in list(tf.paragraphs)[1:]:
        p._p.getparent().remove(p._p)
    _set_runs(tf.paragraphs[0], text)


def _keep_rows(table, keep: dict) -> None:
    """keep: {row_index: token}; other rows removed. Negative indexes count from the end."""
    trs = list(table._tbl.tr_lst)
    n = len(trs)
    wanted = {(i if i >= 0 else n + i): tok for i, tok in keep.items()}
    for i, tr in enumerate(trs):
        if i not in wanted:
            table._tbl.remove(tr)
    for i, tok in wanted.items():
        if tok is None:
            continue
        cells = trs[i].tc_lst
        from pptx.table import _Cell
        for ci, tc in enumerate(cells):
            c = _Cell(tc, table)
            if tc.get("hMerge") or tc.get("vMerge"):
                continue
            txt = tok if ci == 0 else ("{{C%d}}" % ci)
            if tok == "{{KEEP}}":
                continue
            if tok.startswith("{{ROW:findings") and ci == 0:
                continue                                    # the arrow bullet cell
            _set_cell(c, txt if not (tok.startswith("{{ROW:findings") and ci == 1) else tok)


def build(src: Path, dst: Path, product: str) -> None:
    prs = Presentation(str(src))
    layout = LAYOUTS[product]
    kinds = []
    keep_ids = []
    for idx, slide in enumerate(prs.slides, 1):
        kind = layout.get(idx)
        if not kind:
            continue
        kinds.append(kind)
        keep_ids.append(slide.slide_id)
        pics = sorted([s for s in slide.shapes if s.shape_type == MSO_SHAPE_TYPE.PICTURE], key=lambda s: (s.top, s.left))
        for n, pic in enumerate(pics, 1):
            w, h = max(1, int(pic.width / 12700)), max(1, int(pic.height / 12700))
            if kind == "title":
                pic.name = "CLIENT_LOGO"
                pic._element.blipFill.blip.rEmbed  # noqa: B018 - must exist
                pic.image  # noqa: B018
                part = slide.part.related_part(pic._element.blipFill.blip.rEmbed)
                part._blob = _png(w * 2, h * 2, "Client logo")
            else:
                pic.name = f"CHART_{n}"
                part = slide.part.related_part(pic._element.blipFill.blip.rEmbed)
                part._blob = _png(8, 8)
        for shape in slide.shapes:
            if shape.has_text_frame and not shape.is_placeholder and shape.name not in STATIC_TEXT.get(kind, set()):
                if shape.text_frame.text.strip():
                    _keep_protos(shape.text_frame)
            if not shape.has_table:
                continue
            t = shape.table
            if kind == "exec":
                _keep_rows(t, {0: "{{KEEP}}", 1: None})
                _set_cell(t.cell(1, 0), "{{EXEC_PRODUCT}}")
                tf = t.cell(1, 1).text_frame
                for p in list(tf.paragraphs)[1:]:
                    p._p.getparent().remove(p._p)
                _set_runs(tf.paragraphs[0], "{{EXEC_FINDINGS}}")
            elif kind == "versions":
                _keep_rows(t, {0: "{{KEEP}}", 1: "{{ROW:item}}", -1: "{{ROW:total}}"})
            elif kind == "bm_table":
                _keep_rows(t, {0: "{{KEEP}}", 1: "{{KEEP}}", 2: "{{ROW:group}}", 3: "{{ROW:item}}", -1: "{{ROW:total}}"})
                for ci in (1, 2):
                    _set_cell(t.cell(1, ci), "{{ACTION%d}}" % ci)
            elif kind == "li_tables":
                if shape.name == "Table 4":
                    _keep_rows(t, {0: "{{KEEP}}", 1: "{{ROW:group}}", 2: "{{ROW:item}}"})
                else:
                    _keep_rows(t, {0: "{{ROW:item}}", -1: "{{ROW:total}}"})
            elif kind == "findings":
                _keep_rows(t, {0: "{{ROW:findings}}"})
            elif kind == "policy_findings":
                if product == "swp":
                    _keep_rows(t, {0: "{{ROW:header}}", 1: "{{ROW:heading}}", 2: "{{ROW:findings}}"})
                else:
                    _keep_rows(t, {0: "{{ROW:header}}", 1: "{{ROW:findings}}"})
    # drop the other slides
    sld_lst = prs.slides._sldIdLst
    for sld in list(sld_lst):
        if int(sld.get("id")) not in keep_ids:
            prs.part.drop_rel(sld.rId)
            sld_lst.remove(sld)
    # unused slide layouts carry large background pictures: drop them
    used = {id(s.slide_layout.part) for s in prs.slides}
    for master in prs.slide_masters:
        lst = master._element.get_or_add_sldLayoutIdLst()
        for lid in list(lst):
            part = master.part.related_part(lid.rId)
            if id(part) not in used:
                master.part.drop_rel(lid.rId)
                lst.remove(lid)
    cp = prs.core_properties
    cp.keywords = f"tmhc-efficacy:{product}:" + ",".join(kinds)
    cp.title, cp.author, cp.last_modified_by, cp.subject, cp.comments = "Product Efficacy Report", "", "", "", ""
    for slide in prs.slides:          # speaker notes may name the client
        if slide.has_notes_slide:
            for sh in slide.notes_slide.shapes:
                if sh.has_text_frame and sh.text_frame.text.strip():
                    sh.text_frame.text = ""
    dst.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(dst))
    print(f"template written: {dst} ({dst.stat().st_size // 1024} KB, slides: {', '.join(kinds)})")


def strip_history(dst: Path) -> None:
    """Remove revision-history parts (they record author names and old text)."""
    import re
    drop = ("ppt/changesInfos/", "ppt/revisionInfo.xml", "ppt/commentAuthors.xml", "ppt/authors.xml",
            "ppt/comments/", "docProps/custom.xml")
    tmp = dst.with_suffix(".tmp")
    with zipfile.ZipFile(dst) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename.startswith(drop):
                continue
            data = zin.read(item.filename)
            if item.filename == "[Content_Types].xml":
                txt = data.decode("utf-8")
                txt = re.sub(r'<Override PartName="/(?:ppt/changesInfos/[^"]+|ppt/revisionInfo\.xml|'
                             r'ppt/commentAuthors\.xml|ppt/authors\.xml|ppt/comments/[^"]+|docProps/custom\.xml)"[^>]*/>',
                             "", txt)
                data = txt.encode("utf-8")
            elif item.filename.endswith(".rels"):
                txt = data.decode("utf-8")
                txt = re.sub(r'<Relationship [^>]*Target="[^"]*(?:changesInfo|revisionInfo|commentAuthors|authors\.xml|'
                             r'comments/|custom\.xml)[^"]*"[^>]*/>', "", txt)
                data = txt.encode("utf-8")
            zout.writestr(item, data)
    tmp.replace(dst)


def scan(dst: Path, words: list[str]) -> None:
    hits = []
    with zipfile.ZipFile(dst) as z:
        for name in z.namelist():
            if name.endswith((".xml", ".rels")):
                xml = z.read(name).decode("utf-8", "ignore").lower()
                hits += [(name, w) for w in words if w.lower() in xml]
    if hits:
        dst.unlink()
        raise SystemExit(f"client strings still present, template not saved: {sorted(set(hits))[:10]}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("deck")
    ap.add_argument("out")
    ap.add_argument("--product", choices=sorted(LAYOUTS), required=True)
    ap.add_argument("--forbid", action="append", default=[], help="client word that must not remain")
    a = ap.parse_args()
    build(Path(a.deck), Path(a.out), a.product)
    strip_history(Path(a.out))
    if a.forbid:
        scan(Path(a.out), a.forbid)


if __name__ == "__main__":
    sys.exit(main())
