"""Low-level helpers for editing Word XML without losing formatting.

Word splits visible text into many runs (spell-check marks, formatting
changes, revision ids), so a phrase like "Acme Industries Private Limited"
can be spread over five ``<w:t>`` elements. ``replace_text`` stitches the
runs together just enough to substitute the phrase while keeping the first
run's formatting.
"""
from __future__ import annotations

import copy
from typing import Iterable, Iterator, Optional

from docx.oxml.ns import qn

XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"


def iter_paragraphs(root) -> Iterator:
    """Every ``w:p`` under an element, including ones inside text boxes."""
    yield from root.iter(qn("w:p"))


def _own_texts(p) -> list:
    """``w:t`` elements whose nearest paragraph is ``p`` (skip nested text boxes)."""
    out = []
    for t in p.iter(qn("w:t")):
        parent = t.getparent()
        while parent is not None and parent.tag != qn("w:p"):
            parent = parent.getparent()
        if parent is p:
            out.append(t)
    return out


def paragraph_text(p) -> str:
    return "".join(t.text or "" for t in _own_texts(p))


def replace_text(p, old: str, new: str) -> int:
    """Replace every occurrence of ``old`` in paragraph ``p``. Returns the count."""
    count = 0
    while True:
        texts = _own_texts(p)
        full = "".join(t.text or "" for t in texts)
        start = full.find(old)
        if start < 0 or not old:
            return count
        end = start + len(old)
        pos = 0
        first = True
        for t in texts:
            s = t.text or ""
            t_start, t_end = pos, pos + len(s)
            pos = t_end
            if t_end <= start or t_start >= end:
                continue
            a = max(start, t_start) - t_start
            b = min(end, t_end) - t_start
            if first:
                t.text = s[:a] + new + s[b:]
                first = False
            else:
                t.text = s[:a] + s[b:]
            t.set(XML_SPACE, "preserve")
        count += 1


def replace_everywhere(roots: Iterable, mapping: dict[str, str]) -> dict[str, int]:
    hits = {k: 0 for k in mapping}
    for root in roots:
        for p in iter_paragraphs(root):
            for old, new in mapping.items():
                hits[old] += replace_text(p, old, new)
    return hits


def set_cell_text(tc, text: str, bold: Optional[bool] = None, keep_paragraphs: bool = False) -> None:
    """Replace a table cell's content with ``text``, keeping the first run's look.

    ``**bold**`` segments are rendered bold. Newlines become separate
    paragraphs: line N takes the look of the cell's paragraph N (so a
    heading line followed by bullet points keeps its bullets), extra lines
    copy the last paragraph.

    ``keep_paragraphs`` (template building): keep every paragraph's
    formatting but empty them, with ``text`` in the first one.
    """
    paras = tc.findall(qn("w:p"))
    if not paras:
        return
    if keep_paragraphs:
        _fill_paragraph(paras[0], text, bold)
        for extra in paras[1:]:
            _fill_paragraph(extra, "", bold)
        return
    protos = [copy.deepcopy(p) for p in paras]
    for extra in paras[1:]:
        tc.remove(extra)
    lines = text.split("\n") if text else [""]
    targets = [paras[0]]
    for i in range(1, len(lines)):
        clone = copy.deepcopy(protos[min(i, len(protos) - 1)])
        targets[-1].addnext(clone)
        targets.append(clone)
    for p, line in zip(targets, lines):
        _fill_paragraph(p, line, bold)


def _fill_paragraph(p, line: str, bold: Optional[bool]) -> None:
    runs = p.findall(qn("w:r"))
    proto_run = copy.deepcopy(runs[0]) if runs else None
    for r in runs:
        p.remove(r)
    for child in list(p):
        if child.tag in (qn("w:hyperlink"), qn("w:proofErr"), qn("w:bookmarkStart"),
                         qn("w:bookmarkEnd")):
            p.remove(child)
    segments = _split_bold(line)
    for seg_text, seg_bold in segments:
        r = copy.deepcopy(proto_run) if proto_run is not None else _new_run()
        for c in list(r):
            if c.tag != qn("w:rPr"):
                r.remove(c)
        rpr = r.find(qn("w:rPr"))
        want_bold = seg_bold or bool(bold)
        if rpr is None and (want_bold or bold is False):
            rpr = r.makeelement(qn("w:rPr"), {})
            r.insert(0, rpr)
        if rpr is not None:
            for tag in ("w:b", "w:bCs"):
                el = rpr.find(qn(tag))
                if el is not None:
                    rpr.remove(el)
            if want_bold:
                rpr.insert(0, rpr.makeelement(qn("w:b"), {}))
        t = r.makeelement(qn("w:t"), {})
        t.text = seg_text
        t.set(XML_SPACE, "preserve")
        r.append(t)
        p.append(r)


def _new_run():
    from docx.oxml import OxmlElement
    return OxmlElement("w:r")


def _split_bold(line: str) -> list[tuple[str, bool]]:
    parts = line.split("**")
    return [(s, i % 2 == 1) for i, s in enumerate(parts) if s]


def clear_drawings(tc) -> None:
    for r in list(tc.iter(qn("w:r"))):
        if r.find(qn("w:drawing")) is not None or r.find(qn("w:pict")) is not None:
            r.getparent().remove(r)


def set_vmerge(tc, value: Optional[str]) -> None:
    """value: 'restart', 'continue' or None (remove)."""
    tcpr = tc.find(qn("w:tcPr"))
    if tcpr is None:
        tcpr = tc.makeelement(qn("w:tcPr"), {})
        tc.insert(0, tcpr)
    vm = tcpr.find(qn("w:vMerge"))
    if vm is not None:
        tcpr.remove(vm)
    if value:
        el = tcpr.makeelement(qn("w:vMerge"), {})
        if value == "restart":
            el.set(qn("w:val"), "restart")
        # vMerge must follow gridSpan in schema order
        gs = tcpr.find(qn("w:gridSpan"))
        if gs is not None:
            gs.addnext(el)
        else:
            tcw = tcpr.find(qn("w:tcW"))
            (tcw.addnext(el) if tcw is not None else tcpr.insert(0, el))


def find_table_with(doc, token: str):
    for t in doc.tables:
        for tc in t._tbl.iter(qn("w:tc")):
            if token in "".join(x.text or "" for x in tc.iter(qn("w:t"))):
                return t
    return None


def enable_update_fields(doc) -> None:
    """Ask Word to refresh the table of contents when the file is opened."""
    settings = doc.settings.element
    el = settings.find(qn("w:updateFields"))
    if el is None:
        el = settings.makeelement(qn("w:updateFields"), {})
        settings.append(el)
    el.set(qn("w:val"), "true")
