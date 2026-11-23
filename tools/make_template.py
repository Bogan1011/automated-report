"""Turn a finished health-check report into a reusable template.

Usage:
    python tools/make_template.py FINISHED_REPORT.docx OUT_TEMPLATE.docx \
        --rows tools/sep_row_map.yaml \
        --replace "Acme Industries Private Limited=client_name" \
        --replace "Acme Endpoint Policy=policy_name" ...

What it does:
* swaps client-specific strings for {{placeholders}} everywhere (body,
  tables, cover-page text boxes, headers, footers);
* cuts every generated table (executive summary, server overview, policy
  review, both gap tables) down to its header plus one prototype row, and
  tags that row with a token the renderer looks for;
* refuses to save if any of the original client strings are still present.

The prototype rows keep the original borders, shading, fonts and numbering,
so generated reports look exactly like hand-made ones.
"""
from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

import docx
from docx.oxml.ns import qn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tmhc.render.docx_utils import (clear_drawings, replace_everywhere,  # noqa: E402
                                    set_cell_text)


def header_text(table) -> str:
    return " | ".join(c.text.strip() for c in table.rows[0].cells)


def trim_rows(table, keep: int) -> None:
    for row in list(table.rows)[keep:]:
        table._tbl.remove(row._tr)


def tcs(row):
    return row._tr.findall(qn("w:tc"))


def _tag_rows(table, rows: dict, label: str) -> None:
    """Keep the analyst's table; tag Deployed/Status cells of mapped rows with tokens."""
    trs = table._tbl.findall(qn("w:tr"))
    owners: dict[int, list[str]] = {}
    for ri in sorted(rows):
        spec = rows[ri] if isinstance(rows[ri], dict) else {"key": rows[ri]}
        if ri >= len(trs):
            raise SystemExit(f"{label}: row {ri} does not exist (table has {len(trs)} rows)")
        cells = trs[ri].findall(qn("w:tc"))
        if len(cells) < 3:
            raise SystemExit(f"{label}: row {ri} is a heading row, not a data row")
        status, deployed, rec = cells[-1], cells[-2], cells[-3]
        set_cell_text(deployed, "{{=" + spec["key"] + "}}", keep_paragraphs=True)
        if spec.get("recommended"):
            set_cell_text(rec, spec["recommended"])
        # a Status cell merged down over several rows belongs to the first of them
        owner = ri
        while True:
            pr = trs[owner].findall(qn("w:tc"))[-1].find(qn("w:tcPr"))
            vm = pr.find(qn("w:vMerge")) if pr is not None else None
            if vm is None or vm.get(qn("w:val")) == "restart" or owner == 0:
                break
            owner -= 1
        owners.setdefault(owner, []).append(spec["key"])
    for ri, keys in owners.items():
        cell = trs[ri].findall(qn("w:tc"))[-1]
        clear_drawings(cell)
        set_cell_text(cell, "{{?" + "|".join(keys) + "}}")
    print(f"  {label}: tagged {len(rows)} rows ({len(owners)} status cells)")


def build(src: Path, dst: Path, replacements: dict[str, str], row_map: dict | None = None) -> None:
    doc = docx.Document(str(src))
    servers_seen = gaps_seen = 0

    for t in doc.tables:
        h = header_text(t)
        if h.startswith("Location"):
            for row, token in zip(t.rows, ("location", "customer_attendance", "trend_attendance")):
                set_cell_text(tcs(row)[-1], "{{" + token + "}}")
        elif h.startswith("Product | Findings") or h.startswith("Products | Findings"):
            trim_rows(t, 2)
            c0, c1 = tcs(t.rows[1])[0], tcs(t.rows[1])[-1]
            set_cell_text(c0, "{{EXEC_PRODUCT}}")
            set_cell_text(c1, "{{EXEC_FINDING}}")
        elif (h.startswith("Component | Trend Recommended") or h.startswith("Component | Component")) and row_map:
            if row_map.get("tables"):                 # one map per settings table, in order (CECP)
                maps = row_map["tables"]
                if servers_seen < len(maps):
                    _tag_rows(t, maps[servers_seen] or {}, f"table {servers_seen + 1}")
                servers_seen += 1
                continue
            which = "server" if servers_seen == 0 else "policy"
            servers_seen += 1
            _tag_rows(t, row_map.get(which) or {}, which)
        elif h.startswith("Component | Trend Recommended") or h.startswith("Component | Component"):
            token = "{{SERVER_TABLE}}" if servers_seen == 0 else "{{POLICY_TABLE}}"
            servers_seen += 1
            trim_rows(t, 3)
            set_cell_text(tcs(t.rows[1])[0], token)
            data = tcs(t.rows[2])
            for tc, txt in zip(data[:-1], ("{{c}}", "{{r}}", "{{d}}")):
                set_cell_text(tc, txt)
            clear_drawings(data[-1])
            set_cell_text(data[-1], "")
        elif h.startswith("#"):
            token = "{{SERVER_GAPS}}" if gaps_seen == 0 else "{{POLICY_GAPS}}"
            gaps_seen += 1
            trs = t._tbl.findall(qn("w:tr"))
            head_rows = [tr for tr in trs[1:] if len(tr.findall(qn("w:tc"))) == 1]
            gap_rows = [tr for tr in trs[1:] if len(tr.findall(qn("w:tc"))) >= 2]
            if head_rows and gap_rows:
                # sub-heading rows ("In Both ... Policy", "In Exchange Online - ...") and gap rows
                hp, gp = head_rows[0], gap_rows[0]
                for tr in trs[1:]:
                    t._tbl.remove(tr)
                trs[0].addnext(hp)
                hp.addnext(gp)
                set_cell_text(hp.findall(qn("w:tc"))[0], "{{GAP_HEADING}}")
                set_cell_text(gp.findall(qn("w:tc"))[-1], token)
            else:
                trim_rows(t, 2)
                set_cell_text(tcs(t.rows[1])[-1], token)

    roots = [doc.element.body]
    for s in doc.sections:
        for part in (s.header, s.footer, s.first_page_header, s.first_page_footer,
                     s.even_page_header, s.even_page_footer):
            try:
                roots.append(part._element)
            except Exception:
                pass
    hits = replace_everywhere(roots, {k: "{{" + v + "}}" for k, v in replacements.items()})
    for k, n in hits.items():
        print(f"  replaced {n:2d} x {k!r}")

    cp = doc.core_properties
    cp.title, cp.subject, cp.author, cp.last_modified_by = (
        "Technical Health Check Report", "", "", "")
    cp.comments, cp.keywords = "", ""

    dst.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(dst))

    # Safety net: no original client string may survive anywhere in the package.
    leftovers = []
    with zipfile.ZipFile(dst) as z:
        for name in z.namelist():
            if name.endswith((".xml", ".rels")):
                xml = z.read(name).decode("utf-8", "ignore")
                for k, ph in replacements.items():
                    if ph.startswith("m."):          # computed sentences, not client identifiers
                        continue
                    first_word = k.split()[0]
                    if len(first_word) > 3 and first_word in xml:
                        leftovers.append((name, first_word))
    if leftovers:
        dst.unlink()
        raise SystemExit(f"client strings still present, template not saved: {sorted(set(leftovers))}")
    print(f"template written: {dst}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report")
    ap.add_argument("out")
    ap.add_argument("--replace", action="append", default=[],
                    help='"literal text=placeholder_name" (repeatable; longest first)')
    ap.add_argument("--rows", type=Path,
                    help="row map (e.g. tools/sep_row_map.yaml): keep the analyst's tables row for row")
    a = ap.parse_args()
    pairs = [r.split("=", 1) for r in a.replace]
    mapping = dict(sorted(((k, v) for k, v in pairs), key=lambda kv: -len(kv[0])))
    row_map = None
    if a.rows:
        import yaml
        row_map = yaml.safe_load(a.rows.read_text(encoding="utf-8"))
    build(Path(a.report), Path(a.out), mapping, row_map)


if __name__ == "__main__":
    main()
