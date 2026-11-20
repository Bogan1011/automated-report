"""Turn a finished health-check report into a reusable template.

Usage:
    python tools/make_template.py FINISHED_REPORT.docx OUT_TEMPLATE.docx \
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


def build(src: Path, dst: Path, replacements: dict[str, str]) -> None:
    doc = docx.Document(str(src))
    servers_seen = gaps_seen = 0

    for t in doc.tables:
        h = header_text(t)
        if h.startswith("Location"):
            for row, token in zip(t.rows, ("location", "customer_attendance", "trend_attendance")):
                set_cell_text(tcs(row)[-1], "{{" + token + "}}")
        elif h.startswith("Product | Findings"):
            trim_rows(t, 2)
            c0, c1 = tcs(t.rows[1])[0], tcs(t.rows[1])[-1]
            set_cell_text(c0, "{{EXEC_PRODUCT}}")
            set_cell_text(c1, "{{EXEC_FINDING}}")
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
                for k in replacements:
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
    a = ap.parse_args()
    pairs = [r.split("=", 1) for r in a.replace]
    mapping = dict(sorted(((k, v) for k, v in pairs), key=lambda kv: -len(kv[0])))
    build(Path(a.report), Path(a.out), mapping)


if __name__ == "__main__":
    main()
