"""Cloud Email and Collaboration Protection (CECP) exports.

Two files from the console, both optional:

* the detection log export (``result.csv``: Detected, Scan source, Threat
  type, Sender, Recipient, Affected user, Action ...) - the per-threat
  charts and sentences;
* the monthly report PDF ("<Company>'s <Month> Report-YYYYMMDD.pdf") -
  the "Total Items Scanned" panel (total scans, files/emails, threats) and
  the threat counts. When the PDF is missing the totals come from the CSV.

Everything is parsed locally; ``pdftotext`` / ``pdftoppm`` (poppler-utils)
read the PDF, with ``pypdf`` as a text-only fallback.
"""
from __future__ import annotations

import collections
import csv
import datetime as dt
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

MONTH_ABBR = {1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr", 5: "May", 6: "June", 7: "July", 8: "Aug",
              9: "Sept", 10: "Oct", 11: "Nov", 12: "Dec"}

# PDF tile label -> threat type as written in the detection log / report
PDF_THREATS = [("Ransomware", "Ransomware"), ("Malicious files", "Malicious files"),
               ("Malicious URLs", "Malicious URLs"), ("Phishing", "Phishing"), ("Spam", "Spam/Graymail"),
               ("BEC", "BEC"), ("Anomalies", "Anomalies"), ("Data Loss Prevention", "Data Loss Prevention"),
               ("Scam", "Scam")]
# detection-log threat types that are not threats in the analysts' counts
NOT_THREATS = ("unscannable", "suspicious object")


def find_detection_log(logs_dir: Path) -> Optional[Path]:
    for p in sorted(logs_dir.rglob("*.csv")):
        try:
            head = p.read_text(encoding="utf-8-sig", errors="ignore").splitlines()[0]
        except (OSError, IndexError):
            continue
        if "Threat type" in head and ("Scan source" in head or "Security filter" in head):
            return p
    return None


def find_report_pdf(logs_dir: Path) -> Optional[Path]:
    pdfs = sorted(logs_dir.rglob("*.pdf"))
    for p in pdfs:
        if "report" in p.name.lower():
            return p
    return pdfs[0] if pdfs else None


def read_detections(path: Path) -> list[dict]:
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        return [{(k or "").strip(): (v or "").strip() for k, v in row.items()} for row in csv.DictReader(fh)]


def _when(text: str) -> Optional[dt.date]:
    """'Sep 01, 2026 16:32:51' / '2026-09-01 ...' -> date."""
    text = text or ""
    mt = re.search(r"([A-Z][a-z]{2})[a-z]* (\d{1,2}), (\d{4})", text)
    if mt:
        try:
            return dt.datetime.strptime(" ".join(mt.groups()), "%b %d %Y").date()
        except ValueError:
            return None
    mt = re.search(r"(\d{4})-(\d{2})-(\d{2})", text)
    if mt:
        try:
            return dt.date(*(int(x) for x in mt.groups()))
        except ValueError:
            return None
    return None


def pdf_text(path: Path, first: int | None = None, last: int | None = None, layout: bool = True) -> str:
    if shutil.which("pdftotext"):
        cmd = ["pdftotext"] + (["-layout"] if layout else [])
        if first:
            cmd += ["-f", str(first)]
        if last:
            cmd += ["-l", str(last)]
        out = subprocess.run(cmd + [str(path), "-"], capture_output=True, timeout=60)
        return out.stdout.decode("utf-8", "replace")
    try:
        from pypdf import PdfReader
    except ImportError:
        return ""
    reader = PdfReader(str(path))
    pages = reader.pages[(first or 1) - 1:last]
    return "\n".join(p.extract_text() or "" for p in pages)


def _int(s: str) -> int:
    return int(s.replace(",", ""))


def parse_report_pdf(path: Path) -> dict:
    """Totals of the monthly report: period, total / files / emails scans, threats per type."""
    text = pdf_text(path)
    out: dict = {}
    mt = re.search(r"Reporting period:\s*([A-Z][a-z]{2} \d{1,2}, \d{4}).*?-\s*([A-Z][a-z]{2} \d{1,2}, \d{4})", text)
    if mt:
        out["period_start"], out["period_end"] = _when(mt.group(1)), _when(mt.group(2))
    mt = re.search(r"Services:\s*(.+)", text)
    if mt:
        out["services"] = mt.group(1).strip()
    block = text.split("Total Items Scanned", 1)[-1] if "Total Items Scanned" in text else ""
    mt = re.search(r"([\d,]{3,})\s*\n?\s*Total scans", block)
    if mt:
        out["total_scans"] = _int(mt.group(1))
    # "187520   3   27389   40" - files total / files threats / emails total / emails threats
    mt = re.search(r"\n\s*(\d[\d,]*)\s+(\d[\d,]*)\s+(\d[\d,]*)\s+(\d[\d,]*)\s*\n\s*Total scans", block)
    if mt:
        a, b, c, d = (_int(x) for x in mt.groups())
        out.update(files_scans=a, files_threats=b, email_scans=c, email_threats=d)
    det = block.split("Threat Detections", 1)[-1] if "Threat Detections" in block else ""
    det = det.split("Business Email Compromise", 1)[0]
    counts: dict[str, int] = {}
    lines = det.splitlines()
    for i, line in enumerate(lines):
        nums = re.findall(r"\d[\d,]*", line)
        if not nums or re.search(r"[A-Za-z]", line):
            continue
        # the labels are on the next non-empty line, in the same columns
        for nxt in lines[i + 1:i + 3]:
            if re.search(r"[A-Za-z]", nxt):
                labels = [lb.strip() for lb in re.split(r"\s{2,}", nxt.strip()) if lb.strip()]
                for n, lb in zip(nums, labels):
                    counts[lb] = _int(n)
                break
    if counts:
        out["threat_counts"] = {name: counts.get(label, 0) for label, name in PDF_THREATS if label in counts}
    return out


def render_total_panel(pdf: Path, out_png: Path) -> Optional[Path]:
    """Crop the "Total Items Scanned" panel from the report PDF (as the analysts paste it)."""
    if not (shutil.which("pdftotext") and shutil.which("pdftoppm")):
        return None
    for page in range(1, 6):
        with tempfile.TemporaryDirectory() as tmp:
            bbox = Path(tmp) / "b.html"
            subprocess.run(["pdftotext", "-f", str(page), "-l", str(page), "-bbox", str(pdf), str(bbox)],
                           capture_output=True, timeout=60)
            html = bbox.read_text(encoding="utf-8", errors="ignore") if bbox.exists() else ""
            words = re.findall(r'<word xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="([\d.]+)">([^<]*)</word>', html)
            pw = re.search(r'<page width="([\d.]+)" height="([\d.]+)"', html)
            if not words or not pw:
                continue
            top = bottom = None
            for i, (x0, y0, x1, y1, t) in enumerate(words):
                if t == "Items" and i + 1 < len(words) and words[i + 1][4] == "Scanned" and top is None:
                    top = float(y0) - 6
                if t == "Threat" and i + 1 < len(words) and words[i + 1][4] == "Detections" and top is not None:
                    bottom = float(y0) - 12
                    break
            if top is None or bottom is None or bottom <= top:
                continue
            width = float(pw.group(1))
            dpi = 220
            base = Path(tmp) / "pg"
            subprocess.run(["pdftoppm", "-f", str(page), "-l", str(page), "-r", str(dpi), "-png", "-singlefile",
                            str(pdf), str(base)], capture_output=True, timeout=120)
            png = base.with_suffix(".png")
            if not png.exists():
                return None
            from PIL import Image
            k = dpi / 72.0
            with Image.open(png) as im:
                box = (int(18 * k), int(top * k), int((width - 18) * k), int(bottom * k))
                im.crop(box).save(out_png)
            return out_png
    return None


def _top(counter: collections.Counter, n: int) -> list[tuple[str, int]]:
    return [(k, v) for k, v in counter.most_common(n) if k]


def detection_metrics(rows: list[dict], pdf: dict | None = None) -> dict:
    """Everything the detections section and the presentation need."""
    pdf = pdf or {}
    m: dict = {}
    dates = [d for d in (_when(r.get("Detected", "")) for r in rows) if d]
    start = pdf.get("period_start") or (min(dates) if dates else None)
    end = pdf.get("period_end") or (max(dates) if dates else None)
    if start and end:
        if not pdf.get("period_start") and dates:          # a log export covers whole months
            start = start.replace(day=1)
            nxt = (end.replace(day=28) + dt.timedelta(days=4)).replace(day=1)
            end = nxt - dt.timedelta(days=1)
        m["period_start"], m["period_end"] = start.isoformat(), end.isoformat()
        m["period_from"] = f"{start.day:02d} {MONTH_ABBR[start.month]} {start.year}"
        m["period_to"] = f"{end.day:02d} {MONTH_ABBR[end.month]} {end.year}"
        m["period_from_short"] = f"{start.day} {MONTH_ABBR[start.month]}"
        m["period_to_short"] = f"{end.day} {MONTH_ABBR[end.month]} {end.year}"
        m["month_abbr"] = MONTH_ABBR[end.month]
        m["month_name"] = end.strftime("%B")
    by_type = collections.Counter(r.get("Threat type", "") for r in rows)
    csv_threats = {t: n for t, n in by_type.items() if t and not t.lower().startswith(NOT_THREATS)}
    counts = dict(pdf.get("threat_counts") or {}) or csv_threats
    m["threat_counts"] = {t: n for t, n in counts.items() if n}
    m["threats_total"] = sum(m["threat_counts"].values())
    m["total_scans"] = pdf.get("total_scans")
    for k in ("files_scans", "files_threats", "email_scans", "email_threats", "services"):
        if k in pdf:
            m[k] = pdf[k]
    m["total_scans_text"] = f"{m['total_scans']:,}" if m.get("total_scans") else "N/A"
    m["detection_rows"] = len(rows)

    per: dict[str, dict] = {}
    for ttype in m["threat_counts"]:
        sel = [r for r in rows if r.get("Threat type", "") == ttype]
        actions = collections.Counter(r.get("Action", "") or "Unknown" for r in sel)
        info = {"count": m["threat_counts"][ttype], "rows": len(sel), "actions": _top(actions, 10)}
        if ttype == "Malicious URLs":
            urls = collections.Counter(re.sub(r"^[^:]{0,40}:\s*", "", r.get("Security risk / Anomaly name", ""))
                                       for r in sel)
            info["urls"] = _top(urls, 10)
        senders = collections.Counter((r.get("Sender") or f"{r.get('Scan source', '')} URL Detection".strip())
                                      for r in sel)
        info["senders"] = _top(senders, 10)
        recips = collections.Counter(r.get("Recipient") or r.get("Affected user", "") for r in sel)
        info["recipients"] = _top(recips, 10)
        users = collections.Counter(r.get("Affected user", "") for r in sel)
        info["users"] = _top(users, 10)
        per[ttype] = info
    m["threats"] = per
    return m


def action_sentence(ttype: str, info: dict) -> str:
    """The analysts' closing line under each threat section."""
    acts = [a for a, _ in info.get("actions", [])]
    if len(acts) == 1 and acts[0].lower() != "pass":
        return f"All the detections have been {acts[0].replace('Move to Junk Email folder', 'Move to Junk Email Folder')}."
    if acts and all(a.lower() == "pass" for a in acts):
        if ttype == "Malicious URLs":
            return ("The detections are currently being passed. Kindly configure the policy without Monitor Only "
                    "mode to ensure malicious URLs are blocked or quarantined as per the configured policy actions.")
        return ("The detections are currently being passed. Kindly configure the Exchange policy with the "
                "Quarantine action and other service policies without Monitor Only mode to ensure malicious "
                "URLs are blocked or quarantined as per the configured policy actions.")
    if acts:
        parts = ", ".join(f"{a} ({n})" for a, n in info["actions"])
        return f"Actions taken on these detections: {parts}."
    return ""


def count_sentence(ttype: str, info: dict, m: dict, short: bool = False) -> str:
    n = info["count"]
    frm = m.get("period_from_short" if short else "period_from", "")
    to = m.get("period_to_short" if short else "period_to", "")
    verb = "triggered" if ttype.lower().startswith("spam") else "detected"
    if n == 1:
        return f"There was only 1 detection of {ttype} detected from {frm} to {to}."
    return f"There was a total of {n} detections of {ttype} {verb} from {frm} to {to}."
