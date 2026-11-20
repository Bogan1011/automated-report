"""Read the Vision One / Apex Central log exports that accompany a health check.

Two shapes turn up in the evidence pack:

* Detection log exports (``BM 30 days.csv``, ``VM 30 days.csv``, ...) which
  are UTF-16LE, tab separated, with a leading ``#`` row-number column.
* Scan-exclusion exports (``RT dir.csv``, ``Manual file.csv``, ...) which
  are plain UTF-8 single-column lists.

Detection counts feed the narrative sections; exclusion lists corroborate
the exclusion rows already proved by the policy export.
"""
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Optional

from ..models import Fact, Source

# Evidence-pack filename -> (fact key, human label)
DETECTION_LOGS = {
    "vm": ("logs.virus_malware", "Virus/Malware detections"),
    "sg": ("logs.spyware_grayware", "Spyware/Grayware detections"),
    "bm": ("logs.behaviour_monitoring", "Behaviour Monitoring detections"),
    "c&c": ("logs.cc_callback", "C&C callback detections"),
    "nci": ("logs.network_content", "Network content inspection detections"),
    "wv": ("logs.web_violation", "Web reputation violations"),
    "dc": ("logs.device_control", "Device Control events"),
}

EXCLUSION_FILES = {
    "rt dir": ("exclusions.realtime.dirs", "Real-Time scan exclusion directories"),
    "rt file": ("exclusions.realtime.files", "Real-Time scan exclusion files"),
    "schedule dir": ("exclusions.scheduled.dirs", "Scheduled scan exclusion directories"),
    "schedule file": ("exclusions.scheduled.files", "Scheduled scan exclusion files"),
    "manual dir": ("exclusions.manual.dirs", "Manual scan exclusion directories"),
    "manual file": ("exclusions.manual.files", "Manual scan exclusion files"),
    "sn dir": ("exclusions.scannow.dirs", "Scan Now exclusion directories"),
    "sn file": ("exclusions.scannow.files", "Scan Now exclusion files"),
    "bm exception": ("exclusions.bm", "Behaviour Monitoring exceptions"),
}


def _read_text(path: Path) -> str:
    """Decode an export whatever Trend chose to write it as."""
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    for enc in ("utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def read_table(path: str | Path) -> list[dict[str, str]]:
    """Parse a detection-log export into dicts, sniffing the delimiter."""
    p = Path(path)
    text = _read_text(p)
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []
    delim = "\t" if lines[0].count("\t") >= lines[0].count(",") else ","
    rows = list(csv.DictReader(lines, delimiter=delim))
    # Drop the leading row-number column Trend adds ("#").
    cleaned = []
    for r in rows:
        cleaned.append({(k or "").strip(): (v or "").strip().strip('"')
                        for k, v in r.items() if (k or "").strip() not in {"#", ""}})
    return cleaned


def read_list(path: str | Path) -> list[str]:
    """Parse a single-column exclusion export, dropping its header."""
    text = _read_text(Path(path))
    lines = [ln.strip().strip('"') for ln in text.splitlines() if ln.strip()]
    if lines and _looks_like_header(lines[0]):
        lines = lines[1:]
    return lines


def _looks_like_header(line: str) -> bool:
    low = line.lower()
    return ("exclusion list" in low or "full program path" in low
            or low.startswith("scan exclusion"))


def _classify(name: str) -> tuple[Optional[str], Optional[str], str]:
    """Match a filename against the known export names."""
    stem = Path(name).stem.lower()
    for token, (key, label) in EXCLUSION_FILES.items():
        if stem.startswith(token):
            return key, label, "exclusion"
    for token, (key, label) in DETECTION_LOGS.items():
        if stem.startswith(token + " ") or stem == token:
            return key, label, "detection"
    return None, None, ""


def extract_dir(directory: str | Path) -> tuple[list[Fact], dict[str, Any]]:
    """Scan an evidence folder and extract every log/exclusion export in it."""
    d = Path(directory)
    out: list[Fact] = []
    metrics: dict[str, Any] = {}

    for path in sorted(d.rglob("*.csv")):
        key, label, kind = _classify(path.name)
        if not key:
            continue
        try:
            if kind == "detection":
                rows = read_table(path)
                out.append(Fact(key=key, value=len(rows),
                                display=f"{len(rows)} {label.lower()} in period",
                                source=Source.V1_LOGS, evidence=path.name))
                metrics[key] = len(rows)
            else:
                items = read_list(path)
                out.append(Fact(key=key, value=items,
                                display=f"Configured ({len(items)} entries)"
                                        if items else "Not Configured",
                                source=Source.EXCLUSION_CSV, evidence=path.name))
                metrics[key] = len(items)
        except Exception as exc:  # a malformed export must not stop the run
            out.append(Fact(key=f"{key}.error", value=str(exc),
                            display=f"Could not parse {path.name}: {exc}",
                            source=Source.V1_LOGS, confidence=0.0,
                            evidence=path.name))
    return out, metrics


def top_detections(path: str | Path, column: str, limit: int = 10) -> list[tuple[str, int]]:
    """Most frequent values in one column - useful for narrative paragraphs."""
    rows = read_table(path)
    counts = Counter(r.get(column, "") for r in rows if r.get(column))
    return counts.most_common(limit)
