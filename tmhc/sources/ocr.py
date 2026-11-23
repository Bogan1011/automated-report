"""Read console screenshots with plain OCR + image analysis. No AI model, no network.

How it works
------------
1. Tesseract reads every word on the screenshot with its position.
2. For each setting in ``rules/<pack>_ocr.yaml`` we find the page it lives on
   (by its title text) and the setting's label on that page.
3. The state comes from the pixels, not from OCR:
   * checkbox / radio - the small control just left of the label is "on"
     when it is filled blue (Vision One) or has a dark tick/dot in its
     centre (classic Apex One); "off" when it is an empty ring/box.
   * toggle switches - blue with the knob on the right = on; grey = off.
   * text values (licence date, seat count) - read from the OCR text.
4. Every reading carries a confidence and the on-screen text it is based
   on; anything not found is left for the checklist rather than guessed.

Runs comfortably on 2 vCPUs: a few seconds per screenshot.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
SCALE = 2  # OCR at 2x: console fonts are ~11px at 1366x768


def _deps():
    try:
        import cv2  # noqa: F401
        import numpy  # noqa: F401
        import pytesseract  # noqa: F401
        from rapidfuzz import fuzz  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on install
        raise RuntimeError(
            f"OCR reader needs extra packages ({exc.name}). Install with:\n"
            "  pip install -r requirements.txt\n"
            "  and Tesseract: Ubuntu `sudo apt install tesseract-ocr`, Windows the installer from\n"
            "  github.com/UB-Mannheim/tesseract/wiki (add it to PATH)") from None


# --------------------------------------------------------------------------
# page model
# --------------------------------------------------------------------------
@dataclass
class Word:
    t: str
    x: float
    y: float
    w: float
    h: float
    line: tuple

    @property
    def cy(self) -> float:
        return self.y + self.h / 2


@dataclass
class Match:
    text: str
    x: float
    y: float
    h: float
    right: float
    score: float
    line: list


class Page:
    def __init__(self, data: bytes, name: str = ""):
        _deps()
        import cv2
        import numpy as np
        import pytesseract

        arr = np.frombuffer(data, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError(f"cannot decode image {name}")
        self.img = img
        self.name = name
        g = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        g = cv2.resize(g, None, fx=SCALE, fy=SCALE, interpolation=cv2.INTER_CUBIC)
        d = pytesseract.image_to_data(g, output_type=pytesseract.Output.DICT, config="--psm 3")
        self.words: list[Word] = []
        for i, t in enumerate(d["text"]):
            if t.strip() and float(d["conf"][i]) >= 20:
                self.words.append(Word(t, d["left"][i] / SCALE, d["top"][i] / SCALE,
                                       d["width"][i] / SCALE, d["height"][i] / SCALE,
                                       (d["block_num"][i], d["par_num"][i], d["line_num"][i])))
        lines: dict[tuple, list[Word]] = {}
        for w in self.words:
            lines.setdefault(w.line, []).append(w)
        self.lines = [sorted(v, key=lambda w: w.x) for v in lines.values()]
        self.text = "\n".join(" ".join(w.t for w in ln) for ln in
                              sorted(self.lines, key=lambda ln: (ln[0].y, ln[0].x)))

    # -- text search ---------------------------------------------------------
    def find_all(self, label: str, min_score: float = 82) -> list[Match]:
        """Every place `label` appears (fuzzy), best first."""
        from rapidfuzz import fuzz
        target = label.lower()
        n = len(label.split())
        found: list[Match] = []
        for ln in self.lines:
            best: Optional[Match] = None
            for i in range(len(ln)):
                for j in range(i + 1, min(len(ln), i + n + 2) + 1):
                    seg = ln[i:j]
                    txt = " ".join(w.t for w in seg)
                    s = fuzz.ratio(target, txt.lower())
                    # long labels are often cut off at the screen edge
                    if len(label) > 30 and len(txt) > 0.55 * len(label):
                        s = max(s, fuzz.partial_ratio(target, txt.lower()) - 3)
                    if s >= min_score and (best is None or s > best.score):
                        best = Match(txt, seg[0].x, min(w.y for w in seg),
                                     max(w.y + w.h for w in seg) - min(w.y for w in seg),
                                     max(w.x + w.w for w in seg), s, ln)
            if best:
                found.append(best)
        return sorted(found, key=lambda m: -m.score)

    def has_any(self, phrases: Iterable[str], min_score: float = 85) -> bool:
        return any(self.find_all(p, min_score) for p in phrases)

    def text_right_of(self, m: Match, max_gap: float = 90) -> str:
        """Words on the same row to the right of a match (e.g. a dropdown value)."""
        cy = m.y + m.h / 2
        row = sorted([w for w in self.words if abs(w.cy - cy) <= max(6, m.h * 0.7) and w.x >= m.right - 1],
                     key=lambda w: w.x)
        out, last = [], m.right
        for w in row:
            if w.x - last > max_gap:
                break
            out.append(w.t)
            last = w.x + w.w
        return " ".join(out)

    # -- pixel analysis --------------------------------------------------------
    def control_left_of(self, m: Match, search: int = 34) -> Optional[dict]:
        """Checkbox / radio immediately left of a label, and whether it is on."""
        import cv2
        import numpy as np

        x, y, h = int(m.x), int(m.y), max(1, int(m.h))
        cy = y + h // 2
        x0, x1 = max(0, x - search), max(0, x - 1)
        y0, y1 = max(0, cy - 11), min(self.img.shape[0], cy + 12)
        win = self.img[y0:y1, x0:x1]
        if win.size == 0 or win.shape[1] < 6:
            return None
        g = cv2.cvtColor(win, cv2.COLOR_BGR2GRAY).astype(np.int16)
        hsv = cv2.cvtColor(win, cv2.COLOR_BGR2HSV)
        blue = (hsv[..., 0] > 95) & (hsv[..., 0] < 130) & (hsv[..., 1] > 90) & (hsv[..., 2] > 80)
        bgv = int(np.median(g))
        mask = ((np.abs(g - bgv) > 14) | blue).astype(np.uint8)
        mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, np.ones((2, 2), np.uint8))
        n, _, st, _ = cv2.connectedComponentsWithStats(mask, 8)
        cands = []
        for i in range(1, n):
            cx, cy2, w, hh, area = (int(v) for v in st[i])
            if 7 <= w <= 18 and 7 <= hh <= 18 and abs(w - hh) <= 4:
                cands.append((cx + w, cx, cy2, w, hh, area))
        if not cands:
            return None
        _, cx, cy2, w, hh, area = max(cands)          # the one nearest the label
        roi = g[cy2:cy2 + hh, cx:cx + w]
        roi_blue = float(blue[cy2:cy2 + hh, cx:cx + w].mean())
        ix, iy = max(1, int(w * 0.3)), max(1, int(hh * 0.3))
        centre_diff = float(abs(roi[iy:hh - iy, ix:w - ix].mean() - bgv))
        on = roi_blue > 0.25 or centre_diff > 20
        # margin from the decision boundary -> confidence
        margin = max(roi_blue - 0.25, centre_diff - 20) if on else min(0.25 - roi_blue, 20 - centre_diff)
        conf = 0.97 if (centre_diff > 28 or roi_blue > 0.4 or (not on and centre_diff < 12)) else 0.8
        return {"on": on, "blue": round(roi_blue, 2), "centre": round(centre_diff, 1), "conf": conf,
                "margin": round(float(margin), 2), "x": x0 + cx}

    def toggles_below(self, header: Match, width: int = 90) -> list[dict]:
        """Toggle switches in the column under a header such as 'Status'."""
        import cv2
        import numpy as np

        x0, x1 = max(0, int(header.x) - 20), int(header.x) + width
        y0 = int(header.y + header.h + 4)
        y1 = self.img.shape[0] - int(self.img.shape[0] * 0.11)      # stop above the taskbar
        reg = self.img[y0:y1, x0:x1]
        if reg.size == 0:
            return []
        g = cv2.cvtColor(reg, cv2.COLOR_BGR2GRAY).astype(np.int16)
        hsv = cv2.cvtColor(reg, cv2.COLOR_BGR2HSV)
        bgv = int(np.median(g))
        mask = (np.abs(g - bgv) > 18).astype(np.uint8)
        n, _, st, _ = cv2.connectedComponentsWithStats(mask, 8)
        out = []
        for i in range(1, n):
            x, y, w, h, a = (int(v) for v in st[i])
            if 7 <= h <= 16 and 1.5 * h <= w <= 3.2 * h and a / float(w * h) > 0.5:
                sat = float(hsv[y:y + h, x:x + w, 1].mean())
                knob_right = int(np.argmax(g[y:y + h, x:x + w].mean(axis=0))) > w / 2
                on = sat > 50 and knob_right
                off = sat < 25 and not knob_right
                if on or off:                       # ambiguous pills are skipped, not guessed
                    out.append({"y": y0 + y, "on": on})
        return out


# --------------------------------------------------------------------------
# field extraction
# --------------------------------------------------------------------------
def load_specs(pack: str = "apexone_sep") -> dict:
    p = RULES_DIR / f"{pack}_ocr.yaml"
    return yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {"fields": {}}


def _result(key, value, display, conf, quote):
    return {"key": key, "value": value, "display": display, "confidence": round(conf, 2), "quote": quote}


def _probe(page: Page, m: Match) -> Optional[dict]:
    """Control left of a match; if OCR dropped the label's first words, retry from line start."""
    c = page.control_left_of(m)
    if c is None and m.line:
        first = m.line[0]
        if first.x < m.x - 2 and m.x - first.x <= 130:
            c = page.control_left_of(Match(m.text, first.x, m.y, m.h, m.right, m.score, m.line))
    if c is None and m.line and m.line[0].x >= m.x - 2:
        # the label's first word(s) were not read at all: look a little further left
        c = page.control_left_of(m, search=60)
    return c


def _checkbox(page: Page, spec: dict, key: str) -> Optional[dict]:
    for m in page.find_all(spec["label"], spec.get("min_score", 82))[:4]:
        c = _probe(page, m)
        if c is None:
            continue
        on = c["on"]
        display = spec.get("when_on", "Enabled") if on else spec.get("when_off", "Disabled")
        if on and spec.get("number_unit"):
            num = _number_near(page, m, spec["number_unit"])
            if num is not None:
                display = f"{display} ({num} {spec['number_unit']})"
        conf = c["conf"] * (m.score / 100) * spec.get("trust", 1.0)
        mark = "[x]" if on else "[ ]"
        return _result(key, on, display, conf, f"{mark} {m.text}")
    return None


def _number_near(page: Page, m: Match, unit: str) -> Optional[int]:
    """A number on the label's row or within ~45px below it (input boxes)."""
    for w in page.words:
        if m.y - 4 <= w.y <= m.y + m.h + 45 and re.fullmatch(r"\d{1,4}", w.t):
            near_unit = [u for u in page.words if abs(u.cy - w.cy) < 8 and unit.lower() in u.t.lower()]
            if near_unit or abs(w.cy - (m.y + m.h / 2)) < 8:
                return int(w.t)
    return None


def _all_checked(page: Page, spec: dict, key: str) -> Optional[dict]:
    states, quotes = [], []
    for label in spec["labels"]:
        r = _checkbox(page, {"label": label, "trust": spec.get("trust", 1.0)}, key)
        if r is None:
            return None                 # every box must be seen to judge "all"
        states.append(r["value"])
        quotes.append(r["quote"])
    on = all(states)
    off = [q for q, s in zip(quotes, states) if not s]
    display = spec.get("when_on", "Enabled") if on else (
        spec.get("when_off", "Disabled") if not any(states) else "Partially Enabled")
    conf = min(0.97, 0.9 * spec.get("trust", 1.0) + 0.05)
    return _result(key, on, display, conf, "; ".join(off) if off else f"all {len(states)} ticked")


def _radio(page: Page, spec: dict, key: str) -> Optional[dict]:
    seen = []
    for opt in spec["options"]:
        label = opt["label"]
        for m in page.find_all(label, opt.get("min_score", 82))[:3]:
            if not _in_band(page, m, spec):
                continue
            c = _probe(page, m)
            if c is None:
                continue
            seen.append((c["on"], c, m, opt))
            break
    selected = [s for s in seen if s[0]]
    if len(selected) != 1 or len(seen) < min(2, len(spec["options"])):
        return None                     # none or several selected: don't guess
    _, c, m, opt = selected[0]
    conf = c["conf"] * (m.score / 100) * spec.get("trust", 1.0)
    return _result(key, opt.get("value", opt.get("display", label)), opt.get("display", opt["label"]),
                   conf, f"(o) {m.text}")


def _in_band(page: Page, m: Match, spec: dict) -> bool:
    """Respect optional `below`/`above` anchors so repeated words resolve to one block."""
    if spec.get("below"):
        a = page.find_all(spec["below"], 85)
        if not a or m.y <= min(x.y for x in a):
            return False
    if spec.get("above"):
        a = [x for x in page.find_all(spec["above"], 85)]
        if a and m.y >= min(x.y for x in a):
            return False
    return True


def _radio_rows(page: Page, spec: dict, key: str) -> Optional[dict]:
    """Several rows share a word ('Every ...'); the selected row's text is the value.

    OCR often swallows the word on the selected row (the filled radio is read
    as a glyph), so the rows found by text only fix the radio *column*; every
    row in the band is then probed at that column.
    """
    anchors = [m for m in page.find_all(spec["option"], 85) if _in_band(page, m, spec)]
    if not anchors:
        return None
    col_x = min(m.x for m in anchors)
    anchor_ctrl_x = [c["x"] for c in (page.control_left_of(m) for m in anchors) if c]
    if not anchor_ctrl_x:
        return None
    radio_x = sorted(anchor_ctrl_x)[len(anchor_ctrl_x) // 2]
    band = [w for w in page.words if w.x >= col_x - 45 and w.x <= col_x + 400]
    rows: dict[int, list] = {}
    for w in band:
        probe_m = Match(w.t, col_x, w.y, w.h, w.x + w.w, 100, [w])
        if not _in_band(page, probe_m, spec):
            continue
        rows.setdefault(int(w.cy // 8), []).append(w)
    results = []
    for ws in rows.values():
        ws.sort(key=lambda w: w.x)
        row_m = Match(" ".join(w.t for w in ws), col_x, min(w.y for w in ws),
                      max(w.y + w.h for w in ws) - min(w.y for w in ws), ws[-1].x + ws[-1].w, 100, ws)
        c = page.control_left_of(row_m, search=44)
        if c is not None and abs(c["x"] - radio_x) <= 5:     # same column as the radios
            results.append((c, row_m))
    # one row per control (rows of the same line may repeat)
    sel = [(c, m) for c, m in results if c["on"]]
    if len(results) < 2 or len({int(m.y // 8) for _, m in sel}) != 1:
        return None
    c, m = sel[0]
    text = m.text + " " + page.text_right_of(m)
    for rule in spec.get("map", []):
        mt = re.search(rule["re"], text, re.I)
        if mt:
            groups = mt.groups()
            display = rule["display"].format(*groups) if groups else rule["display"]
            if rule.get("singular") and groups and groups[0] == "1":
                display = rule["singular"]
            return _result(key, display, display, c["conf"] * spec.get("trust", 1.0), f"(o) {text.strip()}")
    return None


def _number_box(page: Page, spec: dict, key: str) -> Optional[dict]:
    """Number in an input box / dropdown right of a label.

    General OCR drops digits in pale input boxes ("10" read as "1"), so the
    box is cropped, enlarged and read twice (as-is and thresholded) with a
    digits-only whitelist. The value is used only if both readings agree.
    """
    import cv2
    import numpy as np
    import pytesseract

    for m in page.find_all(spec["label"], spec.get("min_score", 85))[:2]:
        x0, cy = int(m.right) + 2, int(m.y + m.h / 2)
        reg = page.img[max(0, cy - 11):cy + 11, x0:x0 + spec.get("width", 140)]
        if reg.size == 0:
            continue
        g = cv2.cvtColor(reg, cv2.COLOR_BGR2GRAY)
        big = cv2.resize(g, None, fx=4, fy=4, interpolation=cv2.INTER_CUBIC)
        if np.median(big) < 128:
            big = 255 - big
        _, th = cv2.threshold(big, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        cfg = "--psm 7 -c tessedit_char_whitelist=0123456789"
        reads = [pytesseract.image_to_string(im, config=cfg).strip() for im in (big, th)]
        if reads[0] and reads[0] == reads[1] and re.fullmatch(r"\d{1,4}", reads[0]):
            n = int(reads[0])
            display = (spec.get("singular") if n == 1 and spec.get("singular") else spec["display"]).format(n)
            return _result(key, display, display, 0.9 * spec.get("trust", 1.0) * m.score / 100,
                           f"{m.text} [{n}]")
    return None


def _radio_ordered(page: Page, spec: dict, key: str) -> Optional[dict]:
    """Radio buttons in a fixed vertical order, read by position.

    OCR often drops the text of the selected option (the filled radio is
    read as a glyph and swallows the word), so options found by text only
    fix the radio column and the row spacing; every option's row is then
    probed at its expected position.
    """
    opts = spec["options"]
    found = []
    for i, opt in enumerate(opts):
        for m in page.find_all(opt["label"], opt.get("min_score", 85))[:2]:
            if not _in_band(page, m, spec):
                continue
            c = _probe(page, m)
            if c is not None:
                found.append((i, m, c))
                break
    if len(found) < 2:
        return None
    found.sort(key=lambda f: f[0])
    (i0, m0, c0), (i1, m1, _) = found[0], found[-1]
    if i1 == i0:
        return None
    step = (m1.y - m0.y) / (i1 - i0)
    if step < 10:                                   # rows must be stacked vertically
        return None
    col_x = min(c["x"] for _, _, c in found)
    states = []
    for i, opt in enumerate(opts):
        y = m0.y + (i - i0) * step
        probe = Match(opt["label"], col_x + 14, y, m0.h, col_x + 60, 100, [])
        c = page.control_left_of(probe, search=20)
        states.append(c["on"] if c else None)
    on = [i for i, st in enumerate(states) if st]
    if len(on) != 1 or sum(1 for st in states if st is not None) < len(opts) - 1:
        return None                                 # ambiguous: leave it for the checklist
    opt = opts[on[0]]
    conf = 0.9 * spec.get("trust", 1.0)
    return _result(key, opt.get("value", opt["display"]), opt["display"], conf,
                   f"(o) option {on[0] + 1} of {len(opts)}: {opt['label']}")


def _text(page: Page, spec: dict, key: str) -> Optional[dict]:
    for rule in spec["patterns"]:
        mt = re.search(rule["re"], page.text, re.I)
        if mt:
            return _result(key, rule["value"], rule["display"], 0.9 * spec.get("trust", 1.0), mt.group(0))
    return None


def _toggles(page: Page, spec: dict, key: str) -> Optional[dict]:
    hdr = page.find_all(spec.get("column", "Status"), 85)
    if not hdr:
        return None
    t = page.toggles_below(hdr[0])
    if not t:
        return None
    on = sum(1 for x in t if x["on"])
    return {"key": key, "partial": {"on": on, "off": len(t) - on, "page": page.name}}


def _license(page: Page, spec: dict, key_prefix: str) -> list[dict]:
    """Licence table: the endpoint licence that runs longest is the one in force.

    Expired licences stay listed in the console (red cross), so neither the
    first row nor the biggest one can be trusted. Credit-based licences
    (TrendAI Flex) show "Multiple" units on their own row and the endpoint
    allocation on an indented row underneath.
    """
    row_re = re.compile(spec.get("row_re", r"Endpoint|Security|Protection"), re.I)
    lines = [" ".join(w.t for w in ln) for ln in sorted(page.lines, key=lambda ln: (ln[0].y, ln[0].x))]

    def dates(line):
        return [d for d in re.findall(r"(20\d\d)-(\d\d)-(\d\d)", line) if 2015 <= int(d[0]) <= 2045]

    def first_int(line):
        for n in re.findall(r"(?<![\d-])(\d{1,3}(?:,\d{3})+|\d{1,6})(?![\d-])", line):
            v = int(n.replace(",", ""))
            if v > 0:
                return v
        return None

    def clean_name(line):
        name = re.split(r"\s+(Paid|Trial|Evaluation|Free)\b", line)[0]
        name = re.sub(r"^(?:[^A-Za-z]+|[a-z]{1,3}\s+)+", "", name)      # row icons / expand arrow
        return re.sub(r"\bTrendAl\b", "TrendAI", name).strip()             # common OCR slip

    rows = []
    for i, line in enumerate(lines):
        ds = dates(line)
        if not ds or not re.search(r"\b(Paid|Trial|Evaluation|Free)\b", line):
            continue
        name, units = clean_name(line), None
        sub = None
        if re.search(r"\bMultiple\b", line) or first_int(line.split(" Paid ")[-1]) is None:
            # credit licence: allocation rows follow, without dates
            for nxt in lines[i + 1:i + 6]:
                if dates(nxt):
                    break
                if row_re.search(nxt) and first_int(nxt):
                    sub = nxt
                    break
        if sub:
            units = first_int(sub)
            name = f"{name} - {re.split(r'\s+\d', sub)[0].strip()}"
        else:
            after_type = re.split(r"\b(?:Paid|Trial|Evaluation|Free)\b", line, maxsplit=1)[-1]
            units = first_int(re.sub(r"TrendA[Il]\S*", "", after_type))
        if not (row_re.search(line) or sub):
            continue
        rows.append((max(ds), units or 0, name, line + (f" / {sub}" if sub else "")))
    if not rows:
        return []
    expiry, units, name, line = max(rows, key=lambda r: (r[0], r[1]))
    iso = "-".join(expiry)
    out = [_result(f"{key_prefix}.expiry", iso, dt.date.fromisoformat(iso).strftime("%d %B %Y"), 0.9, line)]
    if units:
        out.append(_result(f"{key_prefix}.seats", units, str(units), 0.85, line))
    if name:
        out.append(_result(f"{key_prefix}.name", name, name, 0.8, line))
    others = [r for r in rows if r[0] < expiry]
    if others:
        out.append(_result(f"{key_prefix}.expired_others", len(others),
                           f"{len(others)} older licence row(s) also listed", 0.8, ""))
    return out


KINDS = {"checkbox": _checkbox, "all_checked": _all_checked, "radio": _radio,
         "radio_rows": _radio_rows, "text": _text, "toggles": _toggles, "number_box": _number_box,
         "radio_ordered": _radio_ordered}


def read_page(page: Page, specs: dict, wanted: Optional[set] = None) -> list[dict]:
    out: list[dict] = []
    for key, spec in specs.get("fields", {}).items():
        if wanted is not None and key not in wanted and not key.startswith("license"):
            continue
        if spec.get("page") and not page.has_any(spec["page"]):
            continue
        if spec.get("page_all") and not all(page.has_any([p]) for p in spec["page_all"]):
            continue
        kind = spec["kind"]
        try:
            if kind == "license":
                out.extend(_license(page, spec, key))
                continue
            r = KINDS[kind](page, spec, key)
        except Exception as exc:  # one odd page must not stop the run
            r = None
            out.append({"key": f"_error.{key}", "error": str(exc)})
        if r:
            out.append(r)
    return out


def page_dates(text: str) -> list[str]:
    """Dates visible on a capture (taskbar clock dd-mm-yyyy, console yyyy-mm-dd)."""
    out = []
    for d, m, y in re.findall(r"\b(\d{2})[-/](\d{2})[-/](20\d\d)\b", text):
        out.append(f"{y}-{m}-{d}")
    for y, m, d in re.findall(r"\b(20\d\d)-(\d{2})-(\d{2})\b", text):
        out.append(f"{y}-{m}-{d}")
    valid = []
    for iso in out:
        try:
            dt.date.fromisoformat(iso)
            valid.append(iso)
        except ValueError:
            pass
    return valid


def run(docx_path, cache_path, pack: str = "apexone_sep", progress=print) -> list[dict]:
    """OCR every screenshot in the Word file (cached per image) and store the
    combined readings in the shared screenshot cache as one 'ocr' entry."""
    import hashlib
    import json
    from .screenshots import extract_images

    specs = load_specs(pack)
    spec_hash = hashlib.sha1(json.dumps(specs, sort_keys=True).encode()).hexdigest()[:12]
    cache_path = Path(cache_path)
    data = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {}
    data.setdefault("version", 1)
    data.setdefault("images", {})
    raw = data.setdefault("ocr_pages", {})
    shots = extract_images(docx_path)
    per_page, done = [], 0
    for shot in shots:
        tag = f"{shot.sha1}:{spec_hash}"
        if tag not in raw:
            page = Page(shot.data, shot.filename.split("/")[-1])
            raw[tag] = {"file": shot.filename, "section": shot.section,
                        "results": read_page(page, specs), "dates": page_dates(page.text)}
            done += 1
            if done % 10 == 0:
                progress(f"  OCR {done} new screenshots read...")
        per_page.append(raw[tag]["results"])
    fields = aggregate(per_page, specs)
    from collections import Counter
    dates = Counter(d for tag in raw if tag.split(":")[0] in {sh.sha1 for sh in shots}
                    for d in raw[tag].get("dates", []))
    data["check_date_guess"] = dates.most_common(1)[0][0] if dates else ""
    # where each reading came from, for the review workbook
    origin = {}
    for tag, entry in raw.items():
        for r in entry["results"]:
            if "value" in r:
                origin.setdefault(r["key"], entry["file"])
    for f in fields:
        f["quote"] = f"{origin.get(f['key'], '')}: {f.get('quote', '')}".strip(": ")
    data["images"]["ocr:aggregate"] = {"index": 0, "file": "OCR (all screenshots)", "section": "",
                                       "model": "ocr-tesseract", "page": "", "fields": fields}
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    progress(f"OCR: {len(shots)} screenshots ({done} newly read), {len(fields)} settings recognised")
    return fields


def aggregate(per_page: list[list[dict]], specs: dict) -> list[dict]:
    """Combine readings across pages: best confidence wins; toggles are summed."""
    best: dict[str, dict] = {}
    toggles: dict[str, dict] = {}
    for results in per_page:
        for r in results:
            if "partial" in r:
                agg = toggles.setdefault(r["key"], {"on": 0, "off": 0, "pages": []})
                agg["on"] += r["partial"]["on"]
                agg["off"] += r["partial"]["off"]
                agg["pages"].append(r["partial"]["page"])
            elif "key" in r and "value" in r:
                if r["key"] not in best or r["confidence"] > best[r["key"]]["confidence"]:
                    best[r["key"]] = r
    for key, t in toggles.items():
        total = t["on"] + t["off"]
        if total == 0:
            continue
        if t["off"] == 0:
            display, value = "Enabled", "Enabled"
        elif t["on"] == 0:
            display, value = "Disabled", "Disabled"
        else:
            display, value = "Partially Enabled", "Partially Enabled"
        best[key] = _result(key, value, display, 0.9,
                            f"{t['on']} of {total} notification switches on ({', '.join(t['pages'])})")

    # derived values (e.g. Update Agent options only apply to a customised source)
    for key, spec in specs.get("fields", {}).items():
        for rule in spec.get("derive", []) or []:
            src = best.get(key)
            if src and str(src["value"]) == str(rule["when"]):
                for dkey, (val, disp) in rule["set"].items():
                    best[dkey] = _result(dkey, val, disp, src["confidence"], f"derived from {key}")
    return list(best.values())
