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
    def __init__(self, data: bytes, name: str = "", stretch: Optional[tuple] = None,
                 scale: int = SCALE, section: str = "", checkbox_style: str = "fill"):
        """`stretch=(lo, hi)` maps grey levels lo..hi to the full range before OCR.

        The Server & Workload Protection console draws dropdown values and
        descriptions in dark grey on near-black (text ~75, background ~40);
        plain OCR does not see them at all. Stretching that band makes them
        readable; bright text simply saturates. Pixel analysis of checkboxes
        always uses the original image.
        """
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
        self.section = section
        self._data, self._plain = data, None
        # "fill": ticked boxes are filled/dark-centred (Apex One, Vision One).
        # "tick": every box is a light square; only a ticked one has a tick
        #         drawn inside it (Server & Workload Protection dark theme).
        self.checkbox_style = checkbox_style
        self.stretched = bool(stretch)
        g = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        g = cv2.resize(g, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
        if stretch:
            lo, hi = stretch
            g = 255 - np.clip((g.astype(np.float32) - lo) * 255.0 / (hi - lo), 0, 255).astype(np.uint8)
        d = pytesseract.image_to_data(g, output_type=pytesseract.Output.DICT, config="--psm 3")
        self.words: list[Word] = []
        for i, t in enumerate(d["text"]):
            if t.strip() and float(d["conf"][i]) >= 20:
                self.words.append(Word(t, d["left"][i] / scale, d["top"][i] / scale,
                                       d["width"][i] / scale, d["height"][i] / scale,
                                       (d["block_num"][i], d["par_num"][i], d["line_num"][i])))
        lines: dict[tuple, list[Word]] = {}
        for w in self.words:
            lines.setdefault(w.line, []).append(w)
        self.lines = [sorted(v, key=lambda w: w.x) for v in lines.values()]
        self.text = "\n".join(" ".join(w.t for w in ln) for ln in
                              sorted(self.lines, key=lambda ln: (ln[0].y, ln[0].x)))

    @property
    def plain(self) -> "Page":
        """The same screenshot read without contrast stretching (made on first use)."""
        if not self.stretched:
            return self
        if self._plain is None:
            self._plain = Page(self._data, self.name, section=self.section,
                               checkbox_style=self.checkbox_style)
        return self._plain

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
        if getattr(self, "checkbox_style", "fill") == "tick":
            inner = roi[2:hh - 2, 2:w - 2]
            spread = float(inner.std()) if inner.size else 0.0
            light = abs(float(inner.mean()) - bgv) > 8 if inner.size else False
            on = (spread > 7 and light) or roi_blue > 0.25
            conf = 0.95 if (spread > 12 or spread < 3) else 0.75
            return {"on": on, "blue": round(roi_blue, 2), "centre": round(centre_diff, 1), "conf": conf,
                    "margin": round(abs(spread - 7), 2), "x": x0 + cx, "spread": round(spread, 1)}
        on = roi_blue > 0.25 or centre_diff > 20
        # margin from the decision boundary -> confidence
        margin = max(roi_blue - 0.25, centre_diff - 20) if on else min(0.25 - roi_blue, 20 - centre_diff)
        conf = 0.97 if (centre_diff > 28 or roi_blue > 0.4 or (not on and centre_diff < 12)) else 0.8
        return {"on": on, "blue": round(roi_blue, 2), "centre": round(centre_diff, 1), "conf": conf,
                "margin": round(float(margin), 2), "x": x0 + cx}

    def toggle_left_of(self, m: Match, search: int = 75) -> Optional[dict]:
        """Pill-shaped switch immediately left of a label (Cloud Email and
        Collaboration Protection): blue with the knob right = on, grey = off."""
        import cv2
        import numpy as np

        cy = int(m.y + m.h / 2)
        x0, x1 = max(0, int(m.x) - search), max(0, int(m.x) - 1)
        y0, y1 = max(0, cy - 13), min(self.img.shape[0], cy + 14)
        win = self.img[y0:y1, x0:x1]
        if win.size == 0 or win.shape[1] < 12:
            return None
        g = cv2.cvtColor(win, cv2.COLOR_BGR2GRAY).astype(np.int16)
        hsv = cv2.cvtColor(win, cv2.COLOR_BGR2HSV)
        bgv = int(np.median(g))
        mask = (np.abs(g - bgv) > 22).astype(np.uint8)
        mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, np.ones((3, 3), np.uint8))
        n, _, st, _ = cv2.connectedComponentsWithStats(mask, 8)
        cands = []
        for i in range(1, n):
            x, y, w, h, a = (int(v) for v in st[i])
            if (8 <= h <= 22 and 21 <= w and 1.4 * h <= w <= 3.4 * h and a / float(w * h) > 0.45
                    and x0 + x + w >= m.x - 28):          # right next to the label
                cands.append((x + w, x, y, w, h))
        if not cands:
            return None
        _, x, y, w, h = max(cands)                     # the one nearest the label
        sat = hsv[y:y + h, x:x + w, 1].astype(np.float32)
        hue = hsv[y:y + h, x:x + w, 0]
        blue = float(((hue > 95) & (hue < 130) & (sat > 90)).mean())
        on = blue > 0.25
        conf = 0.95 if (blue > 0.4 or blue < 0.08) else 0.75
        return {"on": on, "blue": round(blue, 2), "conf": conf, "x": x0 + x, "w": w}

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
    if c is None:
        # OCR sometimes merges the box into the first word ("[x]Allow" read as "Allow")
        c = page.control_left_of(Match(m.text, m.x + 18, m.y, m.h, m.right, m.score, m.line), search=26)
    if c is None and m.line:
        # the box was read as a glyph ("@", "B", "|") or the label's first words
        # were dropped: walk left over the preceding words of the row
        x = m.x
        for w in sorted((w for w in m.line if w.x < m.x - 1), key=lambda w: -w.x):
            if x - (w.x + w.w) > 40:
                break
            for probe_x in (w.x + w.w + 3, w.x):
                c = page.control_left_of(Match(m.text, probe_x, m.y, m.h, m.right, m.score, m.line))
                if c is not None:
                    return c
            x = w.x
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
    """Respect optional `below`/`above` anchors so repeated words resolve to one block.

    The match must sit under a `below` anchor with no `above` anchor in
    between (so an anchor word repeated higher up the page, e.g. in a help
    text, does not close the band early).
    """
    below = page.find_all(spec["below"], 85) if spec.get("below") else []
    above = page.find_all(spec["above"], 85) if spec.get("above") else []
    if spec.get("heading"):
        # anchors must be section headings (alone on their row), not words in help text
        def alone(a: Match) -> bool:
            return len(" ".join(w.t for w in a.line)) <= len(a.text) + 8
        below, above = [a for a in below if alone(a)], [a for a in above if alone(a)]
    if spec.get("below"):
        starts = [b.y for b in below if b.y < m.y - 1]
        if not starts:
            return False
        start = max(starts)
        return not any(start < a.y < m.y for a in above)
    if spec.get("above"):
        return any(a.y > m.y for a in above) if above else True
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
    read as a glyph and swallows the word), so options found by text fix the
    row positions and the radio column (from any option whose radio was
    seen); every option's row is then probed at that column.
    """
    opts = spec["options"]
    rows: dict[int, Match] = {}
    ctrls = []
    for i, opt in enumerate(opts):
        # `alt`: the same option without its first word (the selected radio
        # often swallows it: "(@)medium Applies to..." read as "Applies to...")
        for label in [opt["label"]] + list(opt.get("alt", [])):
            hit = None
            for m in page.find_all(label, opt.get("min_score", 85))[:2]:
                if not _in_band(page, m, spec):
                    continue
                if any(abs(m.y - o.y) < 6 for o in rows.values()):
                    continue                        # same row already taken by another option
                hit = m
                break
            if hit is None:
                continue
            rows[i] = hit
            c = _probe(page, hit)
            if c is not None:
                ctrls.append(c)
            break
    if len(rows) < 2 or not ctrls:
        return None
    order = sorted(rows)
    i0, i1 = order[0], order[-1]
    m0, m1 = rows[i0], rows[i1]
    step = (m1.y - m0.y) / (i1 - i0)
    if step < 10:                                   # rows must be stacked vertically
        return None
    col_x = min(c["x"] for c in ctrls)
    states = []
    for i, opt in enumerate(opts):
        y = rows[i].y if i in rows else m0.y + (i - i0) * step
        h = rows[i].h if i in rows else m0.h
        probe = Match(opt["label"], col_x + 14, y, h, col_x + 60, 100, [])
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
    """Regex over the page text. `value`/`display` may use {1}, {2}... (capture groups)."""
    for rule in spec["patterns"]:
        mt = re.search(rule["re"], page.text, re.I | re.S if rule.get("dotall") else re.I)
        if mt:
            groups = [""] + [g or "" for g in mt.groups()]
            val = rule.get("value", rule.get("display"))
            val = val.format(*groups) if isinstance(val, str) else val
            disp = str(rule.get("display", val)).format(*groups)
            return _result(key, val, disp, 0.9 * spec.get("trust", 1.0), mt.group(0)[:160])
    if spec.get("default"):                 # page recognised, pattern absent (e.g. no such task)
        d = spec["default"]
        return _result(key, d.get("value", d["display"]), d["display"], 0.8 * spec.get("trust", 1.0),
                       "not listed on the page")
    return None


_GLYPH = re.compile(r"^[^A-Za-z0-9(]+|[^A-Za-z0-9)%]+$")


def _row_value(page: Page, m: Match, min_x: float = 0, max_x: float = 10_000) -> str:
    """All words on the label's row to its right (any gap), e.g. a dropdown far right."""
    cy = m.y + m.h / 2
    tol = max(5, m.h * 0.6)
    row = sorted([w for w in page.words if abs(w.cy - cy) <= tol and w.x >= max(m.right + 3, min_x)
                  and w.x <= max_x], key=lambda w: w.x)
    txt = " ".join(w.t for w in row)
    return " ".join(t for t in (_GLYPH.sub("", x) for x in txt.split()) if t)


def _reread_value(page: Page, m: Match) -> str:
    """OCR the dropdown area right of a label again from its own crop.

    Used when the page pass read only part of a value ("Inherited" without
    the "(Unlimited)" after it): a small crop, contrast-stretched around its
    own grey levels, is far easier for Tesseract than the whole screen.
    """
    import cv2
    import numpy as np
    import pytesseract

    cy = int(m.y + m.h / 2)
    row = [w for w in page.words if abs(w.cy - cy) <= max(5, m.h * 0.6) and w.x > m.right + 3]
    x0 = int(min((w.x for w in row), default=m.right + 10)) - 6
    reg = page.img[max(0, cy - 10):cy + 10, max(0, x0):x0 + 240]
    if reg.size == 0:
        return ""
    g = cv2.cvtColor(reg, cv2.COLOR_BGR2GRAY).astype(np.float32)
    big = cv2.resize(g, None, fx=4, fy=4, interpolation=cv2.INTER_CUBIC)
    lo, hi = np.percentile(big, 50), np.percentile(big, 99.5)
    st = 255 - np.clip((big - lo) * 255.0 / max(1.0, hi - lo), 0, 255).astype(np.uint8)
    return pytesseract.image_to_string(st, config="--psm 7").strip()


def _clean_value(txt: str) -> str:
    """'Inherited (Unlimited) v' -> 'Unlimited'; 'Quarantine (recommended)' -> 'Quarantine'."""
    t = re.sub(r"\s+[vV¥©’'=~]$", "", txt.strip())      # dropdown arrow read as a letter
    mt = re.search(r"(?i)\b[il1|]n\w{2,8}\s*\(([^()]*)\)?", t)      # "Inherited (x)", OCR variants
    if mt:
        t = mt.group(1)
    t = re.sub(r"(?i)\s*\(recommended\)", "", t)
    return t.strip(" ()")


def _value_right(page: Page, spec: dict, key: str) -> Optional[dict]:
    """Value shown right of a label on the same row (dropdown, status text).

    `map` turns the raw text into the report wording ({re, display, value});
    without a map the cleaned text is used as is. Labels that occur several
    times on a page can be pinned with `below`/`above` or `nth` (0-based,
    top to bottom).
    """
    found = [m for m in page.find_all(spec["label"], spec.get("min_score", 80)) if _in_band(page, m, spec)]
    if "nth" in spec:
        found = sorted(found, key=lambda m: m.y)
        found = found[spec["nth"]:spec["nth"] + 1]
    for m in found[:3]:
        raw = _row_value(page, m, spec.get("min_x", 0), spec.get("max_x", 10_000))
        if not raw and spec.get("next_line"):       # value wrapped onto the next row
            nxt = [w for w in page.words if 4 < w.y - (m.y + m.h) < 22 and w.x >= m.x - 5]
            raw = " ".join(w.t for w in sorted(nxt, key=lambda w: w.x))
        if not raw:
            continue
        nxt_words = [w for w in page.words if 4 < w.y - (m.y + m.h) < 22 and w.x >= m.right - 40]
        nxt = " ".join(w.t for w in sorted(nxt_words, key=lambda w: w.x))
        if spec.get("map") and nxt and not any(re.search(r["re"], _clean_value(raw), re.I)
                                                for r in spec["map"]):
            raw = f"{raw} {nxt}".strip()          # "Inherited" / "(Unlimited)" split over two rows
        if spec.get("map") and not any(re.search(r["re"], _clean_value(raw), re.I) for r in spec["map"]):
            again = _reread_value(page, m)
            if again:
                raw = again
        val = _clean_value(raw)
        conf = 0.85 * spec.get("trust", 1.0) * m.score / 100
        if spec.get("vocab"):                       # snap OCR noise to a known word
            from rapidfuzz import fuzz
            hits = [(fuzz.partial_ratio(v.lower(), val.lower()), -len(v), v) for v in spec["vocab"]]
            best = max(hits)
            if best[0] < 80:
                continue
            val = best[2]
        if spec.get("map"):
            for rule in spec["map"]:
                mt = re.search(rule["re"], val, re.I)
                if mt:
                    groups = [""] + [g or "" for g in mt.groups()]
                    disp = rule["display"].format(*groups)
                    v = rule.get("value", disp)
                    v = v.format(*groups) if isinstance(v, str) else v
                    return _result(key, v, disp, conf, f"{m.text}: {raw}")
            continue
        if len(val) >= spec.get("min_len", 2):
            return _result(key, val, val, conf, f"{m.text}: {raw}")
    if found and spec.get("empty"):           # label seen, nothing entered next to it
        d = spec["empty"]
        return _result(key, d.get("value", d["display"]), d["display"], 0.75 * spec.get("trust", 1.0),
                       f"{found[0].text}: (empty)")
    return None


def _value_list(page: Page, spec: dict, key: str) -> Optional[dict]:
    """Several label: value rows joined into one display ('Virus: Clean' ...)."""
    parts, quotes = [], []
    for item in spec["items"]:
        sub = dict(item, trust=spec.get("trust", 1.0))
        if spec.get("vocab") and "vocab" not in sub:
            sub["vocab"] = spec["vocab"]
        sub.setdefault("below", spec.get("below"))
        sub.setdefault("above", spec.get("above"))
        r = _value_right(page, sub, key)
        if r is None:
            if item.get("optional"):
                continue
            return None
        parts.append(f"{item.get('name', item['label'].rstrip(':'))}: {r['display']}")
        quotes.append(r["quote"])
    head = [spec["prefix"]] if spec.get("prefix") else []
    display = "\n".join(head + parts)
    share = len(parts) / max(1, len(spec["items"]))      # the fullest capture wins
    return _result(key, display, display, 0.85 * spec.get("trust", 1.0) * share, "; ".join(quotes)[:200])


def _segments(page: Page, label: str, min_score: float) -> list[Match]:
    """Every place a label occurs, several per OCR line allowed.

    `Page.find_all` keeps the best match per line, but a side menu entry and
    the setting it opens are often read as one line ("File Blocking  GD File
    Blocking"); the setting is then the second occurrence.
    """
    from rapidfuzz import fuzz
    target, n = label.lower(), len(label.split())
    out: list[Match] = []
    for ln in page.lines:
        cands = []
        for i in range(len(ln)):
            for j in range(i + max(1, n - 1), min(len(ln), i + n + 1) + 1):
                seg = ln[i:j]
                txt = " ".join(w.t for w in seg)
                sc = fuzz.ratio(target, txt.lower())
                if len(label) > 30 and len(txt) > 0.55 * len(label):
                    sc = max(sc, fuzz.partial_ratio(target, txt.lower()) - 3)
                if sc >= min_score:
                    cands.append((sc, i, j, seg, txt))
        used: set[int] = set()
        for sc, i, j, seg, txt in sorted(cands, key=lambda c: -c[0]):
            if used & set(range(i, j)):
                continue
            used |= set(range(i, j))
            out.append(Match(txt, seg[0].x, min(w.y for w in seg), max(w.y + w.h for w in seg) - min(w.y for w in seg),
                             max(w.x + w.w for w in seg), sc, ln))
    return sorted(out, key=lambda m: (-m.score, -m.x))


def _toggle_near(page: Page, m: Match) -> Optional[dict]:
    t = page.toggle_left_of(m)
    if t is None and m.line:
        # the switch is often read as glyph words ("@®", "GD") or the label's
        # first words were dropped: walk left over the preceding words
        x = m.x
        for w in sorted((w for w in m.line if w.x < m.x - 1), key=lambda w: -w.x):
            if x - (w.x + w.w) > 40:
                break
            t = page.toggle_left_of(Match(m.text, w.x, m.y, m.h, m.right, m.score, m.line))
            if t is not None:
                break
            x = w.x
    return t


def _toggle(page: Page, spec: dict, key: str) -> Optional[dict]:
    """On/off switch drawn left of its label (`when_on` / `when_off` wording)."""
    found = [m for m in _segments(page, spec["label"], spec.get("min_score", 82)) if _in_band(page, m, spec)]
    if "nth" in spec:
        found = sorted(found, key=lambda m: m.y)[spec["nth"]:spec["nth"] + 1]
    best = None
    for m in found[:8]:
        t, kind = _toggle_near(page, m), 2
        if t is None and spec.get("checkbox", True):
            t, kind = _probe(page, m), 1           # some options are plain checkboxes
        if t is None:
            continue
        # the setting's own label stands alone on its row; the same words in
        # a help sentence ("...using computer vision techniques") do not
        row = " ".join(w.t for w in (m.line or []) if w.x >= m.x - 60) or m.text
        rank = (kind, round(t["conf"], 1), -max(0, len(row) - len(m.text) - 6), m.score)
        if best is None or rank > best[0]:
            best = (rank, m, t)
    if best:
        _, m, t = best
        on = t["on"]
        display = spec.get("when_on", "Enabled") if on else spec.get("when_off", "Disabled")
        value = spec.get("value_on", on) if on else spec.get("value_off", on)
        conf = t["conf"] * (m.score / 100) * spec.get("trust", 1.0)
        return _result(key, value, display, conf, f"{'(on)' if on else '(off)'} {m.text}")
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
    ordered = sorted(page.lines, key=lambda ln: (ln[0].y, ln[0].x))
    lines = [" ".join(w.t for w in ln) for ln in ordered]

    def valid(d):
        try:
            dt.date(int(d[0]), int(d[1]), int(d[2]))
            return 2015 <= int(d[0]) <= 2045
        except ValueError:
            return False

    def dates(line, words=None):
        found = re.findall(r"(20\d\d)[-. ]?(\d\d)[-. ]?(\d\d)", line)
        good = [d for d in found if valid(d)]
        if words is not None and len(good) < len(found):
            # a misread digit ("2028-04-00"): crop each date and read it again, digits only
            good = [d for d in (_reread_date(page, w) for w in words if re.match(r"20\d\d", w.t)) if d] or good
        return good

    def first_int(line):
        for n in re.findall(r"(?<![\d-])(\d{1,3}(?:,\d{3})+|\d{1,6})(?![\d-])", line):
            v = int(n.replace(",", ""))
            if v > 0:
                return v
        return None

    def clean_name(line):
        name = re.split(r"\s+(Paid|Trial|Evaluation|Free)\b", line)[0]
        name = re.sub(r"^(?:[^A-Za-z]+|[a-z]{1,3}\s+|[A-Z]\s+)+(?=[A-Z][a-z])", "", name)  # row icons / expand arrow
        return re.sub(r"\bTrendAl\b", "TrendAI", name).strip()             # common OCR slip

    rows = []
    for i, line in enumerate(lines):
        ds = dates(line, ordered[i])
        typed = re.search(r"\b(Paid|Trial|Evaluation|Free)\b", line) or any(
            re.fullmatch(r"\W*(Paid|Trial|Evaluation|Free)\W*", prev) for prev in lines[max(0, i - 2):i])
        if not ds or not typed:
            continue
        name, units = clean_name(line), None
        sub = None
        if re.search(r"\bMultiple\b", line) or first_int(line.split(" Paid ")[-1]) is None:
            # credit licence: allocation rows follow, without dates
            for j, nxt in enumerate(lines[i + 1:i + 7], start=i + 1):
                if dates(nxt):
                    break
                if row_re.search(nxt) and first_int(nxt):
                    sub = nxt
                    break
                if row_re.search(nxt) and j + 1 < len(lines) and first_int(lines[j + 1]) \
                        and not dates(lines[j + 1]) and not re.search(r"[A-Za-z]{3}", lines[j + 1]):
                    sub = f"{nxt} {lines[j + 1]}"        # units read on the row below the name
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
    if " / " in line:                               # credit licence: the product row underneath
        product = re.split(r"\s+\d", line.split(" / ", 1)[1])[0].strip()
        product = re.sub(r"^\W+", "", product)
        out.append(_result(f"{key_prefix}.product", product, product, 0.8, line))
    others = [r for r in rows if r[0] < expiry]
    if others:
        out.append(_result(f"{key_prefix}.expired_others", len(others),
                           f"{len(others)} older licence row(s) also listed", 0.8, ""))
    return out


def _reread_date(page: Page, w: Word) -> Optional[tuple]:
    """Read a yyyy-mm-dd date again from its own crop.

    Several enlargements / thresholds are tried; a date is accepted only when
    at least two readings agree on the same valid date.
    """
    import cv2
    import numpy as np
    import pytesseract
    from collections import Counter

    x0, y0 = int(w.x) - 2, int(w.y) - 4
    reg = page.img[max(0, y0):y0 + int(w.h) + 8, max(0, x0):x0 + 80]
    if reg.size == 0:
        return None
    g = cv2.cvtColor(reg, cv2.COLOR_BGR2GRAY)
    if np.median(g) < 128:
        g = 255 - g
    cfg = "--psm 7 -c tessedit_char_whitelist=0123456789-."
    votes: Counter = Counter()
    for fx in (3, 4, 5, 6):
        big = cv2.resize(g, None, fx=fx, fy=fx, interpolation=cv2.INTER_CUBIC)
        _, th = cv2.threshold(big, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        for im in (big, th, cv2.GaussianBlur(big, (3, 3), 0)):
            mt = re.search(r"(20\d\d)[-.]?(\d\d)[-.]?(\d\d)", pytesseract.image_to_string(im, config=cfg))
            if not mt:
                continue
            try:
                dt.date(*(int(x) for x in mt.groups()))
            except ValueError:
                continue
            votes[mt.groups()] += 1
    if votes:
        best, n = votes.most_common(1)[0]
        if n >= 2 and n > sum(votes.values()) / 2:
            return best
    return None


KINDS = {"toggle": _toggle, "checkbox": _checkbox, "all_checked": _all_checked, "radio": _radio,
         "radio_rows": _radio_rows, "text": _text, "toggles": _toggles, "number_box": _number_box,
         "radio_ordered": _radio_ordered, "value_right": _value_right, "value_list": _value_list}


def page_scope(page: Page, specs: dict) -> dict[str, str]:
    """Which policy / scan configuration a page belongs to.

    Field keys may contain placeholders, e.g. ``{p}.heartbeat`` (p = which
    policy) or ``swp.{c}.dim`` (c = which malware scan configuration). The
    window title / breadcrumb at the top of the capture decides ("Policy:
    Base Policy > Linux > Linux Server"); the label the analyst typed above
    the screenshot is the fallback.
    """
    found: dict[str, str] = {}
    head = "\n".join(page.text.splitlines()[:14])
    for dim, values in (specs.get("scopes") or {}).items():
        for name, sc in values.items():
            if any(re.search(pat, head, re.I) for pat in sc.get("head", [])):
                found[dim] = name
                break
        else:
            for name, sc in values.items():
                if any(re.search(pat, page.section or "", re.I) for pat in sc.get("section", [])):
                    found[dim] = name
                    break
    return found


def _expand(key: str, scope: dict[str, str]) -> Optional[str]:
    for dim in re.findall(r"\{(\w)\}", key):
        if dim not in scope:
            return None
        key = key.replace("{" + dim + "}", scope[dim])
    return key


def read_page(page: Page, specs: dict, wanted: Optional[set] = None) -> list[dict]:
    out: list[dict] = []
    scope = page_scope(page, specs) if specs.get("scopes") else {}
    for key, spec in specs.get("fields", {}).items():
        if "{" in key:
            key = _expand(key, scope)
            if key is None:
                continue
        if wanted is not None and key not in wanted and not key.startswith("license"):
            continue
        if spec.get("not_page") and page.has_any(spec["not_page"]):
            continue
        pg = page.plain if spec.get("pass") == "plain" else page
        if spec.get("page") and not page.has_any(spec["page"]):
            continue
        if spec.get("page_all") and not all(page.has_any([p]) for p in spec["page_all"]):
            continue
        kind = spec["kind"]
        try:
            if kind == "license":
                out.extend(_license(pg, spec, key))
                continue
            r = KINDS[kind](pg, spec, key)
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


def run(docx_path, cache_path, pack: str = "apexone_sep", progress=print, tick=None) -> list[dict]:
    """OCR every screenshot in the Word file (cached per image) and store the
    combined readings in the shared screenshot cache as one 'ocr' entry.
    `tick(i, n)` is called after each screenshot (for a progress bar)."""
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
    for n_shot, shot in enumerate(shots, 1):
        tag = f"{shot.sha1}:{spec_hash}"
        if tag not in raw:
            ocr_opts = specs.get("ocr") or {}
            page = Page(shot.data, shot.filename.split("/")[-1],
                        stretch=tuple(ocr_opts["stretch"]) if ocr_opts.get("stretch") else None,
                        scale=int(ocr_opts.get("scale", SCALE)), section=shot.section,
                        checkbox_style=ocr_opts.get("checkbox_style", "fill"))
            raw[tag] = {"file": shot.filename, "section": shot.section,
                        "results": read_page(page, specs), "dates": page_dates(page.text)}
            done += 1
            if done % 10 == 0:
                progress(f"  OCR {done} new screenshots read...")
        per_page.append(raw[tag]["results"])
        if tick:
            tick(n_shot, len(shots))
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
    import itertools
    dims = specs.get("scopes") or {}
    for key0, spec in specs.get("fields", {}).items():
        used = [d for d in re.findall(r"\{(\w)\}", key0) if d in dims]
        for combo in itertools.product(*[list(dims[d]) for d in used]) if used else [()]:
            sc = dict(zip(used, combo))
            key = _expand(key0, sc)
            for rule in spec.get("derive", []) or []:
                src = best.get(key)
                if src and str(src["value"]) == str(rule["when"]):
                    for dkey, (val, disp) in rule["set"].items():
                        dkey = _expand(dkey, sc) or dkey
                        if dkey not in best or rule.get("override", True):
                            best[dkey] = _result(dkey, val, disp, src["confidence"], f"derived from {key}")
    return list(best.values())
