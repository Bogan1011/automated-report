"""OCR control detection on synthetic drawings, and the watch-folder plumbing."""
import shutil

import cv2
import numpy as np
import pytest

from tmhc import watch
from tmhc.sources import ocr

needs_tesseract = pytest.mark.skipif(shutil.which("tesseract") is None, reason="tesseract not installed")


def _page_from(img) -> ocr.Page:
    ok, buf = cv2.imencode(".png", img)
    p = ocr.Page.__new__(ocr.Page)          # skip OCR: we only test pixel analysis here
    p.img, p.name, p.words, p.lines, p.text = img, "synthetic", [], [], ""
    return p


def _canvas(dark: bool):
    bg = (21, 21, 21) if dark else (255, 255, 255)
    return np.full((60, 300, 3), bg, np.uint8)


def _label(x=60, y=24):
    return ocr.Match("label", x, y, 10, x + 120, 100, [])


@pytest.mark.parametrize("dark", [True, False])
def test_unticked_box_reads_off(dark):
    img = _canvas(dark)
    ring = (110, 110, 110) if dark else (160, 160, 160)
    cv2.rectangle(img, (40, 23), (50, 33), ring, 1)
    assert _page_from(img).control_left_of(_label())["on"] is False


def test_blue_filled_box_reads_on():
    img = _canvas(dark=True)
    cv2.rectangle(img, (40, 23), (50, 33), (215, 120, 30), -1)          # BGR blue fill
    cv2.line(img, (42, 28), (45, 31), (255, 255, 255), 1)
    assert _page_from(img).control_left_of(_label())["on"] is True


def test_classic_selected_radio_reads_on():
    img = _canvas(dark=False)
    cv2.circle(img, (45, 28), 5, (170, 170, 170), 1)
    cv2.circle(img, (45, 28), 2, (90, 90, 90), -1)
    assert _page_from(img).control_left_of(_label())["on"] is True


def test_no_control_returns_none():
    assert _page_from(_canvas(dark=False)).control_left_of(_label()) is None


def test_toggles_aggregate_to_partial():
    specs = {"fields": {}}
    per_page = [[{"key": "admin.event_notifications", "partial": {"on": 6, "off": 0, "page": "a"}}],
                [{"key": "admin.event_notifications", "partial": {"on": 4, "off": 2, "page": "b"}}]]
    res = {r["key"]: r for r in ocr.aggregate(per_page, specs)}
    assert res["admin.event_notifications"]["display"] == "Partially Enabled"


def test_derive_rule_sets_na_when_firewall_off():
    specs = {"fields": {"global.firewall_enabled": {"kind": "checkbox", "derive": [
        {"when": "False", "set": {"global.firewall_log_count": [False, "N/A"]}}]}}}
    per_page = [[{"key": "global.firewall_enabled", "value": False, "display": "Disabled", "confidence": 0.9,
                  "quote": ""},
                 {"key": "global.firewall_log_count", "value": True, "display": "Enabled", "confidence": 0.9,
                  "quote": ""}]]
    res = {r["key"]: r for r in ocr.aggregate(per_page, specs)}
    assert res["global.firewall_log_count"]["display"] == "N/A"


def test_page_dates_prefers_real_dates():
    assert ocr.page_dates("ENG 11:23 07-10-2026 and 2026-10-07, bad 31-02-2026") == ["2026-10-07", "2026-10-07"]


def test_specs_have_only_string_keys():
    # unquoted on:/off: in YAML become booleans - guard against it coming back
    specs = ocr.load_specs()
    for key, spec in specs["fields"].items():
        assert all(isinstance(k, str) for k in spec), key


@needs_tesseract
def test_real_ocr_finds_label():
    img = np.full((60, 420, 3), 255, np.uint8)
    cv2.putText(img, "Enable syslog forwarding", (60, 35), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 0, 0), 1, cv2.LINE_AA)
    ok, buf = cv2.imencode(".png", img)
    page = ocr.Page(buf.tobytes(), "t")
    assert page.find_all("Enable syslog forwarding", 75)


# --------------------------------------------------------------------------- watch
def test_watch_creates_profile_and_waits_for_evidence(tmp_path):
    cfg = watch.load_config(tmp_path / "config.yaml")
    folder = cfg["inbox"] / "Acme_Industries"
    folder.mkdir()
    assert watch.find_evidence(folder) == {}
    (folder / "Acme SS.docx").write_bytes(b"x")
    (folder / "logs.zip").write_bytes(b"x")
    (folder / "~$Acme SS.docx").write_bytes(b"lock")      # Word lock file must be ignored
    ev = watch.find_evidence(folder)
    assert ev == {"screenshots_docx": "Acme SS.docx", "logs": "logs.zip"}
    prof = watch.ensure_profile(folder, cfg)
    import yaml
    data = yaml.safe_load(prof.read_text())
    assert data["client_name"] == "Acme Industries"
    assert data["check_date"] == "auto" and data["options"]["reader"] == "ocr"


def test_fingerprint_ignores_status_and_lock_files(tmp_path):
    (tmp_path / "a.docx").write_bytes(b"1")
    fp1 = watch.fingerprint(tmp_path)
    (tmp_path / "STATUS.txt").write_text("x")
    (tmp_path / "~$a.docx").write_text("x")
    assert watch.fingerprint(tmp_path) == fp1


def test_resolve_auto_uses_screenshot_date(tmp_path):
    import json
    import yaml
    (tmp_path / "profile.yaml").write_text("# hdr\nclient_name: X\ncheck_date: auto\nquarter: auto\n")
    (tmp_path / "screenshot_cache.json").write_text(json.dumps({"check_date_guess": "2026-10-07"}))
    watch.resolve_auto_fields(tmp_path / "profile.yaml")
    d = yaml.safe_load((tmp_path / "profile.yaml").read_text())
    assert d["check_date"] == "2026-10-07" and d["quarter"] == "Q4 2026"
    assert (tmp_path / "profile.yaml").read_text().startswith("# hdr")
