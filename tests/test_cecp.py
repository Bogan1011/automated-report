"""Cloud Email and Collaboration Protection (CECP) report."""
import csv
import io
import zipfile
from pathlib import Path

import docx
import pytest
import yaml

from tmhc.cli import build
from tmhc.engine import derive_cecp
from tmhc.engine.evaluate import evaluate, load_rules
from tmhc.models import Fact, HealthCheck, Source
from tmhc.sources import cecp_exports

ROOT = Path(__file__).resolve().parent.parent
COLS = ["Detected", "Organization", "Scan source", "Security filter", "Threat type", "Security risk / Anomaly name",
        "Detected by", "Affected user", "Triggered policy", "Action", "Subject", "Sender", "Recipient"]


def _result_csv() -> str:
    rows = [
        ["Sep 01, 2026 16:32:51", "Default organization", "OneDrive", "Web Reputation", "Malicious URLs",
         "Disease Vector: [https]:[/][/]bad[.]example[/]x", "Web Reputation", "user1@example.com",
         "Default OneDrive Policy ATP (Monitor Only)", "Pass", "", "", ""],
        ["Sep 07, 2026 11:31:05", "Default organization", "Exchange Online", "Correlated Intelligence", "Phishing",
         "Quishing in PDF", "Correlation rule", "user2@example.com", "Default Exchange Policy ATP", "Pass",
         "Invoice", '"Sender A"<a@sender.example>', '"User Two"<user2@example.com>'],
        ["Sep 29, 2026 14:03:37", "Default organization", "OneDrive", "Web Reputation", "Phishing",
         "Credential Phishing: [http]:[/][/]phish[.]example", "Web Reputation", "user1@example.com",
         "Default OneDrive Policy ATP (Monitor Only)", "Pass", "", "", ""],
        ["Sep 30, 2026 13:58:59", "Default organization", "OneDrive", "Malware Scanning", "Unscannable files/URLs",
         "", "", "user3@example.com", "Default OneDrive Policy ATP (Monitor Only)", "Pass", "", "", ""],
    ]
    for i in range(5):
        rows.append([f"Sep {10 + i:02d}, 2026 09:00:00", "Default organization", "Exchange Online",
                     "Advanced Spam Protection", "Spam/Graymail", "Spam", "Antispam engine", "user4@example.com",
                     "Default Exchange Policy ATP", "Move to Junk Email folder", "Offer",
                     f'"News {i % 2}"<news{i % 2}@shop.example>', '"User Four"<user4@example.com>'])
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(COLS)
    w.writerows(rows)
    return buf.getvalue()


def _logs_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("result.csv", "﻿" + _result_csv())
    return path


def test_detection_metrics_and_sentences(tmp_path):
    (tmp_path / "result.csv").write_text(_result_csv(), encoding="utf-8")
    rows = cecp_exports.read_detections(cecp_exports.find_detection_log(tmp_path))
    m = cecp_exports.detection_metrics(rows)
    # unscannable files are not threats; the period covers the whole month
    assert m["threat_counts"] == {"Malicious URLs": 1, "Phishing": 2, "Spam/Graymail": 5}
    assert m["period_from"] == "01 Sept 2026" and m["period_to"] == "30 Sept 2026"
    ph = m["threats"]["Phishing"]
    assert ph["senders"][0] == ("OneDrive URL Detection", 1) or ("OneDrive URL Detection", 1) in ph["senders"]
    assert cecp_exports.count_sentence("Malicious URLs", m["threats"]["Malicious URLs"], m) == \
        "There was only 1 detection of Malicious URLs detected from 01 Sept 2026 to 30 Sept 2026."
    assert cecp_exports.action_sentence("Spam/Graymail", m["threats"]["Spam/Graymail"]) == \
        "All the detections have been Move to Junk Email Folder."
    assert "currently being passed" in cecp_exports.action_sentence("Phishing", ph)


def test_report_pdf_totals(monkeypatch):
    text = """Reporting period: Sep 01, 2026 00:00:00 - Sep 30, 2026 23:59:59(UTC+07:00)
  Services: Exchange Online, OneDrive, SharePoint Online, Microsoft Teams
                                           Total Items Scanned
        Files/Chats/Records                                                          Emails
                                                 214,909
                                                    Total scans
 187520                 3                                                     27389                  40
 Total scans     | Threats detected                                           Total scans     | Threats detected
                                            Threat Detections
                 0                                      0                                        1
           Ransomware                              Malicious files                          Malicious URLs
                 3                                     39                                        0
               Phishing                                 Spam                                      BEC
Business Email Compromise (BEC)
"""
    monkeypatch.setattr(cecp_exports, "pdf_text", lambda *a, **k: text)
    info = cecp_exports.parse_report_pdf(Path("x.pdf"))
    assert info["total_scans"] == 214909 and info["email_threats"] == 40 and info["files_scans"] == 187520
    assert info["threat_counts"]["Spam/Graymail"] == 39 and info["threat_counts"]["Malicious URLs"] == 1


def _facts(hc: HealthCheck, values: dict) -> None:
    for k, (v, d) in values.items():
        hc.add_fact(Fact(key=k, value=v, display=d, source=Source.SCREENSHOT, confidence=0.9))


def _policy_facts() -> dict:
    vals = {"license.expiry": ("2027-05-01", "01 May 2027"), "license.seats": (200, "200"),
            "license.product": ("Email and Collaboration Security - Core", "Email and Collaboration Security - Core"),
            "cecp.dlp.exo": ("Disabled", "Disabled"), "cecp.dlp.collab": ("Disabled", "Disabled"),
            "exo.name": ("Default Exchange Policy ATP", "Default Exchange Policy ATP"),
            "exo.asp": (True, "Enabled"), "exo.asp.apply": ("Incoming", "Incoming Messages"),
            "exo.wrs": (True, "Enabled"), "exo.wrs.apply": ("Incoming", "Incoming Messages"),
            "exo.va": (True, "Enabled"), "exo.va.apply": ("All", "All Messages"),
            "exo.asp.susp_sender": (False, "Disabled"), "exo.asp.other_signals": (False, "Disabled"),
            "exo.fb": (False, "Disabled"), "exo.fb.type": ("Block Specific Files", "Block Specific Files")}
    for sid, svc in (("exo", "Exchange Online"), ("odb", "OneDrive"), ("spo", "SharePoint Online"),
                     ("teams", "Microsoft Teams")):
        vals[f"cecp.svc.{sid}"] = (True, "Configured")
    for p, svc in (("spo", "SharePoint Online"), ("odb", "OneDrive"), ("teams", "Microsoft Teams")):
        vals[f"{p}.name"] = (f"Default {svc} Policy ATP (Monitor Only", f"Default {svc} Policy ATP (Monitor Only")
        vals[f"{p}.description"] = (True, "Monitor only")
        vals[f"{p}.fb"] = (False, "Disabled")
        vals[f"{p}.va"] = (True, "Enabled")
    vals["teams.ms.pml"] = (False, "Disabled")              # only in one collaboration policy
    return vals


def test_gaps_grouped_exchange_then_collaboration():
    hc = HealthCheck(client_name="Acme", check_date="2026-10-27")
    _facts(hc, _policy_facts())
    derive_cecp.derive(hc)
    assert hc.get("spo.name").display.endswith("(Monitor Only)")         # bracket restored
    assert hc.get("exo.fb.type").display == "N/A"                         # option of a module that is off
    assert hc.get("spo.va.monitor").display == "Enabled"                  # monitor-only policy
    evaluate(hc, load_rules("cecp"))
    srv = [g.text for g in hc.gaps_server]
    assert srv and srv[0].startswith("DLP Policy is not configured")
    texts = [(g.heading, g.text) for g in hc.gaps_policy]
    heads = [t for h, t in texts if h]
    assert heads[0] == "In Exchange Online - Default Exchange Policy ATP:"
    assert heads[1].startswith("In Default SharePoint Online Policy ATP (Monitor Only), Default OneDrive")
    assert heads[2] == "In Default Microsoft Teams Policy ATP (Monitor Only):"
    body = [t for h, t in texts if not h]
    assert body[0].startswith("Advanced Spam Protection and Web Reputation are currently applied only")
    from tmhc.render.docx_report import cecp_findings
    lines = cecp_findings(hc)
    assert lines[0] == ("**TrendAI Email and Collaboration Security - Core** License with **200** units valid "
                        "till  **01 May 2027**.")
    assert "\tPolicy is in Monitor Only Mode." in lines
    assert "\tIn Advanced Spam Protection **Suspicious Senders** and **Other Unusual Signals** are disabled." in lines


def test_cecp_end_to_end_word_and_presentation(tmp_path):
    ev = tmp_path / "evidence"
    ev.mkdir()
    _logs_zip(ev / "logs.zip")
    prof = {"client_name": "Acme Industries Private Limited", "product": "Cloud Email and Collaboration Protection",
            "quarter": "Q4 2026", "check_date": "2026-10-27", "report_date": "2026-11-18",
            "prepared_by": "Analyst", "approved_by": "Boss", "account_owner": "Owner",
            "evidence": {"logs": "evidence/logs.zip"}, "options": {"rules": "cecp", "reader": "none"},
            "manual_facts": {"exo.wrs.toc": {"value": False, "display": "Disabled"}}}
    (tmp_path / "profile.yaml").write_text(yaml.safe_dump(prof))
    hc = build(tmp_path / "profile.yaml")
    out = tmp_path / "output"
    report = out / "Acme_CECP_Health_Check_Report_Nov_2026.docx"
    deck = out / "Acme_CECP_Product_Efficacy_Report_Nov_2026.pptx"
    assert report.exists() and deck.exists(), hc.warnings
    d = docx.Document(str(report))
    text = "\n".join(p.text for p in d.paragraphs)
    assert "We collected logs from 01 Sept 2026 to 30 Sept 2026." in text
    assert "Phishing Detections" in text and "Spam/Graymail Detections" in text
    assert "{{" not in d.element.xml.replace("{{m.", "")                # every placeholder filled
    assert "Health Check on 27 Oct 2026 for Acme Industries Private Limited" in text
    gaps = d.tables[-1]
    assert any("Time of Click is disabled" in c.text for r in gaps.rows for c in r.cells)
    from pptx import Presentation
    prs = Presentation(str(deck))
    titles = [s.shapes.title.text if s.shapes.title else "" for s in prs.slides]
    assert "Phishing Detections:" in titles and "Findings & Recommendations" in titles
    alltext = " ".join(sh.text_frame.text for s in prs.slides for sh in s.shapes if sh.has_text_frame)
    assert "{{" not in alltext


# sha1 (first 16 hex) of client / user / analyst names from the engagements the
# templates were made from - stored hashed so the names never enter the repository
_FORBIDDEN = {"05c9fd6469af424b", "38bdbaa21b372d0c", "39ec20baaeb8cf62", "5e3d95446ca61367",
              "a4e625ecc14b89f9", "a60469a9a1a6110b", "baa6b2d49dee66fe", "c72a5701da7eaf6e",
              "d0cf36281988a7a7", "f2966c061ac0aee2", "fb57bff0c1bde385"}


@pytest.mark.parametrize("name", ["cecp_report_template.docx", "cecp_efficacy_template.pptx",
                                  "swp_report_template.docx", "sep_report_template.docx"])
def test_templates_are_scrubbed(name):
    import hashlib
    import re
    path = ROOT / "tmhc" / "render" / "templates" / name
    with zipfile.ZipFile(path) as z:
        xml = " ".join(z.read(n).decode("utf-8", "ignore") for n in z.namelist() if n.endswith((".xml", ".rels")))
    words = set(re.findall(r"[a-z]{4,}", xml.lower()))
    leaked = [w for w in words if hashlib.sha1(w.encode()).hexdigest()[:16] in _FORBIDDEN]
    assert not leaked


def test_ocr_toggle_switch():
    """A blue pill left of a label reads as on, a grey one as off."""
    pytest.importorskip("cv2")
    import shutil
    if not shutil.which("tesseract"):
        pytest.skip("tesseract not installed")
    from PIL import Image, ImageDraw, ImageFont
    from tmhc.sources import ocr
    im = Image.new("RGB", (700, 160), (27, 27, 27))
    d = ImageDraw.Draw(im)
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 16)
    except OSError:
        font = ImageFont.load_default()
    d.rounded_rectangle((20, 30, 56, 48), 9, fill=(45, 100, 220))
    d.ellipse((40, 32, 54, 46), fill=(255, 255, 255))
    d.text((70, 29), "Graymail Detection", fill=(225, 225, 225), font=font)
    d.rounded_rectangle((20, 100, 56, 118), 9, fill=(120, 120, 120))
    d.ellipse((22, 102, 36, 116), fill=(235, 235, 235))
    d.text((70, 99), "File Blocking", fill=(225, 225, 225), font=font)
    buf = io.BytesIO()
    im.save(buf, "PNG")
    page = ocr.Page(buf.getvalue(), "t.png", scale=2)
    assert ocr._toggle(page, {"label": "Graymail Detection"}, "k")["value"] is True
    assert ocr._toggle(page, {"label": "File Blocking"}, "k")["value"] is False


# ---------------------------------------------------------------- website
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from tmhc.web import app as webapp  # noqa: E402


@pytest.fixture
def site(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    webapp.load_config(cfg_path)
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg["defaults"].update(prepared_by="Analyst", zip_password="")
    cfg_path.write_text(yaml.safe_dump(cfg))
    webapp.set_password(cfg_path, "akshay", "correct-horse")
    client = TestClient(webapp.create_app(cfg_path), base_url="http://testserver")
    client.post("/login", data={"username": "akshay", "password": "correct-horse"})
    return client, cfg_path, tmp_path / "inbox"


def test_cecp_tab_and_upload(site, tmp_path):
    client, _, inbox = site
    assert webapp.product_short("Cloud App Security") == "CECP"
    page = client.get("/new?product=CECP").text
    assert "Cloud Email and Collaboration Protection" in page and "result.csv" in page
    zp = _logs_zip(tmp_path / "l.zip")
    r = client.post("/new", data={"client_name": "Acme Mail", "product": "Cloud Email and Collaboration Protection"},
                    files={"logs_zip": ("logs.zip", zp.read_bytes())}, follow_redirects=False)
    assert r.status_code == 303
    prof = yaml.safe_load((inbox / "Acme Mail" / "profile.yaml").read_text())
    assert prof["options"]["rules"] == "cecp"
    assert "detection log found" in client.get(r.headers["location"]).text
    assert "Acme Mail" in client.get("/?tab=CECP").text and "Acme Mail" not in client.get("/?tab=SEP").text
