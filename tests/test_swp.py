"""Server & Workload Protection: exports, rule pack, Word report, presentation, website tabs."""
import csv
import io
import zipfile
from pathlib import Path

import docx
import pytest
import yaml

from tmhc.cli import build
from tmhc.engine.evaluate import evaluate, load_rules
from tmhc.models import Fact, HealthCheck, Source
from tmhc.sources import ocr, swp_exports

COLS = ["Name", "Platform", "Policy", "Status Light", "Status", "Version", "Component Update Status",
        "Anti-Malware Status Light", "Web Reputation Status Light", "Device Control Status Light",
        "Application Control Status Light", "Firewall Status Light", "Intrusion Prevention Status Light",
        "Integrity Monitoring Status Light", "Log Inspection Status Light"]


def _computers_csv() -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(COLS)
    mods_on = ["Anti-Malware: On, Real Time", "Web Reputation: On", "Device Control: Off, not installed",
               "Application Control: Off, not installed", "Firewall: Off, installed",
               "Intrusion Prevention: On, Prevent", "Integrity Monitoring: On", "Log Inspection: On"]
    rows = [("WIN1", "Microsoft Windows Server 2022 (64 bit)", "Windows_Server", "Managed [Green]",
             "Managed (Online)", "20.0.3.22310", "Up-to-Date"),
            ("WIN2", "Microsoft Windows Server 2019 (64 bit)", "Windows_Server", "Critical [Red]", "Offline",
             "20.0.3.18160", "Out-of-Date"),
            ("LIN1", "Ubuntu Linux 22 (64 bit)", "Linux Server", "Warning [Yellow]", "Insufficient Disk Space",
             "20.0.3.28120", "Unknown"),
            ("ORPHAN", "Ubuntu Linux 24 (64 bit)", "None", "Managed [Green]", "Managed (Online)", "20.0.3.22310",
             "Up-to-Date")]
    for r in rows:
        w.writerow(list(r) + mods_on)
    return buf.getvalue()


POLICY_XML = """<?xml version="1.0" encoding="utf-8"?>
<Export type="SecurityProfile"><SecurityProfiles><SecurityProfile id="7"><Name>Linux Server</Name>
</SecurityProfile></SecurityProfiles>
<SecurityProfileLogInspectionRules><SecurityProfileLogInspectionRule id="1"/></SecurityProfileLogInspectionRules>
<AdvancedSettings><SecurityProfileSettings id="7">
<Setting name="settings.configuration.agentHardening" value="false"/>
</SecurityProfileSettings></AdvancedSettings></Export>"""

IPS_CSV = ("Time,Computer,Reason,Action,Direction,Source IP,Destination IP\n"
           + "".join(f"\"Oct 1, 2026\",WIN1,Invalid Traversal,Reset,Incoming,10.0.0.{i % 3},10.1.0.1\n"
                     for i in range(6))
           + "\"Oct 1, 2026\",LIN1,1011242 - Apache Log4j RCE (CVE-2021-44228),Reset,Incoming,10.0.0.9,10.1.0.2\n")
LI_CSV = ("Time,Computer,Reason,Description\n"
          + "".join(f"\"Oct 1, 2026\",WIN{1 + i % 2},1003802 - Directory Server - Microsoft Windows Active Directory,"
                    f"Pre-authentication failed.\n" for i in range(5))
          + "\"Oct 1, 2026\",LIN1,1002831 - Unix - Syslog,Dpkg removed\n")


def _logs_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("SWP Logs/Computers.csv", _computers_csv())
        z.writestr("SWP Logs/Linux Policy.xml", POLICY_XML)
        z.writestr("SWP Logs/Intrusion_Prevention_Events.csv", IPS_CSV)
        z.writestr("SWP Logs/Log_Inspection_Events.csv", LI_CSV)
        z.writestr("SWP Logs/File_Extension_Lists.csv",
                   "Icon,Name,Description,File Extension(s),Rights\n,Exclusion List,,\"EXE, DOC, ZIP\",View-Only\n")
    return path


def test_computers_facts(tmp_path):
    p = tmp_path / "Computers.csv"
    p.write_text(_computers_csv())
    facts, m, _ = swp_exports.computers_facts(p, "20.0.3.29020", "20.0.3.28120", "2026-10-07")
    f = {x.key: x for x in facts}
    assert m["deployed_agents"] == 4 and m["critical"] == 1 and m["warning"] == 1 and m["managed"] == 2
    assert m["without_policy"] == 1
    assert m["critical_line"] == "1 Critical agents: Offline"
    assert m["outdated_agents"] == 3                       # LIN1 already runs the latest Linux build
    assert f["swp.inventory.deployed"].display.startswith("4 Agents (dated 07-10-26)")
    assert f["win.mod.fw"].display == "Licensed | Disabled" and f["win.ips.behavior"].value == "Prevent"


def test_policy_xml_only_explicit_values(tmp_path):
    p = tmp_path / "Linux Policy.xml"
    p.write_text(POLICY_XML)
    facts, info = swp_exports.policy_facts(p)
    f = {x.key: x for x in facts}
    assert f["lin.self_protection"].display == "Disabled"
    assert f["lin.li.rules"].display == "Configured (1 rules)"
    assert "lin.cpu_control" not in f                       # inherited -> left to the screenshots


def test_policy_gaps_grouped_both_and_only():
    hc = HealthCheck(check_date="2026-10-07")
    for p in ("win", "lin"):
        hc.add_fact(Fact(f"{p}.mod.ac", False, "Licensed | Disabled", Source.AGENT_LIST))
    hc.add_fact(Fact("lin.self_protection", False, "Disabled", Source.POLICY_EXPORT))
    hc.add_fact(Fact("win.self_protection", True, "Enabled", Source.SCREENSHOT))
    hc.metrics.update(win_policy_name="Windows_Server", lin_policy_name="Linux Server")
    evaluate(hc, load_rules("swp"))
    texts = [(g.heading, g.text) for g in hc.gaps_policy]
    assert texts[0] == (True, "In Both Windows_Server & Linux Server Policy")
    assert texts[1][1].startswith("Application Control module is disabled")
    assert (True, "In Linux Server only") in texts
    assert not any(t == "In Windows_Server only" for _, t in texts)
    assert texts[-1][1].startswith("In General Setting, Agent Self Protection")


def test_ocr_dropdown_value_cleanup():
    assert ocr._clean_value("Inherited (Unlimited) v") == "Unlimited"
    assert ocr._clean_value("Inhented (Low)") == "Low"
    assert ocr._clean_value("Quarantine (recommended)") == "Quarantine"


def test_swp_end_to_end_word_and_presentation(tmp_path):
    ev = tmp_path / "evidence"
    ev.mkdir()
    _logs_zip(ev / "logs.zip")
    prof = {"client_name": "Acme Industries Private Limited", "product": "Server & Workload Protection",
            "quarter": "Q4 2026", "check_date": "2026-10-07", "report_date": "2026-10-27",
            "prepared_by": "Analyst", "approved_by": "Boss", "account_owner": "Owner",
            "latest_dsa_windows": "20.0.3.29020", "latest_dsa_linux": "20.0.3.28120",
            "evidence": {"logs": "evidence/logs.zip"}, "options": {"rules": "swp", "reader": "none"}}
    (tmp_path / "profile.yaml").write_text(yaml.safe_dump(prof))
    hc = build(tmp_path / "profile.yaml")
    out = tmp_path / "output"
    report = out / "Acme_SWP_Health_Check_Report_Oct_2026.docx"
    deck = out / "Acme_SWP_Product_Efficacy_Report_Oct_2026.pptx"
    assert report.exists() and deck.exists(), hc.warnings
    d = docx.Document(str(report))
    text = "\n".join(p.text for p in d.paragraphs)
    assert "1 Critical agents: Offline" in text and "Kindly remove .exe, .zip extension" in text
    assert "07th Oct 2026" in text
    findings = d.tables[1].rows[1].cells[-1].text
    assert "1 Computers are without policy." in findings
    from pptx import Presentation
    prs = Presentation(str(deck))
    titles = [s.shapes.title.text if s.shapes.title else "" for s in prs.slides]
    assert any("Log Inspection" in t for t in titles) and any("Intrusion Prevention" in t for t in titles)
    alltext = " ".join(sh.text_frame.text for s in prs.slides for sh in s.shapes if sh.has_text_frame)
    assert "{{" not in alltext and "Apache Log4j" in alltext
    charts = sum(1 for s in prs.slides for sh in s.shapes if getattr(sh, "has_chart", False) and sh.has_chart)
    assert charts >= 5


def test_presentation_templates_are_scrubbed():
    """Templates keep one prototype per slide kind, a logo placeholder and no revision history."""
    from pptx import Presentation
    root = Path(__file__).resolve().parent.parent / "tmhc" / "render" / "templates"
    for name in ("sep_efficacy_template.pptx", "swp_efficacy_template.pptx"):
        prs = Presentation(str(root / name))
        assert prs.core_properties.keywords.startswith("tmhc-efficacy:")
        assert any(sh.name == "CLIENT_LOGO" for sh in prs.slides[0].shapes)
        with zipfile.ZipFile(root / name) as z:
            assert not [n for n in z.namelist() if "changesInfo" in n or "comments/" in n]


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


def test_tabs_and_swp_upload(site, tmp_path):
    client, cfg_path, inbox = site
    client.post("/settings", data={"latest_dsa_windows": "20.0.3.29020", "latest_dsa_linux": "20.0.3.28120"})
    d = yaml.safe_load(cfg_path.read_text())["defaults"]
    assert d["latest_dsa_windows"] == "20.0.3.29020" and d["latest_dsa_linux_updated"]
    page = client.get("/new?product=SWP").text
    assert "Server &amp; Workload Protection" in page and 'value="20.0.3.29020"' in page
    zp = _logs_zip(tmp_path / "l.zip")
    r = client.post("/new", data={"client_name": "Acme Servers", "product": "Server & Workload Protection",
                                  "latest_dsa_windows": "20.0.3.29020", "latest_dsa_linux": "20.0.3.28120"},
                    files={"logs_zip": ("logs.zip", zp.read_bytes())}, follow_redirects=False)
    assert r.status_code == 303
    prof = yaml.safe_load((inbox / "Acme Servers" / "profile.yaml").read_text())
    assert prof["options"]["rules"] == "swp" and prof["latest_dsa_linux"] == "20.0.3.28120"
    assert "Computers.csv found" in client.get(r.headers["location"]).text
    swp_tab = client.get("/?tab=SWP").text
    sep_tab = client.get("/?tab=SEP").text
    assert "Acme Servers" in swp_tab and "Acme Servers" not in sep_tab


def test_swp_requires_both_builds(site, tmp_path):
    client, _, inbox = site
    r = client.post("/new", data={"client_name": "NoBuild", "product": "Server & Workload Protection",
                                  "latest_dsa_windows": "20.0.3.29020"},
                    files={"logs_zip": ("logs.zip", _logs_zip(tmp_path / "x.zip").read_bytes())})
    assert "latest Linux agent build" in r.text and not (inbox / "NoBuild").exists()


# ---------------------------------------------------------------- latest builds from Trend Micro
def _fake_fetch(pages):
    def fetch(url):
        return pages.get(url)
    return fetch


def test_latest_builds_lookup_and_manual_override(tmp_path):
    import datetime as dt
    from tmhc import latest_builds as lb
    pages = {
        lb.SEP_README.format(ym="202610"): "<p><b>Security Agent version:</b> 14.0.0.21067</p>"
                                           "<p>Security Agent Version: 3.5.9000</p>",
        lb.SEP_README.format(ym="202609"): "Security Agent version: 14.0.20958",
        lb.DSA_NOTES: "<h3>Deep Security Agent - 20.0.3-31610</h3><p>Build number: 20.0.3-31610</p>"
                      "<p>Build number: 20.0.3-28120</p>",
    }
    found = lb.check(_fake_fetch(pages), today=dt.date(2026, 11, 23))
    assert found["latest_agent_build"][0] == "14.0.21067"
    assert found["latest_dsa_windows"][0] == "20.0.3.31610" == found["latest_dsa_linux"][0]

    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump({"inbox": str(tmp_path), "defaults": {
        "latest_agent_build": "14.0.20958", "latest_dsa_linux": "20.0.3.99999", "latest_dsa_linux_manual": True}}))
    real_check = lb.check
    lb.check = lambda fetch=None, today=None: real_check(_fake_fetch(pages), dt.date(2026, 11, 23))
    try:
        changed = lb.run_scheduled(cfg, log=lambda *_: None)
        d = yaml.safe_load(cfg.read_text())["defaults"]
        assert d["latest_agent_build"] == "14.0.21067" and d["latest_dsa_windows"] == "20.0.3.31610"
        assert d["latest_dsa_linux"] == "20.0.3.99999"              # manual value kept
        assert "latest_agent_build" in changed and d["latest_builds"]["checked"]
        assert lb.run_scheduled(cfg, log=lambda *_: None) == {}     # checked today: not again
        lb.request_check(cfg)                                         # button on the website
        assert (tmp_path / lb.REQUEST_FILE).exists()
        lb.run_scheduled(cfg, log=lambda *_: None)
        assert not (tmp_path / lb.REQUEST_FILE).exists()
    finally:
        lb.check = real_check


def test_settings_manual_and_auto_builds(site):
    client, cfg_path, _ = site
    client.post("/settings", data={"latest_agent_build": "14.0.20000"})
    d = yaml.safe_load(cfg_path.read_text())["defaults"]
    assert d["latest_agent_build"] == "14.0.20000" and d["latest_agent_build_manual"] is True
    assert "set manually" in client.get("/settings").text
    client.post("/settings", data={"latest_agent_build": "14.0.20000", "auto_latest_agent_build": "1"})
    d = yaml.safe_load(cfg_path.read_text())["defaults"]
    assert not d["latest_agent_build_manual"]
    assert (cfg_path.parent / ".check_builds").exists()               # the timer job checks Trend now
    r = client.post("/settings/check-builds", follow_redirects=False)
    assert r.status_code == 303 and "checked=1" in r.headers["location"]
