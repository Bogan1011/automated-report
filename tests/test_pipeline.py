import json
import re

import docx
import pytest

from tmhc.engine.evaluate import load_rules, evaluate, run_check, status_counts, NOT_CAPTURED
from tmhc.models import Fact, HealthCheck, Source, Status
from tmhc.render.docx_report import render
from tmhc.sources import agentlist, policy, screenshots, v1logs


# --------------------------------------------------------------------------- sources
def test_policy_export_maps_settings(cmpolicy):
    facts, pol = policy.extract(cmpolicy)
    f = {x.key: x for x in facts}
    assert pol.name == "Acme Windows"
    assert f["policy.realtime.files_to_scan"].value == "intelliscan"
    assert f["policy.scheduled.files_to_scan"].value == "all"
    assert f["policy.realtime.compressed_max_size"].display == "10 MB"
    assert f["policy.realtime.advanced_malware_detection"].value == "activeaction"
    assert f["policy.dynamic_intelligence_mode"].value is False
    assert f["policy.scheduled.schedule"].display == "Weekly (Friday)"
    assert f["policy.scheduled.resume_missed"].value is True
    assert f["policy.scheduled.resume_interrupted"].value is False
    assert f["policy.bm.event_monitoring"].value is False
    assert f["policy.wr.security_level"].display == "Medium"          # "2" given as a string
    assert f["policy.wr.check_https_off_for"].display == "internal agents"
    assert f["policy.vp.enabled"].value is False
    assert f["policy.ac.enabled"].value is False
    assert f["policy.svc.firewall"].value == (True, False)
    assert all(x.source == Source.POLICY_EXPORT for x in facts)


def test_agent_list_metrics(agent_list):
    _, m = agentlist.extract(agent_list, stale_releases=12)
    assert m["deployed_agents"] == 18
    assert (m["online"], m["offline"]) == (15, 3)
    assert m["latest_build"] == "14.0.20958"
    assert m["outdated_agents"] == 8
    assert m["builds_behind_n3"] == 2          # only 14.0.14320 is older than N-3 (20524)
    assert m["restart_required"] == 2
    assert m["server_agents"] == 2
    assert m["stale_pattern_agents"] == 3      # 1 x 21.349 + 2 x 20.871


def test_utf16_log_export(tmp_path):
    text = "#\tGenerated\tHost\n1\t\"10/06/2026\"\t\"PC1\"\n2\t\"10/07/2026\"\t\"PC2\"\n"
    (tmp_path / "VM 30 days.csv").write_bytes(text.encode("utf-16"))
    (tmp_path / "RT dir.csv").write_text("Scan Exclusion List (Directories)\nC:\\App\n", encoding="utf-8-sig")
    facts, m = v1logs.extract_dir(tmp_path)
    assert m["logs.virus_malware"] == 2
    assert m["exclusions.realtime.dirs"] == 1


# --------------------------------------------------------------------------- engine
def _hc(**facts) -> HealthCheck:
    hc = HealthCheck(client_name="Acme", check_date="2026-10-07", policy_name="Acme Windows")
    for k, v in facts.items():
        value, display = v if isinstance(v, tuple) else (v, str(v))
        hc.add_fact(Fact(k, value, display, Source.MANUAL))
    return hc


@pytest.mark.parametrize("check,value,display,expected", [
    ("enabled", True, "Enabled", True),
    ("enabled", (True, False), "", False),
    ("first_enabled", (True, False), "", True),
    ({"equals": "30 seconds"}, "30 Seconds", "", True),
    ({"in": ["1 hour", "hourly"]}, "12 hours", "", False),
    ("zero", 0, "0", True),
    ({"offline_ratio": 0.05}, (95, 5), "", True),
    ({"offline_ratio": 0.05}, (90, 10), "", False),
    ("date_future", "2028-04-09", "", True),
    ("date_future", "2025-01-01", "", False),
    ("info", True, "", None),
])
def test_checks(check, value, display, expected):
    hc = _hc()
    assert run_check(check, Fact("k", value, display, Source.MANUAL), hc) is expected


def test_precedence_policy_export_beats_screenshot():
    hc = HealthCheck()
    hc.add_fact(Fact("policy.vp.enabled", False, "Disabled", Source.POLICY_EXPORT))
    hc.add_fact(Fact("policy.vp.enabled", True, "Enabled", Source.SCREENSHOT, confidence=0.99))
    assert hc.get("policy.vp.enabled").value is False
    hc.add_fact(Fact("policy.vp.enabled", True, "Enabled", Source.MANUAL))
    assert hc.get("policy.vp.enabled").value is True


def test_evaluate_marks_missing_as_unknown_and_raises_gaps(cmpolicy, agent_list):
    hc = _hc()
    facts, pol = policy.extract(cmpolicy)
    hc.add_facts(facts)
    f, m = agentlist.extract(agent_list)
    hc.add_facts(f)
    hc.metrics.update(m)
    evaluate(hc, load_rules())

    rows = {r.key: r for r in hc.rows_server + hc.rows_policy if r.key}
    assert rows["global.scan_cookies"].status == Status.UNKNOWN
    assert rows["global.scan_cookies"].deployed == NOT_CAPTURED
    assert rows["policy.vp.enabled"].status == Status.CRITICAL

    policy_gaps = " ".join(g.text for g in hc.gaps_policy)
    assert "Dynamic Intelligence Mode is disabled" in policy_gaps
    assert "Check HTTPS URLs is disabled for internal agents" in policy_gaps
    assert "In Real-Time and Scheduled Settings, Advanced malware Detection" in policy_gaps
    # missing data must never produce a gap
    assert not any("cookie" in g.text.lower() for g in hc.gaps_server)
    server_gaps = " ".join(g.text for g in hc.gaps_server)
    assert "8 Agents have outdated Program versions" in server_gaps


def test_gap_text_with_braces_in_values_is_safe():
    hc = _hc(**{"admin.schedule_update": ("{weird}", "{weird} hours")})
    evaluate(hc, load_rules())
    assert any("{weird} hours" in g.text for g in hc.gaps_server)


# --------------------------------------------------------------------------- screenshots
def test_prompt_never_closes_vocabulary_for_pass_values():
    cat = screenshots.field_catalogue(load_rules())
    assert cat["admin.schedule_update"]["vocab"] is None          # 12 hours must stay answerable
    assert cat["policy.realtime.files_to_scan"]["vocab"] == ["all", "intelliscan", "extlist"]
    fields = screenshots.fields_for_section("Schedule update", cat)
    assert set(fields) == {"admin.schedule_update", "admin.deployment_plan"}


def test_cache_filters_low_confidence(tmp_path):
    p = tmp_path / "cache.json"
    p.write_text(json.dumps({"version": 1, "images": {"abc": {"file": "image1.png", "section": "AD",
        "fields": [{"key": "admin.ad_sync", "value": False, "display": "Not Configured", "confidence": 0.9},
                   {"key": "admin.syslog", "value": True, "display": "Enabled", "confidence": 0.3}]}}}))
    facts = screenshots.ShotCache(p).facts(min_confidence=0.6)
    assert [f.key for f in facts] == ["admin.ad_sync"]
    assert facts[0].source == Source.SCREENSHOT


def test_parse_fenced_json():
    assert screenshots._parse_json('```json\n{"page": "x", "fields": []}\n```')["page"] == "x"


# --------------------------------------------------------------------------- render
def test_render_fills_every_placeholder(tmp_path, cmpolicy, agent_list):
    hc = _hc(**{"license.expiry": ("2028-04-09", "09 April 2028"), "license.seats": (20, "20")})
    hc.add_facts(policy.extract(cmpolicy)[0])
    f, m = agentlist.extract(agent_list)
    hc.add_facts(f)
    hc.metrics.update(m)
    hc.prepared_by, hc.quarter, hc.report_date = "Analyst", "Q4 2026", "28/10/2026"
    evaluate(hc, load_rules())
    out = render(hc, tmp_path / "r.docx")

    d = docx.Document(str(out))
    xml = d.element.xml
    assert not re.findall(r"\{\{[a-zA-Z_]+\}\}", xml)
    assert "Acme" in xml
    gap_tables = [t for t in d.tables if t.rows[0].cells[0].text.strip() == "#"]
    assert len(gap_tables) == 2
    assert len(gap_tables[1].rows) - 1 == len(hc.gaps_policy)


# --------------------------------------------------------------------------- analyst-layout template
def test_template_keeps_analyst_tables_row_for_row():
    from tmhc.render.docx_report import DEFAULT_TEMPLATE
    xml = docx.Document(str(DEFAULT_TEMPLATE)).element.xml
    assert "{{SERVER_TABLE}}" not in xml and "{{POLICY_TABLE}}" not in xml
    assert len(re.findall(r"\{\{=[A-Za-z0-9_.]+\}\}", xml)) == 39 + 168
    assert "{{m.license_seats}}" in xml and "{{m.latest_build}}" in xml


def test_render_fills_every_token(tmp_path, cmpolicy, agent_list):
    hc = _hc(**{"license.expiry": ("2028-04-09", "09 April 2028"), "license.seats": (20, "20")})
    hc.add_facts(policy.extract(cmpolicy)[0])
    f, m = agentlist.extract(agent_list)
    hc.add_facts(f)
    hc.metrics.update(m)
    evaluate(hc, load_rules())
    out = render(hc, tmp_path / "r.docx")
    xml = docx.Document(str(out)).element.xml
    assert not re.findall(r"\{\{[=?]", xml)
    assert "Purchased Seat count - 20" in xml
    assert "Not captured" in xml            # synthetic policy lacks many settings: shown, not guessed


def test_checklist_sync_keeps_answers_and_adds_new_rows(tmp_path):
    from tmhc import checklist
    cat = screenshots.field_catalogue(load_rules())
    p = tmp_path / "c.xlsx"
    some = [k for k in cat if k.startswith("global.")][:3]
    checklist.write(p, {k: cat[k] for k in some}, covered=set())
    from openpyxl import load_workbook
    wb = load_workbook(p)
    wb["Checklist"].cell(row=2, column=5, value="Disabled")
    wb.save(p)
    assert checklist.sync(p, cat, covered=set()) is True            # new settings added
    vals = checklist.read_values(p)
    assert vals[some[0]]["deployed"] == "Disabled"                    # answer kept
    assert len(vals) == len(checklist.wanted_keys(cat, set()))
    assert checklist.sync(p, cat, covered=set()) is False           # nothing changed -> no rewrite
