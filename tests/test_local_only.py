"""Privacy guarantees: local by default, cloud only on explicit opt-in."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from openpyxl import load_workbook

from tmhc import checklist
from tmhc.engine.evaluate import load_rules
from tmhc.models import Source
from tmhc.sources import screenshots as s


# --------------------------------------------------------------------------- guards
def test_cloud_refused_without_opt_in():
    with pytest.raises(s.CloudNotAllowed):
        s.make_reader({"reader": "cloud"})


def test_cloud_refused_even_if_key_set(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    with pytest.raises(s.CloudNotAllowed):
        s.make_reader({"reader": "cloud", "allow_cloud": False})


@pytest.mark.parametrize("host", ["http://10.0.0.5:11434", "https://ollama.example.com", "http://api.someai.com"])
def test_local_reader_refuses_non_local_hosts(host):
    with pytest.raises(s.CloudNotAllowed):
        s.make_reader({"reader": "local", "ollama_host": host})


def test_local_reader_accepts_localhost_variants():
    for host in ("http://127.0.0.1:11434", "localhost:11434", "http://localhost:11434"):
        assert s.make_reader({"reader": "local", "ollama_host": host}).name == "local"


def test_remote_lan_host_needs_explicit_flag():
    r = s.make_reader({"reader": "local", "ollama_host": "http://10.0.0.5:11434", "allow_remote_host": True})
    assert r.name == "local"


def test_default_reader_is_local():
    assert s.make_reader({}).name == "local"


# --------------------------------------------------------------------------- fake Ollama
class _FakeOllama(BaseHTTPRequestHandler):
    calls: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps({"models": [{"name": "qwen2.5vl:7b"}]}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _FakeOllama.calls.append(req)
        assert req["messages"][1]["images"], "image must be sent inline to the local model"
        answer = {"page": "Syslog Settings", "fields": [
            {"key": "admin.syslog", "value": False, "display": "Not Configured", "confidence": 0.9,
             "quote": "[ ] Enable syslog forwarding"},
            {"key": "made.up.key", "value": True, "display": "x", "confidence": 1.0},
        ]}
        body = json.dumps({"message": {"content": json.dumps(answer)}}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def ollama():
    srv = HTTPServer(("127.0.0.1", 0), _FakeOllama)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _FakeOllama.calls.clear()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_local_reader_end_to_end(ollama):
    r = s.make_reader({"reader": "local", "ollama_host": ollama})
    r.check()
    shot = s.Shot(1, "Syslog", "media/image45.png", b"\x89PNG fake")
    out = r.read(shot, {"admin.syslog": {"label": "Enable Syslog forwarding", "type": "bool", "vocab": None}})
    assert [f["key"] for f in out["fields"]] == ["admin.syslog"]       # invented keys dropped
    assert _FakeOllama.calls[0]["options"]["temperature"] == 0


def test_local_reader_missing_model_message(ollama):
    r = s.make_reader({"reader": "local", "ollama_host": ollama, "local_model": "llava:13b"})
    with pytest.raises(s.LocalModelUnavailable, match="ollama pull llava:13b"):
        r.check()


def test_local_reader_no_ollama_running():
    r = s.make_reader({"reader": "local", "ollama_host": "http://127.0.0.1:9"})
    with pytest.raises(s.LocalModelUnavailable, match="checklist"):
        r.check()


# --------------------------------------------------------------------------- checklist
def test_checklist_round_trip(tmp_path):
    cat = s.field_catalogue(load_rules())
    covered = {k for k in cat if k.startswith("policy.")}
    path = checklist.write(tmp_path / "c.xlsx", cat, covered, client="Acme")
    wb = load_workbook(path)
    ws = wb["Checklist"]
    keys = [r[0] for r in ws.iter_rows(min_row=2, values_only=True)]
    assert keys and not any(k.startswith("policy.") for k in keys)
    answers = {"global.scan_cookies": "Disabled", "admin.inactive_agent_removal": "Enabled (30 Days)",
               "admin.schedule_update": "12 hours", "license.expiry": "2028-04-09", "license.seats": "914"}
    for row in ws.iter_rows(min_row=2):
        if row[0].value in answers:
            row[4].value = answers[row[0].value]
    wb.save(path)

    facts = {f.key: f for f in checklist.read(path, cat)}
    assert set(facts) == set(answers)                       # blank rows ignored
    assert facts["global.scan_cookies"].value is False
    assert facts["admin.inactive_agent_removal"].value is True
    assert facts["license.seats"].value == 914
    assert facts["license.expiry"].display == "09 April 2028"
    assert all(f.source == Source.MANUAL for f in facts.values())
