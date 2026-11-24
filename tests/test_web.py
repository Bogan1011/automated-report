"""Upload website: login, uploads into the inbox, safety checks."""
import io
import zipfile

import pytest
import yaml

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from tmhc.web import app as webapp  # noqa: E402


@pytest.fixture
def site(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    webapp.load_config(cfg_path)
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg["defaults"].update(prepared_by="Analyst", zip_password="secret-pw")
    cfg_path.write_text(yaml.safe_dump(cfg))
    webapp.set_password(cfg_path, "akshay", "correct-horse")
    client = TestClient(webapp.create_app(cfg_path), base_url="http://testserver")
    return client, cfg_path, tmp_path / "inbox"


def _login(client):
    r = client.post("/login", data={"username": "akshay", "password": "correct-horse"}, follow_redirects=False)
    assert r.status_code == 303


def _docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/media/image1.png", b"png")
    return buf.getvalue()


def _logs_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("Logs/Policy_x.cmpolicy", "{}")
        z.writestr("Logs/Apex One Security Agent List.csv", "a,b\n")
    return buf.getvalue()


def test_requires_login(site):
    client, _, _ = site
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = client.post("/login", data={"username": "akshay", "password": "nope"})
    assert "Wrong user name or password" in r.text


def test_upload_creates_client_folder_with_profile(site):
    client, _, inbox = site
    _login(client)
    r = client.post("/new", data={"client_name": "Acme Industries Pvt Ltd", "prepared_by": "Analyst",
                                  "approved_by": "Boss", "report_date": "2026-11-23",
                                  "latest_agent_build": "14.0.20958"},
                    files={"screenshots_docx": ("acme SS.docx", _docx()), "logs_zip": ("logs.zip", _logs_zip())},
                    follow_redirects=False)
    assert r.status_code == 303
    folder = inbox / "Acme Industries Pvt Ltd" / "SEP Q4 2026"     # client folder / product + quarter
    assert r.headers["location"] == "/r/Acme%20Industries%20Pvt%20Ltd/SEP%20Q4%202026"
    assert (folder / ".go").exists()                              # the watcher starts at once
    assert (folder / "acme SS.docx").exists() and (folder / "logs.zip").exists()
    prof = yaml.safe_load((folder / "profile.yaml").read_text())
    assert prof["client_name"] == "Acme Industries Pvt Ltd"
    assert prof["evidence"]["zip_password"] == "secret-pw"      # from server settings, not the form
    assert prof["check_date"] == "auto"
    assert not list(inbox.glob(".incoming-*"))                    # staging folder renamed away
    page = client.get(r.headers["location"]).text
    assert "policy export found" in page and "agent list found" in page


def test_rejects_bad_names_and_types(site):
    client, _, inbox = site
    _login(client)
    r = client.post("/new", data={"client_name": "../../etc", "latest_agent_build": "14.0.1"},
                    files={"logs_zip": ("l.zip", _logs_zip())},
                    follow_redirects=False)
    assert r.status_code == 303
    assert (inbox / "etc").exists() and not (inbox.parent / "etc").exists()
    r = client.post("/new", data={"client_name": "X", "latest_agent_build": "14.0.1"},
                    files={"extra": ("run.sh", b"#!/bin/sh")})
    assert "only .docx" in r.text
    assert client.get("/client/..%2F..").status_code == 404


def test_cross_site_post_blocked(site):
    client, _, _ = site
    _login(client)
    r = client.post("/settings", data={"prepared_by": "x"}, headers={"origin": "http://evil.example"})
    assert r.status_code == 403


def test_settings_keep_zip_password_when_blank(site):
    client, cfg_path, _ = site
    _login(client)
    client.post("/settings", data={"prepared_by": "New Name", "zip_password": ""})
    d = yaml.safe_load(cfg_path.read_text())["defaults"]
    assert d["prepared_by"] == "New Name" and d["zip_password"] == "secret-pw"


def test_safe_name():
    assert webapp.safe_name("  Acme / Industries: <Pvt> Ltd. ") == "Acme Industries Pvt Ltd"
    assert webapp.safe_name("..") == ""


def test_new_check_requires_latest_build(site):
    client, _, inbox = site
    _login(client)
    r = client.post("/new", data={"client_name": "Acme"}, files={"logs_zip": ("l.zip", _logs_zip())})
    assert "latest Apex One agent build" in r.text and not (inbox / "Acme").exists()


def test_settings_latest_build_prefills_form(site):
    client, cfg_path, _ = site
    _login(client)
    client.post("/settings", data={"latest_agent_build": "14.0.20958"})
    assert yaml.safe_load(cfg_path.read_text())["defaults"]["latest_agent_build"] == "14.0.20958"
    assert 'value="14.0.20958"' in client.get("/new").text


# --------------------------------------------------------------------------- clients, progress
def _new(client, name, **extra):
    data = {"client_name": name, "prepared_by": "Analyst", "approved_by": "Boss",
            "account_owner": "Owner A", "latest_agent_build": "14.0.20958", **extra}
    return client.post("/new", data=data, files={"logs_zip": ("logs.zip", _logs_zip())}, follow_redirects=False)


def test_clients_page_groups_reports_by_quarter(site):
    client, _, inbox = site
    _login(client)
    assert _new(client, "Acme Ltd", quarter="Q3 2026").status_code == 303
    assert _new(client, "Acme Ltd", quarter="Q4 2026", account_owner="Owner B").status_code == 303
    assert sorted(p.name for p in (inbox / "Acme Ltd").iterdir()) == ["SEP Q3 2026", "SEP Q4 2026"]
    r = _new(client, "Acme Ltd", quarter="Q4 2026")
    assert "already has a SEP Q4 2026 report" in r.text            # one report per product and quarter
    page = client.get("/clients").text
    assert "Acme Ltd" in page and "2 reports" in page
    detail = client.get("/clients/Acme%20Ltd").text
    assert detail.index("Q4 2026") < detail.index("Q3 2026")       # newest quarter first
    # next quarter's form starts from the client's last report
    form = client.get("/new?product=SEP&client=Acme%20Ltd").text
    assert 'value="Owner B"' in form and 'value="Acme Ltd"' in form
    assert client.get("/client/Acme%20Ltd", follow_redirects=False).headers["location"] == "/clients/Acme%20Ltd"


def test_progress_api_and_activity(site):
    client, _, inbox = site
    _login(client)
    r = _new(client, "Beta Corp", quarter="Q4 2026")
    folder = inbox / "Beta Corp" / "SEP Q4 2026"
    assert client.get("/api/r/Beta%20Corp/SEP%20Q4%202026").json()["status"] == "queued"
    from tmhc import watch
    (folder / ".building").write_text("x")
    watch.Progress(folder)(42, "Reading screenshots (21 of 50)")
    st = client.get("/api/r/Beta%20Corp/SEP%20Q4%202026").json()
    assert st == {"status": "building", "pct": 42, "detail": "Reading screenshots (21 of 50)"}
    act = client.get("/api/activity").json()["active"]
    assert act[0]["client"] == "Beta Corp" and act[0]["pct"] == 42 and act[0]["url"] == r.headers["location"]
    page = client.get(r.headers["location"]).text
    assert 'id="job-progress"' in page and "42%" in page
    assert client.get("/api/r/Beta%20Corp/..%2F..").status_code == 404


def test_api_requires_login(site):
    client, _, _ = site
    assert client.get("/api/activity").status_code == 401


def test_watch_moves_old_single_folder_reports_into_client_folders(tmp_path):
    from tmhc import watch
    cfg = watch.load_config(tmp_path / "config.yaml")
    inbox = cfg["inbox"]
    old = inbox / "Gamma Industries"                              # the old layout: one folder per client
    old.mkdir()
    (old / "shots.docx").write_bytes(b"x")
    (old / "profile.yaml").write_text(yaml.safe_dump({"client_name": "Gamma Industries", "quarter": "Q3 2026",
                                                      "options": {"rules": "swp"}}))
    (old / "output").mkdir()
    (old / "output" / "r.docx").write_bytes(b"x")
    state = {"Gamma Industries": {"fp": {}, "result": "done"}}
    moved = watch.migrate_loose(cfg, state)
    assert moved == [("Gamma Industries", "Gamma Industries/SWP Q3 2026")]
    job = inbox / "Gamma Industries" / "SWP Q3 2026"
    assert (job / "shots.docx").exists() and (job / "output" / "r.docx").exists()
    assert "Gamma Industries/SWP Q3 2026" in state and watch.iter_jobs(inbox) == [job]
    # evidence dropped straight into the client folder becomes another report
    (inbox / "Gamma Industries" / "new.zip").write_bytes(b"x")
    moved = watch.migrate_loose(cfg, state)
    assert len(moved) == 1 and len(watch.iter_jobs(inbox)) == 2
    assert not (inbox / "Gamma Industries" / "new.zip").exists()
