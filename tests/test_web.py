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
                                  "approved_by": "Boss", "report_date": "2026-11-23"},
                    files={"screenshots_docx": ("acme SS.docx", _docx()), "logs_zip": ("logs.zip", _logs_zip())},
                    follow_redirects=False)
    assert r.status_code == 303
    folder = inbox / "Acme Industries Pvt Ltd"
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
    r = client.post("/new", data={"client_name": "../../etc"}, files={"logs_zip": ("l.zip", _logs_zip())},
                    follow_redirects=False)
    assert r.status_code == 303
    assert (inbox / "etc").exists() and not (inbox.parent / "etc").exists()
    r = client.post("/new", data={"client_name": "X"}, files={"extra": ("run.sh", b"#!/bin/sh")})
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
