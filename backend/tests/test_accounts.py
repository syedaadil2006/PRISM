"""Named accounts, roles, sessions, sign-in lockout, the audit log and security headers."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.db import Database
from app.main import create_app

CODE = "test-code-123"
ADMIN = {"X-PRISM-Token": CODE}
PASSWORD = "correct horse battery"


@pytest.fixture()
def app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("PRISM_AUTH_ENABLED", "true")
    monkeypatch.setenv("PRISM_AUTH_TOKEN", CODE)
    monkeypatch.setenv("PRISM_AUTH_DB_URL", str(tmp_path / "security.db"))
    monkeypatch.setenv("PRISM_AUTH_MAX_FAILED_LOGINS", "3")
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application):
        yield application
    get_settings.cache_clear()


def _client(app) -> TestClient:
    return TestClient(app)


def _make(app, username: str, role: str) -> None:
    response = _client(app).post("/api/admin/users", headers=ADMIN,
                                 json={"username": username, "password": PASSWORD, "role": role})
    assert response.status_code == 201, response.text


def _signed_in(app, username: str, password: str = PASSWORD) -> TestClient:
    client = _client(app)
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return client


def test_password_sign_in_and_status(app):
    _make(app, "asha", "analyst")
    client = _signed_in(app, "asha")
    status = client.get("/api/auth/status").json()
    assert (status["user"], status["role"], status["kind"]) == ("asha", "analyst", "user")
    cookie = client.cookies.get("prism_session")
    assert cookie.startswith("s.") and cookie != CODE
    assert client.get("/api/stats").status_code == 200
    client.post("/api/auth/logout")
    client.cookies.set("prism_session", cookie)  # the old cookie no longer works
    assert client.get("/api/stats").status_code == 401


def test_wrong_password_and_unknown_user_look_the_same(app):
    _make(app, "asha", "analyst")
    bad = _client(app).post("/api/auth/login", json={"username": "asha", "password": "wrong password!!"})
    unknown = _client(app).post("/api/auth/login", json={"username": "nobody", "password": "wrong password!!"})
    assert bad.status_code == unknown.status_code == 401
    assert bad.json() == unknown.json()


def test_roles_are_enforced(app):
    _make(app, "vic", "viewer")
    _make(app, "asha", "analyst")
    viewer, analyst = _signed_in(app, "vic"), _signed_in(app, "asha")

    assert viewer.get("/api/attacks").status_code == 200
    assert viewer.post("/api/simulation/reset").status_code == 403
    assert viewer.get("/api/admin/users").status_code == 403

    assert analyst.post("/api/simulation/reset").status_code == 200
    assert analyst.post("/api/logs/reset").status_code == 403  # clearing data needs an admin
    assert analyst.get("/api/admin/audit").status_code == 403
    assert analyst.post("/api/admin/users", json={"username": "x-y", "password": PASSWORD}).status_code == 403


def test_account_rules(app):
    client = _client(app)
    weak = client.post("/api/admin/users", headers=ADMIN, json={"username": "bob", "password": "short"})
    assert weak.status_code == 400 and "12 characters" in weak.json()["detail"]
    assert client.post("/api/admin/users", headers=ADMIN,
                       json={"username": "Bad Name!", "password": PASSWORD}).status_code == 400
    assert client.post("/api/admin/users", headers=ADMIN,
                       json={"username": "bob", "password": PASSWORD, "role": "root"}).status_code == 400
    _make(app, "bob", "analyst")
    assert client.post("/api/admin/users", headers=ADMIN,
                       json={"username": "bob", "password": PASSWORD}).status_code == 400
    stored = Database(str(Path(get_settings().auth.db_url))).execute("SELECT password_hash FROM users")
    assert stored[0][0].startswith("scrypt$") and PASSWORD not in stored[0][0]


def test_disabling_or_changing_role_ends_sessions(app):
    _make(app, "asha", "analyst")
    client = _signed_in(app, "asha")
    assert _client(app).patch("/api/admin/users/asha", headers=ADMIN, json={"role": "viewer"}).status_code == 200
    assert client.get("/api/stats").status_code == 401
    client = _signed_in(app, "asha")
    assert client.get("/api/auth/status").json()["role"] == "viewer"
    _client(app).patch("/api/admin/users/asha", headers=ADMIN, json={"disabled": True})
    assert client.get("/api/stats").status_code == 401
    assert _client(app).post("/api/auth/login", json={"username": "asha", "password": PASSWORD}).status_code == 401


def test_admins_cannot_lock_themselves_out(app):
    _make(app, "root-admin", "admin")
    admin = _signed_in(app, "root-admin")
    assert admin.patch("/api/admin/users/root-admin", json={"role": "viewer"}).status_code == 409
    assert admin.patch("/api/admin/users/root-admin", json={"disabled": True}).status_code == 409
    assert admin.delete("/api/admin/users/root-admin").status_code == 409
    _make(app, "temp", "viewer")
    assert admin.delete("/api/admin/users/temp").status_code == 204
    assert admin.delete("/api/admin/users/temp").status_code == 404


def test_password_change(app):
    _make(app, "asha", "analyst")
    client = _signed_in(app, "asha")
    other = _signed_in(app, "asha")
    assert client.post("/api/auth/password", json={"current_password": "nope nope nope",
                                                   "new_password": "another long one"}).status_code == 401
    response = client.post("/api/auth/password", json={"current_password": PASSWORD,
                                                       "new_password": "another long one"})
    assert response.status_code == 200
    assert client.get("/api/stats").status_code == 200  # this browser gets a fresh session
    assert other.get("/api/stats").status_code == 401  # other sessions end
    _signed_in(app, "asha", "another long one")


def test_repeated_failures_lock_the_account(app):
    _make(app, "asha", "analyst")
    client = _client(app)
    for _ in range(3):
        assert client.post("/api/auth/login", json={"username": "asha", "password": "wrong password!!"}).status_code == 401
    locked = client.post("/api/auth/login", json={"username": "asha", "password": PASSWORD})
    assert locked.status_code == 429 and "Try again" in locked.json()["detail"]


def test_access_code_can_be_switched_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("PRISM_AUTH_ENABLED", "true")
    monkeypatch.setenv("PRISM_AUTH_TOKEN", CODE)
    monkeypatch.setenv("PRISM_AUTH_DB_URL", str(tmp_path / "security.db"))
    monkeypatch.setenv("PRISM_AUTH_ACCESS_CODE_ENABLED", "false")
    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as client:
            assert client.get("/api/stats", headers=ADMIN).status_code == 401
            assert client.post("/api/auth/login", json={"token": CODE}).status_code == 401
            assert client.get("/api/auth/status").json()["access_code"] is False
    finally:
        get_settings.cache_clear()


def test_audit_log_records_actions_and_detects_tampering(app):
    _make(app, "asha", "analyst")
    _make(app, "vic", "viewer")
    _client(app).post("/api/auth/login", json={"username": "asha", "password": "wrong password!!"})
    analyst, viewer = _signed_in(app, "asha"), _signed_in(app, "vic")
    analyst.post("/api/simulation/reset")
    viewer.post("/api/simulation/reset")  # refused, and recorded

    entries = _client(app).get("/api/admin/audit", headers=ADMIN, params={"limit": 50}).json()
    seen = {(e["actor"], e["action"], e["outcome"]) for e in entries}
    assert ("access-code", "create user", "success") in seen
    assert ("asha", "login", "failed") in seen and ("asha", "login", "success") in seen
    assert ("asha", "POST /api/simulation/reset", "success") in seen
    assert ("vic", "POST /api/simulation/reset", "denied") in seen
    assert all(e["address"] for e in entries)

    check = _client(app).get("/api/admin/audit/verify", headers=ADMIN).json()
    assert check["ok"] is True and check["entries"] == len(entries)

    db = Database(str(Path(get_settings().auth.db_url)))
    db.execute("UPDATE audit SET actor = 'someone-else' WHERE seq = 3")
    check = _client(app).get("/api/admin/audit/verify", headers=ADMIN).json()
    assert (check["ok"], check["first_broken"], check["reason"]) == (False, 3, "entry was changed")


def test_security_headers(app):
    response = _client(app).get("/api/health")
    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert "strict-transport-security" not in headers  # only over HTTPS
    assert "content-security-policy" not in _client(app).get("/docs").headers


def test_local_only_refuses_a_remote_postgres(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PRISM_STORAGE_URL", "postgresql://prism@db.example.org/prism")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="local-only"):
            create_app()
    finally:
        get_settings.cache_clear()


def test_storage_falls_back_to_memory_when_postgres_is_unavailable(tmp_path: Path):
    from app.core.config import StorageSettings
    from app.services.storage import Store

    store = Store(StorageSettings(enabled=True, url="postgresql://prism:secret@127.0.0.1:1/prism"))
    assert store.enabled is False and store.engine is None
    sqlite = Store(StorageSettings(enabled=True, path=tmp_path / "p.db"))
    sqlite.set_meta("k", "1")
    sqlite.set_meta("k", "2")  # upsert
    assert sqlite.get_meta("k") == "2" and sqlite.describe("demo")["engine"] == "sqlite"


@pytest.fixture()
def fresh_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("PRISM_AUTH_ENABLED", "true")
    monkeypatch.setenv("PRISM_AUTH_TOKEN", CODE)
    monkeypatch.setenv("PRISM_AUTH_DB_URL", str(tmp_path / "security.db"))
    monkeypatch.setenv("PRISM_AUTH_DEFAULT_ADMIN_ENABLED", "true")
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application):
        yield application
    get_settings.cache_clear()


def test_fresh_install_has_the_documented_admin_who_must_change_password(fresh_install):
    client = _client(fresh_install)
    assert client.get("/api/auth/status").json()["has_accounts"] is True
    login = client.post("/api/auth/login", json={"username": "Admin", "password": "Admin@123"}).json()
    assert login["user"] == "admin" and login["role"] == "admin" and login["password_change_required"] is True
    blocked = client.get("/api/stats")
    assert blocked.status_code == 403 and blocked.json()["password_change_required"] is True
    assert client.post("/api/auth/password", json={"current_password": "Admin@123",
                                                   "new_password": "Admin@123"}).status_code == 400
    assert client.post("/api/auth/password", json={"current_password": "Admin@123",
                                                   "new_password": "short"}).status_code == 400
    changed = client.post("/api/auth/password", json={"current_password": "Admin@123",
                                                      "new_password": "a much better passphrase"})
    assert changed.status_code == 200 and changed.json()["password_change_required"] is False
    assert client.get("/api/stats").status_code == 200
    assert _client(fresh_install).post("/api/auth/login", json={"username": "admin", "password": "Admin@123"}).status_code == 401
    actions = {e["action"] for e in client.get("/api/admin/audit").json()}
    assert {"create default admin", "change password"} <= actions


def test_default_admin_is_not_recreated(fresh_install):
    store = fresh_install.state.security
    assert store.ensure_default_admin() is False  # accounts exist already
    store.delete_user("admin")
    _make(fresh_install, "someone", "admin")
    assert store.ensure_default_admin() is False and store.get_user("admin") is None


def test_password_reset_by_an_admin_is_temporary(app):
    _make(app, "asha", "analyst")
    _client(app).patch("/api/admin/users/asha", headers=ADMIN, json={"password": "temporary password 1"})
    client = _signed_in(app, "asha", "temporary password 1")
    assert client.get("/api/auth/status").json()["password_change_required"] is True
    assert client.get("/api/stats").status_code == 403
    client.post("/api/auth/password", json={"current_password": "temporary password 1",
                                            "new_password": "my own password 22"})
    assert client.get("/api/stats").status_code == 200
