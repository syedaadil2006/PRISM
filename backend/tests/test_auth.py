"""API access code: required everywhere except health and sign-in."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.auth import resolve_token
from app.core.config import AuthSettings, get_settings
from app.main import create_app

CODE = "test-code-123"


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("PRISM_AUTH_ENABLED", "true")
    monkeypatch.setenv("PRISM_AUTH_DB_URL", str(tmp_path / "security.db"))
    monkeypatch.setenv("PRISM_AUTH_TOKEN", CODE)
    get_settings.cache_clear()
    with TestClient(create_app()) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_api_requires_the_code(client):
    response = client.get("/api/stats")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert client.post("/api/live/events", json={"query": "x.org"}).status_code == 401


def test_health_and_sign_in_are_public(client):
    assert client.get("/api/health").status_code == 200
    status = client.get("/api/auth/status").json()
    assert (status["enabled"], status["authenticated"], status["user"]) == (True, False, None)


def test_wrong_codes_are_rejected(client):
    assert client.get("/api/stats", headers={"X-PRISM-Token": "nope"}).status_code == 401
    assert client.get("/api/stats", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.post("/api/auth/login", json={"token": "nope"}).status_code == 401


def test_header_and_bearer_codes_work(client):
    assert client.get("/api/stats", headers={"X-PRISM-Token": CODE}).status_code == 200
    assert client.get("/api/stats", headers={"Authorization": "Bearer " + CODE}).status_code == 200


def test_dashboard_sign_in_sets_a_strict_http_only_cookie(client):
    response = client.post("/api/auth/login", json={"token": CODE})
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert "prism_session=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert client.get("/api/stats").status_code == 200  # cookie now sent automatically
    assert client.get("/api/auth/status").json()["authenticated"] is True
    client.post("/api/auth/logout")
    client.cookies.clear()
    assert client.get("/api/stats").status_code == 401


def test_the_dashboard_page_itself_loads_without_the_code(client):
    # Only /api is protected; the page must load so it can show the sign-in screen.
    assert client.get("/docs").status_code == 200


def test_a_code_is_generated_once_and_reused(tmp_path: Path):
    settings = AuthSettings(token="", token_file=tmp_path / ".prism_token")
    first = resolve_token(settings)
    assert len(first) >= 24
    assert resolve_token(settings) == first
    assert (tmp_path / ".prism_token").read_text(encoding="utf-8") == first
