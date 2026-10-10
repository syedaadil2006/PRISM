"""Local-only (edge) mode: on by default, and nothing leaves the computer."""

from __future__ import annotations

import asyncio
import importlib.util

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.config import ForwardSettings, PROJECT_ROOT, Settings, get_settings
from app.core.local_only import is_loopback, target_is_local, url_is_local
from app.main import create_app
from app.services.forwarder import Forwarder
from app.services.investigation_service import InvestigationService
from app.services.soc_state import SocState


def _request(app, client_ip: str, path: str) -> int:
    async def go() -> int:
        transport = httpx.ASGITransport(app=app, client=(client_ip, 50000))
        async with httpx.AsyncClient(transport=transport, base_url="http://prism") as client:
            return (await client.get(path)).status_code

    return asyncio.run(go())


def test_local_only_is_the_default():
    assert Settings().local_only is True


def test_requests_from_other_machines_are_refused():
    app = create_app()
    assert _request(app, "192.168.1.50", "/api/health") == 403
    assert _request(app, "203.0.113.5", "/") == 403
    assert _request(app, "10.0.0.7", "/services/collector/health") == 403
    assert _request(app, "127.0.0.1", "/docs") == 200
    assert _request(app, "::1", "/docs") == 200


def test_turning_local_only_off_allows_the_network(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PRISM_LOCAL_ONLY", "false")
    get_settings.cache_clear()
    try:
        assert _request(create_app(), "192.168.1.50", "/docs") == 200
    finally:
        get_settings.cache_clear()


def test_alerts_are_only_sent_to_this_computer():
    forwarder = Forwarder(
        ForwardSettings(webhook_url="https://siem.example.com/hook", splunk_hec_url="http://127.0.0.1:8088/services/collector",
                        syslog_target="10.1.2.3:514"),
        version="t",
    )
    assert forwarder.blocked == ["webhook", "syslog_cef"]
    assert forwarder.status()["targets"] == ["splunk_hec"]
    assert forwarder.status()["blocked_by_local_only"] == ["webhook", "syslog_cef"]
    open_forwarder = Forwarder(ForwardSettings(webhook_url="https://siem.example.com/hook"), version="t", local_only=False)
    assert open_forwarder.status()["targets"] == ["webhook"]


def test_the_language_model_is_never_used():
    settings = Settings()
    settings.llm.provider = "anthropic"
    settings.llm.api_key = "sk-not-real"
    service = InvestigationService(settings, SocState(settings))
    assert service.provider_name == "deterministic"


def test_syslog_is_pinned_to_this_computer(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PRISM_SYSLOG_HOST", "0.0.0.0")
    get_settings.cache_clear()
    try:
        app = create_app()
        with TestClient(app) as client:
            assert app.state.syslog.settings.host == "127.0.0.1"
            info = client.get("/api/live/integrations").json()
            assert info["local_only"]["enabled"] is True
    finally:
        get_settings.cache_clear()


def test_address_checks():
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost") and is_loopback("127.5.5.5")
    assert not is_loopback("192.168.1.1") and not is_loopback("0.0.0.0") and not is_loopback(None)
    assert url_is_local("http://127.0.0.1:8000/x") and not url_is_local("https://example.com")
    assert target_is_local("127.0.0.1:514") and not target_is_local("10.0.0.1:514")


@pytest.mark.parametrize("script", ["live_replay.py", "siem_pull.py"])
def test_scripts_refuse_to_send_off_this_computer(script):
    spec = importlib.util.spec_from_file_location(script[:-3], PROJECT_ROOT / "scripts" / script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.is_local("http://127.0.0.1:8000") and module.is_local("http://localhost:8000")
    assert not module.is_local("http://192.168.1.20:8000")
