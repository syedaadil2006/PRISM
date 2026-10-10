"""Stage 2: ingestion queue, background analysis, backpressure, metrics, backups, retention."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings, StorageSettings, get_settings
from app.main import create_app
from app.services.backup import create_backup, list_backups, verify_backup
from app.services.soc_state import SocState
from app.services.storage import Store

CODE = "scale-test-code"


def _dns(n: int, start: int = 0) -> list[dict]:
    return [{"ts": 1790761620.0 + i, "query": f"host{i}.example.org", "id.orig_h": "10.0.1.15"}
            for i in range(start, start + n)]


@pytest.fixture()
def make_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    clients = []

    def build(**env: str) -> TestClient:
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        get_settings.cache_clear()
        client = TestClient(create_app())
        client.__enter__()
        clients.append(client)
        return client

    yield build
    for client in clients:
        client.__exit__(None, None, None)
    get_settings.cache_clear()


def test_ingestion_only_queues_and_analysis_catches_up(make_client):
    client = make_client(PRISM_LIVE_RECOMPUTE_INTERVAL_SECONDS="3600")
    client.post("/api/live/start")
    result = client.post("/api/live/events", params={"source": "q"}, json=_dns(5)).json()
    assert result["accepted"] == 5 and result["total_events"] == 5
    status = client.get("/api/live/status").json()
    assert status["queued"] == 5 and status["pending_analysis"] is True
    assert client.get("/api/stats").json()["total_events"] == 0  # not analysed yet
    status = client.post("/api/live/flush").json()
    assert status["queued"] == 0 and status["pending_analysis"] is False
    assert client.get("/api/stats").json()["total_events"] == 5
    again = client.post("/api/live/events", params={"source": "q"}, json=_dns(5)).json()
    assert again["accepted"] == 5  # different generated ids: same source, new batch


def test_backpressure_asks_senders_to_retry(make_client):
    client = make_client(PRISM_LIVE_RECOMPUTE_INTERVAL_SECONDS="3600", PRISM_LIVE_MAX_PENDING="10")
    client.post("/api/live/start")
    assert client.post("/api/live/events", params={"source": "b"}, json=_dns(10)).status_code == 200
    busy = client.post("/api/live/events", params={"source": "b"}, json=_dns(3, 100))
    assert busy.status_code == 429 and int(busy.headers["retry-after"]) >= 1
    assert busy.json()["queued"] == 10
    hec = client.post("/services/collector/event", json={"event": {"query": "x.org", "ts": 1790761620.0}})
    assert hec.status_code == 503 and hec.json()["code"] == 9  # Splunk's "server is busy"
    client.post("/api/live/flush")
    assert client.post("/api/live/events", params={"source": "b"}, json=_dns(3, 100)).status_code == 200


def test_analysis_runs_off_the_event_loop():
    """While a slow analysis runs, other work on the event loop is not held up."""
    state = SocState(Settings(dataset="live"))
    state.bootstrap()
    real_compute = state._compute

    def slow_compute(events):  # noqa: ANN001, ANN202
        time.sleep(1.0)
        return real_compute(events)

    state._compute = slow_compute  # type: ignore[method-assign]

    async def scenario() -> tuple[float, int]:
        from app.ingest.parsers import LogRecord  # noqa: F401 - records are plain dicts

        await state.ingest_live(_dns(20), "slow")
        flush = asyncio.create_task(state.flush_live())
        await asyncio.sleep(0.05)
        started = time.perf_counter()
        state.stats()  # what an API read does
        accepted = (await state.ingest_live(_dns(5, 500), "slow")).accepted  # ingestion keeps working
        waited = time.perf_counter() - started
        await flush
        return waited, accepted

    waited, accepted = asyncio.run(scenario())
    assert waited < 0.5 and accepted == 5
    assert len(state.analysis.events) == 20 and state.pending_count == 5
    state.shutdown()


def test_events_survive_a_restart_before_analysis(make_client, tmp_path: Path):
    env = dict(PRISM_STORAGE_ENABLED="true", PRISM_STORAGE_PATH=str(tmp_path / "prism.db"),
               PRISM_LIVE_RECOMPUTE_INTERVAL_SECONDS="3600", PRISM_DATASET="live")
    first = make_client(**env)
    first.post("/api/live/events", params={"source": "r"}, json=_dns(7))
    first.__exit__(None, None, None)  # crash/restart before the analysis ran
    second = make_client(**env)
    assert second.get("/api/stats").json()["total_events"] == 7


def test_metrics_endpoint(make_client):
    client = make_client(PRISM_AUTH_ENABLED="true", PRISM_AUTH_TOKEN=CODE)
    assert client.get("/api/metrics").status_code == 401
    client.get("/api/stats", headers={"Authorization": "Bearer " + CODE})
    body = client.get("/api/metrics", headers={"Authorization": "Bearer " + CODE}).text
    assert "prism_events 56" in body and "prism_attack_chains 1" in body
    assert 'prism_http_requests_total{method="GET",route="/api/stats",status="200"} 1' in body
    assert "prism_http_request_seconds_bucket" in body and "prism_ingest_queue 0" in body


def test_backups_are_consistent_checked_and_pruned(make_client, tmp_path: Path):
    client = make_client(
        PRISM_AUTH_ENABLED="true", PRISM_AUTH_TOKEN=CODE, PRISM_AUTH_DB_URL=str(tmp_path / "security.db"),
        PRISM_STORAGE_ENABLED="true", PRISM_STORAGE_PATH=str(tmp_path / "prism.db"),
        PRISM_BACKUP_DIR=str(tmp_path / "backups"), PRISM_BACKUP_KEEP="2",
    )
    admin = {"X-PRISM-Token": CODE}
    client.post("/api/live/events", headers=admin, params={"source": "bk"}, json=_dns(4))
    manifest = client.post("/api/admin/backups", headers=admin).json()
    assert {f["database"] for f in manifest["files"]} == {"prism", "security"}
    folder = tmp_path / "backups" / manifest["name"]
    assert verify_backup(folder) == []
    with sqlite3.connect(folder / "prism.db") as db:
        assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 4

    for _ in range(2):
        client.post("/api/admin/backups", headers=admin)
    assert len(client.get("/api/admin/backups", headers=admin).json()) == 2  # keep=2

    newest = tmp_path / "backups" / list_backups(get_settings())[0]["name"]
    (newest / "prism.db").write_bytes(b"corrupted")
    assert any("checksum" in p for p in verify_backup(newest))
    audit = client.get("/api/admin/audit", headers=admin, params={"action": "create backup"}).json()
    assert len(audit) == 3


def test_retention_deletes_old_stored_data(tmp_path: Path):
    store = Store(StorageSettings(enabled=True, path=tmp_path / "p.db"))
    state = SocState(Settings(dataset="live"))
    events, _ = state.live.parse([{"ts": 1000000000.0, "query": "old.org"}, {"ts": 1790761620.0, "query": "new.org"}],
                                 "ret", state.inventory)
    store.save_events(events, "live", "s")
    store.save_investigation("old", "2001-01-01T00:00:00+00:00", "{}")
    store.save_investigation("new", "2030-01-01T00:00:00+00:00", "{}")
    assert store.purge_older_than("2020-01-01T00:00:00+00:00") == (1, 1)
    assert store.event_count("s") == 1 and len(store.load_investigations(10)) == 1


def test_restore_script_refuses_damaged_backups(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import importlib.util

    settings = Settings(storage=StorageSettings(enabled=True, path=tmp_path / "prism.db"))
    settings.auth.enabled = False
    settings.backup.dir = tmp_path / "backups"
    def set_meta(value: str) -> None:
        store = Store(settings.storage)
        store.set_meta("k", value)
        store.close()

    set_meta("before")
    manifest = create_backup(settings)
    set_meta("after")

    monkeypatch.setenv("PRISM_BACKUP_DIR", str(settings.backup.dir))
    spec = importlib.util.spec_from_file_location(
        "restore_backup", Path(__file__).resolve().parents[2] / "scripts" / "restore_backup.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "prism_is_running", lambda port: False)

    monkeypatch.setattr("sys.argv", ["restore_backup.py", manifest["name"]])
    assert module.main() == 0
    restored = Store(settings.storage)
    assert restored.get_meta("k") == "before"
    restored.close()
    assert (tmp_path / "prism.db.before-restore").exists()

    (settings.backup.dir / manifest["name"] / "prism.db").write_bytes(b"x")
    assert module.main() == 3
    monkeypatch.setattr(module, "prism_is_running", lambda port: True)
    assert module.main() == 2
    assert json.loads((settings.backup.dir / manifest["name"] / "manifest.json").read_text())["files"]
