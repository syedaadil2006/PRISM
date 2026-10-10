"""Persistent storage: state survives a restart, and data choices never mix."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import BACKEND_ROOT, StorageSettings, get_settings
from app.main import app
from app.services.storage import Store

SYSMON = [json.loads(line) for line in (BACKEND_ROOT / "data" / "demo" / "02_sysmon.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture()
def stored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Run the app against a fresh database file, restartable within the test."""
    monkeypatch.setenv("PRISM_STORAGE_ENABLED", "true")
    monkeypatch.setenv("PRISM_STORAGE_PATH", str(tmp_path / "prism.db"))
    monkeypatch.setenv("PRISM_AGENTS_STEP_DELAY_SECONDS", "0")

    def start(dataset: str = "synthetic") -> TestClient:
        monkeypatch.setenv("PRISM_DATASET", dataset)
        get_settings.cache_clear()
        return TestClient(app)

    yield start
    get_settings.cache_clear()


def _finish(client: TestClient, investigation_id: str) -> dict:
    for _ in range(200):
        current = client.get("/api/agents/investigations/" + investigation_id).json()
        if current["status"] != "active":
            return current
        time.sleep(0.05)
    raise AssertionError("investigation did not finish")


def test_live_events_survive_a_restart(stored):
    with stored() as client:
        result = client.post("/api/live/events", params={"source": "edr-test"}, json=SYSMON[:3]).json()
        assert result["accepted"] == 3
        client.post("/api/live/flush")
        assert client.get("/api/health").json()["events"] == 59
    with stored() as client:
        assert client.get("/api/health").json()["events"] == 59


def test_investigations_and_decisions_survive_a_restart(stored):
    with stored() as client:
        started = client.post("/api/agents/investigations").json()
        done = _finish(client, started["investigation_id"])
        finding = done["findings"][0]["finding_id"]
        client.post(
            "/api/agents/investigations/{}/findings/{}/decision".format(done["investigation_id"], finding),
            params={"decision": "false_positive"},
        )
    with stored() as client:
        again = client.get("/api/agents/investigations/" + done["investigation_id"]).json()
        assert again["status"] == "complete"
        assert again["findings"][0]["analyst_decision"] == "false_positive"
        assert again["metrics"]["analyst_false_positives"] == 1


def test_data_choices_do_not_mix(stored):
    with stored("live") as client:
        client.post("/api/live/events", params={"source": "laptop"}, json=SYSMON[:2])
        client.post("/api/live/flush")
        assert client.get("/api/health").json()["events"] == 2
    with stored("synthetic") as client:
        assert client.get("/api/health").json()["events"] == 56  # demo only, no live events
    with stored("live") as client:
        assert client.get("/api/health").json()["events"] == 2  # live events come back in live mode


def test_reset_forgets_stored_events(stored):
    with stored() as client:
        client.post("/api/live/events", params={"source": "x"}, json=SYSMON[:1])
        client.post("/api/logs/reset")
    with stored() as client:
        assert client.get("/api/health").json()["events"] == 56


def test_a_broken_database_path_falls_back_to_memory(tmp_path: Path):
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x", encoding="utf-8")
    store = Store(StorageSettings(enabled=True, path=blocker / "prism.db"))
    assert store.enabled is False
    store.save_events([], "live", "synthetic")  # no error
    assert store.load_events(10, "synthetic") == []
