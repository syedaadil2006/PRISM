"""Demo Mode: the dataset is revealed progressively and analysis keeps up."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
        # Leave the process showing the full dataset for any later test.
        test_client.post("/api/simulation/reset", params={"show_all": True})


def test_reset_rewinds_to_an_empty_board(client):
    status = client.post("/api/simulation/reset").json()
    assert status["state"] == "idle"
    assert status["revealed"] == 0
    assert status["total"] > 40
    assert client.get("/api/attacks").json() == []


def test_stepping_reveals_events_and_grows_the_chain(client):
    client.post("/api/simulation/reset")

    status = client.post("/api/simulation/step", params={"count": 12}).json()
    assert status["revealed"] == 12
    assert status["state"] == "paused"
    early_chains = client.get("/api/attacks").json()

    client.post("/api/simulation/step", params={"count": 40})
    late_chains = client.get("/api/attacks").json()

    assert late_chains, "the chain should exist once the whole story is revealed"
    if early_chains:
        assert late_chains[0]["event_count"] >= early_chains[0]["event_count"]
    assert late_chains[0]["current_stage"] == "Lateral Movement"


def test_the_prediction_appears_only_once_the_attack_has_moved(client):
    client.post("/api/simulation/reset")
    client.post("/api/simulation/step", params={"count": 8})
    before = client.get("/api/predictions").json()

    client.post("/api/simulation/step", params={"count": 60})
    after = client.get("/api/predictions").json()

    assert after, "DC01 should be predicted once lateral movement is visible"
    assert after[0]["host"] == "DC01"
    if before:
        assert after[0]["score"] >= before[0]["score"]


def test_show_all_drops_gating(client):
    status = client.post("/api/simulation/reset", params={"show_all": True}).json()
    assert status["gating"] is False
    assert status["revealed"] == status["total"]
    assert len(client.get("/api/attacks").json()) == 1
