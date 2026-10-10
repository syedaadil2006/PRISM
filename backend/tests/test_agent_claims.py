"""Agents only claim what the evidence supports, and every finding is checkable.

Regression test for BOTS v1: Cerber never moved laterally, yet the investigation
agent used to report "moved to another host" because the account had signed in
elsewhere. Topology findings (graph exposure, next target) used to fail
verification only because they cite graph facts rather than log events.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import create_app


def _investigate(client: TestClient, chain_id: str) -> dict:
    started = client.post("/api/agents/investigations", params={"chain_id": chain_id}).json()
    for _ in range(400):
        state = client.get("/api/agents/investigations/" + started["investigation_id"]).json()
        if state["status"] != "active":
            return state
        time.sleep(0.05)
    raise AssertionError("investigation did not finish")


@pytest.fixture()
def bots(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PRISM_DATASET", "botsv1")
    monkeypatch.setenv("PRISM_AGENTS_STEP_DELAY_SECONDS", "0")
    get_settings.cache_clear()
    with TestClient(create_app()) as client:
        yield client
    get_settings.cache_clear()


def test_no_movement_claim_without_a_movement_detection(bots):
    state = _investigate(bots, "ATTACK-001")
    claim = next(f for f in state["findings"] if f["agent"] == "investigation")
    assert claim["title"] == "Attack hypothesis partially supported"
    assert "moved to another host" not in claim["statement"]
    assert "no lateral-movement detection supports movement" in claim["statement"]


def test_every_bots_finding_passes_verification(bots):
    for chain_id in ("ATTACK-001", "ATTACK-002"):
        findings = [f for f in _investigate(bots, chain_id)["findings"] if f["agent"] != "verification"]
        assert findings and all(f["verified"] for f in findings), [
            (f["agent"], f["verification_notes"]) for f in findings if not f["verified"]
        ]
        topology = [f for f in findings if f["agent"] in {"graph", "next_target"}]
        assert topology and all(
            any("graph node(s) exist" in note for note in f["verification_notes"]) for f in topology
        )
