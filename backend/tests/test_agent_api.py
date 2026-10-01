"""The agent HTTP surface, including the human-in-the-loop controls."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app


@pytest.fixture(scope="module")
def client():
    # Run the agents at full speed for tests; the delay is a demo affordance.
    get_settings().agents.step_delay_seconds = 0.0
    with TestClient(app) as test_client:
        yield test_client


def _run_investigation(client: TestClient) -> dict:
    started = client.post("/api/agents/investigations")
    assert started.status_code == 200
    investigation_id = started.json()["investigation_id"]

    for _ in range(100):
        payload = client.get("/api/agents/investigations/" + investigation_id).json()
        if payload["status"] in {"complete", "failed"}:
            return payload
        time.sleep(0.05)
    raise AssertionError("investigation did not finish")


@pytest.fixture(scope="module")
def investigation(client):
    return _run_investigation(client)


def test_roster_declares_who_is_narrating(client):
    roster = client.get("/api/agents/roster").json()
    assert roster["enabled"] is True
    assert len(roster["agents"]) == 9
    # With no key configured the deterministic narrator writes the summary, and
    # the UI is entitled to say so.
    assert roster["narrator"] == "deterministic"
    assert roster["llm_configured"] is False


def test_tool_catalogue_is_exposed(client):
    catalogue = client.get("/api/agents/tools").json()
    assert catalogue["count"] >= 15
    names = {tool["name"] for tool in catalogue["tools"]}
    assert {"search_auth_logs", "get_attack_path", "lookup_mitre_technique"} <= names
    for tool in catalogue["tools"]:
        assert tool["schema"]["input_schema"]["type"] == "object"


def test_investigation_completes_with_a_verified_conclusion(investigation):
    assert investigation["status"] == "complete"
    assert investigation["initial_host"] == "HR-PC"
    assert investigation["current_host"] == "FINANCE-PC"
    assert investigation["current_stage"] == "Lateral Movement"
    assert investigation["user"] == "john.doe"
    assert investigation["confidence"] > 0.5
    assert investigation["potential_targets"][0] == "DC01"


def test_every_agent_reports_a_status(investigation):
    assert len(investigation["agents"]) == 9
    for run in investigation["agents"]:
        assert run["status"] in {"complete", "skipped"}
        assert run["label"]
        assert run["purpose"]


def test_timeline_endpoint_returns_agent_actions(client, investigation):
    steps = client.get(
        "/api/agents/investigations/{}/timeline".format(
            investigation["investigation_id"]
        )
    ).json()
    assert steps
    agents_seen = {step["agent"] for step in steps}
    assert {"triage", "correlation", "investigation", "verification"} <= agents_seen
    assert any(step["tool_calls"] for step in steps)


def test_evidence_endpoint_resolves_a_findings_sources(client, investigation):
    finding = investigation["findings"][0]
    payload = client.get(
        "/api/agents/investigations/{}/evidence".format(
            investigation["investigation_id"]
        ),
        params={"finding_id": finding["finding_id"]},
    ).json()

    assert payload["count"] == len(finding["evidence_ids"])
    assert payload["source_event_ids"]

    # Those ids must be real events in the current set.
    events = {e["event_id"] for e in client.get("/api/events", params={"limit": 2000}).json()}
    assert set(payload["source_event_ids"]) <= events


def test_summary_separates_observed_from_predicted(investigation):
    summary = investigation["summary"]
    assert summary["headline"]
    assert summary["narrative"]
    assert summary["observed"]
    assert summary["predicted"]
    assert summary["generated_by"] == "deterministic"
    joined = " ".join(summary["predicted"])
    assert "not observed attacker activity" in joined


def test_analyst_can_mark_a_finding_false_positive(client, investigation):
    investigation_id = investigation["investigation_id"]
    finding_id = investigation["findings"][0]["finding_id"]

    response = client.post(
        "/api/agents/investigations/{}/findings/{}/decision".format(
            investigation_id, finding_id
        ),
        params={"decision": "false_positive"},
        json={"note": "known maintenance window"},
    )
    assert response.status_code == 200

    updated = response.json()
    decided = next(
        f for f in updated["findings"] if f["finding_id"] == finding_id
    )
    assert decided["analyst_decision"] == "false_positive"
    assert decided["analyst_note"] == "known maintenance window"
    # Kept on the record rather than deleted.
    assert len(updated["findings"]) == len(investigation["findings"])


def test_unknown_investigation_is_a_404(client):
    assert client.get("/api/agents/investigations/INV-NOPE").status_code == 404


def test_unknown_chain_is_refused(client):
    response = client.post(
        "/api/agents/investigations", params={"chain_id": "ATTACK-999"}
    )
    assert response.status_code == 400


def test_investigations_are_listed_newest_first(client, investigation):
    rows = client.get("/api/agents/investigations").json()
    assert rows
    assert rows[0]["investigation_id"] == investigation["investigation_id"]
    assert rows[0]["agents_total"] == 9


def test_report_renders_in_both_formats(client, investigation):
    base = "/api/agents/investigations/{}/report".format(investigation["investigation_id"])

    page = client.get(base)
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert investigation["investigation_id"] in page.text
    assert "Predicted (risk estimate, not observed activity)" in page.text

    md = client.get(base, params={"format": "md", "download": True})
    assert md.status_code == 200
    assert "attachment" in md.headers["content-disposition"]
    assert md.text.startswith("# PRISM Investigation Report")
    assert "## Findings" in md.text

    assert client.get(base, params={"format": "pdf"}).status_code == 422
