"""End-to-end checks against the bundled demo dataset and the HTTP API."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_demo_dataset_parses_without_errors(client):
    health = client.get("/api/health").json()
    assert health["status"] == "ok"
    assert health["ingest_errors"] == []
    assert health["events"] > 40
    # All three required log categories are present.
    assert len(health["sources"]) == 3


def test_all_three_log_types_are_normalized(client):
    events = client.get("/api/events", params={"limit": 2000}).json()
    kinds = {e["event_type"] for e in events}
    assert kinds == {"authentication", "dns", "endpoint"}


def test_fragmented_alerts_collapse_into_one_chain(client):
    stats = client.get("/api/stats").json()
    assert stats["active_attack_chains"] == 1
    assert stats["raw_alert_count"] > 20
    assert stats["alert_reduction_ratio"] > 0.9


def test_the_chain_tells_the_expected_story(client):
    chains = client.get("/api/attacks").json()
    assert len(chains) == 1
    chain = chains[0]

    assert chain["initial_host"] == "HR-PC"
    assert chain["current_host"] == "FINANCE-PC"
    assert chain["current_stage"] == "Lateral Movement"
    assert chain["users"] == ["john.doe"]
    assert chain["severity"] == "critical"

    tactics = [stage["tactic"] for stage in chain["stages"]]
    for expected in ("Initial Access", "Execution", "Credential Access", "Lateral Movement"):
        assert expected in tactics
    assert tactics.index("Initial Access") < tactics.index("Lateral Movement")


def test_lateral_movement_is_detected_between_the_right_hosts(client):
    chain = client.get("/api/attacks").json()[0]
    hops = {(m["source_host"], m["destination_host"]) for m in chain["lateral_movements"]}
    assert ("HR-PC", "FINANCE-PC") in hops
    assert len(chain["lateral_movements"]) == 2


def test_the_domain_controller_is_predicted_but_not_compromised(client):
    chain = client.get("/api/attacks").json()[0]
    assert "DC01" not in chain["hosts"], "a failed logon must not mark a host compromised"
    assert "DC01" in chain["targeted_hosts"]

    predictions = client.get("/api/predictions").json()
    assert predictions[0]["host"] == "DC01"
    assert predictions[0]["assurance"] == "predicted"
    assert predictions[0]["score"] > 80
    assert predictions[0]["reasons"]


def test_chain_detail_returns_its_own_evidence(client):
    detail = client.get("/api/attacks/ATTACK-001").json()
    member_ids = set(detail["chain"]["event_ids"])
    assert member_ids
    assert {e["event_id"] for e in detail["events"]} == member_ids
    for link in detail["correlations"]:
        assert link["source_event_id"] in member_ids
        assert link["target_event_id"] in member_ids
        assert link["factors"]


def test_unknown_chain_is_a_404(client):
    assert client.get("/api/attacks/ATTACK-999").status_code == 404


def test_graph_is_server_driven_and_labels_every_state(client):
    graph = client.get("/api/graph").json()
    states = {n["state"] for n in graph["nodes"]}
    assert "compromised" in states
    assert "current_position" in states
    assert "potential_target" in states

    kinds = {n["kind"] for n in graph["nodes"]}
    assert {"user", "host", "process", "domain"} <= kinds

    assurances = {e["assurance"] for e in graph["edges"]}
    assert {"observed", "inferred", "predicted"} <= assurances
    assert any(e["kind"] == "PREDICTED_MOVE" and e["predicted"] for e in graph["edges"])
    # The visualization must stay readable.
    assert len(graph["nodes"]) < 60


def test_graph_can_be_focused_on_one_chain(client):
    focused = client.get("/api/graph", params={"chain_id": "ATTACK-001"}).json()
    assert focused["nodes"]
    for node in focused["nodes"]:
        assert node["attack_chain_ids"] in ([], ["ATTACK-001"])


def test_mitre_matrix_groups_evidence_by_tactic(client):
    matrix = client.get("/api/mitre").json()
    tactics = [t["tactic"] for t in matrix]
    assert "Initial Access" in tactics
    assert "Lateral Movement" in tactics
    assert tactics.index("Initial Access") < tactics.index("Lateral Movement")
    for tactic in matrix:
        for technique in tactic["techniques"]:
            assert technique["occurrences"] == len(technique["evidence"])
            assert all(item["evidence"] for item in technique["evidence"])


def test_host_and_user_views_join_inventory_with_observations(client):
    hosts = {h["name"]: h for h in client.get("/api/hosts").json()}
    assert hosts["FINANCE-PC"]["state"] == "current_position"
    assert hosts["HR-PC"]["state"] == "compromised"
    assert hosts["DC01"]["is_critical_infrastructure"] is True
    assert hosts["DC01"]["prediction_score"] is not None

    users = {u["name"]: u for u in client.get("/api/users").json()}
    assert users["john.doe"]["compromised"] is True
    assert users["sara.lee"]["compromised"] is False
    assert "DC01" in users["john.doe"]["accessible_hosts"]


def test_engine_config_exposes_the_thresholds_behind_detections(client):
    config = client.get("/api/config").json()
    settings = get_settings()
    assert config["correlation_min_score"] == settings.correlation.min_score
    assert config["lateral_window_seconds"] == settings.lateral.window_seconds
    assert sum(config["prediction_weights"].values()) > 0


def test_alert_reduction_is_zero_before_anything_correlates(client):
    """Nothing consolidated means nothing reduced, not a perfect score."""
    client.post("/api/simulation/reset")
    try:
        stats = client.get("/api/stats").json()
        assert stats["active_attack_chains"] == 0
        assert stats["alert_reduction_ratio"] == 0.0
    finally:
        client.post("/api/simulation/reset", params={"show_all": True})


def test_host_state_matches_the_graph(client):
    """A targeted host that is also a scored prediction reads the same in both."""
    hosts = {h["name"]: h for h in client.get("/api/hosts").json()}
    graph = client.get("/api/graph").json()
    graph_states = {
        node["label"]: node["state"] for node in graph["nodes"] if node["kind"] == "host"
    }
    for name, state in graph_states.items():
        assert hosts[name]["state"] == state, name


def test_dashboard_shell_is_never_cached_and_reports_its_build(client):
    from app.core.config import PROJECT_ROOT

    if not (PROJECT_ROOT / "frontend" / "dist" / "index.html").exists():
        return  # dashboard not built in this checkout
    page = client.get("/")
    assert page.headers["cache-control"] == "no-cache"
    build = client.get("/api/health").json()["ui_build"]
    assert build and build.startswith("index-") and build in page.text
