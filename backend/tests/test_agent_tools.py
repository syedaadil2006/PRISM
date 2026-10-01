"""The evidence-retrieval tool layer."""

from __future__ import annotations

import pytest

from app.agents.tools import TOOLS, TOOLS_BY_NAME, ToolContext, ToolError, ToolRegistry
from app.core.config import get_settings
from app.engine.attack_chain import build_chains
from app.engine.correlation import correlate
from app.graph.builder import build_entity_graph
from app.ingest.loader import ingest_directory, load_inventory, normalize_all


@pytest.fixture(scope="module")
def registry():
    settings = get_settings()
    inventory = load_inventory(settings.inventory_file)
    events, _ = ingest_directory(settings.demo_dir, inventory)
    events = normalize_all(events)
    links = correlate(events, settings.correlation)
    graph = build_entity_graph(events, inventory)
    chains = build_chains(events, links, graph, inventory, settings)
    return ToolRegistry(
        ToolContext(events, links, chains, graph, inventory, settings)
    )


def test_every_tool_publishes_a_callable_schema():
    """The catalogue is the tool-calling interface; it has to be complete."""
    for tool in TOOLS:
        schema = tool.schema()
        assert schema["name"] == tool.name
        assert schema["description"]
        assert schema["input_schema"]["type"] == "object"
        assert isinstance(schema["input_schema"]["properties"], dict)


def test_unknown_tool_is_refused(registry):
    with pytest.raises(ToolError):
        registry.call("exfiltrate_everything")


def test_every_call_is_recorded_with_provenance(registry):
    before = len(registry.calls)
    registry.call("get_host_profile", host="HR-PC")
    assert len(registry.calls) == before + 1

    record = registry.calls[-1]
    assert record.tool == "get_host_profile"
    assert record.arguments == {"host": "HR-PC"}
    assert record.call_id
    assert record.duration_ms >= 0


def test_log_search_returns_source_event_ids(registry):
    result, _ = registry.call("search_endpoint_logs", host="HR-PC", suspicious_only=True)
    assert result.found
    assert result.event_ids
    assert len(result.event_ids) == len(result.rows)
    for row in result.rows:
        assert row["event_id"] in result.event_ids


def test_user_access_separates_attempts_from_access(registry):
    """A failed logon must never read as the account having reached a host."""
    result, _ = registry.call("get_user_access", user="john.doe")
    by_host = {row["host"]: row for row in result.rows}

    assert by_host["FINANCE-PC"]["access_succeeded"] is True
    # DC01 saw only failed logons in the demo data.
    assert by_host["DC01"]["activity_seen"] is True
    assert by_host["DC01"]["access_succeeded"] is False
    assert "attempted but not reached: DC01" in result.summary


def test_attack_path_reports_unreachable_honestly(registry):
    reachable, _ = registry.call(
        "get_attack_path", source_host="FINANCE-PC", target_host="DC01"
    )
    assert reachable.found
    assert reachable.rows[0]["hops"] == 1

    missing, _ = registry.call(
        "get_attack_path", source_host="FINANCE-PC", target_host="NOT-A-HOST"
    )
    assert not missing.found
    assert "not in the graph" in missing.summary


def test_mitre_lookup_checks_the_event_against_the_rule(registry):
    """A technique is only confirmed when the cited event satisfies its rule."""
    supported, _ = registry.call(
        "lookup_mitre_technique", technique_id="T1003.001", event_id="edr-0009"
    )
    assert supported.rows[0]["supported_by_event"] is True

    unsupported, _ = registry.call(
        "lookup_mitre_technique", technique_id="T1003.001", event_id="dns-0001"
    )
    assert unsupported.rows[0]["supported_by_event"] is False


def test_unknown_technique_is_not_invented(registry):
    result, _ = registry.call("lookup_mitre_technique", technique_id="T9999")
    assert not result.found
    assert "not in the PRISM mapping table" in result.summary


def test_scoring_tool_matches_the_prediction_engine(registry):
    """The agent layer must not produce different numbers from the dashboard."""
    result, _ = registry.call("score_next_targets", chain_id="ATTACK-001")
    assert result.rows[0]["host"] == "DC01"

    chain = registry.context.chains[0]
    assert result.rows[0]["score"] == chain.predictions[0].score


def test_chain_tool_reports_position_not_just_the_last_stage(registry):
    """Where the attacker is, and where the story ends, are different questions."""
    result, _ = registry.call("get_attack_chain", chain_id="ATTACK-001")
    assert result.meta["current_host"] == "FINANCE-PC"
    # The final stage is on FILE01: an admin share mount, not code execution.
    assert result.rows[-1]["host"] == "FILE01"


def test_related_events_carry_their_scoring_factors(registry):
    result, _ = registry.call("get_related_events", event_id="edr-0009", limit=5)
    assert result.found
    for row in result.rows:
        assert row["factors"]
        for factor in row["factors"]:
            assert factor["name"] and factor["detail"]


def test_tool_names_cover_the_documented_interface():
    """The names the brief specifies must all exist."""
    required = {
        "search_auth_logs",
        "search_dns_logs",
        "search_endpoint_logs",
        "search_events",
        "get_host_neighbors",
        "get_user_access",
        "get_attack_path",
        "get_related_events",
        "get_recent_activity",
        "lookup_mitre_technique",
        "lookup_mitre_tactic",
    }
    assert required <= set(TOOLS_BY_NAME)
