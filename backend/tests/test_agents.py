"""The agents themselves: evidence discipline, verification, and consistency."""

from __future__ import annotations

import asyncio

import pytest

from app.agents.base import AgentWorkspace
from app.agents.llm import NullProvider
from app.agents.narrative import _is_faithful, build_summary
from app.agents.orchestrator import PIPELINE, Orchestrator, new_investigation
from app.agents.state import (
    AgentName,
    AgentStatus,
    AnalystDecision,
    Assurance,
    Investigation,
)
from app.agents.tools import ToolContext, ToolRegistry
from app.agents.verification import VerificationAgent
from app.core.config import get_settings
from app.engine.attack_chain import build_chains
from app.engine.correlation import correlate
from app.graph.builder import build_entity_graph
from app.ingest.loader import ingest_directory, load_inventory, normalize_all


def _context():
    settings = get_settings()
    inventory = load_inventory(settings.inventory_file)
    events, _ = ingest_directory(settings.demo_dir, inventory)
    events = normalize_all(events)
    links = correlate(events, settings.correlation)
    graph = build_entity_graph(events, inventory)
    chains = build_chains(events, links, graph, inventory, settings)
    return settings, ToolContext(events, links, chains, graph, inventory, settings), chains


@pytest.fixture(scope="module")
def completed():
    """One full investigation over the demo dataset."""
    settings, context, chains = _context()
    settings.agents.step_delay_seconds = 0.0
    investigation = new_investigation(chains[0].attack_chain_id, "test")
    result = asyncio.run(
        Orchestrator(settings, NullProvider()).run(investigation, context)
    )
    return result, chains[0]


# --------------------------------------------------------------- discipline --


def test_a_finding_without_evidence_is_refused():
    """The contract the whole layer rests on."""
    settings, context, _ = _context()
    investigation = new_investigation("ATTACK-001", "test")
    workspace = AgentWorkspace(
        AgentName.TRIAGE, investigation, ToolRegistry(context), settings
    )

    with pytest.raises(ValueError, match="no evidence"):
        workspace.finding(
            "Attacker is in the building",
            "I simply know this.",
            assurance=Assurance.OBSERVED,
            confidence=0.99,
            evidence_ids=[],
        )


def test_evidence_carries_the_tool_call_that_produced_it():
    settings, context, _ = _context()
    investigation = new_investigation("ATTACK-001", "test")
    workspace = AgentWorkspace(
        AgentName.GRAPH, investigation, ToolRegistry(context), settings
    )

    result = workspace.call("get_host_profile", host="HR-PC")
    evidence_id = workspace.evidence(result.summary, source=result)

    item = investigation.evidence_item(evidence_id)
    assert item is not None
    assert item.source_tool == "get_host_profile"
    assert item.source_call_id
    assert item.event_ids


# ------------------------------------------------------------- orchestration --


def test_the_full_pipeline_runs_every_agent(completed):
    investigation, _ = completed
    assert investigation.status == "complete"
    assert len(investigation.agents) == len(PIPELINE)
    for run in investigation.agents:
        assert run.status is AgentStatus.COMPLETE, run.agent
        assert run.summary


def test_agents_reach_the_same_conclusion_as_the_rule_engine(completed):
    """The agent layer must not drift away from the pipeline it sits on."""
    investigation, chain = completed
    assert investigation.initial_host == chain.initial_host
    assert investigation.current_host == chain.current_host
    assert investigation.current_stage == chain.current_stage
    assert investigation.potential_targets[0] == chain.predictions[0].host
    assert set(investigation.observed_techniques) <= {
        m.technique_id for m in chain.mitre
    }


def test_every_finding_cites_evidence_that_resolves(completed):
    investigation, _ = completed
    assert investigation.findings
    for finding in investigation.findings:
        assert finding.evidence_ids, finding.title
        for evidence_id in finding.evidence_ids:
            assert investigation.evidence_item(evidence_id) is not None


def test_the_timeline_records_tool_calls_not_deliberation(completed):
    investigation, _ = completed
    assert investigation.steps
    called = {call.tool for step in investigation.steps for call in step.tool_calls}
    assert "get_attack_chain" in called
    assert "score_next_targets" in called
    for step in investigation.steps:
        assert step.action
        # Steps are concise actions, not a reasoning dump.
        assert len(step.action) < 90


def test_prediction_is_labelled_and_never_asserted(completed):
    investigation, _ = completed
    predicted = [
        f for f in investigation.findings if f.assurance is Assurance.PREDICTED
    ]
    assert predicted
    for finding in predicted:
        assert "not observed attacker activity" in finding.statement
        assert " will " not in finding.statement.lower()


def test_metrics_describe_the_real_funnel(completed):
    investigation, _ = completed
    metrics = investigation.metrics
    assert metrics.raw_events == 56
    assert metrics.notable_events > metrics.attack_chains
    assert metrics.correlated_events > 0
    assert metrics.tool_calls > 20
    assert metrics.false_positive_candidates >= 0


# -------------------------------------------------------------- verification --


def test_verification_downgrades_a_finding_with_unresolvable_evidence():
    """The check has to be able to fail, or it is decoration."""
    settings, context, chains = _context()
    settings.agents.step_delay_seconds = 0.0

    investigation = new_investigation(chains[0].attack_chain_id, "test")
    workspace = AgentWorkspace(
        AgentName.GRAPH, investigation, ToolRegistry(context), settings
    )
    fabricated = workspace.evidence(
        "Attacker reached the backup server",
        event_ids=["evt-does-not-exist"],
    )
    finding_id = workspace.finding(
        "Backup server compromised",
        "The attacker reached BACKUP01.",
        assurance=Assurance.OBSERVED,
        confidence=0.9,
        evidence_ids=[fabricated],
    )

    verifier_workspace = AgentWorkspace(
        AgentName.VERIFICATION, investigation, ToolRegistry(context), settings
    )
    asyncio.run(VerificationAgent().run(verifier_workspace))

    finding = investigation.finding(finding_id)
    assert finding is not None
    assert finding.verified is False
    assert finding.confidence < 0.9
    assert finding.confidence_before_verification == 0.9
    assert any("do not resolve" in note for note in finding.verification_notes)


def test_verification_does_not_count_its_own_verdict(completed):
    investigation, _ = completed
    verdict = next(
        f for f in investigation.findings if f.title == "Verification complete"
    )
    others = [f for f in investigation.findings if f is not verdict]
    assert "of {} finding(s)".format(len(others)) in verdict.statement


# ---------------------------------------------------------- human in the loop --


def test_rejected_findings_leave_the_summary_but_stay_on_the_record(completed):
    investigation, _ = completed
    target = next(
        f for f in investigation.findings if f.assurance is Assurance.PREDICTED
    )
    target.analyst_decision = AnalystDecision.REJECTED

    summary = asyncio.run(build_summary(investigation, NullProvider()))
    assert all(target.statement not in line for line in summary.predicted)
    # Still present in the investigation itself.
    assert investigation.finding(target.finding_id) is not None
    target.analyst_decision = None


def test_summary_recommends_and_never_acts(completed):
    """Actions are proposed to the analyst, never reported as already taken."""
    investigation, _ = completed
    summary = investigation.summary
    assert summary is not None
    assert summary.recommended_actions

    claims_of_action = ("automatically", "has been", "have been", "was isolated", "we ")
    for action in summary.recommended_actions:
        lowered = action.lower()
        for phrase in claims_of_action:
            assert phrase not in lowered, action
        # Imperative, addressed to the analyst.
        assert action[0].isupper()


# -------------------------------------------------------------- llm guardrail --


def test_narrative_guard_rejects_invented_facts(completed):
    """A model may rephrase verified findings; it may not add new ones."""
    investigation, _ = completed

    faithful, _ = _is_faithful(
        "The attacker moved from HR-PC to FINANCE-PC using T1021.001.", investigation
    )
    assert faithful

    invented_host, reason = _is_faithful(
        "The attacker also compromised PAYROLL-SRV.", investigation
    )
    assert not invented_host
    assert "PAYROLL-SRV" in reason

    invented_technique, reason = _is_faithful(
        "This also matches T1486 ransomware behaviour.", investigation
    )
    assert not invented_technique
    assert "T1486" in reason


def test_default_narrator_is_deterministic(completed):
    investigation, _ = completed
    assert investigation.summary is not None
    assert investigation.summary.generated_by == "deterministic"


def test_triage_can_decline_and_the_orchestrator_stops():
    """The agent that says no is the one that keeps this from being alert spam."""
    from datetime import datetime, timezone

    from app.models.analysis import AttackChain, AttackStage
    from app.models.events import Action, EventType, NormalizedEvent, Severity

    settings = get_settings()
    settings.agents.step_delay_seconds = 0.0
    inventory = load_inventory(settings.inventory_file)

    when = datetime(2026, 9, 30, 10, 0, tzinfo=timezone.utc)
    quiet = [
        NormalizedEvent(
            event_id="quiet-{}".format(index),
            timestamp=when,
            event_type=EventType.DNS,
            action=Action.NEWLY_OBSERVED_DOMAIN,
            source_host="MKTG-PC",
            domain="vendor-{}.example".format(index),
            severity=Severity.MEDIUM,
            source_log="unit-test",
        )
        for index in range(2)
    ]
    chain = AttackChain(
        attack_chain_id="ATTACK-QUIET",
        name="quiet",
        start_time=when,
        last_seen=when,
        initial_host="MKTG-PC",
        current_host="MKTG-PC",
        hosts=["MKTG-PC"],
        event_ids=[e.event_id for e in quiet],
        event_count=len(quiet),
        stages=[
            AttackStage(
                order=1,
                tactic="Command and Control",
                label="Command and Control",
                timestamp=when,
                host="MKTG-PC",
                event_ids=[e.event_id for e in quiet],
            )
        ],
    )
    graph = build_entity_graph(quiet, inventory)
    context = ToolContext(quiet, [], [chain], graph, inventory, settings)

    investigation = new_investigation("ATTACK-QUIET", "test")
    result = asyncio.run(
        Orchestrator(settings, NullProvider()).run(investigation, context)
    )

    triage = result.agent_run(AgentName.TRIAGE)
    assert triage is not None
    assert triage.status is AgentStatus.COMPLETE
    assert triage.summary == "No investigation required"
    assert result.findings == []

    # Everything downstream is skipped, with the reason recorded.
    downstream = [r for r in result.agents if r.agent is not AgentName.TRIAGE]
    assert all(run.status is AgentStatus.SKIPPED for run in downstream)
    assert all(run.skip_reason for run in downstream)
    assert result.severity == "informational"
