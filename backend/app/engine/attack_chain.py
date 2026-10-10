"""Attack-chain detection: turn scored correlations into one attack story.

The pipeline is deliberately linear and inspectable:

1. group notable events into connected components over the correlation graph
2. order each component chronologically
3. map every event to MITRE techniques
4. collapse consecutive same-tactic events into timeline stages
5. run the lateral-movement rule over the component
6. work out which hosts were actually reached versus merely targeted
7. score potential next targets
8. write the root-cause narrative
"""

from __future__ import annotations

from datetime import datetime, timedelta

import networkx as nx

from app.core.config import Settings
from app.engine import mitre
from app.engine.lateral import detect_lateral_movement
from app.engine.prediction import build_context, predict_next_targets
from app.graph.builder import connectivity_scores, host_subgraph
from app.models.analysis import (
    Assurance,
    AttackChain,
    AttackStage,
    Confidence,
    Correlation,
    MitreMapping,
    RootCause,
    confidence_from_score,
)
from app.models.events import EventType, NormalizedEvent
from app.models.inventory import Inventory

#: Fallback tactics for events no MITRE rule claimed, so the timeline stays complete.
_FALLBACK_TACTIC: dict[str, tuple[str, str]] = {
    "MALICIOUS_ATTACHMENT": ("TA0001", "Initial Access"),
    "PROCESS_CREATE": ("TA0002", "Execution"),
    "SCRIPT_EXEC": ("TA0002", "Execution"),
    "SUSPICIOUS_EXECUTABLE": ("TA0002", "Execution"),
    "DISCOVERY_COMMAND": ("TA0007", "Discovery"),
    "CREDENTIAL_ACCESS": ("TA0006", "Credential Access"),
    "LOGIN_FAILURE": ("TA0006", "Credential Access"),
    "RDP_LOGIN": ("TA0008", "Lateral Movement"),
    "SMB_AUTH": ("TA0008", "Lateral Movement"),
    "NETWORK_LOGON": ("TA0008", "Lateral Movement"),
    "REMOTE_SERVICE_EXEC": ("TA0008", "Lateral Movement"),
    "PRIVILEGED_LOGIN": ("TA0004", "Privilege Escalation"),
    "SUSPICIOUS_DOMAIN": ("TA0011", "Command and Control"),
    "NEWLY_OBSERVED_DOMAIN": ("TA0011", "Command and Control"),
    "HIGH_VOLUME_DNS": ("TA0011", "Command and Control"),
}


def _components(
    events: list[NormalizedEvent], correlations: list[Correlation]
) -> list[list[NormalizedEvent]]:
    """Connected components of the correlation graph, newest-activity first."""
    notable = {e.event_id: e for e in events if e.is_notable}
    graph = nx.Graph()
    graph.add_nodes_from(notable)
    for link in correlations:
        if link.source_event_id in notable and link.target_event_id in notable:
            graph.add_edge(link.source_event_id, link.target_event_id)

    groups: list[list[NormalizedEvent]] = []
    for component in nx.connected_components(graph):
        members = sorted((notable[e] for e in component), key=lambda e: (e.timestamp, e.event_id))
        groups.append(members)
    groups.sort(key=lambda g: g[-1].timestamp, reverse=True)
    return groups


_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def _event_tactic(event: NormalizedEvent, mappings: list[MitreMapping]) -> tuple[str, str]:
    """The tactic that best represents one event.

    The most confident mapping wins, because a high-confidence Execution rule
    describes an event better than a speculative Command-and-Control one. Ties
    are broken by kill-chain position, so genuinely ambiguous events are
    reported at the later stage.
    """
    mine = [m for m in mappings if m.event_id == event.event_id]
    if mine:
        best = max(
            mine,
            key=lambda m: (
                _CONFIDENCE_RANK.get(m.confidence, 0),
                mitre.TACTIC_ORDER.get(m.tactic_id, -1),
            ),
        )
        return best.tactic_id, best.tactic
    return _FALLBACK_TACTIC.get(event.action.value, ("TA0002", "Execution"))


def _stage_host(event: NormalizedEvent) -> str | None:
    """The host a stage should be pinned to.

    A failed logon happened *from* the source host; attributing it to the
    destination would place a stage on a machine the attacker never reached.
    """
    if event.event_type is EventType.AUTHENTICATION and event.outcome == "failure":
        return event.source_host or event.destination_host
    return event.primary_host


def _build_stages(events: list[NormalizedEvent], mappings: list[MitreMapping]) -> list[AttackStage]:
    """Group events into one stage per (tactic, host) pair.

    Interleaved activity (a C2 beacon between two execution events) would
    otherwise fragment the timeline into dozens of one-event stages. Recurrences
    of a tactic on the same host therefore fold back into the stage that already
    represents them, and the stage records when it was last active.
    """
    stages: dict[tuple[str, str], AttackStage] = {}
    for event in events:
        _, tactic = _event_tactic(event, mappings)
        host = _stage_host(event)
        key = (tactic, (host or "unknown").upper())
        techniques = [m.technique_id for m in mappings if m.event_id == event.event_id]

        stage = stages.get(key)
        if stage is None:
            stages[key] = AttackStage(
                order=0,
                tactic=tactic,
                label=tactic,
                timestamp=event.timestamp,
                last_timestamp=event.timestamp,
                host=host,
                user=event.user,
                event_ids=[event.event_id],
                technique_ids=list(techniques),
                description=event.summary(),
                assurance=Assurance.OBSERVED,
            )
            continue

        stage.event_ids.append(event.event_id)
        stage.last_timestamp = event.timestamp
        stage.user = stage.user or event.user
        for tid in techniques:
            if tid not in stage.technique_ids:
                stage.technique_ids.append(tid)

    ordered = sorted(stages.values(), key=lambda s: s.timestamp)
    for position, stage in enumerate(ordered, start=1):
        stage.order = position
    return ordered


def _reached_and_targeted(events: list[NormalizedEvent]) -> tuple[list[str], list[str]]:
    """Split hosts into "attacker actually got here" and "attacker aimed here".

    A failed logon proves intent, not access, so its destination is recorded as
    targeted rather than compromised. This distinction is what keeps a predicted
    next target out of the compromised-host count.
    """
    reached: set[str] = set()
    targeted: set[str] = set()

    for event in events:
        if event.event_type is EventType.AUTHENTICATION:
            if event.source_host:
                reached.add(event.source_host)
            if event.destination_host:
                if event.outcome == "failure":
                    targeted.add(event.destination_host)
                else:
                    reached.add(event.destination_host)
        else:
            if event.primary_host:
                reached.add(event.primary_host)

    targeted -= reached
    return sorted(reached), sorted(targeted)


def _current_host(events: list[NormalizedEvent], reached: list[str]) -> str | None:
    """Where the attacker is running code right now.

    Execution is stronger evidence of presence than an authentication, so the
    most recent endpoint event wins; otherwise fall back to the most recent
    successful logon destination.
    """
    for event in reversed(events):
        if event.event_type is EventType.ENDPOINT and event.primary_host:
            return event.primary_host
    for event in reversed(events):
        if event.destination_host and event.outcome != "failure":
            return event.destination_host
    return reached[-1] if reached else None


def _risk_score(
    events: list[NormalizedEvent],
    mappings: list[MitreMapping],
    lateral_count: int,
    top_prediction: float,
) -> int:
    """A transparent 0-100 chain risk score.

    Each term below is a documented contribution, not a learned weight.
    """
    tactics = {m.tactic_id for m in mappings}
    score = 15.0  # a correlated multi-event chain is never zero risk
    score += min(20.0, 5.0 * len(tactics))
    if "TA0006" in tactics:
        score += 20.0  # credential access
    if "TA0008" in tactics or lateral_count:
        score += 20.0  # lateral movement
    if "TA0011" in tactics:
        score += 10.0  # command and control
    if any(e.severity.value == "critical" for e in events):
        score += 10.0
    score += 0.15 * top_prediction  # proximity to a high-value target
    return int(min(100.0, round(score)))


def _severity_label(risk: int) -> str:
    if risk >= 80:
        return "critical"
    if risk >= 60:
        return "high"
    if risk >= 40:
        return "medium"
    return "low"


def _root_cause(
    events: list[NormalizedEvent],
    stages: list[AttackStage],
    mappings: list[MitreMapping],
    current_host: str | None,
    current_stage: str,
    lateral_count: int,
    top_target: str | None,
) -> RootCause:
    first = events[0]
    first_mappings = [m for m in mappings if m.event_id == first.event_id]
    evidence = first_mappings[0].evidence if first_mappings else first.summary()

    progression: list[str] = []
    for stage in stages:
        progression.append("{} on {}".format(stage.tactic, stage.host or "unknown host"))

    notes = [
        "Stage sequence and host attribution are OBSERVED, taken directly from the source events.",
        "Grouping these events into one chain is CORRELATED, based on shared identity, host and timing.",
    ]
    if lateral_count:
        notes.append(
            "Lateral movement is INFERRED from the rule engine, not stated by any single log record."
        )
    if top_target:
        notes.append(
            "{} is PREDICTED as a next target from graph context; no attacker activity has been "
            "observed on it.".format(top_target)
        )

    status = "{} in progress on {}".format(current_stage, current_host or "an unknown host")
    return RootCause(
        initial_host=first.primary_host,
        initial_user=first.user,
        initial_event_id=first.event_id,
        initial_evidence=evidence,
        observed_progression=progression,
        current_status=status,
        potential_next_target=top_target,
        inference_notes=notes,
    )


def _shows_attack_behaviour(members: list[NormalizedEvent]) -> bool:
    """True if the cluster holds more than routine sign-ins.

    That is: an event a detection rule flagged as suspicious (malicious
    attachment, encoded PowerShell, credential access, suspicious domain,
    admin-share access, password guessing, ...), or a notable non-logon event
    (process, file or DNS activity).
    """
    return any(
        e.suspicious or (e.event_type is not EventType.AUTHENTICATION and e.is_notable)
        for e in members
    )


def build_chains(
    events: list[NormalizedEvent],
    correlations: list[Correlation],
    graph: nx.MultiDiGraph,
    inventory: Inventory,
    settings: Settings,
) -> list[AttackChain]:
    """Detect every attack chain present in the current event set."""
    if not events:
        return []

    connectivity = connectivity_scores(graph)
    projection = host_subgraph(graph)
    latest_overall = max(e.timestamp for e in events)
    known_hosts = inventory.host_names()

    by_pair = {
        frozenset((c.source_event_id, c.target_event_id)): c for c in correlations
    }

    chains: list[AttackChain] = []
    index = 0
    for members in _components(events, correlations):
        if len(members) < settings.correlation.min_chain_events:
            continue
        # A cluster of logons alone is not an attack: someone using their own
        # computer produces exactly that. A chain needs at least one piece of
        # attack behaviour before any host is called compromised.
        if not _shows_attack_behaviour(members):
            continue
        index += 1

        member_ids = {e.event_id for e in members}
        chain_links = [
            c
            for key, c in by_pair.items()
            if key <= member_ids
        ]
        mappings = mitre.map_events(members)
        lateral = detect_lateral_movement(
            members, chain_links, settings.lateral, settings.correlation
        )
        stages = _build_stages(members, mappings)
        reached, targeted = _reached_and_targeted(members)
        current_host = _current_host(members, reached)
        users = sorted({e.user for e in members if e.user})

        chain_id = "ATTACK-{:03d}".format(index)
        ctx = build_context(
            events=members,
            compromised_hosts=set(reached),
            current_host=current_host,
            users=set(users),
            connectivity=connectivity,
            known_hosts=known_hosts,
            attack_chain_id=chain_id,
        )
        predictions = predict_next_targets(inventory, projection, ctx, settings.prediction)

        # The headline stage is whatever the newest event in the chain represents.
        current_stage = _event_tactic(members[-1], mappings)[1] if members else "Unknown"
        top_prediction = predictions[0].score if predictions else 0.0
        risk = _risk_score(members, mappings, len(lateral), top_prediction)
        mean_score = (
            round(sum(c.score for c in chain_links) / len(chain_links), 4) if chain_links else 0.0
        )
        confidence = (
            confidence_from_score(mean_score) if chain_links else Confidence.LOW
        )
        dormant = (latest_overall - members[-1].timestamp) > timedelta(hours=1)

        chains.append(
            AttackChain(
                attack_chain_id=chain_id,
                name="{} -> {}".format(members[0].primary_host or "unknown", current_host or "unknown"),
                status="dormant" if dormant else "active",
                severity=_severity_label(risk),
                risk_score=risk,
                start_time=members[0].timestamp,
                last_seen=members[-1].timestamp,
                initial_host=members[0].primary_host,
                current_host=current_host,
                users=users,
                hosts=reached,
                targeted_hosts=targeted,
                event_ids=[e.event_id for e in members],
                event_count=len(members),
                correlation_count=len(chain_links),
                mean_correlation_score=mean_score,
                current_stage=current_stage,
                stages=stages,
                mitre=mappings,
                lateral_movements=lateral,
                predictions=predictions,
                confidence=confidence,
                root_cause=_root_cause(
                    members,
                    stages,
                    mappings,
                    current_host,
                    current_stage,
                    len(lateral),
                    predictions[0].host if predictions else None,
                ),
            )
        )

    chains.sort(key=lambda c: (c.risk_score, c.last_seen), reverse=True)
    # Renumber so the highest-risk chain is ATTACK-001 in the UI.
    for position, chain in enumerate(chains, start=1):
        new_id = "ATTACK-{:03d}".format(position)
        for prediction in chain.predictions:
            prediction.attack_chain_id = new_id
        chain.attack_chain_id = new_id
    return chains


def latest_activity(chains: list[AttackChain]) -> datetime | None:
    if not chains:
        return None
    return max(c.last_seen for c in chains)
