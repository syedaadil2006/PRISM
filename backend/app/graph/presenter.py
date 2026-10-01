"""Build the Cytoscape.js payload from backend analysis.

The frontend draws exactly what this module emits. No topology, relationship or
node state is decided client side, which is why the same UI works unchanged
against a different dataset.

The payload is deliberately trimmed: only entities that belong to an attack
chain, plus the hosts the chain is predicted to reach next. A screen with four
hundred nodes answers no questions.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.graph import builder
from app.models.analysis import AttackChain, TargetPrediction
from app.models.events import EventType, NormalizedEvent
from app.models.graph import (
    EdgeKind,
    GraphEdge,
    GraphNode,
    GraphPayload,
    NodeKind,
    NodeState,
)
from app.models.inventory import Inventory


class _PayloadBuilder:
    """Accumulates nodes and edges, merging duplicates as it goes."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}

    #: Node states in increasing order of importance; a stronger state wins.
    _STATE_RANK = {
        NodeState.NORMAL: 0,
        NodeState.SUSPICIOUS: 1,
        NodeState.POTENTIAL_TARGET: 2,
        NodeState.COMPROMISED: 3,
        NodeState.CURRENT_POSITION: 4,
    }

    def node(
        self,
        node_id: str,
        label: str,
        kind: NodeKind,
        state: NodeState = NodeState.NORMAL,
        assurance: str = "observed",
        chain_id: str | None = None,
        stage_order: int | None = None,
        **metadata: object,
    ) -> str:
        existing = self.nodes.get(node_id)
        if existing is None:
            self.nodes[node_id] = GraphNode(
                id=node_id,
                label=label,
                kind=kind,
                state=state,
                assurance=assurance,
                attack_chain_ids=[chain_id] if chain_id else [],
                stage_order=stage_order,
                metadata={k: v for k, v in metadata.items() if v is not None},
            )
            return node_id

        if self._STATE_RANK[state] > self._STATE_RANK[existing.state]:
            existing.state = state
            existing.assurance = assurance
        if chain_id and chain_id not in existing.attack_chain_ids:
            existing.attack_chain_ids.append(chain_id)
        if stage_order is not None and (existing.stage_order is None or stage_order < existing.stage_order):
            existing.stage_order = stage_order
        existing.metadata.update({k: v for k, v in metadata.items() if v is not None})
        return node_id

    def edge(
        self,
        source: str,
        target: str,
        kind: EdgeKind,
        label: str = "",
        assurance: str = "observed",
        predicted: bool = False,
        chain_id: str | None = None,
        event_id: str | None = None,
        **metadata: object,
    ) -> None:
        if source not in self.nodes or target not in self.nodes:
            return
        edge_id = "{}|{}|{}".format(source, kind.value, target)
        existing = self.edges.get(edge_id)
        if existing is None:
            self.edges[edge_id] = GraphEdge(
                id=edge_id,
                source=source,
                target=target,
                kind=kind,
                label=label or kind.value.replace("_", " ").title(),
                assurance=assurance,
                predicted=predicted,
                attack_chain_ids=[chain_id] if chain_id else [],
                event_ids=[event_id] if event_id else [],
                metadata={k: v for k, v in metadata.items() if v is not None},
            )
            return
        if chain_id and chain_id not in existing.attack_chain_ids:
            existing.attack_chain_ids.append(chain_id)
        if event_id and event_id not in existing.event_ids:
            existing.event_ids.append(event_id)
        existing.metadata.update({k: v for k, v in metadata.items() if v is not None})

    def payload(self) -> GraphPayload:
        nodes = list(self.nodes.values())
        edges = list(self.edges.values())
        stats = {
            "nodes": len(nodes),
            "edges": len(edges),
            "predicted_edges": sum(1 for e in edges if e.predicted),
            "compromised_hosts": sum(
                1
                for n in nodes
                if n.kind is NodeKind.HOST
                and n.state in {NodeState.COMPROMISED, NodeState.CURRENT_POSITION}
            ),
        }
        return GraphPayload(
            nodes=nodes,
            edges=edges,
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
            stats=stats,
        )


def _stage_index(chain: AttackChain) -> dict[str, int]:
    """Map every event id in a chain to the timeline stage it belongs to."""
    index: dict[str, int] = {}
    for stage in chain.stages:
        for event_id in stage.event_ids:
            index[event_id] = stage.order
    return index


#: Predictions below this score stay in the API and the intel panel but off
#: the graph, so the board shows the targets an analyst would act on.
GRAPH_PREDICTION_FLOOR = 60.0


def _graph_predictions(chain: AttackChain) -> list[TargetPrediction]:
    """The predictions worth drawing: the credible ones, always at least one."""
    credible = [p for p in chain.predictions if p.score >= GRAPH_PREDICTION_FLOOR]
    return credible or chain.predictions[:1]


def _host_state(chain: AttackChain, host: str, predicted: set[str]) -> NodeState:
    upper = host.upper()
    if chain.current_host and upper == chain.current_host.upper():
        return NodeState.CURRENT_POSITION
    if upper in {h.upper() for h in chain.hosts}:
        return NodeState.COMPROMISED
    if upper in predicted:
        return NodeState.POTENTIAL_TARGET
    if upper in {h.upper() for h in chain.targeted_hosts}:
        return NodeState.SUSPICIOUS
    return NodeState.NORMAL


def _add_identities(
    out: _PayloadBuilder, chain: AttackChain, inventory: Inventory
) -> None:
    for user_name in chain.users:
        identity = inventory.user(user_name)
        out.node(
            builder.user_id(user_name),
            user_name,
            NodeKind.USER,
            state=NodeState.COMPROMISED,
            chain_id=chain.attack_chain_id,
            privilege=identity.privilege if identity else None,
            privileged=identity.is_privileged if identity else None,
            department=identity.department if identity else None,
            groups=identity.groups if identity else None,
        )


def _add_event_entities(
    out: _PayloadBuilder,
    chain: AttackChain,
    event: NormalizedEvent,
    stage_order: int | None,
    add_host,
    chain_processes: set[str],
) -> None:
    """Add the entities and relationships one event contributes."""
    host_node = add_host(event.primary_host, stage_order)
    user_node = builder.user_id(event.user) if event.user else None
    event_id = event.event_id

    if event.event_type is EventType.AUTHENTICATION:
        source_node = add_host(event.source_host, stage_order)
        dest_node = add_host(event.destination_host, stage_order)
        if user_node and dest_node:
            out.edge(
                user_node,
                dest_node,
                EdgeKind.LOGGED_INTO,
                label="{} ({})".format(event.action.value, event.outcome or "success"),
                chain_id=chain.attack_chain_id,
                event_id=event_id,
                outcome=event.outcome,
                timestamp=event.timestamp.isoformat(),
            )
        if source_node and dest_node and source_node != dest_node:
            out.edge(
                source_node,
                dest_node,
                EdgeKind.CONNECTED_TO,
                label=event.action.value,
                chain_id=chain.attack_chain_id,
                event_id=event_id,
                outcome=event.outcome,
                timestamp=event.timestamp.isoformat(),
            )
        return

    if event.event_type is EventType.DNS and event.domain:
        domain_node = out.node(
            builder.domain_id(event.domain),
            event.domain,
            NodeKind.DOMAIN,
            state=NodeState.SUSPICIOUS if event.suspicious else NodeState.NORMAL,
            chain_id=chain.attack_chain_id,
            stage_order=stage_order,
            action=event.action.value,
            severity=event.severity.value,
        )
        if host_node:
            out.edge(
                host_node,
                domain_node,
                EdgeKind.RESOLVED,
                label=event.action.value,
                chain_id=chain.attack_chain_id,
                event_id=event_id,
                timestamp=event.timestamp.isoformat(),
            )
        return

    if event.event_type is EventType.ENDPOINT and host_node:
        if event.process:
            process_node = out.node(
                builder.process_id(event.process, event.primary_host),
                event.process,
                NodeKind.PROCESS,
                state=NodeState.SUSPICIOUS if event.suspicious else NodeState.NORMAL,
                chain_id=chain.attack_chain_id,
                stage_order=stage_order,
                command_line=event.command_line,
                action=event.action.value,
                severity=event.severity.value,
                host=event.primary_host,
            )
            out.edge(
                host_node,
                process_node,
                EdgeKind.EXECUTED,
                label=event.action.value,
                chain_id=chain.attack_chain_id,
                event_id=event_id,
                timestamp=event.timestamp.isoformat(),
            )
            # A parent is only worth drawing when it is part of the story
            # itself, such as the Office process that spawned the
            # interpreter. Drawing every explorer.exe just crowds the board.
            if event.parent_process and event.parent_process.lower() in chain_processes:
                parent_node = out.node(
                    builder.process_id(event.parent_process, event.primary_host),
                    event.parent_process,
                    NodeKind.PROCESS,
                    state=NodeState.SUSPICIOUS,
                    chain_id=chain.attack_chain_id,
                    stage_order=stage_order,
                    host=event.primary_host,
                )
                out.edge(
                    parent_node,
                    process_node,
                    EdgeKind.EXECUTED,
                    label="Spawned",
                    chain_id=chain.attack_chain_id,
                    event_id=event_id,
                )
        if event.file_name:
            file_node = out.node(
                builder.file_id(event.file_name, event.primary_host),
                event.file_name,
                NodeKind.FILE,
                state=NodeState.SUSPICIOUS,
                chain_id=chain.attack_chain_id,
                stage_order=stage_order,
                host=event.primary_host,
            )
            out.edge(
                host_node,
                file_node,
                EdgeKind.DROPPED,
                label="Dropped",
                chain_id=chain.attack_chain_id,
                event_id=event_id,
            )


def _add_chain(
    out: _PayloadBuilder,
    chain: AttackChain,
    events: dict[str, NormalizedEvent],
    inventory: Inventory,
) -> None:
    stages = _stage_index(chain)
    drawn_predictions = _graph_predictions(chain)
    predicted = {p.host.upper() for p in drawn_predictions}

    def add_host(name: str | None, stage_order: int | None = None) -> str | None:
        if not name:
            return None
        asset = inventory.host(name)
        state = _host_state(chain, name, predicted)
        return out.node(
            builder.host_id(name),
            name,
            NodeKind.HOST,
            state=state,
            assurance="predicted" if state is NodeState.POTENTIAL_TARGET else "observed",
            chain_id=chain.attack_chain_id,
            stage_order=stage_order,
            role=asset.role if asset else None,
            criticality=asset.criticality if asset else None,
            critical_infrastructure=asset.is_critical_infrastructure if asset else None,
            ip=asset.ip if asset else None,
            zone=asset.zone if asset else None,
        )

    # The attack itself, so the story has an anchor in the graph.
    attack_node = out.node(
        "attack:" + chain.attack_chain_id,
        chain.attack_chain_id,
        NodeKind.ATTACK,
        state=NodeState.COMPROMISED,
        assurance="correlated",
        chain_id=chain.attack_chain_id,
        risk_score=chain.risk_score,
        current_stage=chain.current_stage,
        status=chain.status,
        event_count=chain.event_count,
    )

    _add_identities(out, chain, inventory)

    for host_name in chain.hosts:
        add_host(host_name)
    for host_name in chain.targeted_hosts:
        add_host(host_name)
    for prediction in drawn_predictions:
        add_host(prediction.host)

    if chain.initial_host:
        out.edge(
            attack_node,
            builder.host_id(chain.initial_host),
            EdgeKind.PART_OF,
            label="Origin",
            assurance="correlated",
            chain_id=chain.attack_chain_id,
        )

    chain_processes = {
        events[eid].process.lower()
        for eid in chain.event_ids
        if eid in events and events[eid].process
    }

    for event_id in chain.event_ids:
        event = events.get(event_id)
        if event is not None:
            _add_event_entities(
                out, chain, event, stages.get(event_id), add_host, chain_processes
            )

    for movement in chain.lateral_movements:
        source_node = add_host(movement.source_host)
        dest_node = add_host(movement.destination_host)
        if source_node and dest_node:
            out.edge(
                source_node,
                dest_node,
                EdgeKind.LATERAL_MOVE,
                label="Lateral Movement ({})".format(movement.method),
                assurance="inferred",
                chain_id=chain.attack_chain_id,
                event_id=movement.event_id,
                confidence=movement.confidence.value,
                correlation_score=movement.correlation_score,
            )

    for prediction in drawn_predictions:
        target_node = builder.host_id(prediction.host)
        if chain.current_host:
            out.edge(
                builder.host_id(chain.current_host),
                target_node,
                EdgeKind.PREDICTED_MOVE,
                label="Potential target ({:.0f}/100)".format(prediction.score),
                assurance="predicted",
                predicted=True,
                chain_id=chain.attack_chain_id,
                score=prediction.score,
                confidence=prediction.confidence.value,
            )
        for user_name in chain.users:
            identity = inventory.user(user_name)
            if identity and any(
                h.upper() == prediction.host.upper() for h in identity.accessible_hosts
            ):
                out.edge(
                    builder.user_id(user_name),
                    target_node,
                    EdgeKind.ACCESSES,
                    label="Has access",
                    assurance="inferred",
                    chain_id=chain.attack_chain_id,
                )


def build_presentation_graph(
    chains: list[AttackChain],
    events: list[NormalizedEvent],
    inventory: Inventory,
    chain_id: str | None = None,
) -> GraphPayload:
    """Build the graph the dashboard renders, optionally focused on one chain."""
    by_id = {e.event_id: e for e in events}
    selected = [c for c in chains if chain_id is None or c.attack_chain_id == chain_id]
    out = _PayloadBuilder()
    for chain in selected:
        _add_chain(out, chain, by_id, inventory)
    return out.payload()
