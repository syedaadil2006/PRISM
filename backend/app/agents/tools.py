"""The evidence-retrieval tool layer.

This is the only way an agent is allowed to obtain a fact. Agents do not hold
knowledge and do not reimplement detection: they call these tools, which read
the same analysis the dashboard reads and wrap the same engines the rule-based
pipeline already uses.

Two consequences fall out of that, and both matter:

* every answer an agent gives can be traced to a recorded tool call, and
* the agent layer cannot drift away from the rule-based layer, because there is
  only one implementation of each piece of analysis.

Each tool publishes a JSON-schema parameter spec. That is what makes this a
tool-calling interface rather than a set of helper functions: an LLM provider
can be handed the same catalogue and call the same tools.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable

import networkx as nx

from app.agents.state import EvidenceKind, ToolCall
from app.core.config import Settings
from app.engine import mitre
from app.engine.prediction import build_context, predict_next_targets
from app.graph import builder
from app.models.analysis import AttackChain, Correlation
from app.models.events import EventType, NormalizedEvent
from app.models.inventory import Inventory


@dataclass
class ToolResult:
    """What a tool returns, plus the provenance an agent needs to cite it."""

    summary: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    node_ids: list[str] = field(default_factory=list)
    kind: EvidenceKind = EvidenceKind.EVENT
    #: Facts about the result as a whole rather than about any one row.
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.rows)

    @property
    def found(self) -> bool:
        return bool(self.rows)


@dataclass
class ToolContext:
    """The world a tool reads from. Never mutated by a tool."""

    events: list[NormalizedEvent]
    correlations: list[Correlation]
    chains: list[AttackChain]
    graph: nx.MultiDiGraph
    inventory: Inventory
    settings: Settings

    def chain(self, chain_id: str | None) -> AttackChain | None:
        if not chain_id:
            return None
        for candidate in self.chains:
            if candidate.attack_chain_id == chain_id:
                return candidate
        return None

    def event(self, event_id: str) -> NormalizedEvent | None:
        for candidate in self.events:
            if candidate.event_id == event_id:
                return candidate
        return None


ToolHandler = Callable[[ToolContext, dict[str, Any]], ToolResult]


@dataclass(frozen=True)
class Tool:
    """A named, described, schema-carrying retrieval function."""

    name: str
    category: str
    description: str
    parameters: dict[str, Any]
    handler: ToolHandler

    def schema(self) -> dict[str, Any]:
        """The shape an LLM provider needs to call this tool."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": self.parameters,
                "required": [
                    key
                    for key, spec in self.parameters.items()
                    if spec.get("required", False)
                ],
            },
        }


def _event_row(event: NormalizedEvent) -> dict[str, Any]:
    """The projection of an event an agent reasons over."""
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type.value,
        "action": event.action.value,
        "user": event.user,
        "source_host": event.source_host,
        "destination_host": event.destination_host,
        "source_ip": event.source_ip,
        "process": event.process,
        "parent_process": event.parent_process,
        "domain": event.domain,
        "outcome": event.outcome,
        "severity": event.severity.value,
        "suspicious": event.suspicious,
        "summary": event.summary(),
        "findings": [t.split("finding:", 1)[1] for t in event.tags if t.startswith("finding:")],
    }


def _filter_events(
    ctx: ToolContext,
    event_type: EventType | None,
    args: dict[str, Any],
) -> list[NormalizedEvent]:
    """Shared filtering for the four log-search tools."""
    host = (args.get("host") or "").upper() or None
    user = (args.get("user") or "").lower() or None
    action = (args.get("action") or "").upper() or None
    domain = (args.get("domain") or "").lower() or None
    process = (args.get("process") or "").lower() or None
    suspicious_only = bool(args.get("suspicious_only", False))
    since = args.get("since")
    until = args.get("until")
    window_seconds = args.get("window_seconds")
    around = args.get("around_event_id")

    start: datetime | None = None
    end: datetime | None = None
    if around and window_seconds:
        anchor = ctx.event(str(around))
        if anchor is not None:
            delta = timedelta(seconds=float(window_seconds))
            start, end = anchor.timestamp - delta, anchor.timestamp + delta
    if since:
        start = datetime.fromisoformat(str(since))
    if until:
        end = datetime.fromisoformat(str(until))

    selected: list[NormalizedEvent] = []
    for event in ctx.events:
        if event_type is not None and event.event_type is not event_type:
            continue
        if host and host not in {h.upper() for h in event.hosts()}:
            continue
        if user and (event.user or "").lower() != user:
            continue
        if action and event.action.value != action:
            continue
        if domain and (event.domain or "").lower() != domain:
            continue
        if process and process not in (event.process or "").lower():
            continue
        if suspicious_only and not event.is_notable:
            continue
        if start and event.timestamp < start:
            continue
        if end and event.timestamp > end:
            continue
        selected.append(event)

    selected.sort(key=lambda e: e.timestamp)
    limit = int(args.get("limit", 50))
    return selected[:limit]


def _log_search(event_type: EventType | None, label: str) -> ToolHandler:
    def handler(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
        matches = _filter_events(ctx, event_type, args)
        rows = [_event_row(e) for e in matches]
        hosts = sorted({h for e in matches for h in e.hosts()})
        if matches:
            span = "{} to {}".format(
                matches[0].timestamp.strftime("%H:%M:%S"),
                matches[-1].timestamp.strftime("%H:%M:%S"),
            )
            summary = "{} {} record(s) across {} ({})".format(
                len(matches), label, ", ".join(hosts) or "no host", span
            )
        else:
            summary = "No {} records matched".format(label)
        return ToolResult(
            summary=summary,
            rows=rows,
            event_ids=[e.event_id for e in matches],
            node_ids=[builder.host_id(h) for h in hosts],
            kind=EvidenceKind.EVENT,
        )

    return handler


_SEARCH_PARAMS: dict[str, Any] = {
    "host": {"type": "string", "description": "Host name; matches source or destination"},
    "user": {"type": "string", "description": "Account name"},
    "action": {"type": "string", "description": "Canonical action, e.g. RDP_LOGIN"},
    "suspicious_only": {"type": "boolean", "description": "Only events the normalizer flagged"},
    "around_event_id": {"type": "string", "description": "Centre the window on this event"},
    "window_seconds": {"type": "number", "description": "Half-width of that window"},
    "since": {"type": "string", "description": "ISO-8601 lower bound"},
    "until": {"type": "string", "description": "ISO-8601 upper bound"},
    "limit": {"type": "integer", "description": "Maximum rows (default 50)"},
}


# --------------------------------------------------------------------------- #
# graph tools
# --------------------------------------------------------------------------- #

def _get_host_neighbors(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Which hosts a host can reach, and which were observed talking to it."""
    host = str(args.get("host", "")).upper()
    if not host:
        return ToolResult(summary="No host given", kind=EvidenceKind.GRAPH)

    projection = builder.host_subgraph(ctx.graph)
    node = builder.host_id(host)
    if node not in projection:
        return ToolResult(
            summary="{} is not in the graph".format(host), kind=EvidenceKind.GRAPH
        )

    rows: list[dict[str, Any]] = []
    for peer in sorted(projection.neighbors(node)):
        name = peer.split(":", 1)[1]
        asset = ctx.inventory.host(name)
        observed = any(
            data.get("observed")
            for _, _, data in ctx.graph.edges(node, data=True)
            if data.get("kind") == "CONNECTED_TO"
        )
        rows.append(
            {
                "host": name,
                "role": asset.role if asset else "unknown",
                "criticality": asset.criticality if asset else 0.0,
                "critical_infrastructure": asset.is_critical_infrastructure if asset else False,
                "observed_traffic": observed,
            }
        )

    return ToolResult(
        summary="{} can reach {} host(s): {}".format(
            host, len(rows), ", ".join(r["host"] for r in rows) or "none"
        ),
        rows=rows,
        node_ids=[node] + [builder.host_id(r["host"]) for r in rows],
        kind=EvidenceKind.GRAPH,
    )


def _get_user_access(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Entitlements for an account, and which of them were actually used."""
    user = str(args.get("user", "")).lower()
    identity = ctx.inventory.user(user)
    if identity is None:
        return ToolResult(
            summary="{} is not in the identity inventory".format(user or "?"),
            kind=EvidenceKind.INVENTORY,
        )

    # An attempt is not an access. Track the two separately, because a failed
    # logon against a host must never read as the account having reached it.
    seen: dict[str, list[str]] = {}
    succeeded: dict[str, list[str]] = {}
    for event in ctx.events:
        if (event.user or "").lower() != user:
            continue
        for host in event.hosts():
            seen.setdefault(host.upper(), []).append(event.event_id)
        if event.destination_host and event.outcome == "failure":
            continue
        for host in event.hosts():
            succeeded.setdefault(host.upper(), []).append(event.event_id)

    rows = []
    for host_name in identity.accessible_hosts:
        asset = ctx.inventory.host(host_name)
        key = host_name.upper()
        rows.append(
            {
                "host": host_name,
                "entitled": True,
                "activity_seen": key in seen,
                "access_succeeded": key in succeeded,
                "observed_event_ids": seen.get(key, [])[:5],
                "criticality": asset.criticality if asset else 0.0,
                "critical_infrastructure": asset.is_critical_infrastructure if asset else False,
            }
        )

    reached = [r["host"] for r in rows if r["access_succeeded"]]
    attempted = [r["host"] for r in rows if r["activity_seen"] and not r["access_succeeded"]]
    return ToolResult(
        summary="{} is entitled to {} host(s); reached {}{}".format(
            identity.name,
            len(rows),
            ", ".join(reached) or "none of them",
            "; attempted but not reached: " + ", ".join(attempted) if attempted else "",
        ),
        rows=rows,
        event_ids=[eid for ids in seen.values() for eid in ids][:40],
        node_ids=[builder.user_id(identity.name)]
        + [builder.host_id(r["host"]) for r in rows],
        kind=EvidenceKind.INVENTORY,
    )


def _get_attack_path(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Shortest reachability path between two hosts."""
    source = str(args.get("source_host", "")).upper()
    target = str(args.get("target_host", "")).upper()
    projection = builder.host_subgraph(ctx.graph)
    src, dst = builder.host_id(source), builder.host_id(target)

    if src not in projection or dst not in projection:
        return ToolResult(
            summary="{} or {} is not in the graph".format(source, target),
            kind=EvidenceKind.GRAPH,
        )
    try:
        path = nx.shortest_path(projection, src, dst)
    except nx.NetworkXNoPath:
        return ToolResult(
            summary="No path from {} to {} in the known topology".format(source, target),
            kind=EvidenceKind.GRAPH,
        )

    names = [node.split(":", 1)[1] for node in path]
    return ToolResult(
        summary="{} reaches {} in {} hop(s): {}".format(
            source, target, len(names) - 1, " -> ".join(names)
        ),
        rows=[{"path": names, "hops": len(names) - 1}],
        node_ids=list(path),
        kind=EvidenceKind.GRAPH,
    )


def _get_related_events(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Events the correlation engine already scored against this one.

    The agent does not re-derive correlation: it reads what the engine found,
    which is why the agent view and the rule-based view can never disagree.
    """
    event_id = str(args.get("event_id", ""))
    threshold = float(args.get("min_score", 0.0))

    links = [
        link
        for link in ctx.correlations
        if event_id in (link.source_event_id, link.target_event_id)
        and link.score >= threshold
    ]
    links.sort(key=lambda link: link.score, reverse=True)
    limit = int(args.get("limit", 25))
    links = links[:limit]

    rows = []
    related_ids: list[str] = []
    for link in links:
        other = (
            link.target_event_id
            if link.source_event_id == event_id
            else link.source_event_id
        )
        related_ids.append(other)
        event = ctx.event(other)
        rows.append(
            {
                "related_event_id": other,
                "score": link.score,
                "time_delta_seconds": link.time_delta_seconds,
                "factors": [
                    {"name": f.name, "weight": f.weight, "detail": f.detail}
                    for f in link.factors
                ],
                "summary": event.summary() if event else "",
            }
        )

    return ToolResult(
        summary="{} event(s) correlate with {}{}".format(
            len(rows),
            event_id,
            " at score {:.2f} or better".format(threshold) if threshold else "",
        ),
        rows=rows,
        event_ids=[event_id] + related_ids,
        kind=EvidenceKind.CORRELATION,
    )


def _get_recent_activity(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """What happened on a host or to an account in a trailing window."""
    host = (args.get("host") or "").upper() or None
    user = (args.get("user") or "").lower() or None
    minutes = float(args.get("minutes", 30))

    if not ctx.events:
        return ToolResult(summary="No events loaded")

    latest = max(e.timestamp for e in ctx.events)
    cutoff = latest - timedelta(minutes=minutes)

    matches = [
        e
        for e in ctx.events
        if e.timestamp >= cutoff
        and (not host or host in {h.upper() for h in e.hosts()})
        and (not user or (e.user or "").lower() == user)
    ]
    matches.sort(key=lambda e: e.timestamp)
    matches = matches[: int(args.get("limit", 40))]

    subject = host or user or "the environment"
    flagged = sum(1 for e in matches if e.is_notable)
    return ToolResult(
        summary="{} event(s) on {} in the last {:.0f} minutes, {} flagged".format(
            len(matches), subject, minutes, flagged
        ),
        rows=[_event_row(e) for e in matches],
        event_ids=[e.event_id for e in matches],
        node_ids=[builder.host_id(host)] if host else [],
    )


def _get_privileged_users(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Which accounts hold privilege, optionally only those reaching a host."""
    host = (args.get("host") or "").upper() or None
    rows = []
    for identity in ctx.inventory.users:
        if not identity.is_privileged:
            continue
        if host and not any(h.upper() == host for h in identity.accessible_hosts):
            continue
        rows.append(
            {
                "user": identity.name,
                "privilege": identity.privilege,
                "groups": list(identity.groups),
                "accessible_hosts": list(identity.accessible_hosts),
            }
        )
    rows.sort(key=lambda r: r["privilege"], reverse=True)

    return ToolResult(
        summary="{} privileged account(s){}: {}".format(
            len(rows),
            " able to reach " + host if host else "",
            ", ".join(r["user"] for r in rows) or "none",
        ),
        rows=rows,
        node_ids=[builder.user_id(r["user"]) for r in rows],
        kind=EvidenceKind.INVENTORY,
    )


def _get_host_profile(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Asset facts plus observed activity for one host."""
    host = str(args.get("host", "")).upper()
    asset = ctx.inventory.host(host)
    related = [e for e in ctx.events if host in {h.upper() for h in e.hosts()}]

    row = {
        "host": asset.name if asset else host,
        "known_asset": asset is not None,
        "role": asset.role if asset else "unknown",
        "ip": asset.ip if asset else None,
        "criticality": asset.criticality if asset else 0.0,
        "critical_infrastructure": asset.is_critical_infrastructure if asset else False,
        "reachable_hosts": list(asset.reachable_hosts) if asset else [],
        "event_count": len(related),
        "flagged_event_count": sum(1 for e in related if e.is_notable),
        "accounts_seen": sorted({e.user for e in related if e.user}),
    }
    return ToolResult(
        summary="{} is a {} with criticality {:.1f}; {} event(s), {} flagged".format(
            row["host"], row["role"], row["criticality"],
            row["event_count"], row["flagged_event_count"],
        ),
        rows=[row],
        event_ids=[e.event_id for e in related][:40],
        node_ids=[builder.host_id(host)],
        kind=EvidenceKind.INVENTORY,
    )


# --------------------------------------------------------------------------- #
# MITRE tools
# --------------------------------------------------------------------------- #

def _lookup_mitre_technique(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Look a technique up in the mapping rule table.

    Returns the rules that can assign it and, when an event is given, whether
    that event actually satisfies one. An agent cannot claim a technique the
    rule table would not have produced.
    """
    technique_id = str(args.get("technique_id", "")).upper()
    rules = [rule for rule in mitre.RULES if rule.technique_id.upper() == technique_id]
    if not rules:
        return ToolResult(
            summary="{} is not in the PRISM mapping table".format(technique_id),
            kind=EvidenceKind.MITRE,
        )

    event_id = args.get("event_id")
    supported = None
    evidence_text = ""
    if event_id:
        event = ctx.event(str(event_id))
        if event is not None:
            mapped = [
                m for m in mitre.map_event(event) if m.technique_id.upper() == technique_id
            ]
            supported = bool(mapped)
            evidence_text = mapped[0].evidence if mapped else ""

    rows = [
        {
            "technique_id": rule.technique_id,
            "technique_name": rule.technique_name,
            "tactic_id": rule.tactic_id,
            "tactic": rule.tactic,
            "confidence": rule.confidence.value,
            "explanation": rule.explanation,
            "reference": mitre.ATTACK_BASE_URL + rule.technique_id.replace(".", "/") + "/",
            "supported_by_event": supported,
            "evidence": evidence_text,
        }
        for rule in rules
    ]

    detail = rows[0]
    summary = "{} ({}) belongs to {}".format(
        detail["technique_id"], detail["technique_name"], detail["tactic"]
    )
    if supported is True:
        summary += "; event {} satisfies the rule".format(event_id)
    elif supported is False:
        summary += "; event {} does NOT satisfy the rule".format(event_id)

    return ToolResult(
        summary=summary,
        rows=rows,
        event_ids=[str(event_id)] if event_id else [],
        kind=EvidenceKind.MITRE,
    )


def _lookup_mitre_tactic(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Every technique PRISM can assign under one tactic."""
    query = str(args.get("tactic", "")).strip()
    tactic_id = query.upper()
    if not tactic_id.startswith("TA"):
        matches = [
            tid for tid, name in mitre.TACTIC_NAMES.items() if name.lower() == query.lower()
        ]
        tactic_id = matches[0] if matches else ""

    if tactic_id not in mitre.TACTIC_NAMES:
        return ToolResult(
            summary="{} is not a tactic PRISM maps".format(query),
            kind=EvidenceKind.MITRE,
        )

    rows = [
        {
            "technique_id": rule.technique_id,
            "technique_name": rule.technique_name,
            "confidence": rule.confidence.value,
        }
        for rule in mitre.RULES
        if rule.tactic_id == tactic_id
    ]
    return ToolResult(
        summary="{} ({}) has {} mappable technique(s)".format(
            mitre.TACTIC_NAMES[tactic_id], tactic_id, len(rows)
        ),
        rows=rows,
        kind=EvidenceKind.MITRE,
    )


def _map_event_techniques(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Run the mapping rules over specific events and return what fired."""
    event_ids = args.get("event_ids") or []
    if isinstance(event_ids, str):
        event_ids = [event_ids]

    events = [e for e in (ctx.event(str(eid)) for eid in event_ids) if e is not None]
    mappings = mitre.map_events(events)

    rows = [
        {
            "technique_id": m.technique_id,
            "technique_name": m.technique_name,
            "tactic_id": m.tactic_id,
            "tactic": m.tactic,
            "event_id": m.event_id,
            "evidence": m.evidence,
            "explanation": m.explanation,
            "confidence": m.confidence.value,
            "reference": m.reference,
        }
        for m in mappings
    ]
    techniques = sorted({r["technique_id"] for r in rows})
    return ToolResult(
        summary="{} technique(s) supported by {} event(s): {}".format(
            len(techniques), len(events), ", ".join(techniques) or "none"
        ),
        rows=rows,
        event_ids=[m.event_id for m in mappings],
        kind=EvidenceKind.MITRE,
    )


# --------------------------------------------------------------------------- #
# scoring tools
# --------------------------------------------------------------------------- #

def _score_next_targets(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Run the prediction engine for the current attacker position.

    The Next-Target Agent calls this rather than scoring anything itself, so the
    numbers it reports and the numbers on the dashboard come from one place.
    """
    chain = ctx.chain(args.get("chain_id"))
    if chain is None:
        return ToolResult(summary="No attack chain to score against", kind=EvidenceKind.GRAPH)

    member_ids = set(chain.event_ids)
    members = [e for e in ctx.events if e.event_id in member_ids]
    connectivity = builder.connectivity_scores(ctx.graph)
    projection = builder.host_subgraph(ctx.graph)

    context = build_context(
        events=members,
        compromised_hosts=set(chain.hosts),
        current_host=chain.current_host,
        users=set(chain.users),
        connectivity=connectivity,
        known_hosts=ctx.inventory.host_names(),
        attack_chain_id=chain.attack_chain_id,
    )
    predictions = predict_next_targets(
        ctx.inventory, projection, context, ctx.settings.prediction
    )

    rows = [
        {
            "host": p.host,
            "score": p.score,
            "raw_score": p.raw_score,
            "confidence": p.confidence.value,
            "critical_infrastructure": p.is_critical_infrastructure,
            "narrative": p.narrative,
            "factors": [
                {
                    "name": f.name,
                    "points": f.points,
                    "max_points": f.max_points,
                    "detail": f.detail,
                }
                for f in p.factors
            ],
        }
        for p in predictions
    ]
    top = rows[0] if rows else None
    return ToolResult(
        summary=(
            "Top candidate {} at {:.0f}/100".format(top["host"], top["score"])
            if top
            else "No reachable candidates scored above zero"
        ),
        rows=rows,
        node_ids=[builder.host_id(r["host"]) for r in rows],
        kind=EvidenceKind.GRAPH,
    )


def _get_attack_chain(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """The rule-based chain reconstruction, as already computed."""
    chain = ctx.chain(args.get("chain_id")) or (ctx.chains[0] if ctx.chains else None)
    if chain is None:
        return ToolResult(summary="No attack chain has been detected")

    rows = [
        {
            "order": stage.order,
            "tactic": stage.tactic,
            "host": stage.host,
            "user": stage.user,
            "timestamp": stage.timestamp.isoformat(),
            "last_timestamp": (
                stage.last_timestamp.isoformat() if stage.last_timestamp else None
            ),
            "technique_ids": list(stage.technique_ids),
            "event_ids": list(stage.event_ids),
            "description": stage.description,
        }
        for stage in chain.stages
    ]
    return ToolResult(
        summary="{}: {} stage(s) from {} to {}".format(
            chain.attack_chain_id,
            len(rows),
            chain.initial_host or "?",
            chain.current_host or "?",
        ),
        rows=rows,
        event_ids=list(chain.event_ids),
        node_ids=[builder.host_id(h) for h in chain.hosts],
        meta={
            "attack_chain_id": chain.attack_chain_id,
            "initial_host": chain.initial_host,
            # Where the attacker is operating, which is not the same as the host
            # of the final stage: a share mount moves the story without moving
            # the attacker.
            "current_host": chain.current_host,
            "current_stage": chain.current_stage,
            "users": list(chain.users),
            "reached_hosts": list(chain.hosts),
            "targeted_hosts": list(chain.targeted_hosts),
            "risk_score": chain.risk_score,
            "severity": chain.severity,
            "status": chain.status,
        },
    )


def _get_lateral_movements(ctx: ToolContext, args: dict[str, Any]) -> ToolResult:
    """Movement detections with the rule clauses that produced them."""
    chain = ctx.chain(args.get("chain_id")) or (ctx.chains[0] if ctx.chains else None)
    if chain is None:
        return ToolResult(summary="No attack chain has been detected")

    rows = [
        {
            "movement_id": m.movement_id,
            "source_host": m.source_host,
            "destination_host": m.destination_host,
            "user": m.user,
            "method": m.method,
            "timestamp": m.timestamp.isoformat(),
            "correlation_score": m.correlation_score,
            "confidence": m.confidence.value,
            "rule_evaluation": list(m.rule_evaluation),
            "event_id": m.event_id,
        }
        for m in chain.lateral_movements
    ]
    return ToolResult(
        summary="{} lateral movement(s): {}".format(
            len(rows),
            ", ".join(
                "{} to {}".format(r["source_host"], r["destination_host"]) for r in rows
            )
            or "none",
        ),
        rows=rows,
        event_ids=[r["event_id"] for r in rows],
        node_ids=[builder.host_id(r["destination_host"]) for r in rows],
    )


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #

TOOLS: list[Tool] = [
    Tool(
        name="search_auth_logs",
        category="logs",
        description="Search normalized authentication events (logons, RDP, SMB, privilege).",
        parameters=_SEARCH_PARAMS,
        handler=_log_search(EventType.AUTHENTICATION, "authentication"),
    ),
    Tool(
        name="search_dns_logs",
        category="logs",
        description="Search normalized DNS events, including flagged and beaconing domains.",
        parameters=_SEARCH_PARAMS,
        handler=_log_search(EventType.DNS, "DNS"),
    ),
    Tool(
        name="search_endpoint_logs",
        category="logs",
        description="Search normalized endpoint events: process creation, credential access, file drops.",
        parameters=_SEARCH_PARAMS,
        handler=_log_search(EventType.ENDPOINT, "endpoint"),
    ),
    Tool(
        name="search_events",
        category="logs",
        description="Search every normalized event regardless of source feed.",
        parameters=_SEARCH_PARAMS,
        handler=_log_search(None, "event"),
    ),
    Tool(
        name="get_host_neighbors",
        category="graph",
        description="Hosts reachable from a host, with role and criticality.",
        parameters={"host": {"type": "string", "required": True}},
        handler=_get_host_neighbors,
    ),
    Tool(
        name="get_user_access",
        category="graph",
        description="Which hosts an account is entitled to, and which it was seen on.",
        parameters={"user": {"type": "string", "required": True}},
        handler=_get_user_access,
    ),
    Tool(
        name="get_attack_path",
        category="graph",
        description="Shortest reachability path between two hosts.",
        parameters={
            "source_host": {"type": "string", "required": True},
            "target_host": {"type": "string", "required": True},
        },
        handler=_get_attack_path,
    ),
    Tool(
        name="get_related_events",
        category="graph",
        description="Events the correlation engine scored against a given event, with factors.",
        parameters={
            "event_id": {"type": "string", "required": True},
            "min_score": {"type": "number"},
            "limit": {"type": "integer"},
        },
        handler=_get_related_events,
    ),
    Tool(
        name="get_recent_activity",
        category="graph",
        description="Trailing-window activity for a host or an account.",
        parameters={
            "host": {"type": "string"},
            "user": {"type": "string"},
            "minutes": {"type": "number"},
            "limit": {"type": "integer"},
        },
        handler=_get_recent_activity,
    ),
    Tool(
        name="get_privileged_users",
        category="graph",
        description="Privileged accounts, optionally only those able to reach a host.",
        parameters={"host": {"type": "string"}},
        handler=_get_privileged_users,
    ),
    Tool(
        name="get_host_profile",
        category="graph",
        description="Asset facts and observed activity for one host.",
        parameters={"host": {"type": "string", "required": True}},
        handler=_get_host_profile,
    ),
    Tool(
        name="lookup_mitre_technique",
        category="mitre",
        description="Look up a technique, and check whether an event satisfies its rule.",
        parameters={
            "technique_id": {"type": "string", "required": True},
            "event_id": {"type": "string"},
        },
        handler=_lookup_mitre_technique,
    ),
    Tool(
        name="lookup_mitre_tactic",
        category="mitre",
        description="Every technique PRISM can assign under one tactic.",
        parameters={"tactic": {"type": "string", "required": True}},
        handler=_lookup_mitre_tactic,
    ),
    Tool(
        name="map_event_techniques",
        category="mitre",
        description="Run the mapping rules over specific events and return what fired.",
        parameters={"event_ids": {"type": "array", "required": True}},
        handler=_map_event_techniques,
    ),
    Tool(
        name="score_next_targets",
        category="analysis",
        description="Run the explainable next-target scoring for a chain.",
        parameters={"chain_id": {"type": "string"}},
        handler=_score_next_targets,
    ),
    Tool(
        name="get_attack_chain",
        category="analysis",
        description="The reconstructed chain: stages, hosts, techniques, event ids.",
        parameters={"chain_id": {"type": "string"}},
        handler=_get_attack_chain,
    ),
    Tool(
        name="get_lateral_movements",
        category="analysis",
        description="Movement detections and the rule clauses behind each one.",
        parameters={"chain_id": {"type": "string"}},
        handler=_get_lateral_movements,
    ),
]

TOOLS_BY_NAME: dict[str, Tool] = {tool.name: tool for tool in TOOLS}


class ToolError(RuntimeError):
    """Raised when an agent asks for a tool that does not exist."""


class ToolRegistry:
    """Executes tools against a fixed context and records every call.

    The recording is the point. An investigation that cannot show which tool
    produced a fact is not auditable, and an unauditable investigation is not
    worth more than a guess.
    """

    def __init__(self, context: ToolContext) -> None:
        self.context = context
        self.calls: list[ToolCall] = []

    @property
    def catalogue(self) -> list[dict[str, Any]]:
        return [tool.schema() for tool in TOOLS]

    def call(self, name: str, **arguments: Any) -> tuple[ToolResult, ToolCall]:
        tool = TOOLS_BY_NAME.get(name)
        if tool is None:
            raise ToolError("unknown tool: " + name)

        started = time.perf_counter()
        result = tool.handler(self.context, arguments)
        duration_ms = (time.perf_counter() - started) * 1000

        record = ToolCall(
            call_id="tc-" + uuid.uuid4().hex[:10],
            tool=name,
            arguments={k: v for k, v in arguments.items() if v is not None},
            result_count=result.count,
            result_summary=result.summary,
            duration_ms=round(duration_ms, 3),
            produced_evidence=result.found,
        )
        self.calls.append(record)
        return result, record
