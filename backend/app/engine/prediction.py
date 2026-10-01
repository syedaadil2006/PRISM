"""Explainable next-target scoring.

No learned model: a weighted sum of six factors, each reported with its own
points and a sentence an analyst can check. The output is explicitly labelled
PREDICTED so it can never be mistaken for observed attacker activity.

    Target Score = User Access
                 + Privilege
                 + Graph Connectivity
                 + Host Criticality
                 + Recent Activity
                 + Attack Path Proximity
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from app.core.config import PredictionSettings
from app.models.analysis import (
    Assurance,
    PredictionFactor,
    TargetPrediction,
    confidence_from_score,
)
from app.models.events import EventType, NormalizedEvent
from app.models.inventory import HostAsset, Inventory


@dataclass
class PredictionContext:
    """Everything the scorer needs about the current state of an attack."""

    #: Hosts where attacker activity has actually been observed.
    compromised_hosts: set[str] = field(default_factory=set)
    #: The host the attacker is currently operating from.
    current_host: str | None = None
    #: Accounts involved in the chain.
    users: set[str] = field(default_factory=set)
    #: Hosts the chain has reached for, successfully or not, with evidence text.
    touched_hosts: dict[str, list[str]] = field(default_factory=dict)
    #: Normalised 0-1 graph connectivity per host name.
    connectivity: dict[str, float] = field(default_factory=dict)
    attack_chain_id: str | None = None


def build_context(
    events: list[NormalizedEvent],
    compromised_hosts: set[str],
    current_host: str | None,
    users: set[str],
    connectivity: dict[str, float],
    known_hosts: list[str],
    attack_chain_id: str | None = None,
) -> PredictionContext:
    """Summarise what the chain has recently reached for, with evidence text."""
    touched: dict[str, list[str]] = {}
    upper_hosts = {h.upper() for h in known_hosts}

    def note(host: str | None, detail: str) -> None:
        if not host:
            return
        key = host.upper()
        touched.setdefault(key, [])
        if detail not in touched[key]:
            touched[key].append(detail)

    for event in events:
        if event.event_type is EventType.AUTHENTICATION and event.destination_host:
            outcome = "failed" if event.outcome == "failure" else "successful"
            note(
                event.destination_host,
                "{} {} attempt from {}".format(outcome, event.action.value, event.source_host),
            )
        if event.command_line:
            lowered = event.command_line.lower()
            for host in upper_hosts:
                if host.lower() in lowered:
                    note(host, "referenced in a command line on " + str(event.primary_host))
        if event.event_type is EventType.DNS and event.domain:
            label = event.domain.split(".")[0].upper()
            if label in upper_hosts:
                note(label, "name resolved from " + str(event.source_host))

    return PredictionContext(
        compromised_hosts={h.upper() for h in compromised_hosts},
        current_host=current_host,
        users={u.lower() for u in users},
        touched_hosts=touched,
        connectivity=connectivity,
        attack_chain_id=attack_chain_id,
    )


def _user_access_factor(
    host_name: str, inventory: Inventory, ctx: PredictionContext, settings: PredictionSettings
) -> PredictionFactor:
    entitled = [
        u.name
        for u in inventory.users
        if u.name.lower() in ctx.users
        and any(h.upper() == host_name.upper() for h in u.accessible_hosts)
    ]
    if entitled:
        return PredictionFactor(
            name="User Access",
            points=settings.weight_user_access,
            max_points=settings.weight_user_access,
            detail="Compromised account {} is entitled to {}".format(", ".join(entitled), host_name),
        )
    return PredictionFactor(
        name="User Access",
        points=0.0,
        max_points=settings.weight_user_access,
        detail="No compromised account has recorded access to " + host_name,
    )


def _privilege_factor(
    host_name: str, inventory: Inventory, settings: PredictionSettings
) -> PredictionFactor:
    privileged = [
        u
        for u in inventory.users
        if u.is_privileged and any(h.upper() == host_name.upper() for h in u.accessible_hosts)
    ]
    if not privileged:
        return PredictionFactor(
            name="Privilege",
            points=0.0,
            max_points=settings.weight_privilege,
            detail="No privileged accounts are tied to " + host_name,
        )
    top = max(privileged, key=lambda u: u.privilege)
    return PredictionFactor(
        name="Privilege",
        points=round(settings.weight_privilege * top.privilege, 2),
        max_points=settings.weight_privilege,
        detail="{} privileged account(s) can reach {}, including {}".format(
            len(privileged), host_name, top.name
        ),
    )


def _connectivity_factor(
    host_name: str, ctx: PredictionContext, settings: PredictionSettings
) -> PredictionFactor:
    score = ctx.connectivity.get(host_name.upper(), 0.0)
    return PredictionFactor(
        name="Connectivity",
        points=round(settings.weight_connectivity * score, 2),
        max_points=settings.weight_connectivity,
        detail="Graph connectivity of {} is {:.0f}% of the most connected host".format(
            host_name, score * 100
        ),
    )


def _criticality_factor(host: HostAsset, settings: PredictionSettings) -> PredictionFactor:
    detail = "{} is a {} with criticality {:.1f}".format(host.name, host.role, host.criticality)
    if host.is_critical_infrastructure:
        detail += ", flagged as critical infrastructure"
    return PredictionFactor(
        name="Criticality",
        points=round(settings.weight_criticality * host.criticality, 2),
        max_points=settings.weight_criticality,
        detail=detail,
    )


def _recent_activity_factor(
    host_name: str, ctx: PredictionContext, settings: PredictionSettings
) -> PredictionFactor:
    notes = ctx.touched_hosts.get(host_name.upper(), [])
    if not notes:
        return PredictionFactor(
            name="Recent Activity",
            points=0.0,
            max_points=settings.weight_recent_activity,
            detail="No recent attack-path activity points at " + host_name,
        )
    direct = any(n.startswith(("failed", "successful")) for n in notes)
    weight = 1.0 if direct else 0.6
    return PredictionFactor(
        name="Recent Activity",
        points=round(settings.weight_recent_activity * weight, 2),
        max_points=settings.weight_recent_activity,
        detail="Recent activity toward {}: {}".format(host_name, "; ".join(notes[:3])),
    )


def _proximity_factor(
    host_name: str,
    projection: nx.Graph,
    ctx: PredictionContext,
    settings: PredictionSettings,
) -> PredictionFactor:
    from app.graph.builder import hops_between

    if not ctx.current_host:
        return PredictionFactor(
            name="Path Proximity",
            points=0.0,
            max_points=settings.weight_path_proximity,
            detail="Current attacker position is unknown",
        )
    hops = hops_between(projection, ctx.current_host, host_name)
    if hops is None:
        return PredictionFactor(
            name="Path Proximity",
            points=0.0,
            max_points=settings.weight_path_proximity,
            detail="{} is not reachable from {} in the known topology".format(
                host_name, ctx.current_host
            ),
        )
    return PredictionFactor(
        name="Path Proximity",
        points=round(settings.weight_path_proximity * (1.0 / max(hops, 1)), 2),
        max_points=settings.weight_path_proximity,
        detail="{} is {} hop(s) from the current attacker position ({})".format(
            host_name, hops, ctx.current_host
        ),
    )


def _narrative(host_name: str, factors: list[PredictionFactor], score: float) -> str:
    """One sentence stating why this host scored, and that it is a prediction."""
    top = [f for f in sorted(factors, key=lambda f: f.points, reverse=True) if f.points > 0][:3]
    if not top:
        return "{} scored {:.0f}/100 as a potential target.".format(host_name, score)
    drivers = ", ".join(f.name.lower() for f in top)
    return (
        "{} is a potential next target at {:.0f}/100, driven mainly by {}. "
        "This is a risk-based prediction from graph context, not observed attacker activity."
    ).format(host_name, score, drivers)


def predict_next_targets(
    inventory: Inventory,
    projection: nx.Graph,
    ctx: PredictionContext,
    settings: PredictionSettings,
) -> list[TargetPrediction]:
    """Score every plausible next target and return the strongest candidates."""
    predictions: list[TargetPrediction] = []

    for host in inventory.hosts:
        if host.name.upper() in ctx.compromised_hosts:
            continue  # already reached, so not a prediction

        factors = [
            _user_access_factor(host.name, inventory, ctx, settings),
            _privilege_factor(host.name, inventory, settings),
            _connectivity_factor(host.name, ctx, settings),
            _criticality_factor(host, settings),
            _recent_activity_factor(host.name, ctx, settings),
            _proximity_factor(host.name, projection, ctx, settings),
        ]
        raw = sum(f.points for f in factors)
        if raw <= 0:
            continue

        normalised = min(100.0, round(raw / settings.normalisation_ceiling * 100, 1))
        predictions.append(
            TargetPrediction(
                host=host.name,
                raw_score=round(raw, 2),
                score=normalised,
                confidence=confidence_from_score(normalised / 100.0),
                assurance=Assurance.PREDICTED,
                factors=factors,
                reasons=[f.detail for f in factors if f.points > 0],
                narrative=_narrative(host.name, factors, normalised),
                attack_chain_id=ctx.attack_chain_id,
                is_critical_infrastructure=host.is_critical_infrastructure,
            )
        )

    predictions.sort(key=lambda p: p.score, reverse=True)
    return predictions[: settings.max_predictions]
