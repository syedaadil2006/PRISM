"""Derive the host, user and MITRE page views from the current analysis."""

from __future__ import annotations

from app.engine.mitre import TACTIC_ORDER
from app.ingest.loader import SERVICE_ACCOUNT_RE
from app.models.analysis import AttackChain
from app.models.events import Action, EventType, NormalizedEvent
from app.models.inventory import Inventory
from app.models.views import HostView, TacticView, TechniqueView, UserView


def _chain_host_state(chains: list[AttackChain], host: str) -> tuple[str, list[str], float | None]:
    """Resolve a host's visual state, its chains, and any prediction score."""
    upper = host.upper()
    state = "normal"
    chain_ids: list[str] = []
    prediction: float | None = None
    # Same precedence the graph presenter uses, so a host never reads as
    # "suspicious" on this page while the graph calls it a potential target.
    # A scored prediction is the more actionable label of the two.
    rank = {
        "normal": 0,
        "suspicious": 1,
        "potential_target": 2,
        "compromised": 3,
        "current_position": 4,
    }

    def promote(candidate: str) -> None:
        nonlocal state
        if rank[candidate] > rank[state]:
            state = candidate

    for chain in chains:
        touched = False
        if chain.current_host and chain.current_host.upper() == upper:
            promote("current_position")
            touched = True
        if upper in {h.upper() for h in chain.hosts}:
            promote("compromised")
            touched = True
        if upper in {h.upper() for h in chain.targeted_hosts}:
            promote("suspicious")
            touched = True
        for candidate in chain.predictions:
            if candidate.host.upper() == upper:
                promote("potential_target")
                prediction = max(prediction or 0.0, candidate.score)
                touched = True
        if touched:
            chain_ids.append(chain.attack_chain_id)

    return state, chain_ids, prediction


def build_host_views(
    events: list[NormalizedEvent], chains: list[AttackChain], inventory: Inventory
) -> list[HostView]:
    names = {h.name.upper(): h.name for h in inventory.hosts}
    for event in events:
        for host in event.hosts():
            names.setdefault(host.upper(), host)

    views: list[HostView] = []
    for upper, name in sorted(names.items()):
        related = [e for e in events if upper in {h.upper() for h in e.hosts()}]
        asset = inventory.host(name)
        state, chain_ids, prediction = _chain_host_state(chains, name)
        views.append(
            HostView(
                name=name,
                ip=asset.ip if asset else None,
                role=asset.role if asset else "unknown",
                zone=asset.zone if asset else "unknown",
                os=asset.os if asset else None,
                criticality=asset.criticality if asset else 0.0,
                is_critical_infrastructure=asset.is_critical_infrastructure if asset else False,
                state=state,
                event_count=len(related),
                suspicious_event_count=sum(1 for e in related if e.suspicious),
                first_seen=min((e.timestamp for e in related), default=None),
                last_seen=max((e.timestamp for e in related), default=None),
                users=sorted({e.user for e in related if e.user}),
                attack_chain_ids=chain_ids,
                prediction_score=prediction,
                reachable_hosts=list(asset.reachable_hosts) if asset else [],
            )
        )
    views.sort(key=lambda h: (h.state != "current_position", -h.criticality, h.name))
    return views


def build_user_views(
    events: list[NormalizedEvent], chains: list[AttackChain], inventory: Inventory
) -> list[UserView]:
    names = {u.name.lower(): u.name for u in inventory.users}
    for event in events:
        if event.user:
            names.setdefault(event.user.lower(), event.user)

    compromised = {u.lower() for c in chains for u in c.users}
    views: list[UserView] = []
    for lower, name in sorted(names.items()):
        related = [e for e in events if e.user and e.user.lower() == lower]
        identity = inventory.user(name)
        builtin = identity is None and bool(SERVICE_ACCOUNT_RE.match(name))
        views.append(
            UserView(
                name=name,
                display_name=identity.display_name if identity else None,
                # Windows' own accounts (DWM-*, UMFD-*, SYSTEM, ...) are not people.
                department=identity.department if identity else ("Windows system account" if builtin else None),
                privilege=identity.privilege if identity else 0.0,
                is_privileged=identity.is_privileged if identity else False,
                groups=list(identity.groups) if identity else [],
                accessible_hosts=list(identity.accessible_hosts) if identity else [],
                hosts_observed=sorted({h for e in related for h in e.hosts()}),
                event_count=len(related),
                failed_logons=sum(1 for e in related if e.action is Action.LOGIN_FAILURE),
                compromised=lower in compromised,
                attack_chain_ids=[
                    c.attack_chain_id for c in chains if lower in {u.lower() for u in c.users}
                ],
                first_seen=min((e.timestamp for e in related), default=None),
                last_seen=max((e.timestamp for e in related), default=None),
            )
        )
    views.sort(key=lambda u: (not u.compromised, -u.privilege, u.name))
    return views


def build_mitre_matrix(chains: list[AttackChain]) -> list[TacticView]:
    """Group every mapping by tactic and technique, keeping all evidence."""
    techniques: dict[str, TechniqueView] = {}
    for chain in chains:
        for mapping in chain.mitre:
            view = techniques.get(mapping.technique_id)
            if view is None:
                view = TechniqueView(
                    technique_id=mapping.technique_id,
                    technique_name=mapping.technique_name,
                    tactic_id=mapping.tactic_id,
                    tactic=mapping.tactic,
                    reference=mapping.reference,
                    confidence=mapping.confidence.value,
                )
                techniques[mapping.technique_id] = view
            view.occurrences += 1
            view.evidence.append(mapping)
            if chain.attack_chain_id not in view.attack_chain_ids:
                view.attack_chain_ids.append(chain.attack_chain_id)

    tactics: dict[str, TacticView] = {}
    for view in techniques.values():
        tactic = tactics.get(view.tactic_id)
        if tactic is None:
            tactic = TacticView(
                tactic_id=view.tactic_id,
                tactic=view.tactic,
                order=TACTIC_ORDER.get(view.tactic_id, 99),
            )
            tactics[view.tactic_id] = tactic
        tactic.techniques.append(view)

    ordered = sorted(tactics.values(), key=lambda t: t.order)
    for tactic in ordered:
        tactic.techniques.sort(key=lambda t: t.technique_id)
    return ordered
