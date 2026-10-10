"""PRISM HTTP API.

Every response is derived from the shared analysis in SocState, so the graph,
the chain list and the statistics can never disagree.
"""

from __future__ import annotations

import re

from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from app.api.aggregates import build_host_views, build_mitre_matrix, build_user_views
from app.api.deps import get_state
from app.core.config import PROJECT_ROOT
from app.models.analysis import (
    AttackChain,
    AttackChainDetail,
    Correlation,
    DashboardStats,
    TargetPrediction,
)
from app.models.events import IngestSummary, NormalizedEvent
from app.models.graph import GraphPayload
from app.models.views import EngineConfigView, HealthView, HostView, TacticView, UserView
from app.services.soc_state import SimulationStatus, SocState

router = APIRouter(prefix="/api")

StateDep = Annotated[SocState, Depends(get_state)]


def _ui_build() -> str | None:
    """The hashed bundle name in the built dashboard, e.g. index-Bf_91Y4d.js."""
    try:
        html = (PROJECT_ROOT / "frontend" / "dist" / "index.html").read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r"assets/(index-[^\"']+\.js)", html)
    return match.group(1) if match else None


@router.get("/health", response_model=HealthView, tags=["system"])
def health(state: StateDep) -> HealthView:
    """Liveness plus a summary of what is currently loaded."""
    return HealthView(
        status="ok",
        version=state.settings.version,
        events=len(state.analysis.events),
        chains=len(state.analysis.chains),
        sources=state.sources,
        ingest_errors=state.ingest_errors[:20],
        computed_at=state.analysis.computed_at,
        ui_build=_ui_build(),
    )


@router.get("/config", response_model=EngineConfigView, tags=["system"])
def engine_config(state: StateDep) -> EngineConfigView:
    """The thresholds behind every detection, so the UI can show its own rules."""
    settings = state.settings
    correlation = settings.correlation
    return EngineConfigView(
        correlation_window_seconds=correlation.window_seconds,
        correlation_min_score=correlation.min_score,
        correlation_min_chain_events=correlation.min_chain_events,
        correlation_weights={
            "same_user": correlation.weight_same_user,
            "same_host": correlation.weight_same_host,
            "host_pivot": correlation.weight_host_pivot,
            "shared_ip": correlation.weight_shared_ip,
            "process_continuity": correlation.weight_process_host,
            "domain_overlap": correlation.weight_domain_overlap,
            "suspicious_coincidence": correlation.weight_suspicious_coincidence,
            "time_proximity": correlation.weight_time_proximity,
        },
        lateral_window_seconds=settings.lateral.window_seconds,
        lateral_min_correlation_score=settings.lateral.min_correlation_score,
        lateral_movement_actions=list(settings.lateral.movement_actions),
        prediction_weights={
            "user_access": settings.prediction.weight_user_access,
            "privilege": settings.prediction.weight_privilege,
            "connectivity": settings.prediction.weight_connectivity,
            "criticality": settings.prediction.weight_criticality,
            "recent_activity": settings.prediction.weight_recent_activity,
            "path_proximity": settings.prediction.weight_path_proximity,
        },
        prediction_normalisation_ceiling=settings.prediction.normalisation_ceiling,
        neo4j_enabled=settings.neo4j.enabled,
        demo_mode=settings.demo_mode,
    )


@router.get("/stats", response_model=DashboardStats, tags=["dashboard"])
def stats(state: StateDep) -> DashboardStats:
    """Headline dashboard numbers, framed around fragmentation reduction."""
    return state.stats()


@router.get("/attacks", response_model=list[AttackChain], tags=["attacks"])
def list_attacks(
    state: StateDep,
    status: Annotated[str | None, Query(description="Filter by chain status")] = None,
) -> list[AttackChain]:
    """Every detected attack chain, highest risk first."""
    chains = state.analysis.chains
    if status:
        chains = [c for c in chains if c.status == status]
    return chains


@router.get("/attacks/{chain_id}", response_model=AttackChainDetail, tags=["attacks"])
def get_attack(chain_id: str, state: StateDep) -> AttackChainDetail:
    """One chain with its events and the correlations that built it."""
    chain = state.analysis.chain(chain_id)
    if chain is None:
        raise HTTPException(status_code=404, detail="attack chain " + chain_id + " not found")

    member_ids = set(chain.event_ids)
    events = [e for e in state.analysis.events if e.event_id in member_ids]
    correlations = [
        c
        for c in state.analysis.correlations
        if c.source_event_id in member_ids and c.target_event_id in member_ids
    ]
    return AttackChainDetail(chain=chain, events=events, correlations=correlations)


@router.get("/events", response_model=list[NormalizedEvent], tags=["events"])
def list_events(
    state: StateDep,
    event_type: Annotated[str | None, Query()] = None,
    host: Annotated[str | None, Query()] = None,
    user: Annotated[str | None, Query()] = None,
    suspicious_only: Annotated[bool, Query()] = False,
    chain_id: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> list[NormalizedEvent]:
    """Normalized events, newest first, with the usual triage filters."""
    events = list(state.analysis.events)

    if chain_id:
        chain = state.analysis.chain(chain_id)
        if chain is None:
            raise HTTPException(status_code=404, detail="attack chain " + chain_id + " not found")
        member_ids = set(chain.event_ids)
        events = [e for e in events if e.event_id in member_ids]
    if event_type:
        events = [e for e in events if e.event_type.value == event_type]
    if host:
        needle = host.upper()
        events = [e for e in events if needle in {h.upper() for h in e.hosts()}]
    if user:
        needle = user.lower()
        events = [e for e in events if e.user and e.user.lower() == needle]
    if suspicious_only:
        events = [e for e in events if e.is_notable]

    events.sort(key=lambda e: e.timestamp, reverse=True)
    return events[:limit]


@router.get("/correlations", response_model=list[Correlation], tags=["events"])
def list_correlations(
    state: StateDep,
    event_id: Annotated[str | None, Query(description="Only links touching this event")] = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 300,
) -> list[Correlation]:
    """Scored event-to-event links, with the factors behind each score."""
    correlations = state.analysis.correlations
    if event_id:
        correlations = [c for c in correlations if event_id in (c.source_event_id, c.target_event_id)]
    return correlations[:limit]


@router.get("/graph", response_model=GraphPayload, tags=["graph"])
def get_graph(
    state: StateDep,
    chain_id: Annotated[str | None, Query(description="Focus on one attack chain")] = None,
) -> GraphPayload:
    """The Cytoscape.js payload. All node states are decided server side."""
    if chain_id and state.analysis.chain(chain_id) is None:
        raise HTTPException(status_code=404, detail="attack chain " + chain_id + " not found")
    return state.graph_payload(chain_id)


@router.get("/hosts", response_model=list[HostView], tags=["inventory"])
def list_hosts(state: StateDep) -> list[HostView]:
    """Inventory joined with observed activity and chain state."""
    return build_host_views(state.analysis.events, state.analysis.chains, state.inventory)


@router.get("/users", response_model=list[UserView], tags=["inventory"])
def list_users(state: StateDep) -> list[UserView]:
    """Identities joined with observed activity and chain state."""
    return build_user_views(state.analysis.events, state.analysis.chains, state.inventory)


@router.get("/mitre", response_model=list[TacticView], tags=["mitre"])
def mitre_matrix(state: StateDep) -> list[TacticView]:
    """Observed techniques grouped by tactic, each with its evidence."""
    return build_mitre_matrix(state.analysis.chains)


@router.get("/predictions", response_model=list[TargetPrediction], tags=["predictions"])
def list_predictions(state: StateDep) -> list[TargetPrediction]:
    """Potential next targets across all chains, highest score first."""
    predictions = [p for c in state.analysis.chains for p in c.predictions]
    predictions.sort(key=lambda p: p.score, reverse=True)
    return predictions


@router.post("/logs/ingest", response_model=IngestSummary, tags=["ingest"])
async def ingest_logs(
    state: StateDep,
    files: Annotated[list[UploadFile], File(description="CSV, JSON or JSON-lines log files")],
    log_format: Annotated[
        str | None,
        Query(description="windows_security | sysmon | zeek_dns | prism (auto-detected if omitted)"),
    ] = None,
) -> IngestSummary:
    """Ingest log files and re-run the whole analysis pipeline."""
    payloads: list[tuple[str, bytes]] = []
    for upload in files:
        payloads.append((upload.filename or "upload", await upload.read()))
    if not payloads:
        raise HTTPException(status_code=400, detail="no files supplied")
    return await state.ingest_files(payloads, log_format)


@router.post("/logs/reset", response_model=IngestSummary, tags=["ingest"])
async def reset_logs(state: StateDep) -> IngestSummary:
    """Discard ingested data and reload the configured dataset."""
    await state.clear()
    return IngestSummary(
        accepted=len(state.analysis.events),
        rejected=0,
        total_events=len(state.analysis.events),
        errors=state.ingest_errors[:20],
        sources=state.sources,
    )


@router.get("/simulation", response_model=SimulationStatus, tags=["demo"])
def simulation_status(state: StateDep) -> SimulationStatus:
    """Where the demo simulation currently is."""
    return state.simulation_status()


@router.post("/simulation/start", response_model=SimulationStatus, tags=["demo"])
async def simulation_start(state: StateDep) -> SimulationStatus:
    """Start the attack simulation from the beginning."""
    return await state.start_simulation(restart=True)


@router.post("/simulation/pause", response_model=SimulationStatus, tags=["demo"])
async def simulation_pause(state: StateDep) -> SimulationStatus:
    """Freeze the simulation where it is."""
    return await state.pause_simulation()


@router.post("/simulation/resume", response_model=SimulationStatus, tags=["demo"])
async def simulation_resume(state: StateDep) -> SimulationStatus:
    """Continue a paused simulation."""
    return await state.resume_simulation()


@router.post("/simulation/step", response_model=SimulationStatus, tags=["demo"])
async def simulation_step(
    state: StateDep,
    count: Annotated[int, Query(ge=1, le=100, description="Events to reveal")] = 1,
) -> SimulationStatus:
    """Reveal the next events manually, for presenting at your own pace."""
    return await state.step_simulation(count)


@router.post("/simulation/reset", response_model=SimulationStatus, tags=["demo"])
async def simulation_reset(
    state: StateDep,
    show_all: Annotated[bool, Query(description="Skip the replay and show everything")] = False,
) -> SimulationStatus:
    """Rewind the simulation, or drop gating and show the full dataset."""
    return await state.reset_simulation(show_all=show_all)
