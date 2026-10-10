"""Operations: Prometheus metrics, and backups (admin).

GET /api/metrics needs any signed-in role (a scraper uses the access code as a
Bearer token). Backups live under /api/admin/ so they need an admin.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from app.core.auth import audit
from app.core.metrics import gauge
from app.services.backup import create_backup, list_backups

router = APIRouter(tags=["operations"])


@router.get("/api/metrics", response_class=PlainTextResponse)
def metrics(request: Request) -> PlainTextResponse:
    """PRISM's health and workload in the Prometheus text format."""
    state = request.app.state.soc
    live = state.live
    analysis = state.analysis
    lines: list[str] = []
    lines += request.app.state.request_metrics.lines()
    lines += gauge("prism_events", "Events in the current analysis.", len(analysis.events))
    lines += gauge("prism_attack_chains", "Attack chains found.", len(analysis.chains))
    lines += gauge("prism_active_attack_chains", "Attack chains with status active.",
                   sum(1 for c in analysis.chains if c.status == "active"))
    lines += gauge("prism_ingest_queue", "Events received but not analysed yet.", state.pending_count)
    lines += gauge("prism_ingest_queue_limit", "Queue size at which senders get HTTP 429.", state.settings.live.max_pending)
    lines += gauge("prism_live_received_total", "Live records received.", live.received, "counter")
    lines += gauge("prism_live_accepted_total", "Live events accepted.", live.accepted, "counter")
    lines += gauge("prism_live_duplicates_total", "Live events ignored as duplicates.", live.duplicates, "counter")
    lines += gauge("prism_live_rejected_total", "Live records that could not be read.", live.rejected, "counter")
    lines += gauge("prism_ingest_busy_total", "Batches refused because analysis was behind.",
                   state.counters["ingest_busy"], "counter")
    lines += gauge("prism_analysis_runs_total", "Analysis runs.", state.counters["analysis_runs"], "counter")
    lines += gauge("prism_analysis_seconds_total", "Time spent analysing.",
                   round(state.counters["analysis_seconds"], 3), "counter")
    lines += gauge("prism_last_analysis_seconds", "Duration of the latest analysis.",
                   (state._last_analysis_ms or 0) / 1000)
    lines += gauge("prism_stored_events", "Events kept in storage for this data choice.",
                   state.store.event_count(state.storage_scope))
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@router.get("/api/admin/backups")
def backups(request: Request) -> list[dict]:
    """Backups on this computer, newest first."""
    return list_backups(request.app.state.soc.settings)


@router.post("/api/admin/backups", status_code=201)
async def backup_now(request: Request) -> dict:
    """Back up the databases now (consistent while PRISM runs)."""
    manifest = await asyncio.to_thread(create_backup, request.app.state.soc.settings, "manual")
    principal = getattr(request.state, "principal", None)
    audit(request, principal.username if principal else "unknown", "create backup", target=str(manifest["name"]))
    return manifest
