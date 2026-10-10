"""Real-time ingestion endpoints.

Any log shipper, script or collector can push events the moment they happen:

    POST /api/live/events?source=hr-pc-sysmon
    Content-Type: application/x-ndjson
    {"EventID": "1", "UtcTime": "...", "Computer": "HR-PC", "Image": "..."}

The analysis catches up in the background within about a second, and the
dashboard picks up the result on its next poll.
"""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.deps import get_state
from app.ingest.parsers import PARSERS
from app.services.live_feed import LiveIngestResult, LiveStatus, decode_body, stream_name
from app.services.soc_state import SocState

router = APIRouter(prefix="/api/live", tags=["live"])

StateDep = Annotated[SocState, Depends(get_state)]


@router.get("/status", response_model=LiveStatus)
def live_status(state: StateDep) -> LiveStatus:
    """What the live feed has received, how fast, and whether analysis is current."""
    return state.live_status()


@router.post("/events", response_model=LiveIngestResult)
async def push_events(
    request: Request,
    state: StateDep,
    source: Annotated[
        str | None, Query(description="Name of the sending source, e.g. hr-pc-sysmon")
    ] = None,
    log_format: Annotated[
        str | None,
        Query(
            alias="format",
            description="windows_security | sysmon | zeek_dns | prism (auto-detected if omitted)",
        ),
    ] = None,
) -> LiveIngestResult:
    """Push one or more raw log records as they happen.

    The body may be a JSON object, a JSON array, {"records": [...]}, JSON-lines,
    or CSV with a header row (Content-Type: text/csv).
    """
    if not state.settings.live.enabled:
        raise HTTPException(status_code=403, detail="the live feed is disabled (PRISM_LIVE_ENABLED=false)")
    if log_format is not None and log_format not in PARSERS:
        raise HTTPException(
            status_code=400,
            detail="format must be one of: {}".format(", ".join(sorted(PARSERS))),
        )
    try:
        records = decode_body(await request.body(), request.headers.get("content-type"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="could not read the body: {}".format(exc)) from exc
    if len(records) > state.settings.live.max_batch:
        raise HTTPException(
            status_code=413,
            detail="at most {} records per request".format(state.settings.live.max_batch),
        )
    return await state.ingest_live(records, stream_name(source), log_format)


@router.post("/start", response_model=LiveStatus)
async def start_live(
    state: StateDep,
    clear: Annotated[
        bool, Query(description="Drop the bundled dataset so only live events are analysed")
    ] = True,
) -> LiveStatus:
    """Switch to live analysis. POST /api/logs/reset brings the dataset back."""
    return await state.go_live(clear=clear)


@router.get("/integrations")
def integrations(request: Request, state: StateDep) -> dict:
    """Every way data gets in and out: live feed, HEC, syslog, alert forwarding, storage."""
    syslog = getattr(request.app.state, "syslog", None)
    return {
        "live_feed": {"push_api": "/api/live/events", "watched_folder": str(state.settings.live.watch_dir)},
        "splunk_hec": {"endpoint": "/services/collector/event", "health": "/services/collector/health"},
        "syslog_receiver": syslog.status() if syslog else {"enabled": False},
        "alert_forwarding": state.forwarder.status(),
        "storage": state.store.describe(state.storage_scope),
        "authentication": {"enabled": bool(getattr(request.app.state, "auth_enabled", False))},
        "local_only": {
            "enabled": state.settings.local_only,
            "meaning": "requests from other machines are refused; no data is sent off this computer"
            if state.settings.local_only else "off: network access and outside targets are allowed",
        },
    }


@router.post("/flush", response_model=LiveStatus)
async def flush_live(state: StateDep) -> LiveStatus:
    """Re-run the analysis now instead of waiting for the background loop."""
    await state.flush_live()
    return state.live_status()
