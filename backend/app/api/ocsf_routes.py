"""OCSF export: events and attack chains in the Open Cybersecurity Schema Framework.

OCSF import needs no endpoint of its own: OCSF events are detected
automatically by POST /api/live/events, the Splunk HEC endpoint, file upload
and the watched folder.
"""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response

from app.api.deps import get_state
from app.ocsf import OCSF_VERSION, chain_to_finding, event_to_ocsf
from app.services.soc_state import SocState

router = APIRouter(prefix="/api/ocsf", tags=["ocsf"])

StateDep = Annotated[SocState, Depends(get_state)]
FORMAT = Annotated[str, Query(pattern="^(json|ndjson)$", description="json (array) or ndjson (one event per line)")]


def _respond(items: list[dict], fmt: str) -> Response:
    if fmt == "ndjson":
        return Response("\n".join(json.dumps(i) for i in items) + ("\n" if items else ""), media_type="application/x-ndjson")
    return JSONResponse(items)


@router.get("/events")
def ocsf_events(
    state: StateDep,
    chain_id: Annotated[str | None, Query(description="Only the events of this attack chain")] = None,
    limit: Annotated[int, Query(ge=1, le=50_000)] = 5_000,
    format: FORMAT = "json",
) -> Response:
    """Analysed events as OCSF 1.3 (Authentication, Authorize Session, Process
    Activity, File System Activity, DNS Activity)."""
    events = state.analysis.events
    if chain_id:
        chain = state.analysis.chain(chain_id)
        if chain is None:
            raise HTTPException(status_code=404, detail="attack chain not found")
        wanted = set(chain.event_ids)
        events = [e for e in events if e.event_id in wanted]
    version = state.settings.version
    return _respond([event_to_ocsf(e, version) for e in events[-limit:]], format)


@router.get("/findings")
def ocsf_findings(state: StateDep, format: FORMAT = "json") -> Response:
    """Every attack chain as an OCSF Detection Finding (class 2004), with its
    MITRE ATT&CK techniques and the uids of its events."""
    version = state.settings.version
    return _respond([chain_to_finding(c, version) for c in state.analysis.chains], format)


@router.get("/info")
def ocsf_info() -> dict:
    return {
        "ocsf_version": OCSF_VERSION,
        "export": {
            "events": "/api/ocsf/events",
            "findings": "/api/ocsf/findings",
            "classes": {"3002": "Authentication", "3003": "Authorize Session", "1007": "Process Activity",
                        "1001": "File System Activity", "4003": "DNS Activity", "2004": "Detection Finding"},
        },
        "import": "OCSF events (classes 3002, 3003, 1007, 1001, 4003) are detected automatically by "
                  "POST /api/live/events, the Splunk HEC endpoint, file upload and the watched folder.",
    }
