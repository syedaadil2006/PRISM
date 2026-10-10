"""Detection content and analyst feedback.

* ``GET /api/detection`` - loaded Sigma rules, skipped rules and why, threat
  intel counts, baseline settings, feedback entries.
* ``POST /api/admin/detection/reload`` - re-read rule and intel folders (admin).
* ``POST /api/attacks/{chain_id}/feedback`` - an analyst's verdict on a chain.
  *false_positive* turns the chain's notable events into suppression entries
  so the same harmless pattern stops raising chains; *true_positive* is
  recorded for reporting.
* ``GET /api/feedback`` and ``DELETE /api/feedback/suppressions/{id}``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.deps import get_state
from app.core.auth import audit
from app.detection.engine import build, current, install
from app.services.soc_state import SocState

router = APIRouter(tags=["detection"])
StateDep = Annotated[SocState, Depends(get_state)]


class Feedback(BaseModel):
    verdict: Literal["false_positive", "true_positive"]
    note: str = Field("", max_length=500)


def _who(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    return principal.username if principal else "local"


@router.get("/api/detection")
def detection(state: StateDep) -> dict:
    detections = current()
    return {
        **detections.describe(),
        "rules": [
            {"id": r.id, "title": r.title, "level": r.level, "techniques": r.techniques,
             "logsource": r.category or r.product or "any", "source": r.source.replace("\\", "/").split("/")[-1]}
            for r in detections.rules.rules
        ],
        "skipped_rules": detections.rules.skipped,
    }


@router.post("/api/admin/detection/reload")
async def reload_detection(request: Request, state: StateDep) -> dict:
    """Re-read Sigma rules and intel files, keep analyst feedback, re-evaluate every event."""
    old = current()
    fresh = await asyncio.to_thread(build, state.settings.detection)
    fresh.suppressions, fresh.verdicts = old.suppressions, old.verdicts
    install(fresh)
    await state.reanalyse()
    audit(request, _who(request), "reload detection", detail={"rules": len(fresh.rules.rules),
                                                               "indicators": fresh.intel.count})
    return fresh.describe()


@router.post("/api/attacks/{chain_id}/feedback")
async def chain_feedback(chain_id: str, body: Feedback, request: Request, state: StateDep) -> dict:
    chain = state.analysis.chain(chain_id)
    if chain is None:
        raise HTTPException(status_code=404, detail=f"No attack chain {chain_id}.")
    analyst = _who(request)
    detections = current()
    detections.verdicts.append({
        "chain_id": chain_id, "verdict": body.verdict, "analyst": analyst, "note": body.note,
        "events": str(len(chain.event_ids)), "hosts": ", ".join(chain.hosts),
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    created = []
    if body.verdict == "false_positive":
        ids = set(chain.event_ids)
        events = [e for e in state.analysis.events if e.event_id in ids]
        created = detections.add_false_positive(chain_id, events, analyst, body.note)
    await asyncio.to_thread(state.save_feedback)
    if created:
        await state.reanalyse()
    audit(request, analyst, "chain feedback", target=chain_id,
          detail={"verdict": body.verdict, "suppressions": len(created)})
    return {"verdict": body.verdict, "suppressions_created": [s.__dict__ for s in created],
            "chains_now": len(state.analysis.chains)}


@router.get("/api/feedback")
def feedback() -> dict:
    detections = current()
    return {"suppressions": [s.__dict__ for s in detections.suppressions.values()],
            "verdicts": list(reversed(detections.verdicts[-200:]))}


@router.delete("/api/feedback/suppressions/{suppression_id}")
async def delete_suppression(suppression_id: str, request: Request, state: StateDep) -> dict:
    detections = current()
    removed = detections.suppressions.pop(suppression_id, None)
    if removed is None:
        raise HTTPException(status_code=404, detail="No such suppression.")
    await asyncio.to_thread(state.save_feedback)
    await state.reanalyse()
    audit(request, _who(request), "delete suppression", target=suppression_id,
          detail={"action": removed.action, "indicator": removed.indicator, "host": removed.host})
    return {"removed": suppression_id, "chains_now": len(state.analysis.chains)}
