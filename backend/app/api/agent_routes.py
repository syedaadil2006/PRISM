"""HTTP surface for the agentic investigation layer.

Reads are cheap and safe to poll: an investigation in flight returns its
partially complete state, which is what lets the UI watch agents work. Writes
are limited to starting an investigation and recording an analyst's verdict --
the agents recommend, and nothing here takes a destructive action on a host.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response

from app.agents.state import (
    AGENT_LABELS,
    AGENT_PURPOSE,
    AgentStep,
    AnalystDecision,
    Investigation,
    InvestigationSummaryView,
)
from app.agents.tools import TOOLS
from app.services.investigation_service import InvestigationError, InvestigationService

router = APIRouter(prefix="/api/agents", tags=["agents"])


def get_service(request: Request) -> InvestigationService:
    return request.app.state.investigations


ServiceDep = Annotated[InvestigationService, Depends(get_service)]


@router.get("/roster")
def roster(service: ServiceDep) -> dict[str, Any]:
    """The agent line-up and the layer's current configuration.

    Exposes whether an LLM is in play, because an analyst reading a summary is
    entitled to know who wrote it.
    """
    from app.agents.orchestrator import PIPELINE

    return {
        "enabled": service.settings.agents.enabled,
        "narrator": service.provider_name,
        "llm_configured": service.settings.llm.configured,
        "step_delay_seconds": service.settings.agents.step_delay_seconds,
        "agents": [
            {
                "agent": agent.name.value,
                "label": AGENT_LABELS[agent.name],
                "purpose": AGENT_PURPOSE[agent.name],
                "order": index + 1,
            }
            for index, agent in enumerate(PIPELINE)
        ],
    }


@router.get("/tools")
def tool_catalogue() -> dict[str, Any]:
    """The evidence-retrieval tools available to the agents.

    This is the tool-calling interface: the same schemas an LLM provider would
    be handed if it were driving the investigation directly.
    """
    return {
        "count": len(TOOLS),
        "tools": [
            {
                "name": tool.name,
                "category": tool.category,
                "description": tool.description,
                "schema": tool.schema(),
            }
            for tool in TOOLS
        ],
    }


@router.get("/investigations", response_model=list[InvestigationSummaryView])
def list_investigations(service: ServiceDep) -> list[InvestigationSummaryView]:
    """Every investigation, newest first."""
    return service.summaries()


@router.post("/investigations", response_model=Investigation)
async def start_investigation(
    service: ServiceDep,
    chain_id: Annotated[str | None, Query(description="Chain to investigate")] = None,
) -> Investigation:
    """Open an investigation. The agents run in the background."""
    try:
        return await service.start(chain_id, trigger="analyst")
    except InvestigationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/investigations/latest", response_model=Investigation | None)
def latest_investigation(service: ServiceDep) -> Investigation | None:
    """The most recent investigation, or null if none has been started."""
    return service.latest()


@router.get("/investigations/{investigation_id}", response_model=Investigation)
def get_investigation(investigation_id: str, service: ServiceDep) -> Investigation:
    """One investigation in full, including partial state while it runs."""
    try:
        return service.require(investigation_id)
    except InvestigationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/investigations/{investigation_id}/timeline", response_model=list[AgentStep])
def investigation_timeline(investigation_id: str, service: ServiceDep) -> list[AgentStep]:
    """The agent reasoning timeline: actions, evidence and conclusions.

    Concise steps only. Private deliberation is not recorded and not exposed.
    """
    try:
        return service.require(investigation_id).steps
    except InvestigationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/investigations/{investigation_id}/evidence")
def investigation_evidence(
    investigation_id: str,
    service: ServiceDep,
    finding_id: Annotated[str | None, Query(description="Only this finding's evidence")] = None,
) -> dict[str, Any]:
    """The evidence behind an investigation, or behind one finding."""
    try:
        investigation = service.require(investigation_id)
    except InvestigationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    items = investigation.evidence
    if finding_id:
        finding = investigation.finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        wanted = set(finding.evidence_ids)
        items = [item for item in items if item.evidence_id in wanted]

    return {
        "investigation_id": investigation_id,
        "finding_id": finding_id,
        "count": len(items),
        "evidence": items,
        "source_event_ids": sorted({eid for item in items for eid in item.event_ids}),
    }


@router.post("/investigations/{investigation_id}/findings/{finding_id}/decision",
             response_model=Investigation)
async def record_decision(
    investigation_id: str,
    finding_id: str,
    service: ServiceDep,
    decision: Annotated[AnalystDecision, Query(description="approved | rejected | false_positive")],
    note: Annotated[str, Body(embed=True, description="Optional analyst note")] = "",
) -> Investigation:
    """Record the analyst's verdict on one finding.

    A rejected finding is kept and excluded from the summary rather than
    deleted: the disagreement is part of the record.
    """
    try:
        return await service.decide(investigation_id, finding_id, decision, note)
    except InvestigationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/investigations/{investigation_id}/cancel", response_model=Investigation)
async def cancel_investigation(investigation_id: str, service: ServiceDep) -> Investigation:
    """Stop an investigation that is still running."""
    try:
        return await service.cancel(investigation_id)
    except InvestigationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/investigations/{investigation_id}/report")
def investigation_report(
    investigation_id: str,
    service: ServiceDep,
    format: Annotated[str, Query(pattern="^(html|md)$")] = "html",
    download: Annotated[bool, Query()] = False,
) -> Response:
    """The investigation as a report: HTML (print to PDF) or Markdown."""
    from app.agents.report import render_html, render_markdown

    try:
        investigation = service.require(investigation_id)
    except InvestigationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if format == "md":
        body, media, ext = render_markdown(investigation), "text/markdown", "md"
    else:
        body, media, ext = render_html(investigation), "text/html", "html"
    headers = {}
    if download:
        headers["Content-Disposition"] = 'attachment; filename="{}-report.{}"'.format(
            investigation_id, ext
        )
    return Response(content=body, media_type=media + "; charset=utf-8", headers=headers)
