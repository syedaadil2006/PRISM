"""Agent base: the shared machinery every specialised agent builds on.

An agent does three things and nothing else:

1. call tools to obtain facts,
2. record what it found as evidence, and
3. state a conclusion that cites that evidence.

The workspace below is what enforces that. There is no path for an agent to add
a finding without evidence ids, and no path to add evidence without the tool
call that produced it. An agent that wants to assert something it did not
retrieve has to go and retrieve it first.
"""

from __future__ import annotations

import asyncio
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from app.agents.state import (
    AgentName,
    AgentRun,
    AgentStatus,
    AgentStep,
    EvidenceItem,
    EvidenceKind,
    Finding,
    Investigation,
)
from app.agents.tools import ToolCall, ToolRegistry, ToolResult
from app.core.config import Settings
from app.core.logging_config import get_logger
from app.models.analysis import Assurance

logger = get_logger(__name__)

#: Called after each recorded step so the UI can watch an investigation unfold.
StepListener = Callable[[Investigation, AgentStep], Awaitable[None]]


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


class AgentWorkspace:
    """One agent's handle on the investigation it is contributing to."""

    def __init__(
        self,
        agent: AgentName,
        investigation: Investigation,
        registry: ToolRegistry,
        settings: Settings,
        listener: StepListener | None = None,
    ) -> None:
        self.agent = agent
        self.investigation = investigation
        self.registry = registry
        self.settings = settings
        self._listener = listener
        self._pending_calls: list[ToolCall] = []

    # ------------------------------------------------------------- tools ---

    def call(self, tool: str, **arguments: Any) -> ToolResult:
        """Run a tool and stage its call record for the next step."""
        result, record = self.registry.call(tool, **arguments)
        self._pending_calls.append(record)
        return result

    # ---------------------------------------------------------- evidence ---

    def evidence(
        self,
        summary: str,
        *,
        kind: EvidenceKind = EvidenceKind.EVENT,
        detail: str = "",
        event_ids: list[str] | None = None,
        node_ids: list[str] | None = None,
        source: ToolResult | None = None,
        assurance: Assurance = Assurance.OBSERVED,
    ) -> str:
        """Record a retrieved fact and return its id.

        ``source`` carries the provenance across automatically, so the common
        case cannot forget to cite the tool call that produced the fact.
        """
        call_id = self._pending_calls[-1].call_id if self._pending_calls else ""
        tool_name = self._pending_calls[-1].tool if self._pending_calls else ""

        item = EvidenceItem(
            evidence_id="ev-" + uuid.uuid4().hex[:10],
            kind=kind if source is None else source.kind,
            summary=summary,
            detail=detail,
            event_ids=list(event_ids if event_ids is not None else (source.event_ids if source else [])),
            node_ids=list(node_ids if node_ids is not None else (source.node_ids if source else [])),
            source_tool=tool_name,
            source_call_id=call_id,
            assurance=assurance,
        )
        self.investigation.evidence.append(item)
        return item.evidence_id

    # ---------------------------------------------------------- findings ---

    def finding(
        self,
        title: str,
        statement: str,
        *,
        assurance: Assurance,
        confidence: float,
        evidence_ids: list[str],
    ) -> str:
        """State a conclusion. Requires evidence: that is the whole contract."""
        if not evidence_ids:
            raise ValueError(
                "{} tried to record a finding with no evidence: {}".format(
                    self.agent.value, title
                )
            )
        item = Finding(
            finding_id="fi-" + uuid.uuid4().hex[:10],
            agent=self.agent,
            title=title,
            statement=statement,
            assurance=assurance,
            confidence=round(max(0.0, min(1.0, confidence)), 3),
            evidence_ids=list(evidence_ids),
        )
        self.investigation.findings.append(item)
        return item.finding_id

    # -------------------------------------------------------------- steps ---

    async def step(
        self,
        action: str,
        detail: str = "",
        *,
        evidence_ids: list[str] | None = None,
        finding_ids: list[str] | None = None,
    ) -> AgentStep:
        """Close off one unit of work and publish it to the timeline.

        Whatever tool calls the agent made since the last step are attached
        here, which is what keeps the timeline honest about how a conclusion
        was reached without exposing private reasoning.
        """
        record = AgentStep(
            step_id="st-" + uuid.uuid4().hex[:10],
            agent=self.agent,
            action=action,
            detail=detail,
            tool_calls=list(self._pending_calls),
            evidence_ids=list(evidence_ids or []),
            finding_ids=list(finding_ids or []),
        )
        self._pending_calls.clear()

        self.investigation.steps.append(record)
        self.investigation.updated_at = record.at

        run = self.investigation.agent_run(self.agent)
        if run is not None:
            run.step_ids.append(record.step_id)
            run.tool_call_count += len(record.tool_calls)
            run.finding_ids.extend(record.finding_ids)

        if self._listener is not None:
            await self._listener(self.investigation, record)

        delay = self.settings.agents.step_delay_seconds
        if delay > 0:
            await asyncio.sleep(delay)
        return record


class Agent(ABC):
    """A specialised investigator."""

    name: AgentName
    label: str = ""
    purpose: str = ""

    def should_run(self, investigation: Investigation) -> tuple[bool, str]:
        """Whether the orchestrator should run this agent, and why not if not.

        Agents that cannot contribute are skipped rather than run to produce
        nothing; the orchestrator reports the reason so the skip is visible.
        """
        return True, ""

    @abstractmethod
    async def run(self, workspace: AgentWorkspace) -> str:
        """Do the work and return a one-line summary for the agent panel."""


async def execute(
    agent: Agent,
    investigation: Investigation,
    registry: ToolRegistry,
    settings: Settings,
    listener: StepListener | None = None,
) -> AgentRun:
    """Run one agent, recording status and timing on its AgentRun."""
    run = investigation.agent_run(agent.name)
    if run is None:
        run = AgentRun(agent=agent.name)
        investigation.agents.append(run)

    allowed, reason = agent.should_run(investigation)
    if not allowed:
        run.status = AgentStatus.SKIPPED
        run.skip_reason = reason
        run.summary = reason
        return run

    run.status = AgentStatus.RUNNING
    run.started_at = _now()
    workspace = AgentWorkspace(agent.name, investigation, registry, settings, listener)

    try:
        run.summary = await agent.run(workspace)
        run.status = AgentStatus.COMPLETE
    except Exception as exc:  # noqa: BLE001 - one agent must not kill the run
        run.status = AgentStatus.FAILED
        run.summary = "Agent failed: {}".format(exc)
        logger.exception(
            "agent failed",
            extra={"agent": agent.name.value, "investigation": investigation.investigation_id},
        )
    finally:
        run.finished_at = _now()

    return run
