"""The orchestrator: decide which agents run, in what order, and when to stop.

Running every agent on every case would be the agentic equivalent of alerting on
every event. The orchestrator therefore does two things beyond sequencing:

* it stops early when triage says there is nothing here, and
* it lets each agent decline when its preconditions are not met, recording the
  reason so a skipped agent is visible rather than silently absent.

The order itself is not arbitrary. Triage establishes the subject; correlation
tests whether the cluster is real; investigation gathers the substance; evidence
makes the citations resolvable; graph, MITRE and chain each add a dimension;
next-target projects forward; and verification runs last because it checks
everything the others produced.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.agents import base
from app.agents.base import Agent, StepListener
from app.agents.chain_agent import AttackChainAgent
from app.agents.correlation_agent import CorrelationAgent
from app.agents.evidence import EvidenceAgent
from app.agents.graph_agent import GraphReasoningAgent
from app.agents.investigation import InvestigationAgent
from app.agents.llm import LLMProvider
from app.agents.mitre_agent import MitreAgent
from app.agents.narrative import build_summary
from app.agents.next_target import NextTargetAgent
from app.agents.state import (
    AGENT_LABELS,
    AGENT_PURPOSE,
    AgentName,
    AgentRun,
    AgentStatus,
    Investigation,
    InvestigationMetrics,
)
from app.agents.tools import ToolContext, ToolRegistry
from app.agents.triage import TriageAgent
from app.agents.verification import VerificationAgent
from app.core.config import Settings
from app.core.logging_config import get_logger

logger = get_logger(__name__)

#: Pipeline order. Verification is last by construction.
PIPELINE: list[Agent] = [
    TriageAgent(),
    CorrelationAgent(),
    InvestigationAgent(),
    EvidenceAgent(),
    GraphReasoningAgent(),
    MitreAgent(),
    AttackChainAgent(),
    NextTargetAgent(),
    VerificationAgent(),
]


def new_investigation(
    chain_id: str | None = None, trigger: str = "manual"
) -> Investigation:
    """Create an investigation with its agent roster already laid out.

    The roster exists before any agent runs so the UI can show the full plan
    from the first frame, with everything pending, rather than having agents
    appear one at a time.
    """
    investigation = Investigation(
        investigation_id="INV-" + uuid.uuid4().hex[:6].upper(),
        status="pending",
        attack_chain_id=chain_id,
        trigger=trigger,
    )
    investigation.agents = [
        AgentRun(
            agent=agent.name,
            label=AGENT_LABELS[agent.name],
            purpose=AGENT_PURPOSE[agent.name],
            status=AgentStatus.PENDING,
        )
        for agent in PIPELINE
    ]
    return investigation


class Orchestrator:
    """Runs the pipeline for one investigation."""

    def __init__(
        self,
        settings: Settings,
        provider: LLMProvider,
        listener: StepListener | None = None,
    ) -> None:
        self.settings = settings
        self.provider = provider
        self.listener = listener

    async def run(
        self,
        investigation: Investigation,
        context: ToolContext,
    ) -> Investigation:
        started = datetime.now(tz=timezone.utc)
        investigation.status = "active"
        registry = ToolRegistry(context)

        self._seed_metrics(investigation, context)

        for agent in PIPELINE:
            run = await base.execute(
                agent, investigation, registry, self.settings, self.listener
            )

            # Triage is the one agent allowed to end the investigation.
            if agent.name is AgentName.TRIAGE and not investigation.findings:
                self._skip_remaining(investigation, after=AgentName.TRIAGE)
                investigation.status = "complete"
                investigation.severity = "informational"
                break

            # Keep the running totals current: the UI polls mid-run, and a
            # footer reading "0 tool calls" while agents are visibly working is
            # simply wrong.
            investigation.evidence_count = len(investigation.evidence)
            investigation.metrics.tool_calls = len(registry.calls)
            investigation.metrics.evidence_items = investigation.evidence_count
            investigation.updated_at = datetime.now(tz=timezone.utc)

            logger.info(
                "agent finished",
                extra={
                    "investigation": investigation.investigation_id,
                    "agent": agent.name.value,
                    "status": run.status.value,
                    "tool_calls": run.tool_call_count,
                },
            )

        investigation.evidence_count = len(investigation.evidence)
        investigation.metrics.tool_calls = len(registry.calls)
        investigation.metrics.evidence_items = investigation.evidence_count
        investigation.metrics.investigation_seconds = round(
            (datetime.now(tz=timezone.utc) - started).total_seconds(), 2
        )

        investigation.summary = await build_summary(investigation, self.provider)
        investigation.status = "complete"
        investigation.completed_at = datetime.now(tz=timezone.utc)
        investigation.updated_at = investigation.completed_at
        return investigation

    @staticmethod
    def _skip_remaining(investigation: Investigation, after: AgentName) -> None:
        """Mark everything downstream of a stopping point as skipped."""
        reached = False
        for run in investigation.agents:
            if run.agent is after:
                reached = True
                continue
            if reached and run.status is AgentStatus.PENDING:
                run.status = AgentStatus.SKIPPED
                run.skip_reason = "Triage found nothing that warrants investigation"
                run.summary = run.skip_reason

    @staticmethod
    def _seed_metrics(investigation: Investigation, context: ToolContext) -> None:
        """Record the funnel as it stands before the agents touch anything."""
        notable = [e for e in context.events if e.is_notable]
        clustered = {
            eid for chain in context.chains for eid in chain.event_ids
        }
        investigation.metrics = InvestigationMetrics(
            raw_events=len(context.events),
            notable_events=len(notable),
            correlated_events=len(clustered),
            suspicious_clusters=len(context.chains),
            attack_chains=len(context.chains),
            investigations=1,
            # Flagged events that no chain absorbed: the noise correlation
            # declined to escalate.
            false_positive_candidates=len(
                [e for e in notable if e.event_id not in clustered]
            ),
        )
