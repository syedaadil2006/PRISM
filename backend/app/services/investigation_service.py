"""Owns investigations: starting them, running them, and recording verdicts.

An investigation runs as a background task so the UI can watch it progress
rather than waiting on one long request. The agents write into the investigation
object as they go, and the API reads that same object, so a poll mid-run returns
a partially complete investigation rather than nothing.

Analyst decisions live here too. The agents recommend; the analyst approves,
rejects or marks a false positive; and a rejected finding is excluded from the
summary without being deleted, because the disagreement is itself a record.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from app.agents.base import StepListener
from app.agents.llm import LLMProvider, get_provider
from app.agents.narrative import build_summary
from app.agents.orchestrator import Orchestrator, new_investigation
from app.agents.state import (
    AgentStatus,
    AgentStep,
    AnalystDecision,
    Investigation,
    InvestigationSummaryView,
)
from app.agents.tools import ToolContext
from app.core.config import Settings
from app.core.logging_config import get_logger
from app.services.soc_state import SocState

logger = get_logger(__name__)


class InvestigationError(RuntimeError):
    """Raised when an investigation cannot be started or found."""


class InvestigationService:
    """The agentic layer's entry point."""

    def __init__(self, settings: Settings, soc: SocState) -> None:
        self.settings = settings
        self.soc = soc
        llm = settings.llm
        if settings.local_only and llm.provider != "none":
            # Local-only mode: findings are never sent to an outside model API.
            logger.warning("local-only mode: language model disabled", extra={"provider": llm.provider})
            llm = llm.model_copy(update={"provider": "none"})
        self.provider: LLMProvider = get_provider(llm)
        self._investigations: dict[str, Investigation] = {}
        self._order: list[str] = []
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()
        self._restore()

    # ------------------------------------------------------- persistence ---

    def _restore(self) -> None:
        """Load investigations (and analyst decisions) kept from earlier runs."""
        for data in self.soc.store.load_investigations(self.settings.agents.max_investigations):
            try:
                investigation = Investigation.model_validate_json(data)
            except ValueError as exc:
                logger.warning("skipping unreadable stored investigation", extra={"error": str(exc)})
                continue
            if investigation.status == "active":  # interrupted by a restart
                investigation.status = "cancelled"
            self._investigations[investigation.investigation_id] = investigation
            self._order.append(investigation.investigation_id)

    def _persist(self, investigation: Investigation) -> None:
        self.soc.store.save_investigation(
            investigation.investigation_id,
            investigation.created_at.isoformat(),
            investigation.model_dump_json(),
        )

    # ------------------------------------------------------------- reads ---

    @property
    def provider_name(self) -> str:
        return self.provider.name

    def get(self, investigation_id: str) -> Investigation | None:
        return self._investigations.get(investigation_id)

    def require(self, investigation_id: str) -> Investigation:
        investigation = self.get(investigation_id)
        if investigation is None:
            raise InvestigationError("investigation {} not found".format(investigation_id))
        return investigation

    def list(self) -> list[Investigation]:
        """Newest first."""
        return [self._investigations[i] for i in reversed(self._order)]

    def summaries(self) -> list[InvestigationSummaryView]:
        return [self._summary_view(i) for i in self.list()]

    def latest(self) -> Investigation | None:
        return self._investigations[self._order[-1]] if self._order else None

    def for_chain(self, chain_id: str) -> Investigation | None:
        for investigation in reversed(self.list()):
            if investigation.attack_chain_id == chain_id:
                return investigation
        return None

    @staticmethod
    def _summary_view(investigation: Investigation) -> InvestigationSummaryView:
        return InvestigationSummaryView(
            investigation_id=investigation.investigation_id,
            status=investigation.status,
            created_at=investigation.created_at,
            attack_chain_id=investigation.attack_chain_id,
            initial_host=investigation.initial_host,
            current_host=investigation.current_host,
            current_stage=investigation.current_stage,
            user=investigation.user,
            confidence=investigation.confidence,
            severity=investigation.severity,
            evidence_count=investigation.evidence_count,
            technique_count=len(investigation.observed_techniques),
            potential_targets=list(investigation.potential_targets),
            agents_complete=sum(
                1
                for run in investigation.agents
                if run.status in {AgentStatus.COMPLETE, AgentStatus.SKIPPED}
            ),
            agents_total=len(investigation.agents),
        )

    # ------------------------------------------------------------ running ---

    def _context(self) -> ToolContext:
        """A snapshot of the current analysis for the agents to read."""
        analysis = self.soc.analysis
        return ToolContext(
            events=list(analysis.events),
            correlations=list(analysis.correlations),
            chains=list(analysis.chains),
            graph=analysis.graph,
            inventory=self.soc.inventory,
            settings=self.settings,
        )

    async def start(
        self, chain_id: str | None = None, trigger: str = "manual"
    ) -> Investigation:
        """Open an investigation and run the agent pipeline in the background."""
        if not self.settings.agents.enabled:
            raise InvestigationError("the agent layer is disabled")

        chains = self.soc.analysis.chains
        if chain_id is None:
            if not chains:
                raise InvestigationError("no attack chain is available to investigate")
            chain_id = chains[0].attack_chain_id
        elif self.soc.analysis.chain(chain_id) is None:
            raise InvestigationError("attack chain {} not found".format(chain_id))

        investigation = new_investigation(chain_id, trigger)

        async with self._lock:
            self._investigations[investigation.investigation_id] = investigation
            self._order.append(investigation.investigation_id)
            self._evict_if_needed()

        task = asyncio.create_task(self._run(investigation))
        self._tasks[investigation.investigation_id] = task
        logger.info(
            "investigation started",
            extra={
                "investigation": investigation.investigation_id,
                "chain": chain_id,
                "trigger": trigger,
            },
        )
        return investigation

    async def _run(self, investigation: Investigation) -> None:
        listener: StepListener | None = None
        orchestrator = Orchestrator(self.settings, self.provider, listener)
        try:
            await orchestrator.run(investigation, self._context())
        except asyncio.CancelledError:
            investigation.status = "failed"
            raise
        except Exception as exc:  # noqa: BLE001 - surfaced on the investigation
            investigation.status = "failed"
            logger.exception(
                "investigation failed",
                extra={"investigation": investigation.investigation_id, "error": str(exc)},
            )
        finally:
            self._tasks.pop(investigation.investigation_id, None)
            self._persist(investigation)

    def _evict_if_needed(self) -> None:
        limit = self.settings.agents.max_investigations
        evicted = False
        while len(self._order) > limit:
            oldest = self._order.pop(0)
            self._investigations.pop(oldest, None)
            evicted = True
        if evicted:
            self.soc.store.delete_investigations(set(self._order))

    async def cancel(self, investigation_id: str) -> Investigation:
        investigation = self.require(investigation_id)
        task = self._tasks.get(investigation_id)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if investigation.status == "active":
            investigation.status = "cancelled"
        self._persist(investigation)
        return investigation

    async def shutdown(self) -> None:
        for investigation_id in list(self._tasks):
            await self.cancel(investigation_id)

    async def clear(self) -> None:
        """Drop every investigation, e.g. when the dataset is reloaded."""
        await self.shutdown()
        async with self._lock:
            self._investigations.clear()
            self._order.clear()
        self.soc.store.delete_investigations()

    # -------------------------------------------------- human in the loop ---

    async def decide(
        self,
        investigation_id: str,
        finding_id: str,
        decision: AnalystDecision,
        note: str = "",
    ) -> Investigation:
        """Record an analyst verdict and rebuild the summary around it."""
        investigation = self.require(investigation_id)
        finding = investigation.finding(finding_id)
        if finding is None:
            raise InvestigationError("finding {} not found".format(finding_id))

        finding.analyst_decision = decision
        finding.analyst_note = note
        finding.decided_at = datetime.now(tz=timezone.utc)
        investigation.updated_at = finding.decided_at

        # Confidence follows the findings that survive the analyst's review.
        accepted = [
            f for f in investigation.accepted_findings() if f.verified is not False
        ]
        investigation.confidence = (
            round(sum(f.confidence for f in accepted) / len(accepted), 3)
            if accepted
            else 0.0
        )
        if decision is AnalystDecision.FALSE_POSITIVE:
            investigation.metrics.analyst_false_positives += 1

        investigation.summary = await build_summary(investigation, self.provider)
        self._persist(investigation)
        logger.info(
            "analyst decision recorded",
            extra={
                "investigation": investigation_id,
                "finding": finding_id,
                "decision": decision.value,
            },
        )
        return investigation
