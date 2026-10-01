"""Structured investigation state.

An investigation is not a transcript. It is a record of which agents ran, which
tools they called, what evidence those calls returned, and which findings that
evidence supports. Every finding points at evidence, and every piece of evidence
points at the tool call and the source event ids that produced it.

That chain -- finding -> evidence -> tool call -> source event -> raw log record
-- is what makes a conclusion checkable rather than merely plausible.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from app.models.analysis import Assurance, Confidence, confidence_from_score


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


class AgentName(str, Enum):
    """The specialised agents. Order here is the natural pipeline order."""

    TRIAGE = "triage"
    CORRELATION = "correlation"
    INVESTIGATION = "investigation"
    EVIDENCE = "evidence"
    GRAPH = "graph"
    MITRE = "mitre"
    CHAIN = "chain"
    NEXT_TARGET = "next_target"
    VERIFICATION = "verification"


AGENT_LABELS: dict[AgentName, str] = {
    AgentName.TRIAGE: "Triage Agent",
    AgentName.CORRELATION: "Correlation Agent",
    AgentName.INVESTIGATION: "Investigation Agent",
    AgentName.EVIDENCE: "Evidence Agent",
    AgentName.GRAPH: "Graph Reasoning Agent",
    AgentName.MITRE: "MITRE ATT&CK Agent",
    AgentName.CHAIN: "Attack Chain Agent",
    AgentName.NEXT_TARGET: "Next-Target Agent",
    AgentName.VERIFICATION: "Verification Agent",
}

AGENT_PURPOSE: dict[AgentName, str] = {
    AgentName.TRIAGE: "Decides whether anything here is worth a human's time.",
    AgentName.CORRELATION: "Tests whether separate alerts belong to one attack.",
    AgentName.INVESTIGATION: "Runs the investigation plan, step by step.",
    AgentName.EVIDENCE: "Pulls the supporting records behind every claim.",
    AgentName.GRAPH: "Answers reachability and access questions from the graph.",
    AgentName.MITRE: "Maps observed behaviour to ATT&CK, with evidence.",
    AgentName.CHAIN: "Reconstructs the chronological attack story.",
    AgentName.NEXT_TARGET: "Scores where the attacker could go next.",
    AgentName.VERIFICATION: "Re-checks every conclusion against the evidence.",
}


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    SKIPPED = "skipped"
    FAILED = "failed"


class AnalystDecision(str, Enum):
    """Human-in-the-loop verdict. The agents recommend; the analyst decides."""

    APPROVED = "approved"
    REJECTED = "rejected"
    FALSE_POSITIVE = "false_positive"


class EvidenceKind(str, Enum):
    EVENT = "event"
    GRAPH = "graph"
    MITRE = "mitre"
    INVENTORY = "inventory"
    CORRELATION = "correlation"


class ToolCall(BaseModel):
    """One evidence-retrieval call, recorded so it can be replayed."""

    call_id: str
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result_count: int = 0
    result_summary: str = ""
    duration_ms: float = 0.0
    at: datetime = Field(default_factory=_now)
    #: False when the tool ran but found nothing; the call still happened.
    produced_evidence: bool = True


class EvidenceItem(BaseModel):
    """A retrieved fact, traceable to its source."""

    evidence_id: str
    kind: EvidenceKind
    summary: str
    detail: str = ""
    #: Source events. This is what makes a finding checkable.
    event_ids: list[str] = Field(default_factory=list)
    #: Graph entities the fact concerns, as builder node ids.
    node_ids: list[str] = Field(default_factory=list)
    source_tool: str = ""
    source_call_id: str = ""
    assurance: Assurance = Assurance.OBSERVED
    at: datetime = Field(default_factory=_now)


class Finding(BaseModel):
    """A conclusion an agent reached, and what it rests on."""

    finding_id: str
    agent: AgentName
    title: str
    statement: str
    assurance: Assurance
    confidence: float = 0.5
    evidence_ids: list[str] = Field(default_factory=list)

    #: Set by the Verification Agent.
    verified: bool | None = None
    verification_notes: list[str] = Field(default_factory=list)
    #: Confidence before verification adjusted it, when it did.
    confidence_before_verification: float | None = None

    #: Human-in-the-loop.
    analyst_decision: AnalystDecision | None = None
    analyst_note: str = ""
    decided_at: datetime | None = None

    at: datetime = Field(default_factory=_now)

    @property
    def confidence_label(self) -> Confidence:
        return confidence_from_score(self.confidence)


class AgentStep(BaseModel):
    """One line of the agent reasoning timeline.

    Concise actions, evidence and conclusions only. This is deliberately not a
    chain-of-thought dump: it is the record an analyst reviews.
    """

    step_id: str
    agent: AgentName
    action: str
    detail: str = ""
    at: datetime = Field(default_factory=_now)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)


class AgentRun(BaseModel):
    """The record of one agent's participation in an investigation."""

    agent: AgentName
    label: str = ""
    purpose: str = ""
    status: AgentStatus = AgentStatus.PENDING
    summary: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None
    step_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    tool_call_count: int = 0
    #: Why the orchestrator skipped this agent, when it did.
    skip_reason: str = ""

    @property
    def duration_ms(self) -> float | None:
        if not self.started_at or not self.finished_at:
            return None
        return (self.finished_at - self.started_at).total_seconds() * 1000


class InvestigationMetrics(BaseModel):
    """The funnel: raw telemetry down to one thing a human looks at."""

    raw_events: int = 0
    notable_events: int = 0
    correlated_events: int = 0
    suspicious_clusters: int = 0
    attack_chains: int = 0
    investigations: int = 1
    #: Flagged events no chain absorbed: noise correlation declined to escalate.
    false_positive_candidates: int = 0
    #: Findings the analyst dismissed. A different thing, kept separate.
    analyst_false_positives: int = 0
    tool_calls: int = 0
    evidence_items: int = 0
    #: Wall-clock seconds the agents took, measured, not estimated.
    investigation_seconds: float = 0.0


class AISummary(BaseModel):
    """The analyst-facing conclusion."""

    headline: str
    narrative: str
    observed: list[str] = Field(default_factory=list)
    inferred: list[str] = Field(default_factory=list)
    predicted: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    evidence_count: int = 0
    technique_count: int = 0
    confidence: float = 0.0
    status: str = ""
    #: "deterministic" or the provider name, so the reader knows who wrote it.
    generated_by: str = "deterministic"


class Investigation(BaseModel):
    """Everything known about one investigation."""

    investigation_id: str
    status: str = "pending"  # pending | active | complete | failed
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)
    completed_at: datetime | None = None

    #: The chain that triggered this investigation, when there was one.
    attack_chain_id: str | None = None
    trigger: str = "manual"

    initial_host: str | None = None
    current_host: str | None = None
    current_stage: str | None = None
    user: str | None = None
    observed_techniques: list[str] = Field(default_factory=list)
    potential_targets: list[str] = Field(default_factory=list)

    evidence_count: int = 0
    confidence: float = 0.0
    severity: str = "medium"

    agents: list[AgentRun] = Field(default_factory=list)
    steps: list[AgentStep] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    metrics: InvestigationMetrics = Field(default_factory=InvestigationMetrics)
    summary: AISummary | None = None

    def agent_run(self, agent: AgentName) -> AgentRun | None:
        for run in self.agents:
            if run.agent is agent:
                return run
        return None

    def finding(self, finding_id: str) -> Finding | None:
        for item in self.findings:
            if item.finding_id == finding_id:
                return item
        return None

    def evidence_item(self, evidence_id: str) -> EvidenceItem | None:
        for item in self.evidence:
            if item.evidence_id == evidence_id:
                return item
        return None

    def findings_by_agent(self, agent: AgentName) -> list[Finding]:
        return [f for f in self.findings if f.agent is agent]

    def accepted_findings(self) -> list[Finding]:
        """Findings an analyst has not rejected."""
        return [
            f
            for f in self.findings
            if f.analyst_decision
            not in {AnalystDecision.REJECTED, AnalystDecision.FALSE_POSITIVE}
        ]


class InvestigationSummaryView(BaseModel):
    """The compact row used by the investigation list."""

    investigation_id: str
    status: str
    created_at: datetime
    attack_chain_id: str | None
    initial_host: str | None
    current_host: str | None
    current_stage: str | None = None
    user: str | None
    confidence: float
    severity: str
    evidence_count: int
    technique_count: int
    potential_targets: list[str] = Field(default_factory=list)
    agents_complete: int = 0
    agents_total: int = 0
