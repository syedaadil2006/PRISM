"""Analysis outputs: correlations, MITRE mappings, chains and predictions.

Every model in this module carries its own explanation fields. A detection
without evidence is not shippable in PRISM.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from app.models.events import NormalizedEvent


class Assurance(str, Enum):
    """How PRISM came to believe a statement.

    The UI colour-codes by this value so an analyst never mistakes a prediction
    for observed attacker activity.
    """

    OBSERVED = "observed"
    CORRELATED = "correlated"
    INFERRED = "inferred"
    PREDICTED = "predicted"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def confidence_from_score(score: float) -> Confidence:
    """Map a 0-1 score onto a coarse confidence label."""
    if score >= 0.80:
        return Confidence.HIGH
    if score >= 0.55:
        return Confidence.MEDIUM
    return Confidence.LOW


class CorrelationFactor(BaseModel):
    """One dimension that contributed to a correlation score."""

    name: str
    weight: float
    detail: str


class Correlation(BaseModel):
    """A scored link between two events."""

    source_event_id: str
    target_event_id: str
    score: float
    time_delta_seconds: float
    factors: list[CorrelationFactor] = Field(default_factory=list)
    assurance: Assurance = Assurance.CORRELATED

    @property
    def reasons(self) -> list[str]:
        return [f.detail for f in self.factors]


class MitreMapping(BaseModel):
    """A MITRE ATT&CK technique attributed to a concrete event."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic: str
    event_id: str
    evidence: str
    explanation: str
    confidence: Confidence
    assurance: Assurance = Assurance.OBSERVED
    reference: str | None = None


class AttackStage(BaseModel):
    """One step of the attack story, as shown on the timeline."""

    order: int
    tactic: str
    label: str
    timestamp: datetime
    #: Last time this (tactic, host) stage was seen active.
    last_timestamp: datetime | None = None
    host: str | None = None
    user: str | None = None
    event_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    description: str = ""
    assurance: Assurance = Assurance.OBSERVED


class LateralMovement(BaseModel):
    """An explainable lateral-movement detection."""

    movement_id: str
    timestamp: datetime
    user: str | None
    source_host: str
    destination_host: str
    method: str
    event_id: str
    correlation_score: float
    confidence: Confidence
    assurance: Assurance = Assurance.INFERRED
    #: The rule clauses that fired, in the order the rule evaluates them.
    rule_evaluation: list[str] = Field(default_factory=list)
    explanation: str = ""


class PredictionFactor(BaseModel):
    name: str
    points: float
    max_points: float
    detail: str


class TargetPrediction(BaseModel):
    """A potential, not confirmed, next target."""

    host: str
    raw_score: float
    score: float
    confidence: Confidence
    assurance: Assurance = Assurance.PREDICTED
    factors: list[PredictionFactor] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    narrative: str = ""
    attack_chain_id: str | None = None
    is_critical_infrastructure: bool = False


class RootCause(BaseModel):
    """Analyst-facing root-cause narrative for a chain."""

    initial_host: str | None
    initial_user: str | None
    initial_event_id: str | None
    initial_evidence: str
    observed_progression: list[str] = Field(default_factory=list)
    current_status: str = ""
    potential_next_target: str | None = None
    inference_notes: list[str] = Field(default_factory=list)


class AttackChain(BaseModel):
    """The core PRISM artefact: one correlated attack story."""

    attack_chain_id: str
    name: str
    status: str = "active"
    severity: str = "high"
    risk_score: int = 0

    start_time: datetime
    last_seen: datetime

    initial_host: str | None = None
    current_host: str | None = None
    users: list[str] = Field(default_factory=list)
    #: Hosts where attacker activity was actually observed.
    hosts: list[str] = Field(default_factory=list)
    #: Hosts the chain reached for without (yet) succeeding.
    targeted_hosts: list[str] = Field(default_factory=list)

    event_ids: list[str] = Field(default_factory=list)
    event_count: int = 0
    correlation_count: int = 0
    mean_correlation_score: float = 0.0

    current_stage: str = "Unknown"
    stages: list[AttackStage] = Field(default_factory=list)
    mitre: list[MitreMapping] = Field(default_factory=list)
    lateral_movements: list[LateralMovement] = Field(default_factory=list)
    predictions: list[TargetPrediction] = Field(default_factory=list)
    root_cause: RootCause | None = None
    confidence: Confidence = Confidence.MEDIUM

    @property
    def primary_user(self) -> str | None:
        return self.users[0] if self.users else None


class AttackChainDetail(BaseModel):
    """A chain plus the fully hydrated evidence behind it."""

    chain: AttackChain
    events: list[NormalizedEvent] = Field(default_factory=list)
    correlations: list[Correlation] = Field(default_factory=list)


class DashboardStats(BaseModel):
    active_attack_chains: int
    correlated_events: int
    total_events: int
    compromised_hosts: int
    lateral_movements: int
    potential_targets: int
    mitre_techniques: int
    raw_alert_count: int
    alert_reduction_ratio: float
