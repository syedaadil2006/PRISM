"""Read models for the host, user and MITRE pages.

These join inventory facts with what was actually observed, so a page can show
"this is a domain controller" and "this is where the attacker is" together.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.analysis import MitreMapping


class HostView(BaseModel):
    name: str
    ip: str | None = None
    role: str = "workstation"
    zone: str = "corp"
    os: str | None = None
    criticality: float = 0.0
    is_critical_infrastructure: bool = False
    #: normal | suspicious | compromised | current_position | potential_target
    state: str = "normal"
    event_count: int = 0
    suspicious_event_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    users: list[str] = Field(default_factory=list)
    attack_chain_ids: list[str] = Field(default_factory=list)
    prediction_score: float | None = None
    reachable_hosts: list[str] = Field(default_factory=list)


class UserView(BaseModel):
    name: str
    display_name: str | None = None
    department: str | None = None
    privilege: float = 0.0
    is_privileged: bool = False
    groups: list[str] = Field(default_factory=list)
    accessible_hosts: list[str] = Field(default_factory=list)
    hosts_observed: list[str] = Field(default_factory=list)
    event_count: int = 0
    failed_logons: int = 0
    compromised: bool = False
    attack_chain_ids: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class TechniqueView(BaseModel):
    """One technique, with every event that justified it."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic: str
    reference: str | None = None
    occurrences: int = 0
    confidence: str = "medium"
    attack_chain_ids: list[str] = Field(default_factory=list)
    evidence: list[MitreMapping] = Field(default_factory=list)


class TacticView(BaseModel):
    tactic_id: str
    tactic: str
    order: int
    techniques: list[TechniqueView] = Field(default_factory=list)


class EngineConfigView(BaseModel):
    """The tunables behind every detection, surfaced so the UI can show them."""

    correlation_window_seconds: int
    correlation_min_score: float
    correlation_min_chain_events: int
    correlation_weights: dict[str, float]
    lateral_window_seconds: int
    lateral_min_correlation_score: float
    lateral_movement_actions: list[str]
    prediction_weights: dict[str, float]
    prediction_normalisation_ceiling: float
    neo4j_enabled: bool
    demo_mode: bool


class HealthView(BaseModel):
    status: str
    version: str
    events: int
    chains: int
    sources: list[str] = Field(default_factory=list)
    ingest_errors: list[str] = Field(default_factory=list)
    computed_at: datetime | None = None
