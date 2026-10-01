"""Application configuration.

Every tunable value in PRISM is exposed here so that the correlation,
lateral-movement and prediction engines stay explainable and configurable
instead of relying on magic numbers buried in the detection code.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_ROOT.parent


class CorrelationSettings(BaseSettings):
    """Weights and thresholds used by the correlation engine."""

    model_config = SettingsConfigDict(env_prefix="PRISM_CORRELATION_", extra="ignore")

    # Maximum separation for two events to be considered for correlation at all.
    window_seconds: int = 1800
    # Score at or above which two events are linked into the same attack chain.
    min_score: float = 0.70
    # Minimum number of correlated events before a component is promoted to a chain.
    min_chain_events: int = 2

    weight_same_user: float = 0.35
    weight_same_host: float = 0.25
    weight_host_pivot: float = 0.40
    weight_shared_ip: float = 0.20
    weight_process_host: float = 0.15
    weight_domain_overlap: float = 0.15
    # Two suspicious events on one host inside the window reinforce each other.
    weight_suspicious_coincidence: float = 0.25
    # Fraction of the score contributed purely by temporal proximity.
    weight_time_proximity: float = 0.25


class LateralMovementSettings(BaseSettings):
    """Rule parameters for the explainable lateral-movement rule engine."""

    model_config = SettingsConfigDict(env_prefix="PRISM_LATERAL_", extra="ignore")

    window_seconds: int = 600
    min_correlation_score: float = 0.70
    # Authentication actions that can carry an attacker between hosts.
    movement_actions: tuple[str, ...] = (
        "RDP_LOGIN",
        "SMB_AUTH",
        "NETWORK_LOGON",
        "PRIVILEGED_LOGIN",
        "REMOTE_SERVICE_EXEC",
    )


class PredictionSettings(BaseSettings):
    """Factor weights for the explainable next-target score."""

    model_config = SettingsConfigDict(env_prefix="PRISM_PREDICTION_", extra="ignore")

    weight_user_access: float = 30.0
    weight_privilege: float = 25.0
    weight_connectivity: float = 20.0
    weight_criticality: float = 20.0
    weight_recent_activity: float = 15.0
    weight_path_proximity: float = 20.0
    # Raw score used as the 100/100 reference point when normalising.
    normalisation_ceiling: float = 140.0
    max_predictions: int = 4


class AgentSettings(BaseSettings):
    """The agentic investigation layer.

    The agents are tool-driven: they gather evidence by calling the retrieval
    tools in ``app.agents.tools`` and reason over the graph. An LLM is optional
    and is only ever used to phrase a narrative over findings that have already
    been produced and verified, never to invent evidence. With no provider
    configured the whole layer still runs.
    """

    model_config = SettingsConfigDict(env_prefix="PRISM_AGENTS_", extra="ignore")

    enabled: bool = True
    #: Seconds between agent steps, so an investigation is watchable in a demo.
    step_delay_seconds: float = 0.55
    #: Findings below this confidence are reported but not treated as settled.
    min_finding_confidence: float = 0.45
    #: How far verification drops a finding whose evidence it cannot re-derive.
    verification_downgrade: float = 0.35
    #: Investigations kept in memory before the oldest is dropped.
    max_investigations: int = 20


class LLMSettings(BaseSettings):
    """Optional narrative provider.

    Deliberately modular: swapping provider must not require touching any agent.
    Credentials come from the environment and are never logged or returned by
    the API.
    """

    model_config = SettingsConfigDict(env_prefix="PRISM_LLM_", extra="ignore")

    #: "none" runs the deterministic narrator; "anthropic" uses the Messages API.
    provider: str = "none"
    model: str = "claude-sonnet-5"
    #: Taken from PRISM_LLM_API_KEY, else the provider's own variable.
    api_key: str = ""
    base_url: str = ""
    max_tokens: int = 900
    timeout_seconds: float = 30.0

    @property
    def resolved_api_key(self) -> str:
        if self.api_key:
            return self.api_key
        if self.provider == "anthropic":
            return os.environ.get("ANTHROPIC_API_KEY", "")
        if self.provider == "openai":
            return os.environ.get("OPENAI_API_KEY", "")
        return ""

    @property
    def configured(self) -> bool:
        return self.provider != "none" and bool(self.resolved_api_key)


class Neo4jSettings(BaseSettings):
    """Optional persistent graph store. Disabled by default so the prototype
    runs with zero external services."""

    model_config = SettingsConfigDict(env_prefix="PRISM_NEO4J_", extra="ignore")

    enabled: bool = False
    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: str = ""
    database: str = "neo4j"


class Settings(BaseSettings):
    """Top-level application settings."""

    model_config = SettingsConfigDict(
        env_prefix="PRISM_",
        env_file=(PROJECT_ROOT / ".env", BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "PRISM"
    version: str = "0.1.0"
    log_level: str = "INFO"

    data_dir: Path = BACKEND_ROOT / "data"

    #: Which bundled dataset to load:
    #:   "botsv1"    - real telemetry from Splunk's Boss of the SOC v1 (CC0),
    #:                 the Cerber ransomware scenario. See docs/DATASET.md.
    #:   "synthetic" - the hand-authored HR-PC -> FINANCE-PC -> DC01 scenario.
    #: PRISM_DEMO_DIR / PRISM_INVENTORY_FILE override either.
    #: Stays "synthetic" until backend/scripts/build_botsv1_scenario.py has run.
    dataset: str = "synthetic"
    demo_dir: Path | None = None
    inventory_file: Path | None = None

    @model_validator(mode="after")
    def _resolve_dataset_paths(self) -> "Settings":
        presets = {
            "botsv1": (
                BACKEND_ROOT / "data" / "botsv1" / "scenario",
                BACKEND_ROOT / "data" / "botsv1" / "inventory.json",
            ),
            "synthetic": (
                BACKEND_ROOT / "data" / "demo",
                BACKEND_ROOT / "data" / "inventory" / "topology.json",
            ),
        }
        if self.dataset not in presets:
            raise ValueError(
                "PRISM_DATASET must be one of {}".format(", ".join(sorted(presets)))
            )
        default_dir, default_inventory = presets[self.dataset]
        if self.demo_dir is None:
            self.demo_dir = default_dir
        if self.inventory_file is None:
            self.inventory_file = default_inventory
        return self

    # Load the bundled demo dataset on startup.
    demo_mode: bool = True
    # When true the demo dataset is revealed progressively by the simulator
    # instead of appearing all at once.
    simulation_autostart: bool = False
    simulation_tick_seconds: float = 1.2
    simulation_events_per_tick: int = 1

    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:4173",
        ]
    )

    correlation: CorrelationSettings = Field(default_factory=CorrelationSettings)
    lateral: LateralMovementSettings = Field(default_factory=LateralMovementSettings)
    prediction: PredictionSettings = Field(default_factory=PredictionSettings)
    neo4j: Neo4jSettings = Field(default_factory=Neo4jSettings)
    agents: AgentSettings = Field(default_factory=AgentSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
