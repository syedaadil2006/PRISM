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
    #: Up to this many notable events every candidate pair is scored (exact).
    #: Above it, large datasets use bounded neighbour lists so memory stays linear.
    exact_pair_limit: int = 1500
    max_neighbors_per_key: int = 30
    max_links_per_event: int = 10


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


class LiveSettings(BaseSettings):
    """Real-time ingestion: events pushed over HTTP or appended to watched files.

    Analysis is re-run in the background, throttled so a fast feed cannot keep
    the pipeline permanently busy.
    """

    model_config = SettingsConfigDict(env_prefix="PRISM_LIVE_", extra="ignore")

    enabled: bool = True
    #: Folder whose log files are tailed: new lines are ingested as they appear.
    watch_dir: Path = BACKEND_ROOT / "data" / "live"
    watch_interval_seconds: float = 1.0
    #: Minimum gap between two re-analyses while events keep arriving.
    recompute_interval_seconds: float = 1.0
    #: Oldest events are dropped beyond this, so a long-running feed stays bounded.
    max_events: int = 50_000
    #: Largest number of records accepted in one HTTP request.
    max_batch: int = 5_000
    #: Events waiting for analysis before senders are told to retry (HTTP 429). 0 = no limit.
    max_pending: int = 50_000


class SyslogSettings(BaseSettings):
    """Syslog receiver for Linux servers and network devices. Off by default."""

    model_config = SettingsConfigDict(env_prefix="PRISM_SYSLOG_", extra="ignore")

    enabled: bool = False
    #: 127.0.0.1 accepts only this computer; 0.0.0.0 accepts the network.
    host: str = "127.0.0.1"
    #: 5514 instead of 514 so no administrator rights are needed.
    port: int = 5514
    udp: bool = True
    tcp: bool = True


class ForwardSettings(BaseSettings):
    """Send attack-chain alerts to a SIEM. Nothing is sent unless a target is set."""

    model_config = SettingsConfigDict(env_prefix="PRISM_FORWARD_", extra="ignore")

    webhook_url: str = ""
    splunk_hec_url: str = ""
    splunk_hec_token: str = ""
    #: host:port of a syslog collector; alerts are sent as CEF over UDP.
    syslog_target: str = ""
    min_risk_score: int = 0
    timeout_seconds: float = 5.0
    #: Set false only for a SIEM with a self-signed certificate (lab setups).
    tls_verify: bool = True
    #: "prism" (PRISM's alert JSON) or "ocsf" (an OCSF Detection Finding).
    format: str = "prism"


class AuthSettings(BaseSettings):
    """Sign-in, user accounts, roles and the audit log (see app/core/auth.py)."""

    model_config = SettingsConfigDict(env_prefix="PRISM_AUTH_", extra="ignore")

    enabled: bool = True
    #: Fixed code; when empty one is generated and kept in token_file.
    token: str = ""
    token_file: Path = BACKEND_ROOT / "data" / ".prism_token"
    #: The shared access code (launcher, scripts, collectors). It acts as an
    #: admin; organisations that use named accounts only can switch it off.
    access_code_enabled: bool = True
    #: Users, sessions and the audit log. SQLite file path or postgresql:// URL.
    db_url: str = str(BACKEND_ROOT / "data" / "security.db")
    #: Sessions end this long after sign-in, whatever the activity.
    session_hours: float = 12.0
    #: Sign-in attempts allowed per account (and per address) in the window.
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    min_password_length: int = 12
    #: A fresh installation (no accounts yet) creates this admin on first start.
    #: Its first sign-in must choose a new password before anything else works.
    default_admin_enabled: bool = True
    default_admin_username: str = "admin"
    default_admin_password: str = "Admin@123"
    cookie_max_age_seconds: int = 7 * 24 * 3600


class StorageSettings(BaseSettings):
    """Persistent storage of uploads, live events and investigations."""

    model_config = SettingsConfigDict(env_prefix="PRISM_STORAGE_", extra="ignore")

    enabled: bool = True
    path: Path = BACKEND_ROOT / "data" / "prism.db"
    #: Optional postgresql://user:password@host:5432/db; empty means the SQLite file above.
    url: str = ""
    #: Stored events and investigations older than this are deleted (0 keeps everything).
    retention_days: int = 0


class DetectionSettings(BaseSettings):
    """Sigma rules, threat intelligence and behaviour baselines (see app/detection/)."""

    model_config = SettingsConfigDict(env_prefix="PRISM_DETECTION_", extra="ignore")

    sigma_enabled: bool = True
    #: Folders (or files) of Sigma rules. The bundled set comes first; add a
    #: SigmaHQ checkout or your own folder here.
    sigma_dirs: list[Path] = [BACKEND_ROOT / "detection" / "sigma"]
    #: Folders of indicator files (STIX 2.1 JSON, CSV, or one indicator per line).
    intel_dirs: list[Path] = [BACKEND_ROOT / "data" / "intel"]
    baseline_enabled: bool = True
    #: Events an account or computer needs before departures count as anomalies.
    baseline_min_history: int = 20
    #: How long an account or computer is watched before departures count.
    baseline_learning_hours: float = 24.0
    #: Low-risk patterns repeated on this many different days are routine
    #: (kept as evidence, cannot start a chain). 0 switches this off.
    baseline_routine_days: int = 3


class BackupSettings(BaseSettings):
    """Automatic backups of PRISM's databases (see app/services/backup.py)."""

    model_config = SettingsConfigDict(env_prefix="PRISM_BACKUP_", extra="ignore")

    dir: Path = BACKEND_ROOT / "data" / "backups"
    #: Hours between automatic backups (0 = only when asked for).
    interval_hours: float = 24.0
    #: Newest backups kept; older ones are deleted.
    keep: int = 7


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
    #: Edge / local-only mode (see app/core/local_only.py): data never leaves
    #: this computer. On by default; only PRISM_LOCAL_ONLY=false turns it off.
    local_only: bool = True
    #: Extra networks treated as "this computer" in local-only mode, as CIDRs.
    #: Only for containers: Docker delivers the host's own requests from its
    #: bridge network. Publish the port on 127.0.0.1 so nothing else can reach it.
    local_networks: list[str] = []
    version: str = "0.1.0"
    log_level: str = "INFO"

    data_dir: Path = BACKEND_ROOT / "data"

    #: Which bundled dataset to load:
    #:   "botsv1"    - real telemetry from Splunk's Boss of the SOC v1 (CC0),
    #:                 the Cerber ransomware scenario. See docs/DATASET.md.
    #:   "synthetic" - the hand-authored HR-PC -> FINANCE-PC -> DC01 scenario.
    #:   "live"      - start empty and analyse only events that arrive in real
    #:                 time (POST /api/live/events or the watched folder).
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
            # No bundled dataset and no inventory: everything comes from the live
            # feed, so only computers and accounts actually seen appear. (The
            # demo company's inventory would add its made-up hosts and users.)
            # PRISM_INVENTORY_FILE can point at a real inventory for this site.
            "live": (None, None),
        }
        if self.dataset not in presets:
            raise ValueError(
                "PRISM_DATASET must be one of {}".format(", ".join(sorted(presets)))
            )
        default_dir, default_inventory = presets[self.dataset]
        if self.demo_dir is None:
            self.demo_dir = default_dir
        if self.inventory_file is None and default_inventory is not None:
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
    live: LiveSettings = Field(default_factory=LiveSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    backup: BackupSettings = Field(default_factory=BackupSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    syslog: SyslogSettings = Field(default_factory=SyslogSettings)
    forward: ForwardSettings = Field(default_factory=ForwardSettings)
    agents: AgentSettings = Field(default_factory=AgentSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
