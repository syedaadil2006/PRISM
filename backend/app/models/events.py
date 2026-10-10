"""The PRISM normalized event schema.

Every ingested log line — regardless of whether it started life as a Windows
Security event, a Zeek ``dns.log`` record or a Sysmon process-creation event —
is converted into a :class:`NormalizedEvent`. Downstream engines only ever see
this shape, which is what makes adding a new log source a parser-only change.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventType(str, Enum):
    AUTHENTICATION = "authentication"
    DNS = "dns"
    ENDPOINT = "endpoint"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Action(str, Enum):
    """Canonical action vocabulary.

    Parsers map vendor-specific codes (Windows event IDs, Zeek fields, Sysmon
    event IDs) onto these values so the correlation rules can stay vendor
    agnostic.
    """

    # --- authentication ---
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    RDP_LOGIN = "RDP_LOGIN"
    SMB_AUTH = "SMB_AUTH"
    NETWORK_LOGON = "NETWORK_LOGON"
    PRIVILEGED_LOGIN = "PRIVILEGED_LOGIN"
    REMOTE_SERVICE_EXEC = "REMOTE_SERVICE_EXEC"

    # --- dns ---
    DNS_QUERY = "DNS_QUERY"
    SUSPICIOUS_DOMAIN = "SUSPICIOUS_DOMAIN"
    NEWLY_OBSERVED_DOMAIN = "NEWLY_OBSERVED_DOMAIN"
    HIGH_VOLUME_DNS = "HIGH_VOLUME_DNS"

    # --- endpoint ---
    PROCESS_CREATE = "PROCESS_CREATE"
    POWERSHELL_EXEC = "POWERSHELL_EXEC"
    COMMAND_EXEC = "COMMAND_EXEC"
    DISCOVERY_COMMAND = "DISCOVERY_COMMAND"
    SCRIPT_EXEC = "SCRIPT_EXEC"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    SUSPICIOUS_EXECUTABLE = "SUSPICIOUS_EXECUTABLE"
    MALICIOUS_ATTACHMENT = "MALICIOUS_ATTACHMENT"


#: Actions that move an identity from one host to another.
MOVEMENT_ACTIONS: frozenset[Action] = frozenset(
    {
        Action.RDP_LOGIN,
        Action.SMB_AUTH,
        Action.NETWORK_LOGON,
        Action.PRIVILEGED_LOGIN,
        Action.REMOTE_SERVICE_EXEC,
    }
)

#: Actions that on their own justify pulling an event into a chain.
NOTABLE_ACTIONS: frozenset[Action] = frozenset(
    {
        Action.MALICIOUS_ATTACHMENT,
        Action.POWERSHELL_EXEC,
        Action.SCRIPT_EXEC,
        Action.CREDENTIAL_ACCESS,
        Action.SUSPICIOUS_EXECUTABLE,
        Action.DISCOVERY_COMMAND,
        Action.SUSPICIOUS_DOMAIN,
        Action.NEWLY_OBSERVED_DOMAIN,
        Action.HIGH_VOLUME_DNS,
        Action.RDP_LOGIN,
        Action.PRIVILEGED_LOGIN,
        Action.REMOTE_SERVICE_EXEC,
    }
)


class NormalizedEvent(BaseModel):
    """A single security event in PRISM's common format."""

    model_config = ConfigDict(use_enum_values=False)

    event_id: str
    timestamp: datetime
    event_type: EventType
    action: Action

    user: str | None = None
    source_host: str | None = None
    destination_host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None

    process: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    domain: str | None = None
    file_name: str | None = None
    logon_type: str | None = None
    outcome: str | None = None

    severity: Severity = Severity.LOW
    #: Set by the normalizer when the event matched a suspicious-behaviour rule.
    suspicious: bool = False
    #: Set by normalization when the event is kept for the record but is too
    #: routine to start or extend an attack chain (for example the privileged
    #: logon Windows writes for every administrator session). Says why.
    suppressed: str | None = None
    tags: list[str] = Field(default_factory=list)

    #: Provenance: which log file / feed this came from.
    source_log: str = "unknown"
    #: The untouched original record, so every finding stays traceable.
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def primary_host(self) -> str | None:
        """The host the activity landed on."""
        return self.destination_host or self.source_host

    @property
    def is_notable(self) -> bool:
        if self.suppressed:
            return False
        return (
            self.suspicious
            or self.action in NOTABLE_ACTIONS
            or self.severity.rank >= Severity.MEDIUM.rank
        )

    def hosts(self) -> set[str]:
        return {h for h in (self.source_host, self.destination_host) if h}

    def ips(self) -> set[str]:
        return {ip for ip in (self.source_ip, self.destination_ip) if ip}

    def summary(self) -> str:
        """One-line analyst-readable description."""
        if self.event_type is EventType.AUTHENTICATION:
            target = self.destination_host or self.source_host or "?"
            return f"{self.action.value} {self.user or '?'} -> {target}"
        if self.event_type is EventType.DNS:
            return f"{self.action.value} {self.domain or '?'} from {self.source_host or '?'}"
        return f"{self.action.value} {self.process or self.file_name or '?'} on {self.primary_host or '?'}"


class IngestSummary(BaseModel):
    """Result of an ingestion request."""

    accepted: int
    rejected: int
    total_events: int
    errors: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
