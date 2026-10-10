"""Test helpers: build normalized events without going through a parser."""

from __future__ import annotations

import os
import tempfile

# The existing suite asserts the specifics of the synthetic HR-PC -> FINANCE-PC
# scenario, so it pins that dataset. This must happen before any settings are
# loaded. The BOTSv1 tests (test_botsv1.py) build their own settings.
os.environ.setdefault("PRISM_DATASET", "synthetic")
# Tests run in memory; the storage tests point at their own temporary file.
os.environ.setdefault("PRISM_STORAGE_ENABLED", "false")
# The API access code is switched off for the suite; test_auth.py turns it on.
os.environ.setdefault("PRISM_AUTH_ENABLED", "false")
# Tests that turn it on must never touch the real accounts database.
# The default first-start admin is switched off for the suite; test_accounts.py checks it.
os.environ.setdefault("PRISM_AUTH_DEFAULT_ADMIN_ENABLED", "false")
os.environ.setdefault("PRISM_AUTH_DB_URL", os.path.join(tempfile.mkdtemp(prefix="prism-tests-"), "security.db"))

from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import Settings
from app.models.events import Action, EventType, NormalizedEvent, Severity
from app.models.inventory import HostAsset, Inventory, UserIdentity

BASE_TIME = datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc)

_COUNTER = {"n": 0}


def make_event(
    action: Action,
    *,
    offset_seconds: float = 0,
    event_type: EventType | None = None,
    user: str | None = None,
    source_host: str | None = None,
    destination_host: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    process: str | None = None,
    parent_process: str | None = None,
    command_line: str | None = None,
    domain: str | None = None,
    file_name: str | None = None,
    outcome: str | None = "success",
    severity: Severity = Severity.MEDIUM,
    suspicious: bool = False,
    tags: list[str] | None = None,
    raw: dict | None = None,
    event_id: str | None = None,
) -> NormalizedEvent:
    """Create one event with sensible defaults for whichever action is given."""
    if event_type is None:
        if action.value in {
            "LOGIN_SUCCESS",
            "LOGIN_FAILURE",
            "RDP_LOGIN",
            "SMB_AUTH",
            "NETWORK_LOGON",
            "PRIVILEGED_LOGIN",
        }:
            event_type = EventType.AUTHENTICATION
        elif action.value in {
            "DNS_QUERY",
            "SUSPICIOUS_DOMAIN",
            "NEWLY_OBSERVED_DOMAIN",
            "HIGH_VOLUME_DNS",
        }:
            event_type = EventType.DNS
        else:
            event_type = EventType.ENDPOINT

    _COUNTER["n"] += 1
    return NormalizedEvent(
        event_id=event_id or "test-{:04d}".format(_COUNTER["n"]),
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        event_type=event_type,
        action=action,
        user=user,
        source_host=source_host,
        destination_host=destination_host,
        source_ip=source_ip,
        destination_ip=destination_ip,
        process=process,
        parent_process=parent_process,
        command_line=command_line,
        domain=domain,
        file_name=file_name,
        outcome=outcome,
        severity=severity,
        suspicious=suspicious,
        tags=tags or [],
        source_log="unit-test",
        raw=raw or {},
    )


@pytest.fixture
def settings() -> Settings:
    return Settings()


@pytest.fixture
def inventory() -> Inventory:
    """A four-host environment with one domain controller."""
    return Inventory(
        hosts=[
            HostAsset(
                name="HR-PC",
                ip="10.0.1.15",
                role="workstation",
                criticality=0.3,
                reachable_hosts=["FINANCE-PC", "DC01", "FILE01"],
            ),
            HostAsset(
                name="FINANCE-PC",
                ip="10.0.2.20",
                role="workstation",
                criticality=0.5,
                reachable_hosts=["DC01", "FILE01", "HR-PC"],
            ),
            HostAsset(
                name="DC01",
                ip="10.0.0.10",
                role="domain controller",
                criticality=1.0,
                is_critical_infrastructure=True,
                reachable_hosts=["HR-PC", "FINANCE-PC", "FILE01"],
            ),
            HostAsset(
                name="FILE01",
                ip="10.0.2.30",
                role="file server",
                criticality=0.6,
                reachable_hosts=["DC01"],
            ),
        ],
        users=[
            UserIdentity(
                name="john.doe",
                privilege=0.5,
                accessible_hosts=["HR-PC", "FINANCE-PC", "DC01", "FILE01"],
            ),
            UserIdentity(
                name="admin.k",
                privilege=1.0,
                is_privileged=True,
                accessible_hosts=["DC01", "FILE01"],
            ),
        ],
        known_domains=["microsoft.com"],
    )
