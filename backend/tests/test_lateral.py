"""Lateral-movement rule engine behaviour."""

from __future__ import annotations

from app.engine.correlation import correlate
from app.engine.lateral import detect_lateral_movement
from app.models.events import Action, Severity
from tests.conftest import make_event


def _detect(events, settings):
    links = correlate(events, settings.correlation)
    return detect_lateral_movement(events, links, settings.lateral, settings.correlation)


def test_movement_requires_prior_suspicious_activity_on_the_source(settings):
    """An RDP logon from a clean host is normal remote work, not an intrusion."""
    rdp = make_event(
        Action.RDP_LOGIN,
        user="john.doe",
        source_host="HR-PC",
        destination_host="FINANCE-PC",
    )
    assert _detect([rdp], settings) == []


def test_movement_off_a_compromised_host_is_detected(settings):
    creds = make_event(
        Action.CREDENTIAL_ACCESS,
        user="john.doe",
        source_host="HR-PC",
        destination_host="HR-PC",
        process="powershell.exe",
        suspicious=True,
        severity=Severity.CRITICAL,
    )
    rdp = make_event(
        Action.RDP_LOGIN,
        offset_seconds=323,
        user="john.doe",
        source_host="HR-PC",
        destination_host="FINANCE-PC",
    )
    detections = _detect([creds, rdp], settings)
    assert len(detections) == 1
    movement = detections[0]
    assert movement.source_host == "HR-PC"
    assert movement.destination_host == "FINANCE-PC"
    assert movement.method == "RDP_LOGIN"
    assert movement.assurance.value == "inferred"


def test_failed_logons_do_not_count_as_movement(settings):
    """Intent is not access: a failed attempt must not mark a host reached."""
    creds = make_event(
        Action.CREDENTIAL_ACCESS,
        user="john.doe",
        source_host="FINANCE-PC",
        destination_host="FINANCE-PC",
        suspicious=True,
    )
    failed = make_event(
        Action.RDP_LOGIN,
        offset_seconds=120,
        user="john.doe",
        source_host="FINANCE-PC",
        destination_host="DC01",
        outcome="failure",
    )
    assert _detect([creds, failed], settings) == []


def test_every_clause_of_the_rule_is_reported(settings):
    creds = make_event(
        Action.CREDENTIAL_ACCESS,
        user="john.doe",
        source_host="HR-PC",
        destination_host="HR-PC",
        suspicious=True,
    )
    rdp = make_event(
        Action.RDP_LOGIN,
        offset_seconds=200,
        user="john.doe",
        source_host="HR-PC",
        destination_host="FINANCE-PC",
    )
    movement = _detect([creds, rdp], settings)[0]
    assert len(movement.rule_evaluation) == 5
    joined = " ".join(movement.rule_evaluation)
    assert "HR-PC" in joined
    assert "FINANCE-PC" in joined
    assert "john.doe" in joined
    assert "Correlation score" in joined
    assert movement.explanation


def test_one_hop_reported_by_two_records_is_counted_once(settings):
    """A logon plus its privilege-assignment record is a single movement."""
    creds = make_event(
        Action.CREDENTIAL_ACCESS,
        user="john.doe",
        source_host="HR-PC",
        destination_host="HR-PC",
        suspicious=True,
    )
    rdp = make_event(
        Action.RDP_LOGIN,
        offset_seconds=300,
        user="john.doe",
        source_host="HR-PC",
        destination_host="FINANCE-PC",
    )
    privileged = make_event(
        Action.PRIVILEGED_LOGIN,
        offset_seconds=301,
        user="john.doe",
        source_host="HR-PC",
        destination_host="FINANCE-PC",
    )
    assert len(_detect([creds, rdp, privileged], settings)) == 1


def test_the_window_is_configurable(settings):
    creds = make_event(
        Action.CREDENTIAL_ACCESS,
        user="john.doe",
        source_host="HR-PC",
        destination_host="HR-PC",
        suspicious=True,
    )
    rdp = make_event(
        Action.RDP_LOGIN,
        offset_seconds=900,
        user="john.doe",
        source_host="HR-PC",
        destination_host="FINANCE-PC",
    )
    links = correlate([creds, rdp], settings.correlation)

    tight = settings.lateral.model_copy(update={"window_seconds": 600})
    assert detect_lateral_movement([creds, rdp], links, tight, settings.correlation) == []

    wide = settings.lateral.model_copy(update={"window_seconds": 1200})
    assert detect_lateral_movement([creds, rdp], links, wide, settings.correlation)
