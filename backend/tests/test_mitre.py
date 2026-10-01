"""MITRE mapping layer behaviour."""

from __future__ import annotations

from app.engine.mitre import TACTIC_ORDER, map_event, map_events
from app.models.events import Action, Severity
from tests.conftest import make_event


def test_powershell_maps_to_t1059_001():
    event = make_event(
        Action.POWERSHELL_EXEC,
        user="john.doe",
        source_host="HR-PC",
        process="powershell.exe",
        parent_process="WINWORD.EXE",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
    )
    ids = {m.technique_id for m in map_event(event)}
    assert "T1059.001" in ids
    # The hidden/encoded flags are a separate, independently justified finding.
    assert "T1027" in ids


def test_lsass_access_maps_to_credential_dumping():
    event = make_event(
        Action.CREDENTIAL_ACCESS,
        user="john.doe",
        source_host="HR-PC",
        process="powershell.exe",
        severity=Severity.CRITICAL,
        tags=["finding:powershell.exe opened a handle to lsass.exe"],
    )
    mapping = next(m for m in map_event(event) if m.technique_id == "T1003.001")
    assert mapping.tactic == "Credential Access"
    assert "lsass" in mapping.evidence.lower()
    assert mapping.confidence.value == "high"


def test_rdp_between_two_hosts_maps_to_lateral_movement():
    event = make_event(
        Action.RDP_LOGIN, user="john.doe", source_host="HR-PC", destination_host="FINANCE-PC"
    )
    mapping = next(m for m in map_event(event) if m.technique_id == "T1021.001")
    assert mapping.tactic == "Lateral Movement"
    assert "HR-PC" in mapping.evidence
    assert "FINANCE-PC" in mapping.evidence


def test_local_rdp_logon_is_not_lateral_movement():
    """Source and destination on the same machine is a console session."""
    event = make_event(
        Action.RDP_LOGIN, user="john.doe", source_host="HR-PC", destination_host="HR-PC"
    )
    assert "T1021.001" not in {m.technique_id for m in map_event(event)}


def test_a_single_failed_logon_is_not_brute_force():
    """The T1110 rule fires on the clustered finding, not on one failure."""
    lonely = make_event(
        Action.LOGIN_FAILURE,
        user="sara.lee",
        source_host="MKTG-PC",
        destination_host="MKTG-PC",
        outcome="failure",
    )
    assert "T1110" not in {m.technique_id for m in map_event(lonely)}

    clustered = make_event(
        Action.LOGIN_FAILURE,
        user="john.doe",
        source_host="HR-PC",
        destination_host="FILE01",
        outcome="failure",
        tags=["credential-guessing", "finding:5 failed logons for john.doe within 380s"],
    )
    assert "T1110" in {m.technique_id for m in map_event(clustered)}


def test_every_mapping_explains_itself():
    events = [
        make_event(Action.POWERSHELL_EXEC, source_host="HR-PC", process="powershell.exe"),
        make_event(
            Action.SUSPICIOUS_DOMAIN,
            source_host="HR-PC",
            domain="update-svc-cdn.xyz",
            tags=["finding:on the threat-intel deny list"],
        ),
        make_event(
            Action.RDP_LOGIN, user="john.doe", source_host="HR-PC", destination_host="FINANCE-PC"
        ),
    ]
    mappings = map_events(events)
    assert mappings
    for mapping in mappings:
        assert mapping.evidence, mapping.technique_id
        assert mapping.explanation, mapping.technique_id
        assert mapping.event_id
        assert mapping.tactic_id in TACTIC_ORDER
        assert mapping.reference
        assert mapping.reference.startswith("https://attack.mitre.org/")


def test_no_duplicate_techniques_per_event():
    event = make_event(
        Action.REMOTE_SERVICE_EXEC,
        user="john.doe",
        source_host="FINANCE-PC",
        process="psexec.exe",
        command_line="psexec.exe " + chr(92) * 2 + "FILE01 -s cmd.exe",
    )
    ids = [m.technique_id for m in map_event(event)]
    assert len(ids) == len(set(ids))
    assert "T1021.002" in ids


def test_mappings_come_back_in_chronological_order():
    first = make_event(
        Action.MALICIOUS_ATTACHMENT,
        source_host="HR-PC",
        tags=["file-create"],
        file_name="invoice.docm",
    )
    second = make_event(
        Action.POWERSHELL_EXEC, offset_seconds=60, source_host="HR-PC", process="powershell.exe"
    )
    mappings = map_events([second, first])
    assert mappings[0].technique_id == "T1566.001"
