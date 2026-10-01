"""Normalization: vendor formats in, one common schema out."""

from __future__ import annotations

import json

from app.ingest.loader import decode_records, enrich_auth_failures, enrich_dns_volume, ingest_payload
from app.ingest.parsers import ParseContext, detect_format, parse_records
from app.models.events import Action, EventType, Severity

BS = chr(92)


def test_format_detection_covers_every_supported_source():
    assert detect_format({"EventID": "4624", "Computer": "HR-PC"}) == "windows_security"
    assert detect_format({"Image": "a.exe", "CommandLine": "a"}) == "sysmon"
    assert detect_format({"query": "example.com", "id.orig_h": "10.0.0.1"}) == "zeek_dns"
    assert detect_format({"event_type": "dns", "action": "DNS_QUERY"}) == "prism"


def test_windows_rdp_logon_is_normalized(inventory):
    record = {
        "EventID": "4624",
        "TimeCreated": "2026-09-30T10:12:35Z",
        "Computer": "FINANCE-PC",
        "WorkstationName": "HR-PC",
        "TargetUserName": "CORP" + BS + "john.doe",
        "LogonType": "10",
        "IpAddress": "10.0.1.15",
    }
    ctx = ParseContext(ip_to_host=inventory.ip_to_host(), source_log="t")
    events, errors = parse_records([record], ctx)
    assert errors == []
    event = events[0]
    assert event.event_type is EventType.AUTHENTICATION
    assert event.action is Action.RDP_LOGIN
    assert event.user == "john.doe"          # domain prefix stripped
    assert event.source_host == "HR-PC"
    assert event.destination_host == "FINANCE-PC"
    assert event.logon_type == "RemoteInteractive (RDP)"
    assert event.raw["EventID"] == "4624"    # provenance preserved


def test_machine_accounts_are_dropped_from_the_user_field(inventory):
    record = {"EventID": "4624", "TimeCreated": "2026-09-30T09:38:02Z",
              "Computer": "BACKUP01", "TargetUserName": "CORP" + BS + "BACKUP01$", "LogonType": "5"}
    events, _ = parse_records([record], ParseContext(source_log="t"))
    assert events[0].user is None


def test_office_spawning_powershell_is_flagged(inventory):
    record = {
        "EventID": "1",
        "UtcTime": "2026-09-30T10:02:48Z",
        "Computer": "HR-PC",
        "User": "CORP" + BS + "john.doe",
        "Image": "C:" + BS + "Windows" + BS + "System32" + BS + "powershell.exe",
        "ParentImage": "C:" + BS + "Office16" + BS + "WINWORD.EXE",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
    }
    events, _ = parse_records([record], ParseContext(source_log="t"))
    event = events[0]
    assert event.action is Action.POWERSHELL_EXEC
    assert event.severity is Severity.HIGH
    assert event.suspicious
    findings = [t for t in event.tags if t.startswith("finding:")]
    assert any("WINWORD" in f for f in findings)
    assert any("obfuscation" in f for f in findings)


def test_lsass_handle_access_is_critical(inventory):
    record = {
        "EventID": "10",
        "UtcTime": "2026-09-30T10:06:22Z",
        "Computer": "HR-PC",
        "SourceImage": "C:" + BS + "powershell.exe",
        "TargetImage": "C:" + BS + "Windows" + BS + "System32" + BS + "lsass.exe",
        "GrantedAccess": "0x1010",
    }
    events, _ = parse_records([record], ParseContext(source_log="t"))
    assert events[0].action is Action.CREDENTIAL_ACCESS
    assert events[0].severity is Severity.CRITICAL


def test_dns_deny_list_and_baseline_are_both_applied(inventory):
    ctx = ParseContext(
        ip_to_host=inventory.ip_to_host(),
        known_domains={"microsoft.com"},
        source_log="t",
    )
    records = [
        {"ts": 1790761620.0, "id.orig_h": "10.0.1.15", "query": "update-svc-cdn.xyz"},
        {"ts": 1790761621.0, "id.orig_h": "10.0.1.15", "query": "portal.microsoft.com"},
        {"ts": 1790761622.0, "id.orig_h": "10.0.1.15", "query": "some-vendor.net"},
    ]
    events, errors = parse_records(records, ctx)
    assert errors == []
    assert events[0].action is Action.SUSPICIOUS_DOMAIN
    assert events[0].source_host == "HR-PC"       # resolved from the IP
    assert events[1].action is Action.DNS_QUERY   # baseline domain stays quiet
    assert events[2].action is Action.NEWLY_OBSERVED_DOMAIN


def test_repeated_lookups_become_a_high_volume_finding(inventory):
    ctx = ParseContext(known_domains={"microsoft.com"}, source_log="t")
    base = 1790761620.0
    records = [
        {"ts": base + i * 60, "id.orig_h": "10.0.1.15", "host": "HR-PC", "query": "cdn.microsoft.com"}
        for i in range(6)
    ]
    events, _ = parse_records(records, ctx)
    assert all(e.action is Action.DNS_QUERY for e in events)
    enrich_dns_volume(events)
    assert all(e.action is Action.HIGH_VOLUME_DNS for e in events)
    assert all("beaconing" in e.tags for e in events)


def test_a_single_failed_logon_is_left_alone(inventory):
    ctx = ParseContext(source_log="t")
    records = [
        {"EventID": "4625", "TimeCreated": "2026-09-30T10:10:44Z", "Computer": "FILE01",
         "TargetUserName": "sara.lee", "LogonType": "3", "WorkstationName": "MKTG-PC"}
    ]
    events, _ = parse_records(records, ctx)
    enrich_auth_failures(events)
    assert events[0].severity is Severity.LOW
    assert not events[0].suspicious


def test_three_failed_logons_cluster_into_credential_guessing(inventory):
    ctx = ParseContext(source_log="t")
    records = [
        {"EventID": "4625", "TimeCreated": "2026-09-30T10:10:4{}Z".format(i),
         "Computer": "FILE01", "TargetUserName": "john.doe", "LogonType": "3",
         "WorkstationName": "HR-PC"}
        for i in range(3)
    ]
    events, _ = parse_records(records, ctx)
    enrich_auth_failures(events)
    assert all(e.severity is Severity.MEDIUM for e in events)
    assert all("credential-guessing" in e.tags for e in events)


def test_csv_json_and_jsonl_payloads_all_decode():
    csv_text = "EventID,TimeCreated,Computer\n4624,2026-09-30T10:00:00Z,HR-PC\n"
    assert decode_records(csv_text, "auth.csv") == [
        {"EventID": "4624", "TimeCreated": "2026-09-30T10:00:00Z", "Computer": "HR-PC"}
    ]

    array = json.dumps([{"query": "a.com", "ts": 1}, {"query": "b.com", "ts": 2}])
    assert len(decode_records(array, "dns.json")) == 2

    jsonl = '{"query": "a.com", "ts": 1}\n{"query": "b.com", "ts": 2}\n'
    assert len(decode_records(jsonl, "dns.jsonl")) == 2


def test_bad_records_are_reported_without_aborting_the_batch(inventory):
    payload = '{"query": "good.example", "ts": 1790761620}\n{"nothing": "useful"}\n'
    events, errors = ingest_payload(payload, "mixed.jsonl", inventory)
    assert len(events) == 1
    assert len(errors) == 1
    assert "mixed.jsonl" in errors[0]
