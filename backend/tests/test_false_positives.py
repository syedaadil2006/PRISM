"""A computer's own user doing normal work must not look like an attack.

Records are shaped exactly as scripts/live_windows_collector.ps1 sends them from
a real Windows laptop: sign-ins, unlocks and administrator (UAC) approvals each
write a logon (4624) and a privileged logon (4672) for the person at the keyboard.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app

HOST = "LAPTOP-8BCKHLDK"
USER = "syedaadil2006"
START = datetime(2026, 10, 7, 8, 0, tzinfo=timezone.utc)
_ids = {"n": 0}


def _stamp(minutes: float) -> str:
    return (START + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _security(event_id: str, minutes: float, **fields: str) -> dict:
    _ids["n"] += 1
    record = {"RecordId": "{}-Security-{}".format(HOST, _ids["n"]), "TimeCreated": _stamp(minutes),
              "EventID": event_id, "Computer": HOST}
    record.update(fields)
    return record


def _owner_day() -> list[dict]:
    """A working day: sign-in, unlocks and UAC approvals every few minutes."""
    records = []
    for minute in range(0, 8 * 60, 7):
        logon_type = "2" if minute % 49 else "7"  # mostly UAC/interactive, sometimes unlock
        records.append(_security("4624", minute, TargetUserName="MicrosoftAccount\\" + USER, LogonType=logon_type,
                                 IpAddress="127.0.0.1", WorkstationName=HOST, ProcessName="C:\\Windows\\System32\\consent.exe"))
        records.append(_security("4672", minute, TargetUserName=USER, SubjectUserName=USER))
    records.append(_security("4648", 30, TargetUserName=USER, SubjectUserName=USER, IpAddress="-"))
    return records


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        test_client.post("/api/live/start", params={"clear": True})
        yield test_client
        test_client.post("/api/logs/reset")


def _push(client: TestClient, records: list[dict]) -> None:
    result = client.post("/api/live/events", params={"source": "win-laptop-security"}, json=records).json()
    assert result["rejected"] == 0, result["errors"]
    client.post("/api/live/flush")


def test_the_owner_using_their_own_laptop_is_not_an_attack(client):
    _push(client, _owner_day())
    assert client.get("/api/attacks").json() == []
    user = next(u for u in client.get("/api/users").json() if u["name"] == USER)
    assert user["compromised"] is False
    host = next((h for h in client.get("/api/hosts").json() if h["name"] == HOST), None)
    assert host is None or host["state"] not in {"compromised", "current_position"}
    events = client.get("/api/events", params={"limit": 2000}).json()
    privileged = [e for e in events if e["action"] == "PRIVILEGED_LOGIN"]
    assert privileged and all("console user" in (e["suppressed"] or "") for e in privileged)


def test_a_real_attack_on_the_same_laptop_is_still_caught(client):
    attack = _owner_day()
    attack += [
        {"RecordId": HOST + "-sysmon-1", "EventID": "1", "UtcTime": _stamp(200), "Computer": HOST, "User": USER,
         "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
         "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA"},
        {"RecordId": HOST + "-sysmon-2", "EventID": "10", "UtcTime": _stamp(203), "Computer": HOST, "User": USER,
         "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010"},
    ]
    _push(client, attack)
    chains = client.get("/api/attacks").json()
    assert len(chains) == 1 and HOST in chains[0]["hosts"]
    user = next(u for u in client.get("/api/users").json() if u["name"] == USER)
    assert user["compromised"] is True


def test_a_remote_privileged_logon_is_not_waved_through(client):
    records = _owner_day() + [
        _security("4624", 300, TargetUserName="admin.k", LogonType="10", IpAddress="10.0.0.9", WorkstationName="IT-PC"),
        _security("4672", 300, TargetUserName="admin.k", SubjectUserName="admin.k"),
    ]
    _push(client, records)
    events = client.get("/api/events", params={"limit": 2000}).json()
    remote = [e for e in events if e["action"] == "PRIVILEGED_LOGIN" and e["user"] == "admin.k"]
    assert remote and remote[0]["suppressed"] is None  # still counts as notable


def test_live_mode_shows_only_this_computer_not_the_demo_company(monkeypatch: pytest.MonkeyPatch):
    from app.core.config import get_settings
    from app.main import create_app

    monkeypatch.setenv("PRISM_DATASET", "live")
    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as live:
            records = _owner_day() + [_security("4672", 5, TargetUserName="DWM-6", SubjectUserName="DWM-6")]
            _push(live, records)
            users = {u["name"]: u for u in live.get("/api/users").json()}
            assert set(users) == {USER, "dwm-6"}  # no admin.k, john.doe, maria.gomez ...
            assert users["dwm-6"]["department"] == "Windows system account"
            hosts = {h["name"] for h in live.get("/api/hosts").json()}
            assert hosts == {HOST}  # no HR-PC, FINANCE-PC, DC01 ...
    finally:
        get_settings.cache_clear()
