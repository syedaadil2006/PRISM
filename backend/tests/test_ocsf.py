"""OCSF import and export."""

from __future__ import annotations

import copy
import json
import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import ForwardSettings
from app.ingest.loader import make_context
from app.ingest.parsers import parse_records
from app.main import app
from app.models.inventory import Inventory
from app.ocsf import OCSF_VERSION, event_to_ocsf
from app.services.forwarder import Forwarder

REQUIRED = {
    3002: ["user", "src_endpoint", "dst_endpoint"],
    3003: ["user"],
    1007: ["process", "actor", "device"],
    1001: ["file", "actor", "device"],
    4003: ["query"],
}


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        test_client.post("/api/logs/reset")
        yield test_client
        test_client.post("/api/logs/reset")


def _story(client: TestClient) -> tuple:
    client.post("/api/live/flush")
    chains = client.get("/api/attacks").json()
    return tuple((c["event_count"], c["initial_host"], c["current_host"], c["predictions"][0]["host"],
                  c["predictions"][0]["score"]) for c in chains)


def test_every_exported_event_is_well_formed_ocsf(client):
    events = client.get("/api/ocsf/events").json()
    assert len(events) == 56
    classes = {e["class_uid"] for e in events}
    assert classes == {3002, 3003, 1007, 1001, 4003}
    for event in events:
        assert event["type_uid"] == event["class_uid"] * 100 + event["activity_id"]
        assert isinstance(event["time"], int) and event["severity_id"] in range(0, 7)
        assert event["metadata"]["version"] == OCSF_VERSION and event["metadata"]["product"]["name"] == "PRISM"
        for attribute in REQUIRED[event["class_uid"]]:
            if event["class_uid"] == 3002 and attribute in {"src_endpoint", "dst_endpoint"} and not event.get("is_remote"):
                continue
            assert attribute in event, (event["metadata"]["uid"], attribute)


def test_specific_mappings(client):
    by_uid = {e["metadata"]["uid"]: e for e in client.get("/api/ocsf/events").json()}
    rdp = by_uid["auth-0011"]
    assert (rdp["class_uid"], rdp["logon_type_id"], rdp["is_remote"]) == (3002, 10, True)
    assert rdp["src_endpoint"]["hostname"] == "HR-PC" and rdp["dst_endpoint"]["hostname"] == "FINANCE-PC"
    assert by_uid["auth-0008"]["status_id"] == 2  # failed logon
    assert by_uid["auth-0012"]["class_uid"] == 3003  # privileged logon -> Authorize Session
    lsass = by_uid["edr-0009"]
    assert (lsass["class_uid"], lsass["activity_id"]) == (1007, 3) and lsass["process"]["name"].lower() == "lsass.exe"
    attachment = by_uid["edr-0004"]
    assert attachment["class_uid"] == 1001 and attachment["file"]["name"].endswith(".docm")
    dns = by_uid["dns-0004"]
    assert dns["class_uid"] == 4003 and dns["query"]["hostname"] == "update-svc-cdn.xyz"


def test_prism_ocsf_reads_back_exactly(client):
    before = {e["event_id"]: e for e in client.get("/api/events", params={"limit": 2000}).json()}
    story = _story(client)
    exported = client.get("/api/ocsf/events").json()
    client.post("/api/live/start", params={"clear": True})
    result = client.post("/api/live/events", params={"source": "ocsf"}, json=exported).json()
    assert result["accepted"] == 56 and result["rejected"] == 0
    assert _story(client) == story
    after = {e["event_id"].split(":", 1)[1]: e for e in client.get("/api/events", params={"limit": 2000}).json()}
    for event_id, original in before.items():
        restored = after[event_id]
        for field in ("action", "event_type", "user", "source_host", "destination_host", "process", "domain", "suspicious"):
            assert restored[field] == original[field], (event_id, field)


def test_ocsf_from_other_tools_goes_through_prisms_own_rules(client):
    story = _story(client)
    foreign = copy.deepcopy(client.get("/api/ocsf/events").json())
    for event in foreign:  # what another OCSF producer would send: no PRISM details
        event.pop("unmapped", None) if not event.get("unmapped", {}).get("share_name") else event["unmapped"].pop("prism")
        event.pop("raw_data", None)
    client.post("/api/live/start", params={"clear": True})
    result = client.post("/api/live/events", params={"source": "other-tool"}, json=foreign).json()
    assert result["accepted"] == 56 and result["rejected"] == 0, result["errors"]
    assert _story(client) == story


def test_attack_chains_export_as_detection_findings(client):
    findings = client.get("/api/ocsf/findings").json()
    assert len(findings) == 1
    finding = findings[0]
    assert (finding["class_uid"], finding["type_uid"], finding["category_uid"]) == (2004, 200401, 2)
    info = finding["finding_info"]
    assert info["uid"] == "ATTACK-001" and len(info["related_events"]) == 29
    techniques = {a["technique"]["uid"] for a in info["attacks"]}
    assert {"T1566.001", "T1021.001"} <= techniques
    assert {r["name"] for r in finding["resources"]} >= {"HR-PC", "FINANCE-PC", "FILE01", "DC01"}
    target = finding["unmapped"]["prism"]["predicted_next_targets"][0]
    assert target["host"] == "DC01" and target["assurance"] == "predicted"


def test_ndjson_and_chain_filter(client):
    lines = client.get("/api/ocsf/events", params={"format": "ndjson", "chain_id": "ATTACK-001"}).text.splitlines()
    assert len(lines) == 29 and all(json.loads(l)["class_uid"] for l in lines)
    assert client.get("/api/ocsf/events", params={"chain_id": "NOPE"}).status_code == 404


def test_unsupported_ocsf_is_rejected_clearly():
    ctx = make_context(Inventory(), "t")
    _, errors = parse_records([
        {"class_uid": 2004, "metadata": {"version": "1.3.0"}, "time": 0},
        {"class_uid": 6003, "metadata": {"version": "1.3.0"}, "time": 0},
    ], ctx)
    assert "Detection Findings are PRISM output" in errors[0] and "6003" in errors[1]


def test_alerts_can_be_forwarded_as_ocsf_findings(client):
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("helpers", Path(__file__).with_name("test_integrations.py"))
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)

    helpers._Capture.received = []
    server, url = helpers._serve(helpers._Capture)
    forwarder = Forwarder(ForwardSettings(webhook_url=url + "/ocsf", format="ocsf"), version="t")
    forwarder.notify(app.state.soc.analysis.chains)
    deadline = time.time() + 5
    while not helpers._Capture.received and time.time() < deadline:
        time.sleep(0.05)
    server.shutdown()
    body = json.loads(helpers._Capture.received[0][2])
    assert body["class_uid"] == 2004 and body["finding_info"]["uid"] == "ATTACK-001"


def test_event_to_ocsf_handles_minimal_events():
    events, _ = parse_records([{"ts": 1790761620.0, "query": "example.org"}], make_context(Inventory(), "t"))
    out = event_to_ocsf(events[0])
    assert out["class_uid"] == 4003 and out["query"]["hostname"] == "example.org"
