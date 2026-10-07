"""Real-time ingestion: HTTP push, de-duplication, file tailing, live analysis."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import BACKEND_ROOT, LiveSettings
from app.main import app
from app.models.inventory import Inventory
from app.services.live_feed import LiveFeed, decode_body, stream_name

DEMO = BACKEND_ROOT / "data" / "demo"


def _demo_records() -> dict[str, list[dict]]:
    with (DEMO / "01_windows_security.csv").open(encoding="utf-8") as handle:
        security = list(csv.DictReader(handle))
    sysmon = [json.loads(line) for line in (DEMO / "02_sysmon.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    dns = [json.loads(line) for line in (DEMO / "03_zeek_dns.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    return {"security": security, "sysmon": sysmon, "dns": dns}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client
        test_client.post("/api/logs/reset")


def test_going_live_starts_from_an_empty_analysis(client):
    status = client.post("/api/live/start", params={"clear": True}).json()
    assert status["live_only"] is True
    assert client.get("/api/health").json()["events"] == 0
    assert client.get("/api/stats").json()["active_attack_chains"] == 0


def test_streamed_events_rebuild_the_attack_story(client):
    client.post("/api/live/start", params={"clear": True})
    records = _demo_records()
    # Three independent senders, each pushing in small batches as events "happen".
    for source, rows in (("dc-security", records["security"]), ("edr", records["sysmon"]), ("zeek", records["dns"])):
        for start in range(0, len(rows), 5):
            body = "\n".join(json.dumps(r) for r in rows[start : start + 5])
            result = client.post(
                "/api/live/events",
                params={"source": source},
                content=body,
                headers={"Content-Type": "application/x-ndjson"},
            ).json()
            assert result["rejected"] == 0, result["errors"]
    client.post("/api/live/flush")

    stats = client.get("/api/stats").json()
    assert stats["total_events"] == 56
    assert stats["active_attack_chains"] == 1
    chain = client.get("/api/attacks").json()[0]
    assert chain["initial_host"] == "HR-PC"
    assert chain["current_host"] == "FINANCE-PC"
    assert set(chain["hosts"]) == {"HR-PC", "FINANCE-PC", "FILE01"}
    assert chain["predictions"][0]["host"] == "DC01"

    status = client.get("/api/live/status").json()
    assert status["accepted"] == 56
    assert status["receiving"] is True
    assert status["pending_analysis"] is False
    assert {s["name"] for s in status["streams"]} >= {"dc-security", "edr", "zeek"}


def test_resent_records_are_not_counted_twice(client):
    row = _demo_records()["sysmon"][0]
    first = client.post("/api/live/events", params={"source": "dup-test"}, json=row).json()
    again = client.post("/api/live/events", params={"source": "dup-test"}, json=row).json()
    assert first["accepted"] == 1
    assert again["accepted"] == 0 and again["duplicates"] == 1


def test_records_without_ids_keep_unique_ids_across_batches(client):
    row = {"ts": 1790761620.0, "query": "example.org", "id.orig_h": "10.0.1.15"}
    a = client.post("/api/live/events", params={"source": "no-ids"}, json=row).json()
    b = client.post("/api/live/events", params={"source": "no-ids"}, json=row).json()
    assert a["accepted"] == 1 and b["accepted"] == 1


def test_bad_requests_are_rejected_clearly(client):
    assert client.post("/api/live/events", params={"format": "nope"}, json={}).status_code == 400
    assert client.post("/api/live/events", content="{not json", headers={"Content-Type": "application/json"}).status_code == 400
    too_many = [{"query": "x.org", "ts": 1790761620.0}] * 5001
    assert client.post("/api/live/events", json=too_many).status_code == 413


def test_reset_brings_the_bundled_dataset_back(client):
    client.post("/api/live/start", params={"clear": True})
    client.post("/api/logs/reset")
    assert client.get("/api/health").json()["events"] == 56
    assert client.get("/api/live/status").json()["live_only"] is False


def test_watched_files_are_tailed_line_by_line(tmp_path: Path):
    feed = LiveFeed(LiveSettings(watch_dir=tmp_path))
    log = tmp_path / "edr.jsonl"
    log.write_text('{"EventID": "1", "Computer": "HR-PC"}\n{"EventID": "1"', encoding="utf-8")
    (stream, records, errors), = feed.poll_files()
    assert stream == "file-edr" and len(records) == 1 and errors == []

    # The half-written line is completed later and read exactly once.
    with log.open("a", encoding="utf-8") as handle:
        handle.write(', "Computer": "FINANCE-PC"}\n')
    (_, records, _), = feed.poll_files()
    assert records == [{"EventID": "1", "Computer": "FINANCE-PC"}]
    assert feed.poll_files() == []


def test_watched_csv_keeps_its_header(tmp_path: Path):
    feed = LiveFeed(LiveSettings(watch_dir=tmp_path))
    log = tmp_path / "security.csv"
    log.write_text("RecordId,EventID,Computer\nr1,4625,DC01\n", encoding="utf-8")
    (_, records, _), = feed.poll_files()
    assert records == [{"RecordId": "r1", "EventID": "4625", "Computer": "DC01"}]
    with log.open("a", encoding="utf-8") as handle:
        handle.write("r2,4624,FILE01\n")
    (_, records, _), = feed.poll_files()
    assert records == [{"RecordId": "r2", "EventID": "4624", "Computer": "FILE01"}]


def test_live_ids_are_namespaced_by_source():
    feed = LiveFeed(LiveSettings(watch_dir=Path("missing")))
    row = {"RecordId": "edr-0001", "EventID": "1", "UtcTime": "2026-09-30T10:00:00Z", "Computer": "HR-PC", "Image": "C:\\x.exe"}
    events, errors = feed.parse([row], "laptop-a", Inventory())
    assert errors == [] and events[0].event_id == "laptop-a:edr-0001"


def test_body_decoding_accepts_the_common_shapes():
    assert decode_body(b'{"a": 1}', "application/json") == [{"a": 1}]
    assert decode_body(b'[{"a": 1}, {"a": 2}]', "application/json") == [{"a": 1}, {"a": 2}]
    assert decode_body(b'{"records": [{"a": 1}]}', "application/json") == [{"a": 1}]
    assert decode_body(b'{"a": 1}\n{"a": 2}\n', "application/x-ndjson") == [{"a": 1}, {"a": 2}]
    assert decode_body(b"a,b\n1,2\n", "text/csv") == [{"a": "1", "b": "2"}]
    assert stream_name("HR PC / sysmon!") == "HR-PC-sysmon"
