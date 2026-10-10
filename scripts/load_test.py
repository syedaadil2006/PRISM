"""Load test: how much can PRISM take in, and does it stay responsive?

    python scripts/load_test.py --events 50000 --batch 1000 --senders 4

Sends realistic Windows logon, Sysmon process and DNS events to a running PRISM
over its live API from several parallel senders. Meanwhile a reader keeps
calling /api/stats, as the dashboard does. With --attack, the demo attack is
replayed in the middle of the noise, to check it is still found.
Reports:

* ingestion rate (events per second accepted) and how often PRISM asked the
  senders to slow down (HTTP 429, then honoured with Retry-After);
* API latency (median, 95th percentile, worst) while under load;
* how long the analysis took to catch up with everything sent.

Only talks to PRISM on this computer unless --allow-remote is given. The access
code is read from backend/data/.prism_token. Uses only the standard library.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import ssl
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
HOSTS = [f"WS-{i:03d}" for i in range(1, 121)] + ["FILE01", "FILE02", "MAIL01", "WEB01", "DC01", "DC02"]
USERS = [f"user{i:03d}" for i in range(1, 201)]
PROCESSES = ["chrome.exe", "Teams.exe", "OUTLOOK.EXE", "EXCEL.EXE", "WINWORD.EXE", "msedge.exe", "explorer.exe"]
DOMAINS = ["teams.microsoft.com", "outlook.office365.com", "www.google.com", "github.com",
           "login.microsoftonline.com", "cdn.jsdelivr.net", "www.bing.com", "update.microsoft.com"]


def make_events(count: int, seed: int) -> list[dict]:
    """Ordinary office activity: logons, process starts and DNS lookups."""
    rng = random.Random(seed)
    start = datetime.now(timezone.utc) - timedelta(hours=2)
    events = []
    for i in range(count):
        when = (start + timedelta(seconds=i * 7200 / max(1, count))).strftime("%Y-%m-%dT%H:%M:%SZ")
        user, host = rng.choice(USERS), rng.choice(HOSTS[:120])
        kind = rng.random()
        if kind < 0.35:
            events.append({"RecordId": f"lt-{seed}-{i}", "TimeCreated": when, "EventID": "4624", "Computer": host,
                           "WorkstationName": host, "TargetUserName": f"CORP\\{user}", "LogonType": "2",
                           "IpAddress": "-", "Status": "0x0"})
        elif kind < 0.7:
            events.append({"RecordId": f"lt-{seed}-{i}", "EventID": "1", "UtcTime": when, "Computer": host,
                           "User": f"CORP\\{user}", "Image": "C:\\Program Files\\" + rng.choice(PROCESSES),
                           "ParentImage": "C:\\Windows\\explorer.exe", "CommandLine": "", "ProcessGuid": f"{{{i}}}"})
        else:
            events.append({"uid": f"lt-{seed}-{i}", "ts": datetime.strptime(when, "%Y-%m-%dT%H:%M:%SZ")
                           .replace(tzinfo=timezone.utc).timestamp(), "query": rng.choice(DOMAINS),
                           "id.orig_h": f"10.0.{rng.randint(1, 4)}.{rng.randint(10, 250)}"})
    return events


def demo_attack() -> list[tuple[str, list[dict]]]:
    import csv

    demo = ROOT / "backend" / "data" / "demo"
    with (demo / "01_windows_security.csv").open(encoding="utf-8") as handle:
        security = list(csv.DictReader(handle))
    read = lambda name: [json.loads(l) for l in (demo / name).read_text(encoding="utf-8").splitlines() if l.strip()]  # noqa: E731
    return [("attack-security", security), ("attack-sysmon", read("02_sysmon.jsonl")), ("attack-dns", read("03_zeek_dns.jsonl"))]


class Client:
    def __init__(self, base: str, token: str) -> None:
        self.base = base.rstrip("/")
        self.headers = {"X-PRISM-Token": token, "Content-Type": "application/json"}
        self.context = None
        if self.base.startswith("https") and urlparse(self.base).hostname in {"127.0.0.1", "localhost"}:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE  # PRISM on this computer with a self-signed certificate

    def call(self, method: str, path: str, body: object = None) -> tuple[int, dict, dict]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=self.headers)
        try:
            with urllib.request.urlopen(request, timeout=120, context=self.context) as response:
                return response.status, json.loads(response.read() or b"{}"), dict(response.headers)
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}"), dict(error.headers)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", default=f"http://127.0.0.1:{os.environ.get('PRISM_PORT', '8000')}")
    parser.add_argument("--events", type=int, default=20000)
    parser.add_argument("--batch", type=int, default=1000)
    parser.add_argument("--senders", type=int, default=4)
    parser.add_argument("--attack", action="store_true", help="replay the demo attack in the middle of the load")
    parser.add_argument("--allow-remote", action="store_true")
    args = parser.parse_args()

    if not args.allow_remote and urlparse(args.server).hostname not in {"127.0.0.1", "localhost", "::1"}:
        print("Refusing a remote server without --allow-remote (local-only).")
        return 1
    token_file = ROOT / "backend" / "data" / ".prism_token"
    token = os.environ.get("PRISM_AUTH_TOKEN") or (token_file.read_text(encoding="utf-8").strip() if token_file.exists() else "")
    client = Client(args.server, token)
    if client.call("GET", "/api/health")[0] != 200:
        print(f"PRISM is not answering at {args.server}")
        return 1

    per_sender = args.events // args.senders
    batches = [[] for _ in range(args.senders)]
    for s in range(args.senders):
        events = make_events(per_sender, seed=s)
        batches[s] = [events[i:i + args.batch] for i in range(0, len(events), args.batch)]

    stats = {"accepted": 0, "busy": 0, "errors": 0}
    lock = threading.Lock()
    latencies: list[float] = []
    sending = threading.Event()
    sending.set()

    def sender(index: int) -> None:
        for batch in batches[index]:
            while True:
                status, body, headers = client.call("POST", f"/api/live/events?source=load-{index}", batch)
                if status == 429:
                    with lock:
                        stats["busy"] += 1
                    time.sleep(float(headers.get("Retry-After", "1")))
                    continue
                with lock:
                    if status == 200:
                        stats["accepted"] += body.get("accepted", 0)
                    else:
                        stats["errors"] += 1
                break

    def reader() -> None:
        while sending.is_set():
            started = time.perf_counter()
            client.call("GET", "/api/stats")
            latencies.append((time.perf_counter() - started) * 1000)
            time.sleep(0.2)

    print(f"Sending {per_sender * args.senders:,} events in batches of {args.batch} from {args.senders} senders...")
    read_thread = threading.Thread(target=reader, daemon=True)
    read_thread.start()
    started = time.perf_counter()
    threads = [threading.Thread(target=sender, args=(i,)) for i in range(args.senders)]
    for thread in threads:
        thread.start()
    if args.attack:
        time.sleep(1)
        for stream, records in demo_attack():
            client.call("POST", f"/api/live/events?source={stream}", records)
    for thread in threads:
        thread.join()
    send_seconds = time.perf_counter() - started

    while True:  # wait for the analysis to catch up
        live = client.call("GET", "/api/live/status")[1]
        if not live.get("pending_analysis") and not live.get("queued"):
            break
        time.sleep(0.5)
    caught_up = time.perf_counter() - started
    sending.clear()
    read_thread.join(timeout=5)

    final = client.call("GET", "/api/stats")[1]
    chains = client.call("GET", "/api/attacks")[1]
    live = client.call("GET", "/api/live/status")[1]
    ordered = sorted(latencies) or [0.0]
    result = {
        "events_sent": per_sender * args.senders,
        "events_accepted": stats["accepted"],
        "send_seconds": round(send_seconds, 1),
        "ingest_events_per_second": round(stats["accepted"] / send_seconds) if send_seconds else None,
        "busy_responses_429": stats["busy"],
        "failed_requests": stats["errors"],
        "analysis_caught_up_after_seconds": round(caught_up, 1),
        "last_analysis_seconds": round((live.get("last_analysis_ms") or 0) / 1000, 2),
        "api_latency_ms": {"median": round(statistics.median(ordered), 1),
                           "p95": round(ordered[int(len(ordered) * 0.95) - 1 if len(ordered) > 1 else 0], 1),
                           "max": round(ordered[-1], 1), "samples": len(ordered)},
        "events_analysed": final.get("total_events"),
        "attack_chains": len(chains) if isinstance(chains, list) else None,
        "attack_chain_sizes": sorted((c.get("event_count", 0) for c in chains), reverse=True)[:5]
        if isinstance(chains, list) else None,
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
