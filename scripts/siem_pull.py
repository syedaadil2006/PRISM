"""Pull new events from a SIEM into PRISM's live feed, on a timer.

Splunk:   runs a search through the REST export API
          (POST /services/search/jobs/export, output_mode=json) and forwards each
          result. Results from the Splunk Add-on for Windows / Sysmon / Stream DNS
          are read by PRISM's Splunk adapter.
Elastic:  queries an index pattern (POST /<index>/_search) for documents newer
          than the last one seen; Winlogbeat / Filebeat / Elastic Agent
          documents (ECS) are read by PRISM's ECS adapter.

Only the Python standard library is used. Each poll asks only for events newer
than the newest one already forwarded; PRISM ignores any it already has.

    python scripts/siem_pull.py splunk --url https://splunk:8089 --token <bearer token> \
        --query "index=wineventlog OR index=sysmon" --every 30
    python scripts/siem_pull.py elastic --url https://elastic:9200 --api-key <key> \
        --index "winlogbeat-*,filebeat-*" --every 30
    add --once to pull a single time; --insecure to accept self-signed certificates
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def prism_code() -> str:
    code = os.environ.get("PRISM_AUTH_TOKEN", "").strip()
    if not code:
        try:
            code = (ROOT / "backend" / "data" / ".prism_token").read_text(encoding="utf-8").strip()
        except OSError:
            code = ""
    return code


def http(url: str, body: bytes | None, headers: dict[str, str], insecure: bool, timeout: float = 60) -> bytes:
    context = ssl._create_unverified_context() if insecure else None  # noqa: S323 - opt-in for lab SIEMs
    request = urllib.request.Request(url, data=body, method="POST" if body is not None else "GET", headers=headers)
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return response.read()


def push(prism: str, source: str, records: list[dict]) -> dict:
    """Send records to PRISM in chunks of 1,000; returns the summed result."""
    totals = {"received": 0, "accepted": 0, "duplicates": 0, "rejected": 0}
    headers = {"Content-Type": "application/x-ndjson"}
    code = prism_code()
    if code:
        headers["X-PRISM-Token"] = code
    for start in range(0, len(records), 1000):
        body = "\n".join(json.dumps(r) for r in records[start : start + 1000]).encode("utf-8")
        url = "{}/api/live/events?source={}".format(prism.rstrip("/"), urllib.parse.quote(source))
        result = json.loads(http(url, body, headers, insecure=False))
        for key in totals:
            totals[key] += result.get(key, 0)
    return totals


# ----------------------------------------------------------------- Splunk --

def splunk_auth(args: argparse.Namespace) -> dict[str, str]:
    if args.token:
        return {"Authorization": "Bearer " + args.token}
    if args.user:
        raw = "{}:{}".format(args.user, args.password or "").encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
    raise SystemExit("Splunk needs --token or --user/--password")


#: Offsets for the zone names Splunk can print in _time ("... 10:00:01.415 MDT").
ZONES = {"UTC": 0, "GMT": 0, "Z": 0, "EST": -5, "EDT": -4, "CST": -6, "CDT": -5,
         "MST": -7, "MDT": -6, "PST": -8, "PDT": -7, "IST": 5.5, "CET": 1, "CEST": 2}


def splunk_time(result: dict) -> datetime | None:
    """When a Splunk result happened: the epoch PRISM asks for, else _time."""
    epoch = result.get("prism_epoch")
    if epoch not in (None, ""):
        try:
            return datetime.fromtimestamp(float(epoch), tz=timezone.utc)
        except (TypeError, ValueError):
            pass
    text = str(result.get("_time") or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        pass
    stamp, _, zone = text.rpartition(" ")
    if zone.upper() in ZONES:
        try:
            local = datetime.fromisoformat(stamp)
        except ValueError:
            return None
        return (local - timedelta(hours=ZONES[zone.upper()])).replace(tzinfo=timezone.utc)
    return None


def splunk_record(result: dict) -> dict:
    """What to send PRISM for one Splunk result.

    Data that reached Splunk as JSON (Winlogbeat, Sysmon or Zeek JSON, HEC
    events) keeps the original event in _raw: forward that, so PRISM reads it
    exactly as if it came from the source. Otherwise (Splunk add-on field
    extractions) send the result itself to PRISM's Splunk adapter.
    """
    raw = result.get("_raw")
    if isinstance(raw, str) and raw.lstrip().startswith("{"):
        try:
            original = json.loads(raw)
        except json.JSONDecodeError:
            original = None
        if isinstance(original, dict):
            return original
    return {"result": result}


def pull_splunk(args: argparse.Namespace, since: datetime) -> tuple[list[dict], datetime]:
    query = args.query.strip()
    if not query.lower().startswith(("search ", "|")):
        query = "search " + query
    # Ask for the event time as a number too, so the bookmark never depends on
    # how this Splunk instance formats _time.
    query += " | eval prism_epoch=_time"
    form = urllib.parse.urlencode({
        "search": query,
        "earliest_time": since.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "latest_time": "now",
        "output_mode": "json",
    }).encode("utf-8")
    headers = {"Content-Type": "application/x-www-form-urlencoded", **splunk_auth(args)}
    raw = http(args.url.rstrip("/") + "/services/search/jobs/export", form, headers, args.insecure)
    records: list[dict] = []
    newest = since
    for line in raw.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        result = item.get("result")
        if not isinstance(result, dict) or item.get("preview"):
            continue
        when = splunk_time(result)
        result.pop("prism_epoch", None)
        records.append(splunk_record(result))
        if when is not None:
            newest = max(newest, when)
    return records, newest


# ---------------------------------------------------------------- Elastic --

def elastic_auth(args: argparse.Namespace) -> dict[str, str]:
    if args.api_key:
        return {"Authorization": "ApiKey " + args.api_key}
    if args.user:
        raw = "{}:{}".format(args.user, args.password or "").encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
    return {}


def pull_elastic(args: argparse.Namespace, since: datetime) -> tuple[list[dict], datetime]:
    query = {
        "size": args.batch,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"range": {"@timestamp": {"gt": since.isoformat().replace("+00:00", "Z")}}},
    }
    url = "{}/{}/_search".format(args.url.rstrip("/"), urllib.parse.quote(args.index, safe="*,-_"))
    headers = {"Content-Type": "application/json", **elastic_auth(args)}
    data = json.loads(http(url, json.dumps(query).encode("utf-8"), headers, args.insecure))
    records: list[dict] = []
    newest = since
    for hit in data.get("hits", {}).get("hits", []):
        source = hit.get("_source") or {}
        if not isinstance(source, dict):
            continue
        event = source.get("event")
        if isinstance(event, dict) and not event.get("id") and hit.get("_id"):
            event["id"] = hit["_id"]  # stable id, so a re-pulled document is counted once
        records.append(source)
        stamp = source.get("@timestamp")
        if stamp:
            try:
                newest = max(newest, datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).astimezone(timezone.utc))
            except ValueError:
                pass
    return records, newest


def is_local(url: str) -> bool:
    """True when the PRISM address is this computer (local-only mode)."""
    import ipaddress

    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("siem", choices=["splunk", "elastic"])
    parser.add_argument("--url", required=True, help="Splunk management URL (…:8089) or Elasticsearch URL (…:9200)")
    parser.add_argument("--prism", default="http://127.0.0.1:8000")
    parser.add_argument("--query", default="index=* (sourcetype=*WinEventLog* OR sourcetype=*sysmon* OR sourcetype=stream:dns)")
    parser.add_argument("--index", default="winlogbeat-*,filebeat-*,logs-*")
    parser.add_argument("--token", help="Splunk bearer (authentication) token")
    parser.add_argument("--api-key", help="Elasticsearch API key (base64 id:key)")
    parser.add_argument("--user")
    parser.add_argument("--password")
    parser.add_argument("--since-minutes", type=int, default=15, help="how far back the first pull reaches")
    parser.add_argument("--every", type=int, default=30, help="seconds between pulls")
    parser.add_argument("--batch", type=int, default=1000, help="Elastic: documents per pull")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--insecure", action="store_true", help="accept self-signed TLS certificates")
    parser.add_argument("--allow-remote", action="store_true", help="allow a PRISM on another machine (off: local-only)")
    args = parser.parse_args()
    if not args.allow_remote and not is_local(args.prism):
        print("Refusing to send events to {}: local-only mode keeps data on this computer. Use --allow-remote if intended.".format(args.prism))
        return 1

    since = datetime.now(timezone.utc) - timedelta(minutes=args.since_minutes)
    pull = pull_splunk if args.siem == "splunk" else pull_elastic
    source = "siem-" + args.siem
    print("Pulling from {} {} into PRISM at {} every {}s. Ctrl+C to stop.".format(args.siem, args.url, args.prism, args.every))
    try:
        while True:
            try:
                records, newest = pull(args, since)
                result = push(args.prism, source, records) if records else {"accepted": 0, "duplicates": 0, "rejected": 0}
                print("  {:%H:%M:%S}  fetched {:>5}  accepted {:>5}  duplicates {:>5}  rejected {:>4}".format(
                    datetime.now(), len(records), result["accepted"], result["duplicates"], result["rejected"]))
                since = newest
            except Exception as exc:  # noqa: BLE001 - keep polling through outages
                print("  {:%H:%M:%S}  error: {}".format(datetime.now(), exc))
                if args.once:
                    return 1
            if args.once:
                return 0
            time.sleep(args.every)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
