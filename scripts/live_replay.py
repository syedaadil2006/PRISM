"""Stream a log dataset into a running PRISM, in real time.

Every record is re-timed so the first event happens "now" and the rest follow
at the original spacing (sped up by --speed), then pushed to
POST /api/live/events the moment its time arrives, exactly as a live log
shipper would. Uses only the Python standard library.

    python scripts/live_replay.py                    # the bundled demo attack, ~2 minutes
    python scripts/live_replay.py --speed 60         # faster
    python scripts/live_replay.py --keep-dataset     # add to the current data instead of clearing
    python scripts/live_replay.py --dir path/to/logs --server http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = ROOT / "backend" / "data" / "demo"

#: Field holding the event time, and the id field to keep unique, per format.
TIME_FIELDS = ("TimeCreated", "UtcTime", "ts", "timestamp", "@timestamp")
ID_FIELDS = ("RecordId", "record_id", "uid")


def load(directory: Path) -> list[tuple[datetime, str, dict]]:
    """Read every .csv / .jsonl file into (time, source, record) tuples."""
    rows: list[tuple[datetime, str, dict]] = []
    for path in sorted(directory.glob("*")):
        if path.suffix.lower() == ".csv":
            with path.open(encoding="utf-8-sig") as handle:
                records = list(csv.DictReader(handle))
        elif path.suffix.lower() in {".jsonl", ".ndjson"}:
            records = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        else:
            continue
        for record in records:
            when = event_time(record)
            if when is not None:
                rows.append((when, path.stem, record))
    rows.sort(key=lambda row: row[0])
    return rows


def event_time(record: dict) -> datetime | None:
    for name in TIME_FIELDS:
        value = record.get(name)
        if value in (None, ""):
            continue
        if isinstance(value, (int, float)) or str(value).replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        text = str(value).strip().replace(" ", "T")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def retime(record: dict, when: datetime, run_id: str) -> dict:
    """Move the record to its new time and give it an id unique to this run."""
    out = dict(record)
    for name in TIME_FIELDS:
        if name in out and out[name] not in (None, ""):
            if name == "ts":
                out[name] = when.timestamp()
            else:
                out[name] = when.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            break
    for name in ID_FIELDS:
        if out.get(name):
            out[name] = "{}-{}".format(out[name], run_id)
            break
    return out


def post(url: str, body: bytes, content_type: str = "application/x-ndjson") -> dict:
    request = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": content_type})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR, help="folder of .csv / .jsonl logs")
    parser.add_argument("--speed", type=float, default=30.0, help="how much faster than real time (default 30)")
    parser.add_argument("--keep-dataset", action="store_true", help="do not clear the current data first")
    args = parser.parse_args()

    rows = load(args.dir)
    if not rows:
        print("No .csv or .jsonl records with timestamps found in", args.dir)
        return 1
    base = args.server.rstrip("/") + "/api"
    try:
        urllib.request.urlopen(base + "/health", timeout=5).read()
    except (urllib.error.URLError, OSError):
        print("PRISM is not running at", args.server, "- start it first (Start PRISM.bat).")
        return 1

    if not args.keep_dataset:
        post(base + "/live/start?clear=true", b"", "application/json")
        print("Cleared the bundled dataset: PRISM now analyses only the live feed.")

    run_id = uuid.uuid4().hex[:6]
    first = rows[0][0]
    span = (rows[-1][0] - first).total_seconds() / args.speed
    started = datetime.now(timezone.utc)
    print("Streaming {} events from {} at {}x real time (about {:.0f}s). Watch it at {}".format(
        len(rows), args.dir.name, args.speed, span, args.server))

    try:
        for index, (original, source, record) in enumerate(rows, start=1):
            offset = (original - first).total_seconds() / args.speed
            due = started + timedelta(seconds=offset)
            wait = (due - datetime.now(timezone.utc)).total_seconds()
            if wait > 0:
                time.sleep(wait)
            body = json.dumps(retime(record, datetime.now(timezone.utc), run_id)).encode("utf-8")
            result = post("{}/live/events?source=replay-{}".format(base, source), body)
            what = record.get("query") or record.get("Image") or record.get("EventID") or ""
            print("  [{:>3}/{}] {:<22} {}  {}".format(
                index, len(rows), source, str(what).split("\\")[-1][:40],
                "rejected: " + "; ".join(result["errors"]) if result["rejected"] else ""))
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130
    print("Done. PRISM has analysed the live feed; the dashboard shows the result.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
