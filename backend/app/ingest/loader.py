"""File-based ingestion: CSV / JSON / JSON-lines into NormalizedEvents.

The demo dataset is loaded through exactly the same code path as an operator
uploading a log file, so nothing about the demo is special-cased.
"""

from __future__ import annotations

import csv
import io
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from app.core.logging_config import get_logger
from app.ingest.parsers import LogRecord, ParseContext, parse_records
from app.models.events import Action, NormalizedEvent, Severity
from app.models.inventory import Inventory

logger = get_logger(__name__)

#: How many queries for the same domain from one host counts as high volume.
HIGH_VOLUME_QUERY_COUNT = 5
#: Window (seconds) over which high-volume DNS is measured.
HIGH_VOLUME_WINDOW_SECONDS = 600
#: How many failed logons for one account counts as credential guessing.
AUTH_FAILURE_COUNT = 3
#: Window (seconds) over which failed logons are clustered.
AUTH_FAILURE_WINDOW_SECONDS = 600


def load_inventory(path: Path) -> Inventory:
    """Load the environment inventory, tolerating a missing file."""
    if not path.exists():
        logger.warning("inventory file missing, continuing with empty inventory", extra={"path": str(path)})
        return Inventory()
    data = json.loads(path.read_text(encoding="utf-8"))
    return Inventory.model_validate(data)


def decode_records(raw: str | bytes, filename: str) -> list[LogRecord]:
    """Turn a file payload into a list of raw records.

    Accepts a JSON array, JSON-lines, a single JSON object, or CSV.
    """
    text = raw.decode("utf-8-sig") if isinstance(raw, bytes) else raw
    text = text.strip()
    if not text:
        return []

    suffix = Path(filename).suffix.lower()

    if suffix == ".csv" or (suffix not in {".json", ".jsonl", ".ndjson", ".log"} and "," in text.splitlines()[0] and not text.startswith(("{", "["))):
        reader = csv.DictReader(io.StringIO(text))
        return [{k: v for k, v in row.items() if k is not None} for row in reader]

    if text.startswith("["):
        payload = json.loads(text)
        if not isinstance(payload, list):
            raise ValueError("expected a JSON array")
        return payload
    if text.startswith("{") and "\n" not in text.strip():
        return [json.loads(text)]

    records: list[LogRecord] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError("line {}: {}".format(line_no, exc)) from exc
    return records


def make_context(inventory: Inventory, source_log: str) -> ParseContext:
    return ParseContext(
        ip_to_host=inventory.ip_to_host(),
        known_domains={d.lower().rstrip(".") for d in inventory.known_domains},
        source_log=source_log,
    )


def ingest_payload(
    raw: str | bytes,
    filename: str,
    inventory: Inventory,
    log_format: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Normalize one file payload."""
    try:
        records = decode_records(raw, filename)
    except Exception as exc:  # noqa: BLE001 - reported to the API caller
        return [], ["{}: {}".format(filename, exc)]
    ctx = make_context(inventory, source_log=filename)
    events, errors = parse_records(records, ctx, log_format=log_format)
    return events, ["{}: {}".format(filename, e) for e in errors]


def ingest_directory(
    directory: Path,
    inventory: Inventory,
    patterns: Iterable[str] = ("*.json", "*.jsonl", "*.ndjson", "*.csv", "*.log"),
) -> tuple[list[NormalizedEvent], list[str]]:
    """Normalize every log file in a directory (used for the demo dataset)."""
    events: list[NormalizedEvent] = []
    errors: list[str] = []
    if not directory.exists():
        return events, ["dataset directory not found: {}".format(directory)]

    paths: list[Path] = []
    for pattern in patterns:
        paths.extend(sorted(directory.glob(pattern)))

    for path in sorted(set(paths)):
        if path.name.startswith("_"):
            continue
        file_events, file_errors = ingest_payload(
            path.read_text(encoding="utf-8"), path.name, inventory
        )
        logger.info(
            "ingested log file",
            extra={"file": path.name, "events": len(file_events), "errors": len(file_errors)},
        )
        events.extend(file_events)
        errors.extend(file_errors)
    return events, errors


def _tag(event: NormalizedEvent, tag: str) -> None:
    """Add a tag once, so enrichment can be re-run as live events arrive."""
    if tag not in event.tags:
        event.tags.append(tag)


def _set_finding(event: NormalizedEvent, marker: str, detail: str) -> None:
    """Replace an earlier version of the same aggregate finding.

    Counts in the text grow as live events arrive ("5 queries", then "6"), so
    the previous wording is dropped rather than kept alongside the new one.
    """
    event.tags[:] = [t for t in event.tags if not (t.startswith("finding:") and marker in t)]
    event.tags.append("finding:" + detail)


def enrich_dns_volume(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """Promote repetitive DNS lookups to HIGH_VOLUME_DNS (beaconing signal).

    This is an aggregate that no single log line can express, which is exactly
    the kind of finding the normalization layer should add.
    """
    buckets: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.domain and event.source_host:
            buckets[(event.source_host, event.domain)].append(event)

    for (host, domain), group in buckets.items():
        if len(group) < HIGH_VOLUME_QUERY_COUNT:
            continue
        group.sort(key=lambda e: e.timestamp)
        span = (group[-1].timestamp - group[0].timestamp).total_seconds()
        if span > HIGH_VOLUME_WINDOW_SECONDS:
            continue
        detail = "{} queries for {} from {} within {:.0f}s".format(
            len(group), domain, host, span
        )
        for event in group:
            event.suspicious = True
            if event.action is Action.DNS_QUERY:
                event.action = Action.HIGH_VOLUME_DNS
            if event.severity.rank < Severity.MEDIUM.rank:
                event.severity = Severity.MEDIUM
            _set_finding(event, " queries for {} from {} ".format(domain, host), detail)
            _tag(event, "beaconing")
    return events


def enrich_auth_failures(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """Promote clusters of failed logons to a medium-severity finding.

    One failed logon is a user mistyping a password. Several for the same
    account inside a short window is credential guessing, which is the kind of
    aggregate a per-alert SIEM rule tends to miss.
    """
    by_user: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.action is Action.LOGIN_FAILURE and event.user:
            by_user[event.user].append(event)

    for user, failures in by_user.items():
        if len(failures) < AUTH_FAILURE_COUNT:
            continue
        failures.sort(key=lambda e: e.timestamp)
        span = (failures[-1].timestamp - failures[0].timestamp).total_seconds()
        if span > AUTH_FAILURE_WINDOW_SECONDS:
            continue
        targets = sorted({e.destination_host for e in failures if e.destination_host})
        detail = "{} failed logons for {} across {} within {:.0f}s".format(
            len(failures), user, ", ".join(targets) or "unknown hosts", span
        )
        for event in failures:
            event.suspicious = True
            if event.severity.rank < Severity.MEDIUM.rank:
                event.severity = Severity.MEDIUM
            _set_finding(event, " failed logons for {} ".format(user), detail)
            _tag(event, "credential-guessing")
    return events


def normalize_all(
    events: list[NormalizedEvent],
) -> list[NormalizedEvent]:
    """Apply cross-event enrichment and return events in chronological order."""
    enrich_dns_volume(events)
    enrich_auth_failures(events)
    events.sort(key=lambda e: (e.timestamp, e.event_id))
    return events
