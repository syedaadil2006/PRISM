"""Real-time ingestion: records pushed over HTTP or appended to watched files.

Each source ("stream") keeps its own parse context, so ids minted for records
that carry none keep counting across batches instead of restarting at 1, and
every event id is prefixed with its stream so two sources can never collide.
The watched folder is tailed: only lines appended since the last poll are read.
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from app.core.config import LiveSettings
from app.ingest.loader import decode_records, make_context
from app.ingest.parsers import LogRecord, ParseContext, parse_records
from app.models.events import NormalizedEvent
from app.models.inventory import Inventory

#: File types the watcher tails line by line. A JSON array cannot be tailed.
WATCH_PATTERNS = ("*.jsonl", "*.ndjson", "*.log", "*.csv")


class LiveStreamView(BaseModel):
    name: str
    events: int
    rejected: int
    last_event_at: datetime | None = None
    last_received_at: datetime | None = None


class LiveStatus(BaseModel):
    """What the live feed has received and when the analysis last caught up."""

    enabled: bool
    #: True when events arrived in the last 30 seconds.
    receiving: bool
    #: True after POST /api/live/start cleared the bundled dataset.
    live_only: bool
    watch_dir: str | None
    received: int
    accepted: int
    rejected: int
    duplicates: int
    events_per_minute: int
    last_received_at: datetime | None = None
    pending_analysis: bool = False
    last_analysis_at: datetime | None = None
    last_analysis_ms: float | None = None
    streams: list[LiveStreamView] = []
    recent_errors: list[str] = []


class LiveIngestResult(BaseModel):
    stream: str
    received: int
    accepted: int
    duplicates: int
    rejected: int
    errors: list[str] = []
    total_events: int


def stream_name(raw: str | None, fallback: str = "api") -> str:
    """A safe, short identifier for a source."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", (raw or "").strip()).strip("-.")
    return (name or fallback)[:48]


@dataclass
class _Stream:
    name: str
    ctx: ParseContext
    events: int = 0
    rejected: int = 0
    last_event_at: datetime | None = None
    last_received_at: datetime | None = None


@dataclass
class _Tail:
    offset: int = 0
    header: list[str] | None = None
    remainder: bytes = b""


@dataclass
class LiveFeed:
    """Bookkeeping for the live feed. SocState owns the events themselves."""

    settings: LiveSettings
    streams: dict[str, _Stream] = field(default_factory=dict)
    tails: dict[Path, _Tail] = field(default_factory=dict)
    received: int = 0
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    last_received_at: datetime | None = None
    live_only: bool = False
    recent_errors: deque[str] = field(default_factory=lambda: deque(maxlen=20))
    _arrivals: deque[tuple[float, int]] = field(default_factory=deque)

    # ------------------------------------------------------------- parsing --

    def parse(
        self,
        records: list[LogRecord],
        stream: str,
        inventory: Inventory,
        log_format: str | None = None,
    ) -> tuple[list[NormalizedEvent], list[str]]:
        """Normalize records from one source, namespacing their ids."""
        state = self.streams.get(stream)
        if state is None:
            state = _Stream(name=stream, ctx=make_context(inventory, source_log="live:" + stream))
            self.streams[stream] = state
        events, errors = parse_records(records, state.ctx, log_format=log_format)
        for event in events:
            event.event_id = "{}:{}".format(stream, event.event_id)
        now = datetime.now().astimezone()
        state.last_received_at = now
        state.rejected += len(errors)
        if events:
            newest = max(e.timestamp for e in events)
            if state.last_event_at is None or newest > state.last_event_at:
                state.last_event_at = newest
        self.recent_errors.extend("{}: {}".format(stream, e) for e in errors[:5])
        return events, errors

    def record_arrival(self, stream: str, received: int, accepted: int, duplicates: int, rejected: int) -> None:
        self.received += received
        self.accepted += accepted
        self.duplicates += duplicates
        self.rejected += rejected
        self.streams[stream].events += accepted
        self.last_received_at = datetime.now().astimezone()
        self._arrivals.append((time.monotonic(), received))

    def events_per_minute(self) -> int:
        cutoff = time.monotonic() - 60
        while self._arrivals and self._arrivals[0][0] < cutoff:
            self._arrivals.popleft()
        return sum(count for _, count in self._arrivals)

    # ------------------------------------------------------------- watcher --

    def poll_files(self) -> list[tuple[str, list[LogRecord], list[str]]]:
        """Read lines appended to watched files since the last poll."""
        directory = Path(self.settings.watch_dir)
        if not directory.is_dir():
            return []
        batches: list[tuple[str, list[LogRecord], list[str]]] = []
        paths = sorted({p for pattern in WATCH_PATTERNS for p in directory.glob(pattern)})
        for path in paths:
            if path.name.startswith("_"):
                continue
            records, errors = self._read_new(path)
            if records or errors:
                batches.append((stream_name("file-" + path.stem, "file"), records, errors))
        return batches

    def _read_new(self, path: Path) -> tuple[list[LogRecord], list[str]]:
        tail = self.tails.setdefault(path, _Tail())
        try:
            size = path.stat().st_size
        except OSError:
            return [], []
        if size < tail.offset:  # truncated or replaced: start again
            self.tails[path] = tail = _Tail()
        if size == tail.offset:
            return [], []
        with path.open("rb") as handle:
            handle.seek(tail.offset)
            chunk = handle.read(size - tail.offset)
        tail.offset = size

        data = tail.remainder + chunk
        cut = data.rfind(b"\n")
        if cut < 0:  # no complete line yet
            tail.remainder = data
            return [], []
        complete, tail.remainder = data[: cut + 1], data[cut + 1 :]
        lines = [
            line
            for line in complete.decode("utf-8", errors="replace").replace("﻿", "").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

        if path.suffix.lower() == ".csv":
            if tail.header is None and lines:
                tail.header = next(csv.reader([lines.pop(0)]))
            if not lines or tail.header is None:
                return [], []
            reader = csv.DictReader(io.StringIO("\n".join(lines)), fieldnames=tail.header)
            return [{k: v for k, v in row.items() if k is not None} for row in reader], []

        records: list[LogRecord] = []
        errors: list[str] = []
        for line in lines:
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append("{}: {}".format(path.name, exc))
                continue
            if isinstance(value, dict):
                records.append(value)
            else:
                errors.append("{}: expected one JSON object per line".format(path.name))
        return records, errors

    # ---------------------------------------------------------------- view --

    def status(
        self,
        pending: bool,
        last_analysis_at: datetime | None,
        last_analysis_ms: float | None,
    ) -> LiveStatus:
        receiving = (
            self.last_received_at is not None
            and (datetime.now().astimezone() - self.last_received_at).total_seconds() < 30
        )
        watch_dir = Path(self.settings.watch_dir)
        return LiveStatus(
            enabled=self.settings.enabled,
            receiving=receiving,
            live_only=self.live_only,
            watch_dir=str(watch_dir) if self.settings.enabled else None,
            received=self.received,
            accepted=self.accepted,
            rejected=self.rejected,
            duplicates=self.duplicates,
            events_per_minute=self.events_per_minute(),
            last_received_at=self.last_received_at,
            pending_analysis=pending,
            last_analysis_at=last_analysis_at,
            last_analysis_ms=last_analysis_ms,
            streams=[
                LiveStreamView(
                    name=s.name,
                    events=s.events,
                    rejected=s.rejected,
                    last_event_at=s.last_event_at,
                    last_received_at=s.last_received_at,
                )
                for s in sorted(self.streams.values(), key=lambda s: s.name)
            ],
            recent_errors=list(self.recent_errors),
        )


def decode_body(raw: bytes, content_type: str | None) -> list[LogRecord]:
    """Accept a JSON array, {"records": [...]}, one object, JSON-lines or CSV."""
    text = raw.decode("utf-8-sig").strip()
    if not text:
        return []
    if text.startswith("{") and "\n" not in text:
        value = json.loads(text)
        if isinstance(value, dict) and isinstance(value.get("records"), list):
            return value["records"]
        return [value]
    if text.startswith("{") and (content_type or "").startswith("application/json"):
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            value = None
        if isinstance(value, dict):
            records = value.get("records")
            return records if isinstance(records, list) else [value]
    filename = "live.csv" if "csv" in (content_type or "") else "live.jsonl"
    return decode_records(text, filename)
