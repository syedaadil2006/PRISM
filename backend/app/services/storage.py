"""Persistent storage: keeps PRISM's state across restarts.

A single SQLite file (Python standard library, no server) - or, for larger
deployments, a PostgreSQL database on the organisation's own network
(PRISM_STORAGE_URL, see app/core/db.py) - holds:

* events that arrived after start-up - uploaded files and the live feed - so a
  restart does not lose them (the bundled dataset is simply reloaded from disk).
  Events are kept per *scope* (the data choice: demo, BOTS, live), so events
  added in one mode never appear in another;
* finished investigations, including analyst decisions;
* small settings such as whether PRISM was switched to live-only analysis.

Everything is stored as the same JSON the API returns, so the schema follows
the models instead of being duplicated here.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.core.config import StorageSettings
from app.core.db import Database, describe_url, is_postgres
from app.core.logging_config import get_logger
from app.models.events import NormalizedEvent

logger = get_logger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    scope      TEXT NOT NULL,          -- which data choice they belong to
    event_id   TEXT NOT NULL,
    origin     TEXT NOT NULL,          -- 'upload' or 'live'
    timestamp  TEXT NOT NULL,
    data       TEXT NOT NULL,
    PRIMARY KEY (scope, event_id)
);
CREATE INDEX IF NOT EXISTS events_by_scope_time ON events (scope, timestamp);
CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    data             TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Store:
    """Thin wrapper over one database. Disabled stores do nothing."""

    def __init__(self, settings: StorageSettings) -> None:
        self.enabled = settings.enabled
        self.path = Path(settings.path)
        self.url = settings.url or str(self.path)
        self._db: Database | None = None
        if not self.enabled:
            return
        try:
            self._db = Database(self.url)
            self._db.script(SCHEMA)
        except Exception as exc:  # noqa: BLE001 - any driver or connection error
            # Storage is a convenience: PRISM keeps working in memory without it.
            logger.warning("persistent storage unavailable", extra={"url": describe_url(self.url), "error": str(exc)})
            self.enabled = False
            self._db = None

    @property
    def engine(self) -> str | None:
        return self._db.dialect if self._db is not None else None

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    # -------------------------------------------------------------- events --

    def save_events(self, events: list[NormalizedEvent], origin: str, scope: str) -> None:
        if self._db is None or not events:
            return
        rows = [(scope, e.event_id, origin, e.timestamp.isoformat(), e.model_dump_json()) for e in events]
        self._db.executemany(
            "INSERT INTO events (scope, event_id, origin, timestamp, data) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (scope, event_id) DO UPDATE SET origin = excluded.origin, "
            "timestamp = excluded.timestamp, data = excluded.data",
            rows,
        )

    def load_events(self, limit: int, scope: str) -> list[NormalizedEvent]:
        """The newest ``limit`` stored events of one scope, oldest first."""
        if self._db is None:
            return []
        rows = self._db.execute(
            "SELECT data FROM events WHERE scope = ? ORDER BY timestamp DESC LIMIT ?",
            (scope, max(0, limit)),
        )
        events: list[NormalizedEvent] = []
        for (data,) in reversed(rows):
            try:
                events.append(NormalizedEvent.model_validate_json(data))
            except ValueError as exc:
                logger.warning("skipping unreadable stored event", extra={"error": str(exc)})
        return events

    def trim_events(self, keep: int, scope: str) -> None:
        """Delete all but the newest ``keep`` events of one scope."""
        if self._db is None:
            return
        self._db.execute(
            "DELETE FROM events WHERE scope = ? AND event_id NOT IN "
            "(SELECT event_id FROM events WHERE scope = ? ORDER BY timestamp DESC LIMIT ?)",
            (scope, scope, max(0, keep)),
        )

    def clear_events(self, scope: str) -> None:
        if self._db is None:
            return
        self._db.execute("DELETE FROM events WHERE scope = ?", (scope,))

    def event_count(self, scope: str | None = None) -> int:
        if self._db is None:
            return 0
        if scope is None:
            return int(self._db.execute("SELECT COUNT(*) FROM events")[0][0])
        return int(self._db.execute("SELECT COUNT(*) FROM events WHERE scope = ?", (scope,))[0][0])

    # ------------------------------------------------------ investigations --

    def save_investigation(self, investigation_id: str, created_at: str, data: str) -> None:
        if self._db is None:
            return
        self._db.execute(
            "INSERT INTO investigations (investigation_id, created_at, data) VALUES (?, ?, ?) "
            "ON CONFLICT (investigation_id) DO UPDATE SET created_at = excluded.created_at, data = excluded.data",
            (investigation_id, created_at, data),
        )

    def load_investigations(self, limit: int) -> list[str]:
        """JSON of the newest ``limit`` investigations, oldest first."""
        if self._db is None:
            return []
        rows = self._db.execute(
            "SELECT data FROM investigations ORDER BY created_at DESC LIMIT ?", (max(0, limit),)
        )
        return [data for (data,) in reversed(rows)]

    def delete_investigations(self, keep_ids: set[str] | None = None) -> None:
        """Delete every investigation, or every one not in ``keep_ids``."""
        if self._db is None:
            return
        if keep_ids:
            marks = ",".join("?" for _ in keep_ids)
            self._db.execute(
                "DELETE FROM investigations WHERE investigation_id NOT IN ({})".format(marks),
                tuple(keep_ids),
            )
        else:
            self._db.execute("DELETE FROM investigations")

    def purge_older_than(self, cutoff_iso: str) -> tuple[int, int]:
        """Delete stored events and investigations older than ``cutoff_iso`` (UTC ISO time).

        Returns (events, investigations) deleted.
        """
        if self._db is None:
            return 0, 0
        events = int(self._db.execute("SELECT COUNT(*) FROM events WHERE timestamp < ?", (cutoff_iso,))[0][0])
        investigations = int(
            self._db.execute("SELECT COUNT(*) FROM investigations WHERE created_at < ?", (cutoff_iso,))[0][0]
        )
        self._db.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_iso,))
        self._db.execute("DELETE FROM investigations WHERE created_at < ?", (cutoff_iso,))
        return events, investigations

    # ---------------------------------------------------------------- meta --

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        if self._db is None:
            return default
        rows = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,))
        return rows[0][0] if rows else default

    def set_meta(self, key: str, value: str | None) -> None:
        if self._db is None:
            return
        if value is None:
            self._db.execute("DELETE FROM meta WHERE key = ?", (key,))
        else:
            self._db.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def describe(self, scope: str) -> dict[str, object]:
        location = describe_url(self.url) if is_postgres(self.url) else str(self.path)
        return {
            "enabled": self.enabled,
            "engine": self.engine,
            "path": location if self.enabled else None,
            "scope": scope,
            "stored_events": self.event_count(scope),
            "stored_investigations": len(self.load_investigations(10_000)),
        }


def dumps(value: object) -> str:
    return json.dumps(value, default=str)
