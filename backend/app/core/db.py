"""One small database layer for SQLite (default) and PostgreSQL (optional).

PRISM's SQL is written once, in the subset both engines share: ``?``
placeholders (rewritten to ``%s`` for PostgreSQL), TEXT/INTEGER columns and
``INSERT ... ON CONFLICT (...) DO UPDATE`` upserts. A URL picks the engine:

* ``sqlite:///C:/path/prism.db`` or a plain file path - no server needed;
* ``postgresql://user:password@host:5432/prism`` - needs the optional
  ``psycopg`` package (``pip install -r backend/requirements-postgres.txt``).

PostgreSQL normally runs on the same server or inside the organisation's own
network, so the edge rule (data stays on premises) still holds; in local-only
mode the host must be this computer (checked by the caller).

One connection is shared behind a lock: PRISM is a single server process and
its writes are small, so this keeps things simple and correct.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence
from urllib.parse import urlparse

POSTGRES_SCHEMES = ("postgres://", "postgresql://")


def is_postgres(url: str) -> bool:
    return url.startswith(POSTGRES_SCHEMES)


def postgres_host(url: str) -> str:
    return urlparse(url).hostname or "localhost"


def describe_url(url: str) -> str:
    """The URL without its password, safe for logs and the API."""
    if not is_postgres(url):
        return url
    parsed = urlparse(url)
    netloc = parsed.hostname or ""
    if parsed.username:
        netloc = parsed.username + "@" + netloc
    if parsed.port:
        netloc += ":" + str(parsed.port)
    return parsed._replace(netloc=netloc).geturl()


class Database:
    """A connection plus the engine name ("sqlite" or "postgres")."""

    def __init__(self, url: str) -> None:
        self.url = url
        self._lock = threading.RLock()
        if is_postgres(url):
            import psycopg  # optional dependency, imported only when asked for

            self.dialect = "postgres"
            self._conn: Any = psycopg.connect(url, autocommit=True)
        else:
            path = Path(url[len("sqlite:///"):] if url.startswith("sqlite:///") else url)
            path.parent.mkdir(parents=True, exist_ok=True)
            self.dialect = "sqlite"
            # isolation_level=None: autocommit, transactions only where asked for.
            self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
            self._conn.execute("PRAGMA journal_mode=WAL")

    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.dialect == "postgres" else sql

    def execute(self, sql: str, params: Sequence[Any] = ()) -> list[tuple]:
        with self._lock:
            cursor = self._conn.cursor()
            try:
                cursor.execute(self._sql(sql), tuple(params))
                return list(cursor.fetchall()) if cursor.description else []
            finally:
                cursor.close()

    def executemany(self, sql: str, rows: Sequence[Sequence[Any]]) -> None:
        if not rows:
            return
        with self._lock:
            cursor = self._conn.cursor()
            try:
                cursor.executemany(self._sql(sql), [tuple(r) for r in rows])
            finally:
                cursor.close()

    def script(self, sql: str) -> None:
        """Run several ``;``-separated statements (schema set-up)."""
        for statement in sql.split(";"):
            lines = [line.split("--", 1)[0] for line in statement.splitlines()]
            if "".join(lines).strip():
                self.execute("\n".join(lines))

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """All statements inside commit together or not at all."""
        with self._lock:
            self.execute("BEGIN")
            try:
                yield
            except BaseException:
                self.execute("ROLLBACK")
                raise
            self.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self._conn.close()
