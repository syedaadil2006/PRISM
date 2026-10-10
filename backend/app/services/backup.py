"""Backups and data retention.

* **Backups** copy PRISM's SQLite databases (stored events and investigations,
  and accounts plus the audit log) into ``backend/data/backups/<time>/`` using
  SQLite's online backup, so they are consistent even while PRISM is running.
  Each backup has a ``manifest.json`` with SHA-256 checksums. Only the newest
  ``keep`` backups are kept. PostgreSQL databases are backed up with the
  database's own tools (``pg_dump``); they are listed as skipped here.
* **Restoring** is done with ``scripts/restore_backup.py`` while PRISM is
  stopped (replacing a database under a running server is unsafe).
* **Retention** deletes stored events and investigations older than
  ``retention_days`` (0 keeps everything). The audit log is never trimmed:
  deleting entries would break its hash chain.

Backups stay on this computer, in line with local-only mode.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import Settings
from app.core.db import is_postgres
from app.core.logging_config import get_logger

logger = get_logger(__name__)


def _databases(settings: Settings) -> list[tuple[str, str]]:
    """(name, url-or-path) of every database PRISM uses."""
    found: list[tuple[str, str]] = []
    if settings.storage.enabled:
        found.append(("prism", settings.storage.url or str(settings.storage.path)))
    if settings.auth.enabled:
        found.append(("security", settings.auth.db_url))
    return found


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def create_backup(settings: Settings, label: str = "manual") -> dict[str, object]:
    """Back up every SQLite database now. Returns the manifest."""
    root = Path(settings.backup.dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target = root / f"{stamp}-{label}"
    suffix = 1
    while target.exists():
        suffix += 1
        target = root / f"{stamp}-{label}-{suffix}"
    target.mkdir(parents=True)

    files, skipped = [], []
    for name, location in _databases(settings):
        if is_postgres(location):
            skipped.append({"database": name, "reason": "PostgreSQL: back up with pg_dump"})
            continue
        source_path = Path(location[len("sqlite:///"):] if location.startswith("sqlite:///") else location)
        if not source_path.exists():
            skipped.append({"database": name, "reason": "not created yet"})
            continue
        out = target / f"{name}.db"
        source = sqlite3.connect(source_path)
        destination = sqlite3.connect(out)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        files.append({
            "database": name, "file": out.name, "restore_to": str(source_path.resolve()),
            "bytes": out.stat().st_size, "sha256": _sha256(out),
        })

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "label": label,
        "prism_version": settings.version,
        "name": target.name,
        "files": files,
        "skipped": skipped,
    }
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    prune_backups(settings)
    logger.info("backup created", extra={"backup": target.name, "files": len(files)})
    return manifest


def list_backups(settings: Settings) -> list[dict[str, object]]:
    """Newest first."""
    root = Path(settings.backup.dir)
    if not root.is_dir():
        return []
    backups = []
    for manifest_path in root.glob("*/manifest.json"):
        try:
            backups.append(json.loads(manifest_path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return sorted(backups, key=lambda b: str(b.get("name", "")), reverse=True)


def prune_backups(settings: Settings) -> int:
    """Delete all but the newest ``keep`` backups. Returns how many were removed."""
    keep = max(1, settings.backup.keep)
    root = Path(settings.backup.dir)
    removed = 0
    for backup in list_backups(settings)[keep:]:
        folder = root / str(backup["name"])
        if folder.is_dir() and folder.parent == root:
            shutil.rmtree(folder, ignore_errors=True)
            removed += 1
    return removed


def verify_backup(folder: Path) -> list[str]:
    """Problems with a backup folder (empty list = intact)."""
    try:
        manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"manifest unreadable: {exc}"]
    problems = []
    for entry in manifest.get("files", []):
        path = folder / entry["file"]
        if not path.exists():
            problems.append(f"{entry['file']} is missing")
        elif _sha256(path) != entry["sha256"]:
            problems.append(f"{entry['file']} does not match its checksum")
    return problems
