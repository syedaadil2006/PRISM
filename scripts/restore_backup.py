"""Restore PRISM's databases from a backup (backend/data/backups/<name>).

    python scripts/restore_backup.py                  # list backups
    python scripts/restore_backup.py 20261010-120000-manual

Stop PRISM first (close the "PRISM server" window): replacing a database under
a running server is unsafe, so this refuses while PRISM answers on its port.
The backup's checksums are verified first, and the current databases are kept
next to the originals as *.before-restore, so a restore can be undone.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.services.backup import verify_backup  # noqa: E402

BACKUPS = Path(os.environ.get("PRISM_BACKUP_DIR", ROOT / "backend" / "data" / "backups"))


def prism_is_running(port: int) -> bool:
    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE  # only asking our own computer whether PRISM is up
    for url in (f"http://127.0.0.1:{port}/api/health", f"https://127.0.0.1:{port}/api/health"):
        try:
            urllib.request.urlopen(url, timeout=2, context=insecure if url.startswith("https") else None)
            return True
        except Exception:  # noqa: BLE001 - any failure means "not answering"
            continue
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("backup", nargs="?", help="backup folder name (omit to list)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PRISM_PORT", "8000")))
    args = parser.parse_args()

    backups = sorted((p for p in BACKUPS.glob("*") if (p / "manifest.json").exists()), reverse=True)
    if not args.backup:
        if not backups:
            print(f"No backups in {BACKUPS}")
            return 0
        for folder in backups:
            manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
            names = ", ".join(f["database"] for f in manifest["files"]) or "nothing"
            print(f"{folder.name:40} {manifest['created_at']}  ({names})")
        return 0

    folder = BACKUPS / args.backup
    if not (folder / "manifest.json").exists():
        print(f"No backup called {args.backup} in {BACKUPS}")
        return 1
    if prism_is_running(args.port):
        print("PRISM is running. Close the \"PRISM server\" window, then run this again.")
        return 2
    problems = verify_backup(folder)
    if problems:
        print("This backup is damaged and was not restored:\n  " + "\n  ".join(problems))
        return 3

    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        target = Path(entry["restore_to"])
        target.parent.mkdir(parents=True, exist_ok=True)
        for extra in ("-wal", "-shm"):  # SQLite side files belong to the old database
            side = target.with_name(target.name + extra)
            if side.exists():
                side.unlink()
        if target.exists():
            shutil.copy2(target, target.with_name(target.name + ".before-restore"))
        shutil.copy2(folder / entry["file"], target)
        print(f"Restored {entry['database']} -> {target}")
    print("Done. Start PRISM again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
