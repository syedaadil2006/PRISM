"""User accounts, sign-in sessions and the audit log.

* **Accounts** have one of three roles - ``viewer`` (read only), ``analyst``
  (investigate, ingest, decide on findings) and ``admin`` (also manage users,
  read the audit log, clear data). Passwords are stored only as scrypt hashes
  (Python standard library) with a per-user random salt.
* **Sessions** are random 256-bit tokens. Only their SHA-256 hash is stored,
  so a copy of the database cannot be used to sign in. They expire after
  ``session_hours`` and are revoked when the account is disabled, deleted, its
  role changes or its password changes.
* **Failed sign-ins** are limited per account and per address
  (``max_failed_logins`` within ``lockout_minutes``).
* **The audit log** is append-only and hash-chained: every entry stores the
  SHA-256 of the previous entry plus its own content, so editing or deleting
  an entry breaks the chain and :meth:`verify_audit` reports where. (That makes
  tampering *evident*; preventing it needs write-once storage or shipping the
  log to a separate system.)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.core.config import AuthSettings
from app.core.db import Database

ROLES = ("viewer", "analyst", "admin")
ROLE_RANK = {role: rank for rank, role in enumerate(ROLES, start=1)}
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    last_login    TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    session_hash TEXT PRIMARY KEY,
    username     TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    address      TEXT
);
CREATE INDEX IF NOT EXISTS sessions_by_user ON sessions (username);
CREATE TABLE IF NOT EXISTS audit (
    seq       INTEGER PRIMARY KEY,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    address   TEXT NOT NULL,
    detail    TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
)
"""

# scrypt cost: 16 MB of memory and ~50 ms per hash - slow for guessing, fine for sign-in.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1


class AccountError(ValueError):
    """A request about accounts that cannot be carried out (shown to the user)."""


@dataclass(frozen=True)
class Principal:
    """Who is making a request."""

    username: str
    role: str
    kind: str  # "user" (named account) or "access-code" (shared code: launcher, scripts)

    def can(self, role: str) -> bool:
        return ROLE_RANK.get(self.role, 0) >= ROLE_RANK[role]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    encode = lambda raw: base64.b64encode(raw).decode("ascii")  # noqa: E731
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${encode(salt)}${encode(digest)}"


def check_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def _session_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _entry_hash(prev_hash: str, fields: dict[str, object]) -> str:
    body = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class SecurityStore:
    """Accounts, sessions, sign-in throttling and the audit log in one database."""

    SESSION_PREFIX = "s."

    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings
        self.db = Database(settings.db_url)
        self.db.script(SCHEMA)
        self._failures: dict[str, list[float]] = {}
        self._failures_lock = threading.Lock()

    def close(self) -> None:
        self.db.close()

    # ------------------------------------------------------------ accounts --

    def _validate_password(self, username: str, password: str) -> None:
        if len(password) < self.settings.min_password_length:
            raise AccountError(f"The password must be at least {self.settings.min_password_length} characters.")
        if password.lower() == username.lower():
            raise AccountError("The password must not be the user name.")

    def list_users(self) -> list[dict[str, object]]:
        rows = self.db.execute("SELECT username, role, disabled, created_at, last_login FROM users ORDER BY username")
        return [
            {"username": u, "role": role, "disabled": bool(disabled), "created_at": created, "last_login": last}
            for u, role, disabled, created, last in rows
        ]

    def get_user(self, username: str) -> dict[str, object] | None:
        return next((u for u in self.list_users() if u["username"] == username), None)

    def create_user(self, username: str, password: str, role: str) -> dict[str, object]:
        username = username.strip().lower()
        if not USERNAME_RE.match(username):
            raise AccountError("User names are 3-64 characters: lowercase letters, digits, '.', '_' or '-'.")
        if role not in ROLES:
            raise AccountError(f"The role must be one of: {', '.join(ROLES)}.")
        if username == "access-code":
            raise AccountError("That user name is reserved.")
        self._validate_password(username, password)
        if self.get_user(username):
            raise AccountError("A user with that name already exists.")
        self.db.execute(
            "INSERT INTO users (username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, 0, ?)",
            (username, hash_password(password), role, _iso(_now())),
        )
        return self.get_user(username) or {}

    def update_user(
        self, username: str, *, role: str | None = None, disabled: bool | None = None, password: str | None = None
    ) -> dict[str, object]:
        user = self.get_user(username)
        if not user:
            raise KeyError(username)
        if role is not None:
            if role not in ROLES:
                raise AccountError(f"The role must be one of: {', '.join(ROLES)}.")
            self.db.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
        if disabled is not None:
            self.db.execute("UPDATE users SET disabled = ? WHERE username = ?", (int(disabled), username))
        if password is not None:
            self._validate_password(username, password)
            self.db.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hash_password(password), username))
        if role is not None or disabled or password is not None:
            self.revoke_sessions(username)
        return self.get_user(username) or {}

    def delete_user(self, username: str) -> None:
        if not self.get_user(username):
            raise KeyError(username)
        self.revoke_sessions(username)
        self.db.execute("DELETE FROM users WHERE username = ?", (username,))

    def authenticate(self, username: str, password: str) -> Principal | None:
        username = username.strip().lower()
        rows = self.db.execute("SELECT password_hash, role, disabled FROM users WHERE username = ?", (username,))
        if not rows:
            check_password(password, hash_password("timing-equaliser"))  # same cost as a real check
            return None
        stored, role, disabled = rows[0]
        if disabled or not check_password(password, stored):
            return None
        self.db.execute("UPDATE users SET last_login = ? WHERE username = ?", (_iso(_now()), username))
        return Principal(username, role, "user")

    # ------------------------------------------------------------ sessions --

    def create_session(self, username: str, address: str) -> str:
        token = secrets.token_urlsafe(32)
        now = _now()
        expires = now + timedelta(hours=self.settings.session_hours)
        self.db.execute(
            "INSERT INTO sessions (session_hash, username, created_at, expires_at, address) VALUES (?, ?, ?, ?, ?)",
            (_session_hash(token), username, _iso(now), _iso(expires), address),
        )
        return self.SESSION_PREFIX + token

    def session_principal(self, cookie: str | None) -> Principal | None:
        if not cookie or not cookie.startswith(self.SESSION_PREFIX):
            return None
        rows = self.db.execute(
            "SELECT s.expires_at, u.username, u.role, u.disabled FROM sessions s "
            "JOIN users u ON u.username = s.username WHERE s.session_hash = ?",
            (_session_hash(cookie[len(self.SESSION_PREFIX):]),),
        )
        if not rows:
            return None
        expires_at, username, role, disabled = rows[0]
        if disabled or datetime.fromisoformat(expires_at) <= _now():
            return None
        return Principal(username, role, "user")

    def end_session(self, cookie: str | None) -> None:
        if cookie and cookie.startswith(self.SESSION_PREFIX):
            self.db.execute(
                "DELETE FROM sessions WHERE session_hash = ?", (_session_hash(cookie[len(self.SESSION_PREFIX):]),)
            )

    def revoke_sessions(self, username: str) -> None:
        self.db.execute("DELETE FROM sessions WHERE username = ?", (username,))

    def purge_expired_sessions(self) -> None:
        self.db.execute("DELETE FROM sessions WHERE expires_at <= ?", (_iso(_now()),))

    # ------------------------------------------------------- sign-in limits --

    def locked_for(self, *keys: str) -> int:
        """Seconds until sign-in is allowed again for any of ``keys`` (0 = allowed)."""
        window = self.settings.lockout_minutes * 60
        now = time.monotonic()
        wait = 0.0
        with self._failures_lock:
            for key in keys:
                recent = [t for t in self._failures.get(key, []) if now - t < window]
                self._failures[key] = recent
                if len(recent) >= self.settings.max_failed_logins:
                    wait = max(wait, window - (now - recent[0]))
        return int(wait) + (1 if wait else 0)

    def record_failure(self, *keys: str) -> None:
        with self._failures_lock:
            for key in keys:
                self._failures.setdefault(key, []).append(time.monotonic())

    def clear_failures(self, *keys: str) -> None:
        with self._failures_lock:
            for key in keys:
                self._failures.pop(key, None)

    # ----------------------------------------------------------- audit log --

    def audit(
        self, actor: str, action: str, *, target: str = "", outcome: str = "success", address: str = "",
        detail: dict[str, object] | None = None,
    ) -> None:
        fields = {
            "ts": _iso(_now()), "actor": actor, "action": action, "target": target, "outcome": outcome,
            "address": address, "detail": json.dumps(detail or {}, sort_keys=True, default=str),
        }
        with self.db.transaction():
            last = self.db.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
            seq, prev_hash = (last[0][0] + 1, last[0][1]) if last else (1, GENESIS)
            entry_hash = _entry_hash(prev_hash, {"seq": seq, **fields})
            self.db.execute(
                "INSERT INTO audit (seq, ts, actor, action, target, outcome, address, detail, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (seq, fields["ts"], actor, action, target, outcome, address, fields["detail"], prev_hash, entry_hash),
            )

    def audit_entries(self, limit: int = 200, actor: str | None = None, action: str | None = None) -> list[dict]:
        sql = "SELECT seq, ts, actor, action, target, outcome, address, detail FROM audit"
        clauses, params = [], []
        if actor:
            clauses.append("actor = ?")
            params.append(actor)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        rows = self.db.execute(sql + " ORDER BY seq DESC LIMIT ?", (*params, max(1, min(limit, 5000))))
        return [
            {"seq": s, "ts": ts, "actor": a, "action": act, "target": t, "outcome": o, "address": ad,
             "detail": json.loads(d)}
            for s, ts, a, act, t, o, ad, d in rows
        ]

    def verify_audit(self) -> dict[str, object]:
        """Re-compute the hash chain. ``first_broken`` names the first bad entry."""
        rows = self.db.execute(
            "SELECT seq, ts, actor, action, target, outcome, address, detail, prev_hash, hash FROM audit ORDER BY seq"
        )
        prev_hash, expected_seq = GENESIS, 1
        for seq, ts, actor, action, target, outcome, address, detail, stored_prev, stored_hash in rows:
            fields = {"seq": seq, "ts": ts, "actor": actor, "action": action, "target": target,
                      "outcome": outcome, "address": address, "detail": detail}
            if seq != expected_seq or stored_prev != prev_hash or _entry_hash(prev_hash, fields) != stored_hash:
                reason = "missing entry" if seq != expected_seq else "entry was changed"
                return {"ok": False, "entries": len(rows), "first_broken": expected_seq, "reason": reason}
            prev_hash, expected_seq = stored_hash, seq + 1
        return {"ok": True, "entries": len(rows), "first_broken": None, "reason": None}
