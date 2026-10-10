"""API authentication, roles and auditing.

Every /api request must come from a signed-in principal, except the health
check and the sign-in endpoints. A principal is either:

* a **named account** (viewer, analyst or admin) signed in on the dashboard -
  the ``prism_session`` cookie holds a random session token (see
  app/core/security_store.py); or
* the **shared access code** - used by the launcher, scripts and collectors via
  the ``X-PRISM-Token`` header or ``Authorization: Bearer <code>``, or signed in
  on the dashboard. It acts as an admin and can be switched off
  (PRISM_AUTH_ACCESS_CODE_ENABLED=false) once named accounts exist.

The code comes from PRISM_AUTH_TOKEN, or is generated once and kept in a local
file (``backend/data/.prism_token``) that is never committed. Comparisons are
constant-time.

What each role may do (:func:`required_role`): viewers read; analysts also
investigate, decide on findings and ingest data; admins also manage accounts,
read the audit log and clear data. Every request that changes something, and
every refused request, is written to the audit log.
"""

from __future__ import annotations

import hmac
import secrets
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import AuthSettings
from app.core.logging_config import get_logger
from app.core.security_store import Principal, SecurityStore

logger = get_logger(__name__)

COOKIE_NAME = "prism_session"
HEADER_NAME = "X-PRISM-Token"
#: Paths that work without signing in.
PUBLIC_PATHS = frozenset({"/api/health", "/api/auth/status", "/api/auth/login", "/api/auth/logout"})
#: Requests that need an admin besides everything under /api/admin/.
ADMIN_ACTIONS = frozenset({("POST", "/api/logs/reset"), ("POST", "/api/live/start")})
#: High-volume machine ingestion: not written to the audit log one by one.
UNAUDITED = frozenset({"/api/live/events", "/api/live/flush"})
ACCESS_CODE = Principal("access-code", "admin", "access-code")


def resolve_token(settings: AuthSettings) -> str:
    """The configured code, or the one stored on disk (created if missing)."""
    if settings.token:
        return settings.token
    path = Path(settings.token_file)
    try:
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    except OSError:
        pass
    token = secrets.token_urlsafe(24)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(token, encoding="utf-8")
        logger.info("generated a new access code", extra={"file": str(path)})
    except OSError as exc:
        logger.warning("could not save the access code; it lasts until restart", extra={"error": str(exc)})
    return token


def presented_token(request: Request) -> str | None:
    header = request.headers.get(HEADER_NAME)
    if header:
        return header.strip()
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.cookies.get(COOKIE_NAME)


def is_valid(candidate: str | None, token: str) -> bool:
    return bool(candidate) and bool(token) and hmac.compare_digest(candidate.encode("utf-8"), token.encode("utf-8"))


def client_address(request: Request) -> str:
    return request.client.host if request.client else ""


def current_principal(request: Request) -> Principal | None:
    """Who sent this request, or None when nobody is signed in."""
    state = request.app.state
    if not getattr(state, "auth_enabled", False):
        return ACCESS_CODE
    candidate = presented_token(request)
    if getattr(state, "access_code_enabled", True) and is_valid(candidate, state.auth_token):
        return ACCESS_CODE
    store: SecurityStore | None = getattr(state, "security", None)
    return store.session_principal(candidate) if store else None


def required_role(method: str, path: str) -> str:
    if path.startswith("/api/admin/") or (method, path) in ADMIN_ACTIONS:
        return "admin"
    if method in {"GET", "HEAD"} or path.startswith("/api/auth/"):
        return "viewer"
    return "analyst"


def audit(request: Request, actor: str, action: str, **kwargs: object) -> None:
    store: SecurityStore | None = getattr(request.app.state, "security", None)
    if store is None:
        return
    try:
        store.audit(actor, action, address=client_address(request), **kwargs)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 - auditing must never break a request
        logger.error("could not write audit entry", extra={"action": action, "error": str(exc)})


class AuthMiddleware(BaseHTTPMiddleware):
    """401 without a principal, 403 when the role is too low; audits changes."""

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001, ANN201
        path, method = request.url.path, request.method
        if method == "OPTIONS" or not path.startswith("/api/") or path in PUBLIC_PATHS:
            return await call_next(request)

        principal = current_principal(request)
        if principal is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "Sign-in required. Sign in on the dashboard, or send the X-PRISM-Token header."},
                headers={"WWW-Authenticate": "Bearer"},
            )
        needed = required_role(method, path)
        if not principal.can(needed):
            audit(request, principal.username, f"{method} {path}", outcome="denied",
                  detail={"role": principal.role, "required": needed})
            return JSONResponse(
                status_code=403,
                content={"detail": f"Your role ({principal.role}) cannot do this; it needs {needed}."},
            )

        if principal.must_change_password and not path.startswith("/api/auth/"):
            return JSONResponse(
                status_code=403,
                content={"detail": "Choose a new password before using PRISM.", "password_change_required": True},
            )

        request.state.principal = principal
        response = await call_next(request)
        # Sign-in and successful admin actions write their own, more specific entries.
        described = path.startswith("/api/auth/") or (path.startswith("/api/admin/") and response.status_code < 400)
        if method not in {"GET", "HEAD"} and path not in UNAUDITED and not described:
            audit(request, principal.username, f"{method} {path}",
                  outcome="success" if response.status_code < 400 else f"failed ({response.status_code})",
                  target=request.url.query)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Browser hardening headers; HSTS when PRISM is served over HTTPS."""

    CSP = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001, ANN201
        response = await call_next(request)
        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        # The interactive API docs load their own scripts, so they keep the default policy.
        if not request.url.path.startswith(("/docs", "/redoc")):
            headers.setdefault("Content-Security-Policy", self.CSP)
        if request.url.scheme == "https":
            headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return response
