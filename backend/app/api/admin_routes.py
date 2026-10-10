"""Administration: user accounts and the audit log (admin role only).

The role check itself happens in the auth middleware (everything under
/api/admin/ needs an admin); these handlers only do the work and audit it.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel

from app.core.auth import audit
from app.core.security_store import AccountError, SecurityStore

router = APIRouter(prefix="/api/admin", tags=["admin"])


class Account(BaseModel):
    username: str
    role: str
    disabled: bool
    created_at: str
    last_login: str | None = None
    must_change_password: bool = False


class NewAccount(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class AccountChange(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    #: Sets a new password (for example after the user forgot theirs).
    password: str | None = None


class AuditEntry(BaseModel):
    seq: int
    ts: str
    actor: str
    action: str
    target: str
    outcome: str
    address: str
    detail: dict


class AuditCheck(BaseModel):
    ok: bool
    entries: int
    first_broken: int | None = None
    reason: str | None = None


def _store(request: Request) -> SecurityStore:
    store = getattr(request.app.state, "security", None)
    if store is None:
        raise HTTPException(status_code=404, detail="User accounts are not enabled (PRISM_AUTH_ENABLED=false).")
    return store


def _actor(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    return principal.username if principal else "unknown"


@router.get("/users", response_model=list[Account])
def list_users(request: Request) -> list[dict]:
    return _store(request).list_users()


@router.post("/users", response_model=Account, status_code=201)
def create_user(request: Request, body: NewAccount) -> dict:
    store = _store(request)
    try:
        user = store.create_user(body.username, body.password, body.role)
    except AccountError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(request, _actor(request), "create user", target=str(user["username"]), detail={"role": body.role})
    return user


@router.patch("/users/{username}", response_model=Account)
def update_user(request: Request, username: str, body: AccountChange) -> dict:
    store = _store(request)
    actor = _actor(request)
    if username == actor and (body.disabled or (body.role is not None and body.role != "admin")):
        raise HTTPException(status_code=409, detail="You cannot disable your own account or remove your own admin role.")
    try:
        # A password set by an admin is temporary: the user chooses their own at next sign-in.
        user = store.update_user(username, role=body.role, disabled=body.disabled, password=body.password,
                                 require_change=body.password is not None and username != actor)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such user.") from exc
    except AccountError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    changes = {k: v for k, v in {"role": body.role, "disabled": body.disabled}.items() if v is not None}
    if body.password is not None:
        changes["password"] = "reset"
    audit(request, actor, "update user", target=username, detail=changes)
    return user


@router.delete("/users/{username}", status_code=204, response_class=Response)
def delete_user(request: Request, username: str) -> Response:
    store = _store(request)
    actor = _actor(request)
    if username == actor:
        raise HTTPException(status_code=409, detail="You cannot delete your own account.")
    try:
        store.delete_user(username)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="No such user.") from exc
    audit(request, actor, "delete user", target=username)
    return Response(status_code=204)


@router.get("/audit", response_model=list[AuditEntry])
def audit_log(
    request: Request,
    limit: int = Query(200, ge=1, le=5000),
    actor: str | None = None,
    action: str | None = None,
) -> list[dict]:
    """Newest entries first."""
    return _store(request).audit_entries(limit=limit, actor=actor, action=action)


@router.get("/audit/verify", response_model=AuditCheck)
def verify_audit(request: Request) -> dict:
    """Re-check the audit log's hash chain; reports the first changed or missing entry."""
    return _store(request).verify_audit()
