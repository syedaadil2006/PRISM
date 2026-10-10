"""Sign-in endpoints: named accounts or the shared access code become a session cookie."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from app.core.auth import COOKIE_NAME, audit, client_address, current_principal, is_valid, presented_token
from app.core.security_store import AccountError, SecurityStore

router = APIRouter(prefix="/api/auth", tags=["auth"])


class AuthStatus(BaseModel):
    enabled: bool
    authenticated: bool
    user: str | None = None
    role: str | None = None
    #: "user" (named account) or "access-code".
    kind: str | None = None
    #: Whether named accounts can sign in (the sign-in screen shows the form).
    accounts: bool = False
    access_code: bool = True


class LoginRequest(BaseModel):
    username: str | None = None
    password: str | None = None
    #: The shared access code (instead of a user name and password).
    token: str | None = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


def _security(request: Request) -> SecurityStore | None:
    return getattr(request.app.state, "security", None)


def _status(request: Request) -> AuthStatus:
    state = request.app.state
    enabled = bool(getattr(state, "auth_enabled", False))
    principal = current_principal(request)
    return AuthStatus(
        enabled=enabled,
        authenticated=principal is not None,
        user=principal.username if principal and enabled else None,
        role=principal.role if principal else None,
        kind=principal.kind if principal and enabled else None,
        accounts=_security(request) is not None,
        access_code=bool(getattr(state, "access_code_enabled", True)),
    )


def _set_cookie(request: Request, response: Response, value: str, max_age: int) -> None:
    response.set_cookie(
        COOKIE_NAME, value, max_age=max_age, httponly=True, samesite="strict",
        secure=request.url.scheme == "https", path="/",
    )


@router.get("/status", response_model=AuthStatus)
def auth_status(request: Request) -> AuthStatus:
    """Whether sign-in is required, and who this browser is signed in as."""
    return _status(request)


@router.post("/login", response_model=AuthStatus)
def login(request: Request, response: Response, body: LoginRequest) -> AuthStatus:
    """Sign in with a user name and password, or with the access code.

    Sets an HttpOnly, SameSite=Strict cookie (Secure over HTTPS). Repeated
    failures lock the account and the address for a while (HTTP 429).
    """
    state = request.app.state
    if not getattr(state, "auth_enabled", False):
        return _status(request)
    store = _security(request)
    address = client_address(request)
    account = (body.username or "").strip().lower()
    keys = ("addr:" + address,) + (("user:" + account,) if account else ())

    if store is not None:
        wait = store.locked_for(*keys)
        if wait:
            audit(request, account or "access-code", "login", outcome="locked out")
            raise HTTPException(
                status_code=429, detail=f"Too many failed sign-ins. Try again in {max(1, wait // 60)} minute(s)."
            )

    if body.token is not None:
        if getattr(state, "access_code_enabled", True) and is_valid(body.token.strip(), state.auth_token):
            if store is not None:
                store.clear_failures(*keys)
            audit(request, "access-code", "login")
            _set_cookie(request, response, body.token.strip(), state.auth_cookie_max_age)
            return AuthStatus(enabled=True, authenticated=True, user="access-code", role="admin",
                              kind="access-code", accounts=store is not None, access_code=True)
        if store is not None:
            store.record_failure(*keys)
        audit(request, "access-code", "login", outcome="failed")
        raise HTTPException(status_code=401, detail="That access code is not correct.")

    if store is None or not account or not body.password:
        raise HTTPException(status_code=400, detail="Enter a user name and password.")
    principal = store.authenticate(account, body.password)
    if principal is None:
        store.record_failure(*keys)
        audit(request, account, "login", outcome="failed")
        raise HTTPException(status_code=401, detail="That user name or password is not correct.")
    store.clear_failures(*keys)
    store.purge_expired_sessions()
    cookie = store.create_session(principal.username, address)
    audit(request, principal.username, "login")
    _set_cookie(request, response, cookie, int(store.settings.session_hours * 3600))
    return AuthStatus(enabled=True, authenticated=True, user=principal.username, role=principal.role,
                      kind="user", accounts=True, access_code=bool(getattr(state, "access_code_enabled", True)))


@router.post("/logout", response_model=AuthStatus)
def logout(request: Request, response: Response) -> AuthStatus:
    principal = current_principal(request)
    store = _security(request)
    if store is not None:
        store.end_session(presented_token(request))
    if principal is not None and getattr(request.app.state, "auth_enabled", False):
        audit(request, principal.username, "logout")
    response.delete_cookie(COOKIE_NAME, path="/")
    return AuthStatus(enabled=bool(getattr(request.app.state, "auth_enabled", False)), authenticated=False,
                      accounts=store is not None, access_code=bool(getattr(request.app.state, "access_code_enabled", True)))


@router.post("/password", response_model=AuthStatus)
def change_password(request: Request, response: Response, body: PasswordChange) -> AuthStatus:
    """Change your own password. Signs out your other sessions."""
    principal = current_principal(request)
    store = _security(request)
    if principal is None or principal.kind != "user" or store is None:
        raise HTTPException(status_code=400, detail="Only named accounts have a password to change.")
    if store.authenticate(principal.username, body.current_password) is None:
        audit(request, principal.username, "change password", outcome="failed")
        raise HTTPException(status_code=401, detail="The current password is not correct.")
    try:
        store.update_user(principal.username, password=body.new_password)
    except AccountError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(request, principal.username, "change password")
    cookie = store.create_session(principal.username, client_address(request))
    _set_cookie(request, response, cookie, int(store.settings.session_hours * 3600))
    return AuthStatus(enabled=True, authenticated=True, user=principal.username, role=principal.role, kind="user",
                      accounts=True, access_code=bool(getattr(request.app.state, "access_code_enabled", True)))
