"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Request

from app.services.soc_state import SocState


def get_state(request: Request) -> SocState:
    """The process-wide SOC state, attached to the app at startup."""
    return request.app.state.soc
