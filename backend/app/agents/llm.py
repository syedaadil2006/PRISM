"""Optional LLM provider, kept deliberately small.

The agents do not need a model to work. Every fact in an investigation is
retrieved through the tool layer and checked by the Verification Agent before
anything is written up, so the model's only job is to phrase a summary over
findings that are already settled.

That boundary is the whole design. A model that can only rewrite verified
findings cannot invent a host, a technique or an event id, because it is never
asked to supply one. Swapping provider means adding a class here and nothing
else.
"""

from __future__ import annotations

from typing import Protocol

from app.core.config import LLMSettings
from app.core.logging_config import get_logger

logger = get_logger(__name__)


class LLMProvider(Protocol):
    """Anything that can turn a prompt into prose, or decline to."""

    name: str

    async def complete(self, system: str, prompt: str) -> str | None:
        """Return prose, or None to fall back to the deterministic narrator."""
        ...


class NullProvider:
    """The default. Declines every request, which is a valid answer."""

    name = "deterministic"

    async def complete(self, system: str, prompt: str) -> str | None:
        return None


class AnthropicProvider:
    """Anthropic Messages API.

    Failures here are never fatal: a timeout, a missing dependency or a bad key
    all degrade to the deterministic narrator rather than to an empty summary.
    """

    name = "anthropic"

    def __init__(self, settings: LLMSettings) -> None:
        self._settings = settings

    async def complete(self, system: str, prompt: str) -> str | None:
        try:
            import httpx
        except ImportError:
            logger.warning("httpx is not installed; using the deterministic narrator")
            return None

        base_url = self._settings.base_url or "https://api.anthropic.com"
        try:
            async with httpx.AsyncClient(timeout=self._settings.timeout_seconds) as client:
                response = await client.post(
                    base_url.rstrip("/") + "/v1/messages",
                    headers={
                        "x-api-key": self._settings.resolved_api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": self._settings.model,
                        "max_tokens": self._settings.max_tokens,
                        "system": system,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:  # noqa: BLE001 - never break an investigation
            logger.warning(
                "llm request failed, falling back to the deterministic narrator",
                extra={"error": str(exc)},
            )
            return None

        blocks = payload.get("content") or []
        text = "".join(
            block.get("text", "") for block in blocks if block.get("type") == "text"
        ).strip()
        return text or None


def get_provider(settings: LLMSettings) -> LLMProvider:
    """Resolve the configured provider, degrading to null when unusable."""
    if not settings.configured:
        if settings.provider != "none":
            logger.warning(
                "llm provider configured without a key; using the deterministic narrator",
                extra={"provider": settings.provider},
            )
        return NullProvider()

    if settings.provider == "anthropic":
        return AnthropicProvider(settings)

    logger.warning(
        "unknown llm provider; using the deterministic narrator",
        extra={"provider": settings.provider},
    )
    return NullProvider()
