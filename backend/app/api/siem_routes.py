"""Splunk HTTP Event Collector (HEC) compatible ingestion.

Tools that can send to Splunk HEC (Splunk forwarders and apps, Cribl, Fluent Bit,
Vector, Logstash, custom scripts) can send to PRISM unchanged:

    POST /services/collector/event
    Authorization: Splunk <PRISM access code>
    {"time": 1727690000, "host": "hr-pc", "sourcetype": "sysmon", "event": {...}}

Several events may be sent back to back in one body, as HEC allows. The
``event`` object can be any format PRISM reads (Windows Security, Sysmon, Zeek
DNS, ECS/Winlogbeat, PRISM native); plain-text events are not parsed. Responses
use HEC's codes so senders interpret them correctly.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.auth import is_valid
from app.services.live_feed import stream_name

router = APIRouter(prefix="/services/collector", tags=["siem"])

TIME_KEYS = ("TimeCreated", "UtcTime", "ts", "timestamp", "@timestamp", "_time")


def _hec(code: int, text: str, status: int = 200, **extra: Any) -> JSONResponse:
    return JSONResponse({"text": text, "code": code, **extra}, status_code=status)


def _token(request: Request) -> str | None:
    authorization = request.headers.get("Authorization", "")
    for prefix in ("splunk ", "bearer "):
        if authorization.lower().startswith(prefix):
            return authorization[len(prefix):].strip()
    return request.headers.get("X-PRISM-Token") or request.query_params.get("token")


def _objects(body: str) -> list[Any]:
    """HEC bodies are JSON objects back to back, optionally separated by whitespace."""
    decoder = json.JSONDecoder()
    objects: list[Any] = []
    index = 0
    while True:
        while index < len(body) and body[index] in " \t\r\n":
            index += 1
        if index >= len(body):
            return objects
        value, index = decoder.raw_decode(body, index)
        objects.extend(value if isinstance(value, list) else [value])


@router.get("/health")
def hec_health() -> JSONResponse:
    return _hec(17, "HEC is healthy")


@router.post("")
@router.post("/event")
@router.post("/event/1.0")
async def hec_event(request: Request) -> JSONResponse:
    state = request.app.state.soc
    if getattr(request.app.state, "auth_enabled", False):
        token = _token(request)
        if not token:
            return _hec(2, "Token is required", 401)
        if not is_valid(token, request.app.state.auth_token):
            return _hec(4, "Invalid token", 403)
    if not state.settings.live.enabled:
        return _hec(9, "Server is busy", 503)

    raw = (await request.body()).decode("utf-8-sig", errors="replace")
    if not raw.strip():
        return _hec(5, "No data", 400)
    try:
        objects = _objects(raw)
    except json.JSONDecodeError:
        return _hec(6, "Invalid data format", 400)
    if len(objects) > state.settings.live.max_batch:
        return _hec(6, "Too many events in one request", 413)

    batches: dict[str, list[dict[str, Any]]] = defaultdict(list)
    skipped = 0
    for item in objects:
        if not isinstance(item, dict) or "event" not in item:
            return _hec(12, "Event field is required", 400)
        event = item["event"]
        if not isinstance(event, dict):
            skipped += 1  # plain-text events: PRISM needs structured fields
            continue
        record = dict(event)
        if item.get("time") is not None and not any(key in record for key in TIME_KEYS):
            record["timestamp"] = item["time"]
        source = item.get("source") or item.get("sourcetype") or "splunk"
        batches[stream_name("hec-" + str(source), "hec")].append(record)

    accepted = duplicates = rejected = 0
    errors: list[str] = []
    for stream, records in batches.items():
        result = await state.ingest_live(records, stream)
        accepted += result.accepted
        duplicates += result.duplicates
        rejected += result.rejected
        errors.extend(result.errors[:5])
    return _hec(
        0,
        "Success",
        prism={
            "received": len(objects),
            "accepted": accepted,
            "duplicates": duplicates,
            "rejected": rejected + skipped,
            "skipped_text_events": skipped,
            "errors": errors[:10],
        },
    )
