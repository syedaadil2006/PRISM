"""Elastic Common Schema (ECS) adapter: Winlogbeat, Filebeat, Packetbeat, Elastic Agent.

These shippers wrap the original log in ECS fields. Rather than duplicate the
detection logic, each ECS document is unwrapped into the native record shape
the existing parsers already understand:

* ``winlog.channel == Security / System``  -> Windows Security parser
* ``winlog.channel == ...Sysmon/Operational`` -> Sysmon parser (event 22 -> DNS)
* ``dns.question.name`` (Filebeat Zeek module, Packetbeat, Elastic Agent) -> DNS parser
* ``event.category`` authentication (Linux auth, VPNs, cloud) -> a native logon event

So a Winlogbeat event and the same event read from a CSV export produce the
same NormalizedEvent.
"""

from __future__ import annotations

from typing import Any

from app.ingest.parsers import (
    LogRecord,
    ParseContext,
    ParseError,
    _clean_host,
    _clean_ip,
    _clean_user,
    _parse_timestamp,
    parse_sysmon,
    parse_windows_security,
    parse_zeek_dns,
)
from app.models.events import Action, EventType, NormalizedEvent, Severity


def _path(record: LogRecord, dotted: str) -> Any:
    """Read ``a.b.c`` from nested objects, or from a flattened ``"a.b.c"`` key."""
    if dotted in record:
        return record[dotted]
    current: Any = record
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _first(record: LogRecord, *paths: str) -> Any:
    for dotted in paths:
        value = _path(record, dotted)
        if isinstance(value, list):
            value = value[0] if value else None
        if value not in (None, "", "-"):
            return value
    return None


def is_ecs(record: LogRecord) -> bool:
    keys = set(record)
    if "winlog" in keys or any(str(k).startswith("winlog.") for k in keys):
        return True
    has_ecs_shape = "@timestamp" in keys and bool(keys & {"event", "host", "dns", "source", "ecs", "agent"})
    return has_ecs_shape or "ecs.version" in keys


def parse_ecs(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    timestamp = _first(record, "@timestamp", "event.created")
    channel = str(_first(record, "winlog.channel") or "")
    code = _first(record, "winlog.event_id", "event.code")
    computer = _first(record, "winlog.computer_name", "host.hostname", "host.name")
    record_id = _first(record, "winlog.record_id", "event.id")
    data = _path(record, "winlog.event_data") or {}
    if not isinstance(data, dict):
        data = {}
    uid = "ecs-{}-{}-{}".format(str(computer or "host").split(".")[0].lower(), channel.split("/")[0] or "event", record_id) if record_id else None

    if channel in {"Security", "System"} or (channel == "" and code and str(code).isdigit() and int(code) >= 4600 and data):
        native = dict(data)
        native.update(EventID=str(code), TimeCreated=timestamp, Computer=computer)
        if data.get("ImagePath") and not native.get("ServiceFileName"):
            native["ServiceFileName"] = data["ImagePath"]
        if uid:
            native["RecordId"] = uid
        event = parse_windows_security(native, ctx)
        return _mark(event, record)

    if "sysmon" in channel.lower():
        if str(code) == "22":
            query = data.get("QueryName")
            if not query:
                raise ParseError("Sysmon DNS event without QueryName")
            native = {"timestamp": timestamp, "query": query, "host": computer, "process": data.get("Image")}
            if uid:
                native["uid"] = uid
            return _mark(parse_zeek_dns(native, ctx), record)
        native = dict(data)
        native.update(EventID=str(code), UtcTime=data.get("UtcTime") or timestamp, Computer=computer)
        if uid:
            native["RecordId"] = uid
        return _mark(parse_sysmon(native, ctx), record)

    query = _first(record, "dns.question.name", "zeek.dns.query")
    if query:
        native = {
            "timestamp": timestamp,
            "query": query,
            "id.orig_h": _first(record, "source.ip", "client.ip"),
            "id.resp_h": _first(record, "destination.ip", "server.ip"),
            "host": _first(record, "host.hostname", "host.name") if not _first(record, "source.ip") else None,
            "qtype_name": _first(record, "dns.question.type"),
            "process": _first(record, "process.name"),
        }
        uid_value = _first(record, "zeek.session_id", "event.id")
        if uid_value:
            native["uid"] = "ecs-dns-" + str(uid_value)
        return _mark(parse_zeek_dns({k: v for k, v in native.items() if v is not None}, ctx), record)

    categories = _path(record, "event.category") or []
    if isinstance(categories, str):
        categories = [categories]
    if "authentication" in categories:
        return _mark(_authentication(record, timestamp, ctx), record)

    raise ParseError("ECS document is not a Windows, Sysmon, DNS or authentication event")


def _authentication(record: LogRecord, timestamp: Any, ctx: ParseContext) -> NormalizedEvent:
    """Linux auth, VPN and cloud sign-ins as normalized logon events."""
    outcome = str(_first(record, "event.outcome") or "success").lower()
    failed = outcome == "failure"
    source_ip = _clean_ip(_first(record, "source.ip"))
    host = _clean_host(_first(record, "host.hostname", "host.name"))
    source_host = _clean_host(_first(record, "source.domain")) or ctx.resolve_host(source_ip)
    return NormalizedEvent(
        event_id=str(_first(record, "event.id") or ctx.next_id("auth")),
        timestamp=_parse_timestamp(timestamp),
        event_type=EventType.AUTHENTICATION,
        action=Action.LOGIN_FAILURE if failed else Action.LOGIN_SUCCESS,
        user=_clean_user(_first(record, "user.name")),
        source_host=source_host,
        destination_host=host,
        source_ip=source_ip,
        process=_first(record, "process.name"),
        outcome="failure" if failed else "success",
        severity=Severity.LOW if failed else Severity.INFO,
        tags=["ecs:authentication"] + (["failed-logon"] if failed else []),
        source_log=ctx.source_log,
        raw=dict(record),
    )


def _mark(event: NormalizedEvent, record: LogRecord) -> NormalizedEvent:
    if "ecs" not in event.tags:
        event.tags.append("ecs")
    event.raw = dict(record)
    return event
