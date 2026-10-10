"""OCSF (Open Cybersecurity Schema Framework) import and export.

PRISM keeps its own internal event schema (NormalizedEvent); this module maps
it to and from OCSF 1.3 so PRISM can exchange data with OCSF tools (Amazon
Security Lake, OCSF-capable SIEMs, data pipelines) without custom mapping.

Event classes:

    PRISM                                         OCSF class (uid)
    logons, failed logons, RDP, network/SMB       Authentication (3002)
    privileged logon (Windows 4672)               Authorize Session (3003), Assign Privileges
    process launch / process access (lsass)       Process Activity (1007), Launch / Open
    file creation (e.g. a malicious attachment)   File System Activity (1001), Create
    DNS lookups                                   DNS Activity (4003), Query
    attack chains (output only)                   Detection Finding (2004)

Export keeps every PRISM-specific detail in OCSF's ``unmapped`` extension
point (``unmapped.prism``), so OCSF written by PRISM reads back exactly. OCSF
from other tools (no ``unmapped.prism``) is translated into the native record
shapes PRISM's parsers read, so the same detection rules apply to it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app.ingest.parsers import (
    LogRecord,
    ParseContext,
    ParseError,
    parse_sysmon,
    parse_windows_security,
    parse_zeek_dns,
)
from app.models.analysis import AttackChain
from app.models.events import Action, EventType, NormalizedEvent

OCSF_VERSION = "1.3.0"

SEVERITY_ID = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEVERITY_NAME = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
CONFIDENCE_ID = {"low": 1, "medium": 2, "high": 3}
CATEGORY = {1: "System Activity", 2: "Findings", 3: "Identity & Access Management", 4: "Network Activity",
            6: "Application Activity"}
CLASS_NAME = {
    1001: "File System Activity",
    1007: "Process Activity",
    2004: "Detection Finding",
    3002: "Authentication",
    3003: "Authorize Session",
    4001: "Network Activity",
    4003: "DNS Activity",
    6003: "API Activity",
}
LOGON_TYPE_ID = {
    "Interactive": 2, "Network": 3, "Batch": 4, "Service": 5, "Unlock": 7, "NetworkCleartext": 8,
    "NewCredentials": 9, "RemoteInteractive (RDP)": 10, "CachedInteractive": 11,
}


def _ms(when: datetime) -> int:
    return int(when.astimezone(timezone.utc).timestamp() * 1000)


def _base(class_uid: int, category_uid: int, activity_id: int, activity_name: str, when: datetime,
          severity: str, version: str, uid: str | None, **extra: Any) -> dict[str, Any]:
    severity_id = SEVERITY_ID.get(severity, 0)
    event: dict[str, Any] = {
        "class_uid": class_uid,
        "class_name": CLASS_NAME[class_uid],
        "category_uid": category_uid,
        "category_name": CATEGORY[category_uid],
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": class_uid * 100 + activity_id,
        "time": _ms(when),
        "severity_id": severity_id,
        "severity": SEVERITY_NAME.get(severity_id, "Unknown"),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "PRISM", "vendor_name": "Team FORTZ", "version": version},
        },
    }
    if uid:
        event["metadata"]["uid"] = uid
    event.update({k: v for k, v in extra.items() if v not in (None, {}, [])})
    return event


def _user(name: str | None) -> dict[str, Any]:
    """OCSF requires a user on several classes; an unknown one is typed, not invented."""
    return {"name": name} if name else {"type_id": 0, "type": "Unknown"}


def _endpoint(hostname: str | None, ip: str | None) -> dict[str, Any] | None:
    endpoint = {k: v for k, v in (("hostname", hostname), ("ip", ip)) if v}
    return endpoint or None


def _proc(name: str | None, path: str | None = None, cmd: str | None = None, parent: dict | None = None,
          user: str | None = None) -> dict[str, Any] | None:
    if not (name or path):
        return None
    process: dict[str, Any] = {"name": name or (path or "").replace("\\", "/").split("/")[-1]}
    if path:
        process["file"] = {"name": process["name"], "path": path}
    if cmd:
        process["cmd_line"] = cmd
    if parent:
        process["parent_process"] = parent
    if user:
        process["user"] = {"name": user}
    return process


# --------------------------------------------------------------------------- #
# export: NormalizedEvent -> OCSF
# --------------------------------------------------------------------------- #

def event_to_ocsf(event: NormalizedEvent, version: str = "") -> dict[str, Any]:
    raw = event.raw or {}
    severity = event.severity.value
    code = raw.get("EventID") or raw.get("EventCode")
    common: dict[str, Any] = {
        "message": event.summary(),
        "status_id": 2 if event.outcome == "failure" else 1,
        "status": "Failure" if event.outcome == "failure" else "Success",
        "raw_data": json.dumps(raw, default=str) if raw else None,
        "unmapped": {"prism": event.model_dump(mode="json", exclude={"raw"})},
    }
    uid = event.event_id

    if event.event_type is EventType.AUTHENTICATION:
        if event.action is Action.PRIVILEGED_LOGIN:
            out = _base(3003, 3, 1, "Assign Privileges", event.timestamp, severity, version, uid,
                        user=_user(event.user),
                        device={"hostname": event.primary_host} if event.primary_host else None,
                        **common)
        else:
            logon_type_id = LOGON_TYPE_ID.get(event.logon_type or "", 0)
            if not logon_type_id:
                logon_type_id = {Action.RDP_LOGIN: 10, Action.NETWORK_LOGON: 3, Action.SMB_AUTH: 3}.get(event.action, 0)
            out = _base(3002, 3, 1, "Logon", event.timestamp, severity, version, uid,
                        user=_user(event.user),
                        src_endpoint=_endpoint(event.source_host, event.source_ip),
                        dst_endpoint=_endpoint(event.destination_host, event.destination_ip),
                        device={"hostname": event.destination_host} if event.destination_host else None,
                        logon_type_id=logon_type_id or None,
                        is_remote=bool(event.source_host and event.destination_host and event.source_host != event.destination_host),
                        **common)
            share = raw.get("ShareName")
            if share and share != "-":
                out["unmapped"]["share_name"] = share
    elif event.event_type is EventType.NETWORK:
        blocked = event.action is Action.CONNECTION_BLOCKED
        out = _base(4001, 4, 5 if blocked else 1, "Refuse" if blocked else "Open", event.timestamp, severity, version,
                    uid, src_endpoint=_endpoint(event.source_host, event.source_ip),
                    dst_endpoint=_endpoint(event.destination_host, event.destination_ip),
                    disposition="Blocked" if blocked else "Allowed", **common)
        if raw.get("dpt"):
            out["dst_endpoint"] = {**(out.get("dst_endpoint") or {}), "port": int(raw["dpt"]) if str(raw["dpt"]).isdigit() else raw["dpt"]}
    elif event.event_type is EventType.CLOUD:
        out = _base(6003, 6, 99, "Other", event.timestamp, severity, version, uid,
                    api={"operation": event.process, "service": {"name": raw.get("eventSource")}},
                    actor={"user": _user(event.user)},
                    src_endpoint=_endpoint(None, event.source_ip),
                    cloud={"provider": "AWS", "region": raw.get("awsRegion"), "account": {"uid": raw.get("recipientAccountId")}},
                    **common)
    elif event.event_type is EventType.DNS:
        out = _base(4003, 4, 1, "Query", event.timestamp, severity, version, uid,
                    query={k: v for k, v in (("hostname", event.domain), ("type", raw.get("qtype_name"))) if v},
                    src_endpoint=_endpoint(event.source_host, event.source_ip),
                    dst_endpoint=_endpoint(None, event.destination_ip),
                    actor={"process": _proc(event.process)} if event.process else None,
                    **common)
    else:
        host = event.primary_host
        device = {"hostname": host} if host else None
        user = event.user
        if raw.get("TargetImage"):  # process access, e.g. a handle opened on lsass
            out = _base(1007, 1, 3, "Open", event.timestamp, severity, version, uid,
                        process=_proc(None, raw.get("TargetImage")),
                        actor={"process": _proc(event.process, raw.get("SourceImage") or raw.get("Image"), event.command_line),
                               "user": _user(user)},
                        device=device, **common)
            if raw.get("GrantedAccess"):
                out["unmapped"]["granted_access"] = raw["GrantedAccess"]
        elif raw.get("TargetFilename") or (str(code) == "11" and event.file_name):
            out = _base(1001, 1, 1, "Create", event.timestamp, severity, version, uid,
                        file={"name": event.file_name, "path": raw.get("TargetFilename") or event.file_name},
                        actor={"process": _proc(event.process, raw.get("Image"), event.command_line,
                                                _proc(event.parent_process, raw.get("ParentImage"))),
                               "user": _user(user)},
                        device=device, **common)
        else:
            out = _base(1007, 1, 1, "Launch", event.timestamp, severity, version, uid,
                        process=_proc(event.process, raw.get("Image"), event.command_line,
                                      _proc(event.parent_process, raw.get("ParentImage")), user),
                        actor={"user": _user(user)},
                        device=device, **common)
    if code:
        out["metadata"]["event_code"] = str(code)
    if event.source_log:
        out["metadata"]["log_name"] = event.source_log
    return out


def chain_to_finding(chain: AttackChain, version: str = "", activity_id: int = 1) -> dict[str, Any]:
    """An attack chain as an OCSF Detection Finding (2004)."""
    seen: set[tuple[str, str]] = set()
    attacks = []
    for mapping in chain.mitre:
        key = (mapping.tactic_id, mapping.technique_id)
        if key in seen:
            continue
        seen.add(key)
        attacks.append({
            "tactic": {"uid": mapping.tactic_id, "name": mapping.tactic},
            "technique": {"uid": mapping.technique_id, "name": mapping.technique_name},
        })
    root = getattr(chain, "root_cause", None)
    confidence = str(getattr(chain.confidence, "value", chain.confidence))
    finding = _base(
        2004, 2, activity_id, "Create" if activity_id == 1 else "Update",
        datetime.now(tz=timezone.utc), chain.severity, version, chain.attack_chain_id,
        message=chain.name,
        status_id=1, status="New",
        risk_score=chain.risk_score,
        confidence_id=CONFIDENCE_ID.get(confidence),
        finding_info={
            "uid": chain.attack_chain_id,
            "title": chain.name,
            "desc": getattr(root, "summary", None) or "Correlated attack chain detected by PRISM.",
            "types": ["Attack Chain"],
            "first_seen_time": _ms(chain.start_time),
            "last_seen_time": _ms(chain.last_seen),
            "analytic": {"name": "PRISM correlation engine", "type_id": 1, "type": "Rule"},
            "attacks": attacks,
            "related_events": [{"uid": event_id} for event_id in chain.event_ids],
        },
        resources=[{"name": host, "type": "Host"} for host in chain.hosts]
        + [{"name": host, "type": "Host", "labels": ["targeted"]} for host in chain.targeted_hosts],
        unmapped={"prism": {
            "status": chain.status,
            "initial_host": chain.initial_host,
            "current_host": chain.current_host,
            "current_stage": chain.current_stage,
            "users": list(chain.users),
            "lateral_movements": [
                {"from": m.source_host, "to": m.destination_host, "method": m.method, "assurance": "inferred"}
                for m in chain.lateral_movements
            ],
            "predicted_next_targets": [
                {"host": p.host, "score": p.score, "assurance": "predicted"} for p in chain.predictions
            ],
        }},
    )
    return finding


# --------------------------------------------------------------------------- #
# import: OCSF -> NormalizedEvent
# --------------------------------------------------------------------------- #

SUPPORTED_CLASSES = {1001, 1007, 3002, 3003, 4003}


def is_ocsf(record: LogRecord) -> bool:
    return "class_uid" in record and isinstance(record.get("metadata"), dict)


def _get(record: dict, dotted: str) -> Any:
    current: Any = record
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _iso(record: dict) -> str:
    value = record.get("time")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    if value:
        return str(value)
    raise ParseError("OCSF event has no time")


def _path(process: Any) -> str | None:
    if not isinstance(process, dict):
        return None
    return _get(process, "file.path") or process.get("name")


def parse_ocsf(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    class_uid = int(record.get("class_uid") or 0)
    if class_uid == 2004:
        raise ParseError("OCSF Detection Findings are PRISM output, not input events")
    if class_uid not in SUPPORTED_CLASSES:
        raise ParseError("OCSF class {} is not one PRISM reads".format(class_uid))

    # OCSF written by PRISM carries the exact original event.
    prism = _get(record, "unmapped.prism")
    if isinstance(prism, dict) and prism.get("event_id"):
        restored = dict(prism)
        raw = record.get("raw_data")
        try:
            restored["raw"] = json.loads(raw) if isinstance(raw, str) else {}
        except json.JSONDecodeError:
            restored["raw"] = {}
        restored.setdefault("source_log", ctx.source_log)
        return NormalizedEvent.model_validate(restored)

    # OCSF from other tools: translate into native records so PRISM's own
    # detection rules decide what is suspicious, exactly as for Windows/Sysmon/Zeek.
    when = _iso(record)
    uid = _get(record, "metadata.uid")
    activity = int(record.get("activity_id") or 0)
    host = _get(record, "device.hostname")

    if class_uid == 3002:
        failed = int(record.get("status_id") or 1) == 2
        native = {
            "EventID": _get(record, "metadata.event_code") or ("4625" if failed else "4624"),
            "TimeCreated": when,
            "Computer": _get(record, "dst_endpoint.hostname") or host,
            "WorkstationName": _get(record, "src_endpoint.hostname"),
            "IpAddress": _get(record, "src_endpoint.ip"),
            "DestinationIp": _get(record, "dst_endpoint.ip"),
            "TargetUserName": _get(record, "user.name"),
            "LogonType": str(record.get("logon_type_id")) if record.get("logon_type_id") else None,
            "ShareName": _get(record, "unmapped.share_name"),
            "RecordId": uid,
        }
        return parse_windows_security({k: v for k, v in native.items() if v}, ctx)

    if class_uid == 3003:
        native = {"EventID": "4672", "TimeCreated": when, "Computer": host or _get(record, "dst_endpoint.hostname"),
                  "SubjectUserName": _get(record, "user.name"), "TargetUserName": _get(record, "user.name"), "RecordId": uid}
        return parse_windows_security({k: v for k, v in native.items() if v}, ctx)

    if class_uid == 4003:
        native = {"ts": when, "query": _get(record, "query.hostname"), "qtype_name": _get(record, "query.type"),
                  "id.orig_h": _get(record, "src_endpoint.ip"), "id.resp_h": _get(record, "dst_endpoint.ip"),
                  "host": _get(record, "src_endpoint.hostname") if not _get(record, "src_endpoint.ip") else None,
                  "process": _get(record, "actor.process.name"), "uid": uid}
        return parse_zeek_dns({k: v for k, v in native.items() if v}, ctx)

    user = _get(record, "actor.user.name") or _get(record, "process.user.name")
    if class_uid == 1007 and activity == 3:  # Open: a process opened another (credential theft)
        native = {"EventID": "10", "UtcTime": when, "Computer": host, "User": user,
                  "SourceImage": _path(_get(record, "actor.process")), "Image": _path(_get(record, "actor.process")),
                  "TargetImage": _path(record.get("process")), "GrantedAccess": _get(record, "unmapped.granted_access"),
                  "CommandLine": _get(record, "actor.process.cmd_line"), "RecordId": uid}
    elif class_uid == 1001:
        actor = _get(record, "actor.process")
        native = {"EventID": "11", "UtcTime": when, "Computer": host, "User": user,
                  "TargetFilename": _get(record, "file.path") or _get(record, "file.name"),
                  "Image": _path(actor), "ParentImage": _path(_get(record, "actor.process.parent_process")),
                  "RecordId": uid}
    else:  # 1007 Launch (and other process activity)
        process = record.get("process") or {}
        native = {"EventID": "1", "UtcTime": when, "Computer": host, "User": user or _get(record, "process.user.name"),
                  "Image": _path(process), "CommandLine": process.get("cmd_line") if isinstance(process, dict) else None,
                  "ParentImage": _path(_get(record, "process.parent_process")), "RecordId": uid}
    return parse_sysmon({k: v for k, v in native.items() if v}, ctx)
