"""Log parsers: vendor formats in, NormalizedEvent out.

Adding a new log source means writing one parser and registering it. Nothing
downstream of this module knows about vendor field names.

Supported formats
-----------------
``windows_security``
    Windows Security channel records (event IDs 4624/4625/4648/4672/5140/7045),
    as CSV or JSON. This is the shape produced by wevtutil/Winlogbeat and by the
    Security-Datasets (Mordor) Windows host datasets.
``sysmon``
    Sysmon records (event IDs 1/10/11), as JSON.
``zeek_dns``
    Zeek dns.log records, as JSON lines or a JSON array.
``prism``
    Already-normalized PRISM events, for replay and round-tripping.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from dateutil import parser as date_parser

from app.ingest import indicators
from app.models.events import Action, EventType, NormalizedEvent, Severity

LogRecord = dict[str, Any]


class ParseError(ValueError):
    """Raised when a record cannot be turned into a NormalizedEvent."""


@dataclass
class ParseContext:
    """Environment knowledge that helps parsers resolve identifiers."""

    ip_to_host: dict[str, str] = field(default_factory=dict)
    known_domains: set[str] = field(default_factory=set)
    source_log: str = "unknown"
    #: Monotonic counter used to mint stable ids when logs lack them.
    counter: dict[str, int] = field(default_factory=lambda: {"n": 0})

    def next_id(self, prefix: str = "evt") -> str:
        self.counter["n"] += 1
        return "{}-{:05d}".format(prefix, self.counter["n"])

    def resolve_host(self, ip: str | None) -> str | None:
        if not ip:
            return None
        return self.ip_to_host.get(ip)


def _get(record: LogRecord, *names: str) -> Any:
    """Fetch the first present, non-empty key from a record (case tolerant)."""
    lowered = {str(k).lower(): v for k, v in record.items()}
    for name in names:
        if name in record and record[name] not in (None, "", "-"):
            return record[name]
        value = lowered.get(name.lower())
        if value not in (None, "", "-"):
            return value
    return None


def _parse_timestamp(value: Any) -> datetime:
    if value is None:
        raise ParseError("record has no timestamp")
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    else:
        text = str(value).strip()
        try:
            dt = date_parser.isoparse(text)
        except ValueError:
            try:
                dt = datetime.fromtimestamp(float(text), tz=timezone.utc)
            except ValueError:
                dt = date_parser.parse(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _clean_host(value: Any) -> str | None:
    """Normalise a hostname; returns None for IPs and placeholder values."""
    if value in (None, "", "-"):
        return None
    text = str(value).strip().rstrip("$")
    if not text or text in {"-", "::1", "127.0.0.1"}:
        return None
    try:
        ipaddress.ip_address(text)
        return None
    except ValueError:
        pass
    return text.split(".")[0].upper()


def _clean_ip(value: Any) -> str | None:
    if value in (None, "", "-"):
        return None
    text = str(value).strip()
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


def _clean_user(value: Any) -> str | None:
    """Strip domain prefixes and drop machine/service accounts."""
    if value in (None, "", "-"):
        return None
    text = str(value).strip()
    if text.endswith("$"):
        return None
    if text.upper() in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}:
        return None
    if "\\" in text:
        text = text.split("\\")[-1]
    if "@" in text:
        text = text.split("@")[0]
    return text.lower()


def _basename(path: Any) -> str | None:
    if path in (None, "", "-"):
        return None
    text = str(path).replace("/", "\\")
    return text.split("\\")[-1]


#: Windows logon types mapped onto canonical actions.
_LOGON_TYPE_ACTION = {
    "2": Action.LOGIN_SUCCESS,   # interactive
    "3": Action.NETWORK_LOGON,   # network (SMB and friends)
    "4": Action.LOGIN_SUCCESS,   # batch
    "5": Action.LOGIN_SUCCESS,   # service
    "7": Action.LOGIN_SUCCESS,   # unlock
    "8": Action.NETWORK_LOGON,   # network cleartext
    "9": Action.LOGIN_SUCCESS,   # new credentials
    "10": Action.RDP_LOGIN,      # remote interactive (RDP)
    "11": Action.LOGIN_SUCCESS,  # cached interactive
}

_LOGON_TYPE_LABEL = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


def parse_windows_security(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    """Normalize a Windows Security channel record."""
    code = str(_get(record, "EventID", "event_id") or "").strip()
    timestamp = _parse_timestamp(_get(record, "TimeCreated", "timestamp", "@timestamp", "UtcTime"))

    destination_host = _clean_host(_get(record, "Computer", "ComputerName", "destination_host"))
    source_host = _clean_host(_get(record, "WorkstationName", "SourceWorkstation", "source_host"))
    source_ip = _clean_ip(_get(record, "IpAddress", "SourceIp", "source_ip"))
    destination_ip = _clean_ip(_get(record, "DestinationIp", "destination_ip"))
    user = _clean_user(_get(record, "TargetUserName", "SubjectUserName", "user"))
    logon_type = str(_get(record, "LogonType", "logon_type") or "").strip() or None
    share = _get(record, "ShareName", "RelativeTargetName")
    process = _basename(_get(record, "ProcessName", "process"))
    service_file = _basename(_get(record, "ServiceFileName", "ImagePath"))

    if source_host is None and source_ip:
        source_host = ctx.resolve_host(source_ip)

    tags: list[str] = ["win:" + code] if code else []
    severity = Severity.INFO
    suspicious = False
    outcome = "success"

    if code == "4625":
        action = Action.LOGIN_FAILURE
        outcome = "failure"
        severity = Severity.LOW
        tags.append("failed-logon")
    elif code == "4672":
        action = Action.PRIVILEGED_LOGIN
        severity = Severity.MEDIUM
        tags.append("privileged")
    elif code == "5140":
        action = Action.SMB_AUTH
        severity = Severity.LOW
        tags.append("smb-share")
    elif code == "7045":
        action = Action.REMOTE_SERVICE_EXEC
        severity = Severity.HIGH
        suspicious = True
        tags.append("service-install")
        process = process or service_file
    elif code == "4648":
        action = Action.NETWORK_LOGON
        severity = Severity.LOW
        tags.append("explicit-credentials")
    else:
        # 4624 and anything else describing a successful logon.
        action = _LOGON_TYPE_ACTION.get(logon_type or "", Action.LOGIN_SUCCESS)
        if action is Action.RDP_LOGIN:
            severity = Severity.MEDIUM
            tags.append("rdp")
        elif action is Action.NETWORK_LOGON and share:
            action = Action.SMB_AUTH
            tags.append("smb-share")

    if action is Action.SMB_AUTH and share and "ADMIN$" in str(share).upper():
        suspicious = True
        severity = Severity.HIGH
        tags.append("admin-share")

    if (
        source_host
        and destination_host
        and source_host != destination_host
        and action in {Action.RDP_LOGIN, Action.SMB_AUTH, Action.NETWORK_LOGON}
    ):
        tags.append("remote-origin")

    return NormalizedEvent(
        event_id=str(_get(record, "RecordId", "record_id") or ctx.next_id("auth")),
        timestamp=timestamp,
        event_type=EventType.AUTHENTICATION,
        action=action,
        user=user,
        source_host=source_host,
        destination_host=destination_host,
        source_ip=source_ip,
        destination_ip=destination_ip,
        process=process,
        logon_type=_LOGON_TYPE_LABEL.get(logon_type or "", logon_type),
        outcome=outcome,
        severity=severity,
        suspicious=suspicious,
        tags=tags,
        source_log=ctx.source_log,
        raw=dict(record),
    )


def parse_sysmon(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    """Normalize a Sysmon record (process create / process access / file create)."""
    code = str(_get(record, "EventID", "event_id") or "1").strip()
    timestamp = _parse_timestamp(_get(record, "UtcTime", "TimeCreated", "timestamp", "@timestamp"))
    host = _clean_host(_get(record, "Computer", "ComputerName", "source_host"))
    user = _clean_user(_get(record, "User", "user", "SubjectUserName"))
    image = _basename(_get(record, "Image", "SourceImage", "process"))
    parent = _basename(_get(record, "ParentImage", "parent_process"))
    command_line = _get(record, "CommandLine", "command_line")
    target_file = _basename(_get(record, "TargetFilename", "file_name"))
    target_image = _basename(_get(record, "TargetImage"))
    granted_access = _get(record, "GrantedAccess")

    findings = indicators.process_findings(image, command_line, parent)
    tags: list[str] = ["sysmon:" + code]
    severity = Severity.INFO
    suspicious = bool(findings)

    if code == "10":
        # ProcessAccess: a handle was opened against another process.
        action = Action.CREDENTIAL_ACCESS
        severity = Severity.CRITICAL
        suspicious = True
        tags.append("process-access")
        if target_image:
            findings.append((image or "process") + " opened a handle to " + target_image)
        if granted_access:
            findings.append("GrantedAccess=" + str(granted_access))
    elif code == "11":
        is_bad_file = bool(target_file) and any(
            str(target_file).lower().endswith(ext)
            for ext in indicators.MALICIOUS_ATTACHMENT_EXTENSIONS
        )
        written_by_mail_or_office = bool(parent or image) and any(
            office in (image or "").lower() or office in (parent or "").lower()
            for office in indicators.OFFICE_PROCESSES
        )
        if not is_bad_file:
            action = Action.PROCESS_CREATE
        elif written_by_mail_or_office:
            action = Action.MALICIOUS_ATTACHMENT
        else:
            action = Action.SUSPICIOUS_EXECUTABLE
        tags.append("file-create")
        if is_bad_file:
            severity = Severity.HIGH
            suspicious = True
            findings.append("Suspicious file " + str(target_file) + " written to disk")
    elif indicators.is_credential_activity(image, command_line):
        action = Action.CREDENTIAL_ACCESS
        severity = Severity.CRITICAL
        suspicious = True
    elif indicators.is_remote_exec(image, command_line):
        action = Action.REMOTE_SERVICE_EXEC
        severity = Severity.HIGH
        suspicious = True
    elif image and image.lower() in {"powershell.exe", "pwsh.exe"}:
        action = Action.POWERSHELL_EXEC
        severity = Severity.HIGH if findings else Severity.MEDIUM
        suspicious = suspicious or bool(findings)
    elif image and image.lower() in {"wscript.exe", "cscript.exe", "mshta.exe"}:
        action = Action.SCRIPT_EXEC
        severity = Severity.HIGH
        suspicious = True
    elif image and findings and any(
        office in image.lower() for office in indicators.OFFICE_PROCESSES
    ):
        # An Office process opening a document that itself looks malicious.
        action = Action.MALICIOUS_ATTACHMENT
        severity = Severity.HIGH
        suspicious = True
    elif parent and any(office in parent.lower() for office in indicators.OFFICE_PROCESSES):
        action = Action.MALICIOUS_ATTACHMENT
        severity = Severity.HIGH
        suspicious = True
    elif indicators.is_discovery_command(command_line):
        # Enumeration is not malicious on its own, but it is worth correlating.
        action = Action.DISCOVERY_COMMAND
        severity = Severity.MEDIUM
        findings.extend(indicators.discovery_findings(command_line))
        tags.append("discovery")
    elif image and image.lower() == "cmd.exe":
        action = Action.COMMAND_EXEC
        severity = Severity.MEDIUM if findings else Severity.LOW
    elif findings:
        action = Action.SUSPICIOUS_EXECUTABLE
        severity = Severity.HIGH
    else:
        action = Action.PROCESS_CREATE
        severity = Severity.INFO

    if suspicious:
        tags.append("suspicious-process")

    return NormalizedEvent(
        event_id=str(_get(record, "RecordId", "record_id") or ctx.next_id("edr")),
        timestamp=timestamp,
        event_type=EventType.ENDPOINT,
        action=action,
        user=user,
        source_host=host,
        destination_host=host,
        source_ip=_clean_ip(_get(record, "SourceIp", "source_ip")),
        destination_ip=_clean_ip(_get(record, "DestinationIp", "destination_ip")),
        process=image,
        parent_process=parent,
        command_line=str(command_line) if command_line else None,
        file_name=target_file,
        outcome="success",
        severity=severity,
        suspicious=suspicious,
        tags=tags + ["finding:" + f for f in findings],
        source_log=ctx.source_log,
        raw=dict(record),
    )


def parse_zeek_dns(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    """Normalize a Zeek dns.log record."""
    timestamp = _parse_timestamp(_get(record, "ts", "timestamp", "@timestamp"))
    query = _get(record, "query", "domain")
    if not query:
        raise ParseError("DNS record has no query")
    domain = str(query).strip().rstrip(".").lower()

    source_ip = _clean_ip(_get(record, "id.orig_h", "id_orig_h", "src_ip", "source_ip"))
    destination_ip = _clean_ip(_get(record, "id.resp_h", "id_resp_h", "dst_ip", "destination_ip"))
    host = _clean_host(_get(record, "host", "source_host", "Computer")) or ctx.resolve_host(source_ip)
    process = _basename(_get(record, "process", "Image"))

    findings = indicators.domain_findings(domain)
    qtype = _get(record, "qtype_name", "qtype") or "A"
    tags = ["zeek:dns", "qtype:" + str(qtype)]

    unseen = (
        not indicators.is_internal_domain(domain)
        and bool(ctx.known_domains)
        and domain not in ctx.known_domains
        and not any(domain.endswith("." + known) for known in ctx.known_domains)
    )

    if findings:
        action = Action.SUSPICIOUS_DOMAIN
        severity = Severity.HIGH
    elif unseen:
        action = Action.NEWLY_OBSERVED_DOMAIN
        severity = Severity.MEDIUM
        findings.append(domain + " has not been observed in this environment before")
    else:
        action = Action.DNS_QUERY
        severity = Severity.INFO

    return NormalizedEvent(
        event_id=str(_get(record, "uid", "record_id") or ctx.next_id("dns")),
        timestamp=timestamp,
        event_type=EventType.DNS,
        action=action,
        user=_clean_user(_get(record, "user")),
        source_host=host,
        source_ip=source_ip,
        destination_ip=destination_ip,
        process=process,
        domain=domain,
        outcome=str(_get(record, "rcode_name") or "NOERROR"),
        severity=severity,
        suspicious=action is not Action.DNS_QUERY,
        tags=tags + ["finding:" + f for f in findings],
        source_log=ctx.source_log,
        raw=dict(record),
    )


def parse_prism(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    """Accept an already-normalized PRISM event."""
    payload = dict(record)
    payload.setdefault("event_id", ctx.next_id("evt"))
    payload.setdefault("source_log", ctx.source_log)
    payload.setdefault("raw", dict(record))
    return NormalizedEvent.model_validate(payload)


Parser = Callable[[LogRecord, ParseContext], NormalizedEvent]

PARSERS: dict[str, Parser] = {
    "windows_security": parse_windows_security,
    "sysmon": parse_sysmon,
    "zeek_dns": parse_zeek_dns,
    "prism": parse_prism,
}


def _parse_botsv1(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    # Imported lazily: the BOTS adapter builds on the parsers in this module.
    from app.ingest.bots import parse_bots

    return parse_bots(record, ctx)


PARSERS["botsv1"] = _parse_botsv1


def detect_format(record: LogRecord) -> str:
    """Best-effort format sniffing so ingestion works without a format hint."""
    keys = {str(k).lower() for k in record}
    # Splunk export lines (BOTS) are checked first: their field extractions
    # include names such as "action" that would otherwise look native.
    if isinstance(record.get("result"), dict) and "sourcetype" in record["result"]:
        return "botsv1"
    if record.get("dataset") == "botsv1" or {"sourcetype", "_time"} <= keys:
        return "botsv1"
    if {"event_type", "action"} <= keys:
        return "prism"
    if keys & {"query", "qtype_name", "id.orig_h", "id_orig_h"}:
        return "zeek_dns"
    if keys & {"image", "parentimage", "commandline", "targetfilename", "targetimage"}:
        return "sysmon"
    if keys & {"eventid", "event_id"}:
        return "windows_security"
    raise ParseError("unable to detect log format from keys: " + str(sorted(keys)))


def parse_records(
    records: Iterable[LogRecord],
    ctx: ParseContext,
    log_format: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Parse raw records, collecting per-record errors instead of aborting."""
    events: list[NormalizedEvent] = []
    errors: list[str] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append("record {}: expected an object".format(index))
            continue
        try:
            fmt = log_format or detect_format(record)
            events.append(PARSERS[fmt](record, ctx))
        except Exception as exc:  # noqa: BLE001 - reported back to the caller
            errors.append("record {}: {}".format(index, exc))
    return events, errors
