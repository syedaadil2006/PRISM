"""More log sources: firewalls (CEF), Linux auditd, AWS CloudTrail, Microsoft Entra ID / 365 sign-ins.

Each parser maps the source onto PRISM's normalized event and, like the
built-in parsers, attaches plain-language findings when something stands out:

* **CEF** (ArcSight Common Event Format, written by Palo Alto, Fortinet, Check
  Point, Cisco and most firewalls/proxies): connections allowed or blocked,
  ``network`` events. Accepts ``{"message": "CEF:0|..."}`` or the raw line.
* **Linux auditd**: ``EXECVE``/``SYSCALL`` become process events (with the full
  command line rebuilt from ``a0..aN``), ``USER_LOGIN``/``USER_AUTH`` become
  sign-ins. Accepts JSON key/values or the raw ``type=... msg=audit(...)`` line.
* **AWS CloudTrail** records: console sign-ins and role assumptions are sign-ins;
  other API calls are ``cloud`` events, with changes that weaken security
  (logging stopped, keys created, admin policies attached, buckets made public)
  flagged.
* **Microsoft Entra ID (Azure AD) / Microsoft 365 sign-in logs** (Graph
  ``signIns`` or the Azure Monitor export): sign-ins with failure reasons,
  location and Microsoft's risk level.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from app.ingest import indicators
from app.ingest.parsers import LogRecord, ParseContext, ParseError, _clean_user, _parse_timestamp
from app.models.events import Action, EventType, NormalizedEvent, Severity

# -------------------------------------------------------------------- CEF --

CEF_HEADER = re.compile(r"CEF:(\d+)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|"
                        r"((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|((?:[^|\\]|\\.)*)\|(.*)$")
CEF_EXT = re.compile(r"(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|\s*$)")
BLOCK_WORDS = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "reset-both", "reset"}
LATERAL_PORTS = {"445": "SMB", "3389": "RDP", "5985": "WinRM", "5986": "WinRM", "135": "RPC", "22": "SSH"}


def _is_private(ip: str | None) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def parse_cef_line(line: str) -> dict[str, Any]:
    start = line.find("CEF:")
    match = CEF_HEADER.match(line[start:]) if start >= 0 else None
    if not match:
        raise ParseError("not a CEF line")
    version, vendor, product, dev_version, signature, name, severity, extension = match.groups()
    record: dict[str, Any] = {"cef_version": version, "deviceVendor": vendor, "deviceProduct": product,
                              "deviceVersion": dev_version, "signatureId": signature, "name": name,
                              "cef_severity": severity}
    for key, value in CEF_EXT.findall(extension):
        record[key] = value.replace("\\=", "=").replace("\\\\", "\\").strip()
    return record


def parse_cef(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    fields = dict(record)
    line = record.get("message") or record.get("raw") or record.get("_raw")
    if isinstance(line, str) and "CEF:" in line:
        fields = {**parse_cef_line(line), **{k: v for k, v in record.items() if k not in {"message", "raw", "_raw"}}}
    when = fields.get("rt") or fields.get("end") or fields.get("start") or fields.get("timestamp") or fields.get("@timestamp")
    if isinstance(when, str) and when.isdigit():
        when = int(when) / 1000  # CEF rt is milliseconds since 1970
    timestamp = _parse_timestamp(when)
    src, dst = fields.get("src"), fields.get("dst")
    port = str(fields.get("dpt") or "")
    act = str(fields.get("act") or fields.get("outcome") or fields.get("deviceAction") or "").lower()
    blocked = act in BLOCK_WORDS or any(w in act.split() for w in BLOCK_WORDS)
    findings: list[str] = []
    severity, suspicious = Severity.INFO, False
    if blocked and src and dst and _is_private(src) and not _is_private(dst):
        findings.append(f"outbound connection from {src} to {dst}:{port or '?'} was blocked by the firewall")
        severity = Severity.LOW
    service = LATERAL_PORTS.get(port)
    if service and _is_private(src) and _is_private(dst) and not blocked and port != "22":
        findings.append(f"{service} connection between internal hosts {src} -> {dst}")
    tags = ["network", "cef", f"vendor:{str(fields.get('deviceVendor') or 'unknown').lower()}"]
    return NormalizedEvent(
        event_id=str(fields.get("externalId") or fields.get("eventId") or f"cef-{timestamp.timestamp():.3f}-{src}-{dst}-{port}"),
        timestamp=timestamp,
        event_type=EventType.NETWORK,
        action=Action.CONNECTION_BLOCKED if blocked else Action.NETWORK_CONNECTION,
        user=_clean_user(fields.get("suser") or fields.get("duser")),
        source_host=ctx.ip_to_host.get(src) if src else None,
        destination_host=(ctx.ip_to_host.get(dst) if dst else None) or fields.get("dhost"),
        source_ip=src,
        destination_ip=dst,
        domain=fields.get("dhost") if fields.get("dhost") and not ctx.ip_to_host.get(dst or "") else None,
        outcome="failure" if blocked else "success",
        severity=severity,
        suspicious=suspicious,
        tags=tags + ["finding:" + f for f in findings],
        source_log=ctx.source_log,
        raw=dict(record),
    )


def is_cef(record: LogRecord) -> bool:
    for key in ("message", "raw", "_raw"):
        value = record.get(key)
        if isinstance(value, str) and "CEF:" in value[:200]:
            return True
    return {"devicevendor", "deviceproduct"} <= {str(k).lower() for k in record}


# ----------------------------------------------------------------- auditd --

AUDIT_TYPES = {"EXECVE", "SYSCALL", "USER_LOGIN", "USER_AUTH", "USER_START", "USER_CMD", "CRED_ACQ", "USER_ACCT",
               "ADD_USER", "ADD_GROUP", "USER_CHAUTHTOK"}
AUDIT_MSG = re.compile(r"audit\((\d+(?:\.\d+)?):(\d+)\)")


def parse_audit_line(line: str) -> dict[str, Any]:
    """``type=EXECVE msg=audit(1690000000.123:456): argc=2 a0="ls" a1=2D6C`` -> dict."""
    record: dict[str, Any] = {}
    for key, value in re.findall(r"(\w+)=(\"[^\"]*\"|'[^']*'|[^\s']+)", line):
        if value.startswith("'"):  # user-space records nest their fields: msg='op=login acct="x" res=success'
            for inner_key, inner_value in re.findall(r"(\w+)=(\"[^\"]*\"|[^\s]+)", value.strip("'")):
                record.setdefault(inner_key, inner_value.strip('"'))
        else:
            record.setdefault(key, value.strip('"'))
    if "type" not in record:
        raise ParseError("not an auditd line")
    msg = AUDIT_MSG.search(line)
    if msg:
        record["msg"] = msg.group(0)
    return record


def _audit_hex(value: Any) -> str:
    text = str(value or "")
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", text) and len(text) >= 4:
        try:
            return bytes.fromhex(text).decode("utf-8", "replace").replace("\x00", " ")
        except ValueError:
            return text
    return text


def parse_auditd(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    fields = dict(record)
    line = record.get("message") or record.get("raw")
    if isinstance(line, str) and "type=" in line:
        fields = {**parse_audit_line(line), **{k: v for k, v in record.items() if k not in {"message", "raw"}}}
    kind = str(fields.get("type", "")).upper()
    msg = AUDIT_MSG.search(str(fields.get("msg") or ""))
    when = fields.get("timestamp") or fields.get("@timestamp") or (float(msg.group(1)) if msg else None)
    timestamp = _parse_timestamp(when)
    host = str(fields.get("node") or fields.get("hostname") or fields.get("host") or "").upper() or None
    if host in {"?", "(NONE)"}:
        host = None
    serial = msg.group(2) if msg else f"{timestamp.timestamp():.3f}"
    user = _clean_user(fields.get("acct") or fields.get("AUID") or fields.get("UID") or fields.get("user")
                       or fields.get("auid_name"))
    findings: list[str] = []
    tags = ["auditd", "auditd:" + kind.lower(), "linux"]
    common = dict(timestamp=timestamp, user=user, source_log=ctx.source_log, raw=dict(record))

    if kind in {"EXECVE", "SYSCALL", "USER_CMD"}:
        args = [_audit_hex(fields[f"a{i}"]) for i in range(int(fields.get("argc") or 0) or 64) if f"a{i}" in fields]
        command = " ".join(args) or _audit_hex(fields.get("cmd")) or str(fields.get("exe") or "")
        exe = str(fields.get("exe") or (args[0] if args else "") or "").strip('"')
        process = exe.rsplit("/", 1)[-1] or None
        findings += indicators.process_findings(process, command, None)
        lowered = command.lower()
        reverse_shell = any(s in lowered for s in ("/dev/tcp/", "nc -e", "bash -i", "mkfifo /tmp"))
        if reverse_shell:
            findings.append("reverse shell pattern in command line")
        suspicious = bool(findings)
        return NormalizedEvent(
            event_id=f"auditd-{host or 'linux'}-{serial}-{kind.lower()}",
            event_type=EventType.ENDPOINT,
            action=Action.COMMAND_EXEC if suspicious else Action.PROCESS_CREATE,
            source_host=host, destination_host=host, process=process, command_line=command or None,
            severity=Severity.HIGH if reverse_shell else (Severity.MEDIUM if suspicious else Severity.INFO),
            suspicious=suspicious, tags=tags + ["finding:" + f for f in findings], **common)

    if kind in {"ADD_USER", "ADD_GROUP", "USER_CHAUTHTOK"}:
        return NormalizedEvent(
            event_id=f"auditd-{host or 'linux'}-{serial}-{kind.lower()}",
            event_type=EventType.ENDPOINT, action=Action.COMMAND_EXEC, source_host=host, destination_host=host,
            process=str(fields.get("exe") or "").rsplit("/", 1)[-1] or None,
            severity=Severity.MEDIUM, suspicious=True,
            tags=tags + [f"finding:account change on Linux host: {kind}"], **common)

    if kind in AUDIT_TYPES:
        addr = str(fields.get("addr") or "")
        remote = addr not in {"", "?", "127.0.0.1", "::1"}
        success = str(fields.get("res") or "").lower() in {"success", "yes", "1"}
        action = Action.LOGIN_SUCCESS if success else Action.LOGIN_FAILURE
        if success and remote:
            action = Action.NETWORK_LOGON
        return NormalizedEvent(
            event_id=f"auditd-{host or 'linux'}-{serial}-{kind.lower()}",
            event_type=EventType.AUTHENTICATION, action=action,
            source_host=ctx.ip_to_host.get(addr) if remote else host, destination_host=host,
            source_ip=addr if remote else None, logon_type="ssh" if remote else "local",
            outcome="success" if success else "failure",
            severity=Severity.LOW if success else Severity.INFO, tags=tags, **common)
    raise ParseError(f"auditd record type {kind or '?'} is not used by PRISM")


def is_auditd(record: LogRecord) -> bool:
    line = record.get("message") or record.get("raw")
    if isinstance(line, str) and line.startswith("type=") and "audit(" in line:
        return True
    return str(record.get("type", "")).upper() in AUDIT_TYPES and ("msg" in record or "auid" in record)


# ------------------------------------------------------------- CloudTrail --

RISKY_CLOUD_CALLS: dict[str, tuple[str, Severity]] = {
    "StopLogging": ("CloudTrail logging was stopped", Severity.CRITICAL),
    "DeleteTrail": ("a CloudTrail trail was deleted", Severity.CRITICAL),
    "UpdateTrail": ("a CloudTrail trail was changed", Severity.MEDIUM),
    "PutEventSelectors": ("CloudTrail event selection was changed", Severity.MEDIUM),
    "DeleteFlowLogs": ("VPC flow logs were deleted", Severity.HIGH),
    "DisableGuardDuty": ("GuardDuty was disabled", Severity.CRITICAL),
    "DeleteDetector": ("a GuardDuty detector was deleted", Severity.CRITICAL),
    "CreateAccessKey": ("a new access key was created", Severity.HIGH),
    "CreateLoginProfile": ("a console password was set for an IAM user", Severity.HIGH),
    "UpdateLoginProfile": ("an IAM user's console password was changed", Severity.MEDIUM),
    "CreateUser": ("an IAM user was created", Severity.MEDIUM),
    "AttachUserPolicy": ("a policy was attached to an IAM user", Severity.MEDIUM),
    "AttachRolePolicy": ("a policy was attached to a role", Severity.MEDIUM),
    "PutUserPolicy": ("an inline policy was added to an IAM user", Severity.MEDIUM),
    "AddUserToGroup": ("an IAM user was added to a group", Severity.MEDIUM),
    "PutBucketPolicy": ("an S3 bucket policy was changed", Severity.MEDIUM),
    "PutBucketAcl": ("an S3 bucket ACL was changed", Severity.MEDIUM),
    "DeleteBucketEncryption": ("S3 bucket encryption was removed", Severity.HIGH),
    "AuthorizeSecurityGroupIngress": ("a security group was opened for inbound traffic", Severity.MEDIUM),
}
LOGGING_CALLS = {"StopLogging", "DeleteTrail", "DeleteFlowLogs", "DisableGuardDuty", "DeleteDetector"}


def parse_cloudtrail(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    name = str(record.get("eventName") or "")
    identity = record.get("userIdentity") or {}
    user = (identity.get("userName") or (identity.get("sessionContext", {}).get("sessionIssuer", {}) or {}).get("userName")
            or str(identity.get("arn") or "").rsplit("/", 1)[-1] or identity.get("type"))
    account = str(record.get("recipientAccountId") or identity.get("accountId") or "aws")
    source_ip = record.get("sourceIPAddress")
    if source_ip and not re.fullmatch(r"[0-9a-fA-F:.]+", str(source_ip)):
        source_ip = None  # an AWS service name such as "ec2.amazonaws.com"
    error = record.get("errorCode")
    response = record.get("responseElements") or {}
    target = f"AWS-{account}"
    findings: list[str] = []
    tags = ["cloud", "aws", "cloudtrail", "aws:" + str(record.get("eventSource") or "").split(".")[0]]
    common = dict(timestamp=_parse_timestamp(record.get("eventTime")), user=_clean_user(user),
                  destination_host=target, source_ip=source_ip, source_log=ctx.source_log, raw=dict(record))
    event_id = "aws-" + str(record.get("eventID") or f"{name}-{record.get('eventTime')}")

    if name == "ConsoleLogin":
        failed = (isinstance(response, dict) and response.get("ConsoleLogin") == "Failure") or bool(error)
        mfa = str((record.get("additionalEventData") or {}).get("MFAUsed", "")).lower()
        if not failed and mfa == "no":
            findings.append("console sign-in without MFA")
        if identity.get("type") == "Root":
            findings.append("sign-in as the AWS root user")
        return NormalizedEvent(
            event_id=event_id, event_type=EventType.AUTHENTICATION,
            action=Action.LOGIN_FAILURE if failed else Action.LOGIN_SUCCESS,
            logon_type="cloud-console", outcome="failure" if failed else "success",
            severity=Severity.MEDIUM if findings else Severity.LOW, suspicious=identity.get("type") == "Root",
            tags=tags + ["finding:" + f for f in findings], **common)

    risky = RISKY_CLOUD_CALLS.get(name)
    params = str(record.get("requestParameters") or "")
    if name in {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"} and "AdministratorAccess" in params:
        risky = ("the AdministratorAccess policy was attached", Severity.HIGH)
    if name in {"PutBucketPolicy", "PutBucketAcl"} and ('"*"' in params or "AllUsers" in params or "'*'" in params):
        risky = ("an S3 bucket was made public", Severity.HIGH)
    action = Action.CLOUD_API_CALL
    severity, suspicious = Severity.INFO, False
    if risky and not error:
        text, severity = risky
        findings.append(f"{text} by {user or 'unknown identity'}")
        action = Action.CLOUD_LOGGING_DISABLED if name in LOGGING_CALLS else Action.CLOUD_PRIVILEGE_CHANGE
        suspicious = severity.rank >= Severity.HIGH.rank
    elif error in {"AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"}:
        findings.append(f"{name} was denied ({error})")
        severity = Severity.LOW
    return NormalizedEvent(
        event_id=event_id, event_type=EventType.CLOUD, action=action,
        process=name or None, outcome="failure" if error else "success",
        severity=severity, suspicious=suspicious, tags=tags + ["finding:" + f for f in findings], **common)


def is_cloudtrail(record: LogRecord) -> bool:
    keys = {str(k).lower() for k in record}
    return {"eventname", "eventsource"} <= keys and ("awsregion" in keys or "useridentity" in keys)


# ------------------------------------------------------------- Entra / 365 --

def parse_entra_signin(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    props = record.get("properties") if isinstance(record.get("properties"), dict) else record
    status = props.get("status") or {}
    code = status.get("errorCode", props.get("resultType", 0))
    failed = str(code) not in {"0", ""}
    location = props.get("location") or {}
    place = ", ".join(str(v) for v in (location.get("city"), location.get("countryOrRegion")) if v)
    risk = str(props.get("riskLevelDuringSignIn") or props.get("riskLevelAggregated") or "none").lower()
    app = str(props.get("appDisplayName") or props.get("resourceDisplayName") or "Microsoft 365")
    findings: list[str] = []
    if failed:
        reason = status.get("failureReason") or props.get("resultDescription") or f"error {code}"
        findings.append(f"sign-in to {app} failed: {reason}")
    if risk in {"medium", "high"}:
        findings.append(f"Microsoft rated this sign-in {risk} risk")
    if str(props.get("isInteractive", "true")).lower() == "true" and props.get("clientAppUsed") in {
            "Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP", "Other clients"}:
        findings.append(f"legacy authentication protocol used ({props.get('clientAppUsed')})")
    user = props.get("userPrincipalName") or props.get("userDisplayName")
    return NormalizedEvent(
        event_id="entra-" + str(props.get("id") or record.get("correlationId") or f"{user}-{props.get('createdDateTime')}"),
        timestamp=_parse_timestamp(props.get("createdDateTime") or record.get("time")),
        event_type=EventType.AUTHENTICATION,
        action=Action.LOGIN_FAILURE if failed else Action.LOGIN_SUCCESS,
        user=_clean_user(str(user).split("@")[0]) if user else None,
        destination_host="M365-" + re.sub(r"[^A-Za-z0-9]+", "-", app).strip("-").upper()[:30],
        source_ip=props.get("ipAddress"),
        logon_type="cloud",
        outcome="failure" if failed else "success",
        severity=Severity.HIGH if risk == "high" else (Severity.MEDIUM if risk == "medium" or len(findings) > 1 else Severity.LOW),
        suspicious=risk == "high",
        tags=["cloud", "entra", "m365"] + (["location:" + place] if place else []) + ["finding:" + f for f in findings],
        source_log=ctx.source_log,
        raw=dict(record),
    )


def is_entra_signin(record: LogRecord) -> bool:
    props = record.get("properties") if isinstance(record.get("properties"), dict) else record
    keys = {str(k).lower() for k in props}
    return "userprincipalname" in keys and ("appdisplayname" in keys or "createddatetime" in keys)


def register(parsers: dict, detectors: list) -> None:
    parsers.update({"cef": parse_cef, "auditd": parse_auditd, "cloudtrail": parse_cloudtrail,
                    "entra_signin": parse_entra_signin})
    detectors.extend([("cloudtrail", is_cloudtrail), ("entra_signin", is_entra_signin),
                      ("cef", is_cef), ("auditd", is_auditd)])
