"""Adapter for Splunk's Boss of the SOC (BOTS) v1 dataset exports.

BOTSv1 is published by Splunk under CC0 at github.com/splunk/botsv1. The
json-by-sourcetype files are Splunk search exports: one
``{"preview": false, "offset": N, "result": {...}}`` object per line, with
Splunk's field extractions (``EventCode``, ``ComputerName``, ``query{}``) rather
than the raw vendor field names.

This module does one thing: rename those fields to the vendor names the
existing parsers already understand, then hand the record to that parser. It
contains no detection logic of its own, so BOTS data is judged by exactly the
same rules as any other Windows, Sysmon or DNS log.

What it does to a record, exhaustively:

* unwraps the Splunk ``result`` envelope,
* copies fields across under the vendor name the parser expects,
* converts timestamps to UTC (see ``_utc``), and
* mints a stable event id from the record's own identifiers.

It never edits a value. The original BOTS record is kept in ``raw`` so any
finding can be traced back to the exact line in Splunk's file.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.ingest.parsers import (
    LogRecord,
    ParseContext,
    ParseError,
    parse_sysmon,
    parse_windows_security,
    parse_zeek_dns,
)
from app.models.events import NormalizedEvent

#: BOTSv1 was indexed on a Splunk server in US Mountain time. Splunk's ``_time``
#: carries the suffix "MDT" (UTC-6 throughout August 2016). Verified against
#: records carrying both clocks: Sysmon ``_time`` 17:58:59 MDT has
#: ``UtcTime`` 23:58:59.
_MDT_OFFSET = timedelta(hours=-6)

SOURCETYPE_SECURITY = "WinEventLog:Security"
SOURCETYPE_SYSMON = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
SOURCETYPE_DNS = "stream:dns"

#: Recorded on every BOTS event so the UI and API can always tell real
#: dataset records apart from synthetic ones.
DATASET_TAG = "dataset:botsv1"


def is_bots_record(record: LogRecord) -> bool:
    """True for a BOTS export line or an already-unwrapped BOTS result."""
    if "result" in record and isinstance(record["result"], dict):
        return "sourcetype" in record["result"]
    return record.get("dataset") == "botsv1" or (
        "sourcetype" in record and "_time" in record
    )


def _unwrap(record: LogRecord) -> LogRecord:
    if "result" in record and isinstance(record["result"], dict):
        return record["result"]
    return record


def _first(value: Any) -> Any:
    """Splunk multivalue fields arrive as lists; take the first value."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _last(value: Any) -> Any:
    if isinstance(value, list):
        return value[-1] if value else None
    return value


def _utc(result: LogRecord) -> str:
    """Return the record's time as a UTC ISO-8601 string.

    Prefers a field that is already UTC; falls back to converting Splunk's
    Mountain-time ``_time``.
    """
    utc_time = result.get("UtcTime")
    if utc_time:
        return str(utc_time).replace(" ", "T") + "Z"

    stamp = result.get("timestamp")
    if stamp and str(stamp).endswith("Z"):
        return str(stamp)

    local = result.get("_time")
    if not local:
        raise ParseError("BOTS record has no timestamp")
    text = str(local)
    for suffix in (" MDT", " MST"):
        text = text.replace(suffix, "")
    parsed = datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
    as_utc = (parsed - _MDT_OFFSET).replace(tzinfo=timezone.utc)
    return as_utc.isoformat().replace("+00:00", "Z")


def _host(value: Any) -> str | None:
    """Short host name from an FQDN such as we8105desk.waynecorpinc.local."""
    value = _first(value)
    if not value or value in {"-", "::1", "127.0.0.1"}:
        return None
    return str(value).split(".")[0]


def _security(result: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    # Account_Name is [subject, target] on logon events; the target is the
    # account that logged on, which is the one PRISM tracks.
    accounts = result.get("Account_Name")
    domains = result.get("Account_Domain")
    target = _last(accounts)
    target_domain = _last(domains)
    account = (
        "{}\\{}".format(target_domain, target)
        if target and target_domain and target_domain != "-"
        else target
    )

    host = _host(result.get("ComputerName") or result.get("host"))
    translated = {
        "RecordId": "bots-sec-{}-{}".format(host or "unknown", result.get("RecordNumber", "")),
        "EventID": result.get("EventCode"),
        "TimeCreated": _utc(result),
        "Computer": host,
        "WorkstationName": _host(result.get("Workstation_Name")),
        "TargetUserName": account,
        "SubjectUserName": _first(accounts),
        "LogonType": result.get("Logon_Type"),
        "IpAddress": _first(result.get("Source_Network_Address")),
        "ShareName": _first(result.get("Share_Name")),
        "ProcessName": _first(result.get("Process_Name")),
        "ServiceFileName": result.get("Service_File_Name"),
    }
    event = parse_windows_security(translated, ctx)
    return _finish(event, result)


def _sysmon(result: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    host = _host(result.get("Computer") or result.get("host"))
    translated = {
        "RecordId": "bots-sysmon-{}-{}".format(host or "unknown", result.get("RecordID", "")),
        "EventID": result.get("EventCode"),
        "UtcTime": _utc(result),
        "Computer": host,
        "User": result.get("User"),
        "Image": result.get("Image"),
        "SourceImage": result.get("SourceImage"),
        "ParentImage": result.get("ParentImage"),
        "CommandLine": result.get("CommandLine"),
        "TargetFilename": result.get("TargetFilename"),
        "TargetImage": result.get("TargetImage"),
        "GrantedAccess": result.get("GrantedAccess"),
        "SourceIp": result.get("SourceIp"),
        "DestinationIp": result.get("DestinationIp"),
    }
    event = parse_sysmon(translated, ctx)
    return _finish(event, result)


def _dns(result: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    query = _first(result.get("query{}")) or result.get("query")
    if not query:
        raise ParseError("BOTS DNS record carries no query (a response-only record)")
    stamp = _utc(result)
    translated = {
        "uid": "bots-dns-{}-{}-{}".format(
            stamp, result.get("src_ip", ""), result.get("transaction_id", "")
        ),
        "ts": stamp,
        "id.orig_h": result.get("src_ip"),
        "id.resp_h": result.get("dest_ip"),
        "query": query,
        "qtype_name": _first(result.get("query_type{}")),
        "rcode_name": _first(result.get("reply_code{}")),
    }
    event = parse_zeek_dns(translated, ctx)
    return _finish(event, result)


def _finish(event: NormalizedEvent, result: LogRecord) -> NormalizedEvent:
    """Mark the event as real BOTS data and keep the untouched original."""
    if DATASET_TAG not in event.tags:
        event.tags.append(DATASET_TAG)
    event.raw = dict(result)
    return event


_BY_SOURCETYPE = {
    SOURCETYPE_SECURITY: _security,
    SOURCETYPE_SYSMON: _sysmon,
    SOURCETYPE_DNS: _dns,
}


def parse_bots(record: LogRecord, ctx: ParseContext) -> NormalizedEvent:
    """Parse one BOTSv1 export line (wrapped or unwrapped)."""
    result = _unwrap(record)
    sourcetype = result.get("sourcetype")
    handler = _BY_SOURCETYPE.get(str(sourcetype))
    if handler is None:
        raise ParseError(
            "BOTS sourcetype {} is not one PRISM models".format(sourcetype)
        )
    return handler(result, ctx)
