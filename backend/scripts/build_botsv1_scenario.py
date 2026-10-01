"""Cut the BOTSv1 Cerber ransomware scenario out of the downloaded files.

Input (backend/data/botsv1/raw/, fetched from Splunk's public BOTSv1 bucket):
    botsv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json.gz
    botsv1.stream-dns.json.gz
    botsv1.security-logons.jsonl.gz   (stream-filtered by filter_bots_security.py)

Output (backend/data/botsv1/scenario/):
    01_security.jsonl, 02_sysmon.jsonl, 03_dns.jsonl   records in the window
Beside it (backend/data/botsv1/):
    inventory.json                                    context derived from data
    MANIFEST.json                                     provenance for all of it

The only operations applied to BOTS records are *selection* (time window,
event types PRISM models) and *field trimming*. No value is edited and no
record is invented. Everything this script decides is written to the manifest.

The inventory is where judgement enters, because BOTS ships no asset inventory.
Every inventory fact is either derived from the data before the incident window
(and the manifest says how) or marked as an assumption.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

RAW = Path(__file__).resolve().parents[1] / "data" / "botsv1" / "raw"
ROOT = Path(__file__).resolve().parents[1] / "data" / "botsv1"
#: Only log files live here: the loader ingests every JSON file in it.
OUT = ROOT / "scenario"

SYSMON_FILE = "botsv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json.gz"
DNS_FILE = "botsv1.stream-dns.json.gz"
SECURITY_FILE = "botsv1.security-logons.jsonl.gz"

SOURCE_BASE = "https://s3.amazonaws.com/botsdataset/botsv1/json-by-sourcetype/"
MDT = timedelta(hours=-6)

#: Sysmon event IDs the PRISM parser models. Others (3 network, 7 image
#: load, 2/5/6) are left out and counted in the manifest.
SYSMON_CODES = {"1", "10", "11"}

#: Fields retained per sourcetype. Anything else is dropped (counted, not edited).
KEEP = {
    "sysmon": (
        "_time", "sourcetype", "host", "Computer", "EventCode", "RecordID", "UtcTime",
        "User", "Image", "ParentImage", "CommandLine", "ParentCommandLine",
        "ProcessGuid", "ProcessId", "CurrentDirectory", "Hashes", "IntegrityLevel",
        "TargetFilename", "TargetImage", "SourceImage", "GrantedAccess",
    ),
    "dns": (
        "_time", "sourcetype", "timestamp", "src_ip", "dest_ip", "src_port",
        "transaction_id", "query{}", "query_type{}", "reply_code{}",
        "message_type{}", "answer",
    ),
}

#: Role-based criticality. BOTS contains no business context, so these are
#: assumptions and are labelled as such in the inventory and manifest.
ASSUMED_CRITICALITY = {
    "domain controller": 1.0,
    "server": 0.6,
    "workstation": 0.3,
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def splunk_records(path: Path) -> Iterator[dict]:
    """Yield records from either a Splunk export or our filtered extract."""
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                data = json.loads(line)
            except ValueError:
                continue
            yield data.get("result", data)


def to_utc(record: dict) -> datetime | None:
    """UTC timestamp, preferring fields that are already UTC."""
    utc_time = record.get("UtcTime")
    if utc_time:
        return datetime.fromisoformat(str(utc_time)[:19]).replace(tzinfo=timezone.utc)
    stamp = record.get("timestamp")
    if stamp and str(stamp).endswith("Z"):
        return datetime.fromisoformat(str(stamp)[:19]).replace(tzinfo=timezone.utc)
    local = record.get("_time")
    if not local:
        return None
    parsed = datetime.strptime(str(local)[:19], "%Y-%m-%d %H:%M:%S")
    return (parsed - MDT).replace(tzinfo=timezone.utc)


def first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def short(host) -> str | None:
    host = first(host)
    if not host or host in {"-", "::1", "127.0.0.1"}:
        return None
    return str(host).split(".")[0].lower()


def base_domain(name: str) -> str:
    parts = name.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else parts[0]


def trim(record: dict, kind: str) -> dict:
    kept = {k: record[k] for k in KEEP[kind] if k in record}
    kept["dataset"] = "botsv1"
    return kept


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", default="2016-08-24T16:00:00")
    parser.add_argument("--end", default="2016-08-24T18:30:00")
    args = parser.parse_args()

    start = datetime.fromisoformat(args.start).replace(tzinfo=timezone.utc)
    end = datetime.fromisoformat(args.end).replace(tzinfo=timezone.utc)
    OUT.mkdir(parents=True, exist_ok=True)

    manifest: dict = {
        "dataset": "Boss of the SOC v1 (BOTSv1)",
        "publisher": "Splunk Inc.",
        "license": "CC0-1.0",
        "homepage": "https://github.com/splunk/botsv1",
        "window_utc": [start.isoformat(), end.isoformat()],
        "window_note": (
            "10:00-12:30 US Mountain time on 24 Aug 2016, bracketing the Cerber "
            "ransomware execution on we8105desk and the benign Nessus scan and "
            "Acronis backup activity around it."
        ),
        "sources": {},
        "selection": {},
    }

    # ------------------------------------------------------------------ sysmon
    sysmon_path = RAW / SYSMON_FILE
    kept_sysmon: list[dict] = []
    dropped_codes: Counter[str] = Counter()
    host_ip_votes: Counter[tuple[str, str]] = Counter()
    connections: Counter[tuple[str, str]] = Counter()
    sysmon_users: dict[str, set[str]] = defaultdict(set)

    for record in splunk_records(sysmon_path):
        when = to_utc(record)
        host = short(record.get("host") or record.get("Computer"))
        code = str(record.get("EventCode"))
        # Pre-window network telemetry feeds reachability and address mapping.
        if code == "3" and when and when < start and record.get("Initiated") == "true":
            src, dst = record.get("SourceIp"), record.get("DestinationIp")
            if host and src and src.startswith("192.168."):
                host_ip_votes[(src, host)] += 1
            if host and dst and dst.startswith("192.168."):
                connections[(host, dst)] += 1
        if code == "1" and when and when < start and host:
            user = str(record.get("User") or "")
            if "\\" in user and not user.upper().startswith(("NT AUTHORITY", "WINDOW MANAGER", "IIS APPPOOL")):
                sysmon_users[user.split("\\")[-1].lower()].add(host)
        if not when or not (start <= when < end):
            continue
        if code not in SYSMON_CODES:
            dropped_codes[code] += 1
            continue
        kept_sysmon.append(trim(record, "sysmon"))

    kept_sysmon.sort(key=lambda r: str(r.get("UtcTime")))
    manifest["sources"]["sysmon"] = {
        "file": SYSMON_FILE,
        "url": SOURCE_BASE + SYSMON_FILE,
        "sha256": sha256(sysmon_path),
        "bytes": sysmon_path.stat().st_size,
    }
    manifest["selection"]["sysmon"] = {
        "kept_event_codes": sorted(SYSMON_CODES),
        "kept_records": len(kept_sysmon),
        "dropped_in_window_by_event_code": dict(sorted(dropped_codes.items())),
        "dropped_reason": "PRISM's Sysmon parser models event IDs 1, 10 and 11 only.",
        "fields_retained": list(KEEP["sysmon"]),
    }

    # --------------------------------------------------------------------- dns
    dns_path = RAW / DNS_FILE
    kept_dns: list[dict] = []
    known_names: set[str] = set()
    dns_host_ip: Counter[tuple[str, str]] = Counter()
    response_only = 0

    for record in splunk_records(dns_path):
        when = to_utc(record)
        query = first(record.get("query{}"))
        names = record.get("name{}") or []
        answers = record.get("answer") or []
        if isinstance(names, str):
            names = [names]
        if isinstance(answers, str):
            answers = [answers]
        for name in set(names):
            if name.endswith("waynecorpinc.local") and not name.startswith("_"):
                for answer in set(answers):
                    if str(answer).startswith("192.168."):
                        dns_host_ip[(name.split(".")[0].lower(), answer)] += 1
        if when and when < start and query:
            name = str(query).lower().rstrip(".")
            known_names.add(name if "." not in name else base_domain(name))
            continue
        if not when or not (start <= when < end):
            continue
        if not query:
            response_only += 1
            continue
        kept_dns.append(trim(record, "dns"))

    kept_dns.sort(key=lambda r: str(r.get("timestamp")))
    manifest["sources"]["dns"] = {
        "file": DNS_FILE,
        "url": SOURCE_BASE + DNS_FILE,
        "sha256": sha256(dns_path),
        "bytes": dns_path.stat().st_size,
    }
    manifest["selection"]["dns"] = {
        "kept_records": len(kept_dns),
        "dropped_response_only_records_in_window": response_only,
        "dropped_reason": "Response-only stream records carry no query field.",
        "fields_retained": list(KEEP["dns"]),
    }

    # ---------------------------------------------------------------- security
    security_path = RAW / SECURITY_FILE
    kept_security: list[dict] = []
    entitlement: dict[str, Counter[str]] = defaultdict(Counter)
    security_codes: Counter[str] = Counter()

    for record in splunk_records(security_path):
        when = to_utc(record)
        code = str(record.get("EventCode"))
        host = short(record.get("ComputerName") or record.get("host"))
        target = record.get("Account_Name")
        target = target[-1] if isinstance(target, list) and target else target
        account = str(target or "").lower()
        if (
            when
            and when < start
            and code == "4624"
            and host
            and account
            and not account.endswith("$")
            and account not in {"-", "anonymous logon", "system"}
        ):
            entitlement[account][host] += 1
        if not when or not (start <= when < end):
            continue
        security_codes[code] += 1
        kept_security.append(record)

    kept_security.sort(key=lambda r: str(r.get("_time")))
    manifest["sources"]["security"] = {
        "file": SECURITY_FILE,
        "derived_from": SOURCE_BASE + "botsv1.WinEventLog-Security.json.gz",
        "derivation": (
            "Stream-filtered with backend/scripts/filter_bots_security.py: event "
            "IDs 4624, 4625, 4648, 4672, 5140, 7045 only, fields trimmed. The 3.8 "
            "GB source was never stored in full."
        ),
        "sha256_of_extract": sha256(security_path),
        "bytes": security_path.stat().st_size,
    }
    manifest["selection"]["security"] = {
        "kept_records": len(kept_security),
        "kept_by_event_code": dict(sorted(security_codes.items())),
    }

    # --------------------------------------------------------------- inventory
    ip_for_host: dict[str, str] = {}
    ip_evidence: dict[str, str] = {}
    for (host, ip), count in sorted(dns_host_ip.items(), key=lambda kv: -kv[1]):
        if host not in ip_for_host and host != "waynecorpinc":
            ip_for_host[host] = ip
            ip_evidence[host] = "DNS answer ({} responses)".format(count)
    # Fallback: the dominant self-reported source address in Sysmon.
    best_host_for_ip: dict[str, tuple[str, int]] = {}
    for (ip, host), count in host_ip_votes.items():
        if count > best_host_for_ip.get(ip, ("", 0))[1]:
            best_host_for_ip[ip] = (host, count)
    for ip, (host, count) in best_host_for_ip.items():
        if host not in ip_for_host and ip not in ip_for_host.values():
            ip_for_host[host] = ip
            ip_evidence[host] = "Sysmon self-reported source address ({} connections)".format(count)

    domain_ips = {ip for (name, ip) in dns_host_ip if name == "waynecorpinc"}

    in_window_hosts = {short(r.get("host")) for r in kept_sysmon} | {
        short(r.get("ComputerName") or r.get("host")) for r in kept_security
    }
    in_window_hosts |= set(ip_for_host)
    in_window_hosts.discard(None)

    host_for_ip = {ip: host for host, ip in ip_for_host.items()}
    reach: dict[str, set[str]] = defaultdict(set)
    for (src_host, dst_ip), count in connections.items():
        dst_host = host_for_ip.get(dst_ip)
        if dst_host and dst_host != src_host and count >= 3:
            reach[src_host].add(dst_host)
            reach[dst_host].add(src_host)

    hosts = []
    for name in sorted(in_window_hosts):
        ip = ip_for_host.get(name)
        if ip and ip in domain_ips:
            role, evidence = "domain controller", "The AD domain name waynecorpinc resolves to this host's address"
        elif name.endswith("desk"):
            role, evidence = "workstation", "Host naming convention (…desk)"
        else:
            role, evidence = "server", "Host naming convention (…srv)"
        hosts.append(
            {
                "name": name.upper(),
                "ip": ip,
                "role": role,
                "criticality": ASSUMED_CRITICALITY[role],
                "is_critical_infrastructure": role == "domain controller",
                "reachable_hosts": sorted(h.upper() for h in reach.get(name, set()) if h in in_window_hosts),
                "zone": "waynecorpinc.local",
                "provenance": {
                    "ip": ip_evidence.get(name, "not observed"),
                    "role": evidence,
                    "criticality": "ASSUMED from role; BOTS has no business context",
                    "reachable_hosts": "Observed connections before the incident window",
                },
            }
        )

    users = []
    accounts = set(entitlement) | set(sysmon_users)
    for account in sorted(accounts):
        observed_hosts = {h for h, c in entitlement.get(account, {}).items()} | sysmon_users.get(account, set())
        observed_hosts &= in_window_hosts
        if not observed_hosts:
            continue
        privileged = "admin" in account
        users.append(
            {
                "name": account,
                "privilege": 0.9 if privileged else 0.3,
                "is_privileged": privileged,
                "accessible_hosts": sorted(h.upper() for h in observed_hosts),
                "groups": [],
                "provenance": {
                    "accessible_hosts": "Successful logons (4624) or process activity before the incident window",
                    "privilege": "ASSUMED: accounts named *admin* treated as privileged",
                },
            }
        )

    inventory = {
        "hosts": hosts,
        "users": users,
        "known_domains": sorted(known_names),
        "provenance": {
            "known_domains": (
                "Every DNS name queried by any client before the incident window, "
                "reduced to its registered domain. 'Newly observed' is therefore "
                "measured against the dataset's own history."
            ),
        },
    }

    # ------------------------------------------------------------------ write
    def dump(name: str, rows: list[dict]) -> None:
        with (OUT / name).open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, separators=(",", ":")) + "\n")

    dump("01_security.jsonl", kept_security)
    dump("02_sysmon.jsonl", kept_sysmon)
    dump("03_dns.jsonl", kept_dns)
    (ROOT / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")

    manifest["inventory"] = {
        "hosts": len(hosts),
        "users": len(users),
        "known_domains": len(known_names),
        "assumptions": [
            "Host criticality is assigned by role, not taken from BOTS.",
            "Accounts containing 'admin' are treated as privileged.",
            "Entitlement means the account was seen logging on or running processes before the window, not an ACL.",
        ],
    }
    manifest["totals"] = {
        "security": len(kept_security),
        "sysmon": len(kept_sysmon),
        "dns": len(kept_dns),
        "all": len(kept_security) + len(kept_sysmon) + len(kept_dns),
    }
    (ROOT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest["totals"], indent=2))
    print(json.dumps(manifest["inventory"], indent=2))


if __name__ == "__main__":
    main()
