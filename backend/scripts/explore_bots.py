"""Look for the incident in BOTSv1 directly, rather than assuming where it is.

Subcommands:
    procs  <sysmon.json.gz> [--host H]         Sysmon process creations (EventCode 1)
    dns    <dns.json.gz> --src IP [--day D]    DNS queries from one client
    ipmap  <sysmon.json.gz>                    IP -> hostname pairs seen in Sysmon
"""

from __future__ import annotations

import argparse
import gzip
import json
from collections import Counter
from typing import Iterator


def records(path: str) -> Iterator[dict]:
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                yield json.loads(line)["result"]
            except (ValueError, KeyError):
                continue


def first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def cmd_procs(args: argparse.Namespace) -> None:
    rows = []
    for r in records(args.path):
        if str(r.get("EventCode")) != "1":
            continue
        if args.host and str(r.get("host", "")).lower() != args.host.lower():
            continue
        rows.append(r)
    rows.sort(key=lambda r: r.get("_time", ""))
    print("{} process creations".format(len(rows)))
    for r in rows[: args.limit]:
        print(
            "{} {:<11} {:<24} {:<28} <- {:<22} | {}".format(
                r.get("_time", "")[:19],
                r.get("host", ""),
                str(r.get("User", ""))[:24],
                str(r.get("Image", "")).split("\\")[-1][:28],
                str(r.get("ParentImage", "")).split("\\")[-1][:22],
                str(r.get("CommandLine", ""))[:150],
            )
        )


def cmd_dns(args: argparse.Namespace) -> None:
    counts: Counter[str] = Counter()
    firsts: dict[str, str] = {}
    for r in records(args.path):
        if r.get("src_ip") != args.src:
            continue
        stamp = r.get("_time", "")
        if args.day and not stamp.startswith(args.day):
            continue
        query = first(r.get("query{}")) or r.get("query")
        if not query:
            continue
        counts[query] += 1
        firsts.setdefault(query, stamp)
    print("{} distinct queries".format(len(counts)))
    for query, count in sorted(counts.items(), key=lambda kv: firsts[kv[0]])[: args.limit]:
        print("{} {:>5}  {}".format(firsts[query][:19], count, query))


def cmd_ipmap(args: argparse.Namespace) -> None:
    pairs: Counter[tuple[str, str]] = Counter()
    for r in records(args.path):
        for ip_key, host_key in (("SourceIp", "SourceHostname"), ("DestinationIp", "DestinationHostname")):
            ip, host = r.get(ip_key), r.get(host_key)
            if ip and host and ip.startswith("192.168."):
                pairs[(ip, str(host).split(".")[0].lower())] += 1
    for (ip, host), count in sorted(pairs.items()):
        if count >= 5:
            print("{:<16} {:<22} {}".format(ip, host, count))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("procs")
    p.add_argument("path")
    p.add_argument("--host")
    p.add_argument("--limit", type=int, default=200)
    d = sub.add_parser("dns")
    d.add_argument("path")
    d.add_argument("--src", required=True)
    d.add_argument("--day")
    d.add_argument("--limit", type=int, default=200)
    m = sub.add_parser("ipmap")
    m.add_argument("path")
    args = parser.parse_args()
    {"procs": cmd_procs, "dns": cmd_dns, "ipmap": cmd_ipmap}[args.cmd](args)


if __name__ == "__main__":
    main()
