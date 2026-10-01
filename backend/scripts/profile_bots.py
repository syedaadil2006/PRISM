"""Profile a BOTSv1 json-by-sourcetype file: what is actually in it.

Usage:
    python profile_bots.py <file.json.gz> [--field NAME ...]

Reports the record count, the time span, the busiest hosts and the event codes,
plus value counts for any extra fields requested. This is the "inspect before
claiming" step: it is how we know which telemetry the dataset really contains.
"""

from __future__ import annotations

import argparse
import gzip
import json
from collections import Counter


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--field", action="append", default=[])
    parser.add_argument("--top", type=int, default=12)
    args = parser.parse_args()

    records = 0
    first = last = None
    hosts: Counter[str] = Counter()
    codes: Counter[str] = Counter()
    extra: dict[str, Counter[str]] = {name: Counter() for name in args.field}
    keys: Counter[str] = Counter()

    with gzip.open(args.path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                result = json.loads(line)["result"]
            except (ValueError, KeyError):
                continue
            records += 1
            stamp = result.get("_time") or result.get("timestamp") or result.get("UtcTime")
            if stamp:
                first = stamp if first is None or stamp < first else first
                last = stamp if last is None or stamp > last else last
            hosts[str(result.get("host", "?"))] += 1
            codes[str(result.get("EventCode", "-"))] += 1
            if records <= 2000:
                keys.update(result.keys())
            for name in args.field:
                value = result.get(name)
                if isinstance(value, list):
                    value = value[0] if value else None
                extra[name][str(value)] += 1

    print("file:     ", args.path)
    print("records:  ", records)
    print("time span:", first, "->", last)
    print("hosts:    ", hosts.most_common(args.top))
    print("codes:    ", codes.most_common(args.top))
    for name, counter in extra.items():
        print("{:<10}".format(name + ":"), counter.most_common(args.top))
    print("fields (first 2000 records):", sorted(k for k in keys if not k.startswith("_") or k == "_time"))


if __name__ == "__main__":
    main()
