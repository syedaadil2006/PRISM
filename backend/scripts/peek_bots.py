"""Print the field names and a sample of BOTSv1 records, read from stdin.

Usage:
    curl -s <url> | gunzip | python peek_bots.py EVENTCODE [EVENTCODE ...]

Stops as soon as one example of each requested EventCode has been seen, so only
a small prefix of the stream is transferred. With no codes given, prints the
first record's keys and sample values.
"""

from __future__ import annotations

import json
import sys

WANTED = set(sys.argv[1:])
SKIP = {"Message", "body", "_raw", "punct"}


def show(result: dict) -> None:
    for key in sorted(result):
        if key in SKIP:
            continue
        value = result[key]
        text = json.dumps(value)
        print("   {:<28} {}".format(key, text[:110]))


seen: set[str] = set()
for count, line in enumerate(sys.stdin, start=1):
    try:
        result = json.loads(line)["result"]
    except (ValueError, KeyError):
        continue
    code = str(result.get("EventCode", ""))
    if not WANTED:
        show(result)
        break
    if code in WANTED and code not in seen:
        seen.add(code)
        print("== EventCode {} (record {}) ==".format(code, count))
        show(result)
    if seen == WANTED or count > 400000:
        print("scanned {} records".format(count))
        break
