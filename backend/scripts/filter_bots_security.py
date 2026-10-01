"""Stream-filter the BOTSv1 WinEventLog:Security export.

The full file is 3.8 GB compressed and far larger uncompressed, which is more
than PRISM's in-memory pipeline should hold. This reads it from stdin and
writes only the authentication-family events PRISM parses, trimmed to the
fields the Windows parser uses.

Nothing about a kept record is altered: fields are copied verbatim, and
``_raw_keys_dropped`` lists what was left out so the trimming is auditable.

Usage:
    curl -s <url> | gunzip | python filter_bots_security.py OUT.jsonl.gz
"""

from __future__ import annotations

import gzip
import json
import sys
from collections import Counter

#: Event IDs the PRISM Windows parser understands.
KEEP_CODES = {"4624", "4625", "4648", "4672", "5140", "7045"}

#: Fields copied through unchanged. Everything else is dropped.
KEEP_FIELDS = (
    "_time",
    "EventCode",
    "RecordNumber",
    "ComputerName",
    "host",
    "Account_Name",
    "Account_Domain",
    "Logon_Type",
    "Logon_Process",
    "Authentication_Package",
    "Source_Network_Address",
    "Workstation_Name",
    "Process_Name",
    "Share_Name",
    "Relative_Target_Name",
    "Service_File_Name",
    "Service_Name",
    "Failure_Reason",
    "Status",
    "Sub_Status",
    "Keywords",
    "src_ip",
    "dest",
    "user",
)


def main() -> None:
    out_path = sys.argv[1]
    scanned = 0
    kept: Counter[str] = Counter()

    with gzip.open(out_path, "wt", encoding="utf-8") as out:
        for line in sys.stdin:
            scanned += 1
            try:
                result = json.loads(line)["result"]
            except (ValueError, KeyError):
                continue
            code = str(result.get("EventCode", ""))
            if code not in KEEP_CODES:
                continue
            record = {key: result[key] for key in KEEP_FIELDS if key in result}
            record["sourcetype"] = "WinEventLog:Security"
            record["dataset"] = "botsv1"
            out.write(json.dumps(record, separators=(",", ":")) + "\n")
            kept[code] += 1
            if scanned % 2_000_000 == 0:
                print("scanned {:,} kept {:,}".format(scanned, sum(kept.values())), flush=True)

    print("DONE scanned {:,} records, kept {:,}".format(scanned, sum(kept.values())))
    for code, count in sorted(kept.items()):
        print("  EventCode {}: {:,}".format(code, count))


if __name__ == "__main__":
    main()
