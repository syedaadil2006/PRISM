"""Next-target prediction benchmark on the OTRF APT29 dataset (MITRE ATT&CK Evaluations round 2).

    1. Download apt29_evals_day1_manual.zip and apt29_evals_day2_manual.zip from
       https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/apt29
       and unzip them into FOLDER/day1 and FOLDER/day2.
    2. python scripts/benchmark_apt29.py FOLDER

Ground truth comes from the raw logs, not from PRISM: the first remote-execution
process (WinRM wsmprovhost.exe / PsExec PSEXESVC.exe) on a computer the attacker
had not used before. For each move, PRISM sees only the events before it. The
network map is neutral (every computer reaches every other, the domain
controller is critical, no account permissions), and no setting is tuned.
"""

import glob
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
ROOT = Path(__file__).resolve().parent.parent
os.environ.update({"PRISM_LOG_LEVEL": "ERROR"})
sys.path.insert(0, str(ROOT / "backend"))

# --- 1. keep only the records PRISM's parsers use ---------------------------
SECURITY = {4624, 4625, 4648, 4672, 5140}
SYSMON = {1, 11, 22}

for day in (1, 2):
    source = glob.glob(str(HERE / f"day{day}" / "*.json"))[0]
    kept = 0
    with open(source, encoding="utf-8") as fin, open(HERE / f"day{day}.ndjson", "w", encoding="utf-8") as fout:
        for line in fin:
            r = json.loads(line)
            channel = (r.get("Channel") or "").lower()
            event_id = r.get("EventID")
            host = (r.get("Hostname") or "").split(".")[0].upper()
            if channel == "security" and event_id in SECURITY:
                out = {k: r.get(k) for k in ("TargetUserName", "SubjectUserName", "LogonType", "IpAddress",
                                             "WorkstationName", "ShareName", "ProcessName", "Status")
                       if r.get(k) is not None}
                out.update({"RecordId": f"apt29-d{day}-sec-{r.get('RecordNumber')}-{host}", "EventID": str(event_id),
                            "TimeCreated": r.get("@timestamp"), "Computer": host})
            elif channel.endswith("sysmon/operational") and (
                    event_id in SYSMON or (event_id == 10 and "lsass" in (r.get("TargetImage") or "").lower())):
                out = {k: r.get(k) for k in ("Image", "ParentImage", "CommandLine", "User", "TargetFilename",
                                             "SourceImage", "TargetImage", "GrantedAccess", "QueryName",
                                             "ProcessGuid", "Hashes") if r.get(k) is not None}
                out.update({"RecordId": f"apt29-d{day}-sys-{r.get('RecordNumber')}-{host}", "EventID": str(event_id),
                            "UtcTime": r.get("UtcTime"), "Computer": host})
                if event_id == 22:  # Sysmon DNS: give the DNS parser what it reads
                    out = {"uid": out["RecordId"], "ts": r.get("@timestamp"), "query": r.get("QueryName"),
                           "host": host, "Computer": host}
            else:
                continue
            fout.write(json.dumps(out) + "\n")
            kept += 1
    print(f"day {day}: kept {kept} records")

# --- 2. predict each move from the events before it ------------------------
from app.core.config import Settings  # noqa: E402
from app.detection import engine  # noqa: E402
from app.engine.attack_chain import build_chains  # noqa: E402
from app.engine.correlation import correlate  # noqa: E402
from app.graph.builder import build_entity_graph  # noqa: E402
from app.ingest.loader import load_inventory, make_context, normalize_all  # noqa: E402
from app.ingest.parsers import parse_records  # noqa: E402

HOSTS = {"NEWYORK": "10.0.0.4", "SCRANTON": "10.0.1.4", "UTICA": "10.0.1.5", "NASHUA": "10.0.1.6"}
inventory_file = HERE / "inventory.json"
inventory_file.write_text(json.dumps({
    "hosts": [{"name": name, "ip": ip,
               "role": "domain controller" if name == "NEWYORK" else "workstation",
               "criticality": 1.0 if name == "NEWYORK" else 0.3,
               "is_critical_infrastructure": name == "NEWYORK",
               "reachable_hosts": [h for h in HOSTS if h != name]} for name, ip in HOSTS.items()],
    "users": [], "known_domains": [],
}), encoding="utf-8")

settings = Settings()
engine.install(engine.build(settings.detection))
inventory = load_inventory(inventory_file)

# The attacker's start on each day (public emulation plan) and the moves seen in the raw logs.
START = {1: "SCRANTON", 2: "UTICA"}
REMOTE_EXEC = ("wsmprovhost.exe", "psexesvc.exe")


def moves(records: list[dict], day: int) -> list[tuple[datetime, str]]:
    seen = {START[day]}
    found = []
    for r in sorted(records, key=lambda r: r.get("UtcTime") or ""):
        image = (r.get("Image") or "").lower()
        if r.get("EventID") == "1" and image.endswith(REMOTE_EXEC) and r["Computer"] not in seen:
            seen.add(r["Computer"])
            when = datetime.strptime(r["UtcTime"][:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            found.append((when, r["Computer"]))
    return found


results = []
for day in (1, 2):
    records = [json.loads(l) for l in (HERE / f"day{day}.ndjson").read_text(encoding="utf-8").splitlines()]
    events, errors = parse_records(records, make_context(inventory, f"apt29-day{day}"))
    print(f"day {day}: {len(events)} events parsed, {len(errors)} rejected"
          + (f" (e.g. {errors[0][:90]})" if errors else ""))
    full = normalize_all([e.model_copy(deep=True) for e in events])
    chains = build_chains(full, correlate(full, settings.correlation), build_entity_graph(full, inventory),
                          inventory, settings)
    print(f"   whole day: {len(chains)} chain(s): " + "; ".join(
        f"{c.attack_chain_id} {len(c.event_ids)} ev, hosts {sorted(c.hosts)}, {len(c.lateral_movements)} lateral"
        for c in chains))
    for when, actual in moves(records, day):
        prefix = normalize_all([e.model_copy(deep=True) for e in events if e.timestamp < when])
        cut = build_chains(prefix, correlate(prefix, settings.correlation), build_entity_graph(prefix, inventory),
                           inventory, settings)
        attacker = [c for c in cut if START[day] in c.hosts]
        chain = max(attacker, key=lambda c: len(c.event_ids), default=None)
        ranked = [p.host for p in chain.predictions] if chain else []
        results.append((day, when, actual, ranked, chain.current_host if chain else None))
        print(f"   move at {when:%H:%M:%S} to {actual}: PRISM's ranking {ranked[:3]} "
              f"(attacker last seen on {chain.current_host if chain else '-'})")

scored = [r for r in results if r[3]]
top1 = sum(1 for r in scored if r[3][0] == r[2])
top3 = sum(1 for r in scored if r[2] in r[3][:3])
print(f"\nAPT29 moves: {len(results)}; with a prediction: {len(scored)}; top-1 {top1}/{len(scored)}, top-3 {top3}/{len(scored)}")
