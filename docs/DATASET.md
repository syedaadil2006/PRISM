# The PRISM demo dataset

## What it is, plainly

The dataset in `backend/data/demo/` is **synthetic**. It was authored for this
prototype; it is not an export from a real network, and it is not a copy of a
public corpus.

What it is *not* synthetic about is the format. Each file is written in the exact
schema of the public source it stands in for, so a real export drops in with no
code changes:

| File | Format | Real-world equivalent |
| --- | --- | --- |
| `01_windows_security.csv` | Windows Security channel, CSV | `wevtutil` / Winlogbeat exports; the Windows host logs in Security-Datasets (Mordor) and Splunk BOTS |
| `02_sysmon.jsonl` | Sysmon events 1 / 10 / 11, JSON-lines | Sysmon via Winlogbeat; the Sysmon captures in Security-Datasets |
| `03_zeek_dns.jsonl` | Zeek `dns.log`, JSON-lines | Zeek network sensor output; the Zeek logs in Splunk BOTS |

`backend/data/inventory/topology.json` holds the environment context: hosts with
roles and criticality, accounts with privilege and entitlements, network
reachability, and the baseline of already-seen domains.

## Why synthetic

The brief asks for a public dataset, and notes that a documented synthetic
supplement is acceptable where a corpus lacks one of the three required log
categories. In practice that gap is the normal case, not the exception:

- Splunk BOTS is distributed as a Splunk index rather than plain log files, and
  is several gigabytes.
- Security-Datasets captures are typically endpoint-heavy: a given scenario has
  rich Sysmon and Windows Security data but often no matching DNS capture for
  the same hosts and clock.

Correlating across all three feeds requires one coherent timeline with shared
hosts, accounts and addresses. Rather than stitch two corpora together and
silently invent the join keys, the whole demo scenario is synthetic and labelled
as such. Every technique in it is modelled on documented behaviour, and the
field names and value formats are the real ones.

## Using a real dataset instead

Ingestion is a parser, not a special case, so real data goes through the same
path:

```bash
curl -X POST http://localhost:8000/api/logs/ingest -F "files=@security.csv" -F "files=@sysmon.jsonl" -F "files=@dns.log"
```

Or drop the files into `backend/data/demo/` and restart. To replace the demo
entirely, set `PRISM_DEMO_DIR` to another directory.

Two things to update for a real environment:

1. `backend/data/inventory/topology.json` — hosts, criticality and account
   entitlements. Without it, correlation and chain detection still work, but
   next-target prediction has nothing to score against.
2. `backend/app/ingest/indicators.py` — the deny list and the baseline of known
   domains.

## The scenario

Wednesday 30 September 2026, a small Windows domain: eight hosts, six accounts,
one domain controller.

| Time (UTC) | Feed | What happened |
| --- | --- | --- |
| 09:31 – 10:00 | all three | Ordinary morning traffic: logons, Teams, Chrome, share access, a nightly backup job |
| 10:01:55 | Sysmon 11 | Outlook writes a macro-bearing invoice document to Temp on HR-PC |
| 10:02:12 | Sysmon 1 | Word opens that document |
| 10:02:12 | Sysmon 1 | Word spawns PowerShell with hidden-window and encoded-command flags |
| 10:03 – 10:08 | Zeek | Six lookups for `update-svc-cdn.xyz` at a steady cadence |
| 10:03:31 | Sysmon 1 | Identity enumeration (`whoami /all`) |
| 10:04:18 | Sysmon 1 | Domain group enumeration (`net group`) |
| 10:06:22 | Sysmon 10 | PowerShell opens a handle to LSASS |
| 10:10 – 10:11 | Windows 4625 | Three failed logons for `john.doe` from HR-PC |
| 10:12:35 | Windows 4624 | **RDP from HR-PC to FINANCE-PC**, logon type 10 |
| 10:12:36 | Windows 4672 | Privileged logon on FINANCE-PC |
| 10:13:10 | Sysmon 1 | Encoded PowerShell on FINANCE-PC, parent `wmiprvse.exe` |
| 10:13 – 10:16 | Zeek | `cdn-telemetry-sync.top`, then a DGA-shaped label |
| 10:14:02 | Sysmon 1 | A dump utility run against LSASS |
| 10:15:12 | Sysmon 1 | Registry hive export of the SAM |
| 10:15:40 | Windows 5140 | **`ADMIN$` on FILE01 mounted from FINANCE-PC** |
| 10:16 – 10:17 | Windows 4625 | Two failed logons against **DC01** from FINANCE-PC |
| 10:18:15 | Sysmon 1 | A remote-execution utility pointed at FILE01 |
| 10:21 – 10:29 | all three | Ordinary traffic resumes |

## What PRISM should produce

Out of 56 normalized events, 32 would raise an alert in a per-event console.
PRISM returns **one** attack chain:

- **Initial host** HR-PC, **current host** FINANCE-PC, **current stage** Lateral Movement
- **Account** `john.doe`, **risk** 100/100
- **Reached** HR-PC, FINANCE-PC, FILE01. **Targeted but not reached** DC01
- **Two** lateral movements: HR-PC to FINANCE-PC (RDP), FINANCE-PC to FILE01 (SMB admin share)
- **16** MITRE techniques across 8 tactics
- **Top prediction** DC01 at 92.9/100

The noise is the point. Three findings stay *out* of the chain, because nothing
ties them to it: an administrator's legitimate RDP session to DC01 at 09:31, a
newly observed vendor domain from IT-PC, and a single failed logon for
`sara.lee` who simply mistyped her password.

## Extending it

The scenario is three plain text files. Add events by appending rows in the same
format and restarting, or by uploading through `/api/logs/ingest`. Only the
timestamps, hosts, accounts and addresses need to line up — correlation does the
rest.
