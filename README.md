# PRISM

### Agentic SOC investigation platform

**Don't show the analyst 1,000 isolated alerts. Show one connected attack story:
where it started, how it moved, what it is doing now, and what it may target
next — investigated, evidenced and verified before it reaches them.**

PRISM ingests authentication, DNS and endpoint logs, normalizes them into
one schema, and correlates them into an attack graph. A layer of specialised AI
agents then runs over that graph: they gather evidence through a tool interface,
reason about reachability and access, map ATT&CK, project the next target, and
check each other's conclusions before anything is shown.

On the bundled demo dataset:

```
56 raw events → 32 would alert → 29 correlated → 1 cluster → 1 attack chain → 1 investigation
```

**The agents do not need an LLM.** Every fact is retrieved through the tool
layer and re-derived by the Verification Agent. A model is optional, may only
rephrase findings that are already verified, and its output is discarded if it
introduces a host or technique that was not in the verified set.

```
              john.doe
                 │
               HR-PC ──────────── update-svc-cdn.xyz   (C2 beaconing)
                 │
      Outlook attachment → Word → PowerShell → LSASS access
                 │
            RDP logon  (lateral movement, inferred)
                 ▼
            FINANCE-PC   ← attacker is here now
                 │
      credential dumping · SAM export · ADMIN$ on FILE01
                 │
                 ▼
          ⚠ POTENTIAL TARGET
                DC01       92.9/100 · predicted, not observed
```

---

## System architecture

```mermaid
flowchart TB
    subgraph SRC["Log sources"]
        S1["Windows Security<br/>logons, failed logons, shares"]
        S2["Sysmon<br/>processes, file writes, DNS"]
        S3["Zeek DNS"]
        S4["Splunk BOTS v1 export"]
    end

    subgraph IN["Ways in"]
        I1["Bundled dataset / file upload<br/>POST /api/logs/ingest"]
        I2["Live push API<br/>POST /api/live/events"]
        I3["Watched folder<br/>backend/data/live"]
        I4["Windows collector<br/>asks permission first"]
    end

    subgraph CORE["PRISM backend: FastAPI + Python"]
        C1["Parse and normalize<br/>one event schema"]
        C2["Enrich<br/>beaconing, credential guessing"]
        C3["Entity graph<br/>NetworkX"]
        C4["Correlation engine<br/>weighted factors, score >= 0.70"]
        C5["Attack chains<br/>connected components"]
        C6["Lateral movement<br/>clause-by-clause rule"]
        C7["MITRE ATT&CK mapping<br/>19 named rules"]
        C8["Next-target prediction<br/>6 factors, 0-100, PREDICTED"]
        C1 --> C2 --> C3 --> C4 --> C5
        C5 --> C6
        C5 --> C7
        C5 --> C8
    end

    subgraph AG["Investigation agents: 17 tools, evidence required"]
        A1["Triage, Correlation, Investigation, Evidence,<br/>Graph, MITRE, Chain, Next-Target"]
        A2["Verification agent<br/>re-checks and downgrades"]
        A3["Analyst decision<br/>approve, reject, false positive"]
        A1 --> A2 --> A3
    end

    subgraph UI["Dashboard: React + Cytoscape.js"]
        U1["Simple view<br/>plain-English story"]
        U2["Analyst view<br/>attack graph, timeline, MITRE"]
        U3["Reports<br/>HTML / PDF / Markdown"]
    end

    S1 & S2 & S3 & S4 --> IN
    I1 & I2 & I3 & I4 --> C1
    C6 & C7 & C8 --> API["REST API /api<br/>OpenAPI docs at /docs"]
    C5 --> A1
    A3 --> API
    API --> U1 & U2 & U3

    LLM["Optional LLM<br/>rewords verified findings only"] -.-> A2
    NEO["Optional Neo4j mirror"] -.- C3
```

| Layer | What it does |
|---|---|
| **Ways in** | Logs arrive from the bundled dataset, file upload, the live push API, the watched folder, or the Windows collector (which only starts after the user agrees). |
| **Normalize and enrich** | Every source becomes one event schema; cross-event findings (DNS beaconing, clusters of failed logons) are added. |
| **Detection engine** | Rule-based and explainable: weighted correlation, chains as connected components, a clause-by-clause lateral-movement rule, 19 MITRE mapping rules, six-factor next-target scoring. No trained ML model. |
| **Investigation agents** | Nine deterministic agents work only through 17 tools; no finding without evidence; the Verification agent re-checks everything and the analyst has the final say. |
| **API and dashboard** | FastAPI serves the results and the built dashboard from one process on port 8000. The React dashboard has a Simple view for anyone and an Analyst view for experts. |

Full detail: **[docs/TECHNICAL_OVERVIEW.md](docs/TECHNICAL_OVERVIEW.md)** (algorithms, APIs, data flow, design decisions,
security, AI components) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Quick start

### One click (Windows)

Double-click **`Start PRISM.bat`**. The launcher (`scripts/start-prism.ps1`) runs in three steps:

1. **Checks this computer**: Windows 10 or newer (64-bit), processor, memory (4 GB minimum), free disk space
   (2 GB minimum) and whether port 8000 is free.
2. **Checks what PRISM needs**: Python 3.11 to 3.14, Node.js 20+, the backend packages, the dashboard packages and
   the dashboard build.
3. **Asks before installing anything.** If something is missing it lists exactly what it will download, from
   where and where it will go, and waits for you to answer **Y**. Answering **N** installs nothing.
4. **Asks which data to analyse:** **1** real-time data from this computer (its own Windows event logs:
   the last 24 hours, then new events live), **2** real recorded attack data (Splunk BOTS v1, 19,672 events,
   ready in about 10–20 seconds), or **3** the demo scenario. Enter picks 1. Only choice 1 asks for permission
   to collect from this computer (and, separately, for administrator approval); the demo and BOTS data ship
   with PRISM and need neither.
5. **Signs you in automatically.** The API is protected by an access code that PRISM creates on first
   start (`backend/data/.prism_token`, never committed); the launcher opens the dashboard already signed
   in. Anyone else gets a sign-in screen.
6. **Keeps everything on this computer** (local-only mode, the default). Network mode is only offered when
   `PRISM_LOCAL_ONLY=false`.
7. **Asks before collecting real-time data.** After PRISM starts, it asks whether it may read this
   computer's own Windows event logs as they happen (see [Real-time feed](#real-time-feed)). On **Y** it
   starts the read-only collector in a minimised window; logon and Sysmon events additionally need
   Windows' administrator approval (UAC), which you can refuse. On **N** nothing is collected.

| Missing | What the launcher installs (with your permission) |
|---|---|
| Python 3.11 to 3.14 | Python 3.12 for your user account (alongside any other Python), via winget or python.org. A newer Python that the packages do not support yet is skipped rather than compiled from source |
| Node.js 20+ | A portable Node.js LTS from nodejs.org, unpacked into `.tools/node` |
| Backend packages | Creates `.venv` and installs `backend/requirements.txt` from pypi.org |
| Dashboard packages and build | `npm ci` from npmjs.org, then `npm run build` |

No administrator rights are needed, nothing is installed system-wide, and no security or antivirus settings
are changed. The first setup needs an internet connection; later launches skip every satisfied step and start
in seconds. Packages are reinstalled when `requirements.txt` or `package-lock.json` change, the dashboard is
rebuilt when its source changes (for example after `git pull`), and a `.venv` copied from another computer is
rebuilt. PRISM then runs on http://localhost:8000 in a minimised window; close that window to stop it.

### Manual setup

Requires Python 3.11 to 3.14 and Node 20+.

```bash
python -m venv .venv
```

```bash
.venv/Scripts/python.exe -m pip install -r backend/requirements-dev.txt
```

```bash
npm --prefix frontend install
```

Run the backend (serves the API, and the built UI if `frontend/dist` exists):

```bash
.venv/Scripts/python.exe -m uvicorn app.main:app --app-dir backend --port 8000
```

Run the frontend in a second terminal:

```bash
npm --prefix frontend run dev
```

Open **http://localhost:5173**. API docs are at **http://localhost:8000/docs**.

On macOS or Linux use `.venv/bin/python` instead of `.venv/Scripts/python.exe`.

### Single-process mode

Build the UI once and the backend serves everything from port 8000:

```bash
npm --prefix frontend run build
```

```bash
.venv/Scripts/python.exe -m uvicorn app.main:app --app-dir backend --port 8000
```

Then open **http://localhost:8000**.

### Docker

```bash
docker compose up -d --build
docker compose exec prism cat /data/.prism_token
```

Then open http://localhost:8000 and sign in as `Admin` / `Admin@123` (you will be asked to choose a new password).
Use another port with `PRISM_PORT=8010 docker compose up -d`.
* One container serves the API and the dashboard. It runs as an unprivileged user with a read-only file
  system, and the port is published on 127.0.0.1 only.
* Databases, the access code, backups and an optional HTTPS certificate live in the `prism-data` volume. Put
  `prism.crt` and `prism.key` in `/data/tls` to serve HTTPS.
* `PRISM_DATASET=botsv1 docker compose up -d` analyses the BOTS data instead of the demo.
* For the optional Neo4j mirror, set `PRISM_NEO4J_PASSWORD` and run
  `docker compose --profile neo4j up -d --build`.

### Signing in

**Default login (first start):**

| User name | Password |
|---|---|
| `Admin` | `Admin@123` |

* A new installation creates this admin account the first time PRISM starts.
* The **first sign-in asks you to choose a new password** of at least 12 characters, and nothing else works until
  you do. So the published default only gets you as far as setting your own password.
* If you upgraded from an earlier version that already had accounts, the default is not created.

**Access code:** another way to sign in, used by the launcher and scripts.
* `Start PRISM.bat` opens the dashboard already signed in with it. Nothing to type.
* Otherwise, open the **Access code** tab and paste the code. PRISM creates a random code on first start, so
  every installation has a different one and it is never published. Read it with:
  * on the computer running PRISM: `Get-Content backend\data\.prism_token`
  * with Docker: `docker compose exec prism cat /data/.prism_token`
* The access code has admin rights. To use a code of your own choosing, set `PRISM_AUTH_TOKEN`.

**Team accounts:** on the **Admin** page, create an account for each person, as viewer, analyst or admin.
* The audit log then records each person's actions under their own name.
* Passwords an admin sets or resets are temporary: the user picks their own at the next sign-in.
* Optional settings:
  * `PRISM_AUTH_ACCESS_CODE_ENABLED=false` allows named accounts only.
  * `PRISM_AUTH_DEFAULT_ADMIN_ENABLED=false` skips the default admin on new installations.

### Tests

```bash
.venv/Scripts/python.exe -m pytest backend/tests -c backend/pytest.ini --rootdir backend
```

98 tests cover normalization, correlation, MITRE mapping, lateral movement,
prediction scoring, the demo simulation, the agent tool layer, evidence
discipline, verification, the human-in-the-loop controls and the HTTP API.

---

## The demo

Press **Start attack simulation** on the dashboard. The backend replays the
dataset one event at a time through the real pipeline — correlating,
re-scoring and re-predicting after every tick — so you watch the chain assemble
itself rather than an animation of a fixed picture.

Worth watching: partway through, the top predicted target is **FILE01**. Once
the attacker reaches FINANCE-PC and starts probing the domain controller, the
prediction flips to **DC01**. The score is recomputed from the graph each time.

Other controls: **Step** advances one event at a time for presenting at your own
pace, **Rewind** returns to an empty board, **Show full dataset** skips the
replay.

---

## What it does

### 1. Normalizes three log formats into one schema
Windows Security CSV (4624/4625/4648/4672/5140/7045), Sysmon JSON (1/10/11) and
Zeek `dns.log` all become `NormalizedEvent`. Format is auto-detected per record;
the untouched original is kept on every event so any finding is traceable back to
its source line. Adding a log source means writing one parser — nothing
downstream knows vendor field names.

### 2. Finds what a single log line cannot say
Some findings only exist across events: six lookups for one domain at a steady
cadence is beaconing; three failed logons for one account in six minutes is
credential guessing. One failed logon is somebody mistyping a password, and
PRISM leaves it alone.

### 3. Correlates with named, weighted factors
Every link between two events carries the reasons it exists:

```
edr-0009  ↔  auth-0011        score 1.00
  +0.35  Same account involved: john.doe
  +0.25  Shared host: HR-PC
  +0.40  HR-PC was used as the source for activity against FINANCE-PC
  +0.20  Events are 6m 13s apart
```

Time proximity alone is capped below the threshold, so two unrelated events one
second apart never link. The strongest single factor is the **host pivot**: a
compromised host becoming the source of activity against a new one.

### 4. Builds the chain from the graph, not from a rulebook
Correlations form a graph over notable events; each connected component becomes
an attack chain. No rule spells out "phishing then PowerShell then RDP" — the
story emerges from the evidence, which is why the same engine handles paths it
has never seen.

### 5. Maps MITRE ATT&CK with evidence
Each of the 19 mapping rules states its technique, its confidence, the event it
fired on, and why:

```
T1003.001  OS Credential Dumping: LSASS Memory      Credential Access   high
  evidence:  powershell.exe opened a handle to lsass.exe; GrantedAccess=0x1010
  source:    edr-0009
  why:       A process read or dumped LSASS memory, where Windows keeps
             credential material.
```

### 6. Detects lateral movement, clause by clause
The rule is written out and every detection reports which clauses fired:

```
PASS  Host HR-PC showed suspicious activity 373s earlier: CREDENTIAL_ACCESS ...
PASS  HR-PC was then used as the source of RDP_LOGIN activity
PASS  The activity reached FINANCE-PC
PASS  The same account (john.doe) is involved in both events
PASS  Correlation score 1.00 meets the configured minimum of 0.70
```

Window and threshold are configuration, not code.

### 7. Predicts the next target, arithmetically
Six weighted factors, each reporting its own points and its own sentence:

| Factor | Points | Why |
| --- | --- | --- |
| User Access | +30.0 / 30 | Compromised account john.doe is entitled to DC01 |
| Privilege | +25.0 / 25 | 2 privileged accounts can reach DC01, including admin.k |
| Connectivity | +20.0 / 20 | Graph connectivity of DC01 is 100% of the most connected host |
| Criticality | +20.0 / 20 | DC01 is a domain controller with criticality 1.0, flagged critical |
| Recent Activity | +15.0 / 15 | Recent activity toward DC01: failed LOGIN_FAILURE attempt from FINANCE-PC |
| Path Proximity | +20.0 / 20 | DC01 is 1 hop from the current attacker position (FINANCE-PC) |

Raw 130.0, normalised to **92.9/100**. Deliberately not a learned model: an
analyst who cannot audit a prediction will not act on it.

### 8. Investigates autonomously, and shows its work

Press **Start investigation**. Nine specialised agents run in sequence, each one
gathering what it needs through a tool interface rather than from memory:

```
✓ Triage Agent          Investigation required, severity critical
✓ Correlation Agent     29 related events, joined by same host (40x), host pivot (25x)
✓ Investigation Agent   Attack hypothesis confirmed (5 evidence items)
✓ Evidence Agent        34 record(s) behind 3 finding(s) so far
✓ Graph Reasoning       Reachability mapped from FINANCE-PC; 2 exposed hosts
✓ MITRE ATT&CK Agent    16 technique(s) across 8 tactic(s)
✓ Attack Chain Agent    11 stage(s), 2 host crossing(s)
✓ Next-Target Agent     DC01 at 93/100; then IT-PC 68, BACKUP01 50
✓ Verification Agent    7/7 verified, confidence 87%
```

Every step records the tools it called and what they returned. Expanding a
finding shows the evidence, the tool that retrieved it, and the source event ids
— which resolve to the original vendor log record.

The contract is enforced in code, not in a prompt: `AgentWorkspace.finding()`
raises if handed an empty evidence list. There is no path to an unsupported
claim.

### 9. Checks its own conclusions

The Verification Agent re-derives what each finding rests on and downgrades
what does not hold. It catches unresolvable citations, evidence spanning far
outside the correlation window, predicted targets that are not actually
reachable, and causal language over merely correlated evidence.

A failed finding is **downgraded and annotated, not deleted** — silently
dropping a conclusion hides the disagreement. The test suite plants a fabricated
evidence item and asserts the check catches it.

### 10. Leaves the decision with the analyst

Each finding carries **Approve**, **Reject** and **Mark false positive**. A
rejected finding stays on the record, leaves the summary, and confidence is
recomputed over what survives.

Recommended actions are phrased as recommendations and tested to stay that way.
There is no containment path in the code: PRISM does not act on hosts.

### 11. Never lets a guess look like a fact
Every statement carries how it was derived, in the API and in the UI:

| Label | Meaning |
| --- | --- |
| **Observed** | Straight from a source log record |
| **Correlated** | Events grouped by shared identity, host, address or timing |
| **Inferred** | A rule-engine conclusion no single record states |
| **Predicted** | Risk-based graph scoring, not attacker activity |

DC01 is scored at 92.9/100 and labelled `predicted`. It is never counted as a
compromised host, because the only thing observed on it is two **failed** logons.
A failed logon proves intent, not access.

---

## The dashboard

Seven pages: **Dashboard**, **Investigation**, **Attack Chains**, **Events**,
**MITRE ATT&CK**, **Hosts**, **Users**.

The dashboard answers the six questions in one screen:

| Question | Where |
| --- | --- |
| Where did it start? | Headline and root-cause panel — HR-PC |
| What happened? | Timeline: Initial Access → Execution → C2 → Discovery → Credential Access → Lateral Movement |
| Where is the attacker now? | Cyan node in the graph — FINANCE-PC |
| What is happening now? | Current stage — Lateral Movement |
| What could happen next? | Pink dotted edge — DC01 |
| Why? | Prediction factor breakdown, correlation factors, rule clauses |

The graph is Cytoscape.js. Shape encodes what an entity is, colour encodes the
state the backend assigned it, and line style encodes assurance — a predicted
relationship is dotted pink and can never be confused with an observed one.
Clicking a timeline stage spotlights its nodes; clicking any node or edge opens
its backing record, including the source event ids.

**No topology or relationship is hardcoded in the frontend.** `/api/graph`
returns node states and edge assurance; the UI maps those to shape, colour and
line style and nothing else. Point it at a different dataset and the picture
changes with no frontend edits.

---

## Ingesting your own logs

Use the **Ingest logs** button on the Events page, or:

```bash
curl -X POST http://localhost:8000/api/logs/ingest -F "files=@security.csv" -F "files=@sysmon.jsonl"
```

Formats are auto-detected; pass `?log_format=windows_security|sysmon|zeek_dns|prism`
to force one. Malformed records are reported individually rather than failing the
upload. The full pipeline re-runs before the response returns.

For prediction to be meaningful in your environment, update
`backend/data/inventory/topology.json` with your hosts, their criticality, and
account entitlements. See [docs/DATASET.md](docs/DATASET.md).

---

## Real-time feed

PRISM also analyses events **as they happen**. Anything that can send HTTP, or append a line
to a file, can feed it:

| Way in | How |
|---|---|
| **Push API** | `POST /api/live/events?source=<name>` with one JSON record, a JSON array, `{"records": [...]}`, JSON-lines, or CSV (`Content-Type: text/csv`). Formats are auto-detected. |
| **Watched folder** | Append lines to any `*.jsonl`, `*.ndjson`, `*.log` or `*.csv` file in `backend/data/live/`. New lines are picked up within about a second. |
| **Windows collector** | Offered by `Start PRISM.bat` (it asks first), or run `scripts/live_windows_collector.ps1` directly. Forwards this computer's own new Security (4624, 4625, 4648, 4672, 5140), System (7045) and Sysmon (1, 10, 11, 22) events. Run it from an administrator PowerShell to include the Security and Sysmon logs. It only reads logs. |
| **Live demo** | With PRISM running: `.venv\Scripts\python.exe scripts\live_replay.py`. It streams the demo attack in real time with current timestamps (`--speed 30` by default). |

```bash
curl -X POST "http://localhost:8000/api/live/events?source=hr-pc-sysmon" -H "X-PRISM-Token: <code from backend/data/.prism_token>" -H "Content-Type: application/x-ndjson" --data-binary @events.jsonl
```

Each source keeps its own ids (prefixed with the source name), resent records are counted once,
and the analysis is re-run in the background at most once a second (and never more often than
twice its own run time), so a fast sender gets an immediate answer. `GET /api/live/status` shows
events received per source, events per minute and whether the analysis has caught up; the top bar
of the dashboard shows **LIVE FEED** while events arrive. `POST /api/live/start` clears the bundled
dataset so only live events are analysed (`POST /api/logs/reset` brings it back), or start with
`PRISM_DATASET=live`. Settings use the `PRISM_LIVE_` prefix (`WATCH_DIR`, `RECOMPUTE_INTERVAL_SECONDS`,
`MAX_EVENTS`, `MAX_BATCH`, `ENABLED`).

Every re-analysis still runs over all retained events, so very large live volumes (tens of thousands of
events) are re-analysed less often; `PRISM_LIVE_MAX_EVENTS` (default 50,000) bounds memory.

---

## Local-only (edge) mode

**By default, all data stays on the computer PRISM runs on.** This is enforced in code
(`backend/app/core/local_only.py`), not left to configuration:

| Rule | What happens |
|---|---|
| Other machines cannot reach PRISM | Every request that does not come from this computer gets **403**, even if the server was started listening on the network |
| Nothing is forwarded off the computer | Alert targets (webhook, Splunk HEC, CEF syslog) are only used if they are on this computer; others are blocked and listed in `GET /api/live/integrations` |
| No outside AI service | The optional language model is never used; summaries are written by the built-in deterministic narrator |
| Syslog stays local | The syslog receiver only listens on `127.0.0.1` |
| No internet requests from the dashboard | No web fonts or other outside resources; Windows' own fonts are used |
| Scripts stay local | The Windows collector, live replay and SIEM pull refuse to send to another machine unless given `-AllowRemote` / `--allow-remote` |

`Start PRISM.bat` does not offer network mode in local-only mode. Verified on a running server deliberately
listening on the whole network: requests through the network address were refused (403), outside alert
targets were blocked, the summary was written by the deterministic narrator, and PRISM opened **no**
outgoing connections. The only time PRISM uses the internet is first-time setup (downloading Python,
Node.js and packages), and only after you agree.

`PRISM_LOCAL_ONLY=false` turns these rules off (for example to receive logs from other computers).

---

## SIEM integration and live log sources

PRISM plugs into an existing security stack in both directions.

**In: more live log sources**

| Source | How |
|---|---|
| **Winlogbeat, Filebeat, Packetbeat, Elastic Agent** (Elastic Common Schema) | Send their JSON to `POST /api/live/events`, or let the pull connector read it from Elasticsearch. Windows Security, System, Sysmon (including DNS event 22), Zeek DNS and generic ECS authentication events are understood. |
| **Splunk HTTP Event Collector** | `POST /services/collector/event` with `Authorization: Splunk <access code>`. Speaks HEC's protocol and response codes, so Splunk forwarders, Cribl, Fluent Bit, Vector or Logstash can send to PRISM unchanged. |
| **Syslog** (Linux servers, network devices) | `PRISM_SYSLOG_ENABLED=true` opens UDP/TCP port 5514. sshd logons (accepted, failed, invalid user) and sudo commands become events. Off by default. |
| **Other computers** | In network mode (see below) the Windows collector runs on any PC: `scripts\live_windows_collector.ps1 -Server http://<PRISM-PC>:8000 -Token <code>`. |

**In: pull from a SIEM** — `scripts/siem_pull.py` polls on a timer and forwards only new events:

```bash
python scripts/siem_pull.py splunk --url https://splunk:8089 --token <bearer token> --query "index=wineventlog OR index=sysmon"
```

```bash
python scripts/siem_pull.py elastic --url https://elastic:9200 --api-key <key> --index "winlogbeat-*,filebeat-*"
```

**Out: alerts to a SIEM** — whenever an attack chain appears or changes, PRISM sends one alert to each
configured target (background thread; nothing is sent unless a target is set):

| Target | Setting |
|---|---|
| Webhook (SOAR, chat bridges, any JSON receiver) | `PRISM_FORWARD_WEBHOOK_URL` |
| Splunk HEC (`sourcetype=prism:attack_chain`) | `PRISM_FORWARD_SPLUNK_HEC_URL`, `PRISM_FORWARD_SPLUNK_HEC_TOKEN` |
| Syslog in CEF (QRadar, ArcSight, Microsoft Sentinel, …) | `PRISM_FORWARD_SYSLOG_TARGET=host:port` |

Each alert carries the chain id, hosts, users, stage, MITRE techniques, lateral movements (labelled
*inferred*) and the predicted next target (labelled *predicted*).

**Network mode** (only with `PRISM_LOCAL_ONLY=false`). `Start PRISM.bat` then asks whether other computers may send logs. Only on **Y** does PRISM
listen on the network (and syslog on port 5514); it then prints the addresses to use. Windows Firewall
may ask for permission. `GET /api/live/integrations` shows what is enabled and what has been received
and sent.

Verified against **real Splunk 10.6 and Elasticsearch 8.17**, run locally in Docker and bound to this
computer: the demo attack loaded into each (into Splunk through its own HEC) was pulled back by
`siem_pull.py` and rebuilt into the same story; repeated polls fetched only new events; duplicates already
in the SIEM were counted once; and PRISM's alerts arrived in Splunk (`sourcetype=prism:attack_chain`) and
Elasticsearch. Splunk results whose `_raw` is JSON are forwarded as the original event.
`PRISM_FORWARD_TLS_VERIFY=false` accepts a SIEM's self-signed certificate (lab use only).

---

## OCSF (Open Cybersecurity Schema Framework)

PRISM's internal schema is its own `NormalizedEvent` (Pydantic models in `backend/app/models/`). On top of
it, PRISM reads and writes **OCSF 1.3**, the open standard behind Amazon Security Lake and supported by
major SIEM vendors (`backend/app/ocsf.py`):

| PRISM | OCSF class |
|---|---|
| Logons, failed logons, RDP, network/SMB | Authentication (3002) |
| Privileged logon (Windows 4672) | Authorize Session (3003), Assign Privileges |
| Process launch / process access (e.g. lsass) | Process Activity (1007), Launch / Open |
| File creation (e.g. a malicious attachment) | File System Activity (1001), Create |
| DNS lookups | DNS Activity (4003), Query |
| Attack chains | **Detection Finding (2004)** with MITRE ATT&CK techniques and related event uids |

* **Export:** `GET /api/ocsf/events` (optionally `?chain_id=` and `?format=ndjson`) and `GET /api/ocsf/findings`.
  `PRISM_FORWARD_FORMAT=ocsf` sends alerts as OCSF Detection Findings.
* **Import:** OCSF events are detected automatically by the live API, Splunk HEC endpoint, file upload and the
  watched folder. OCSF written by PRISM reads back exactly (PRISM details travel in OCSF's `unmapped`
  extension); OCSF from other tools is translated into native records so PRISM's own detection rules apply.
* **Verified:** the demo attack exported to OCSF and re-imported, both exactly and stripped to what another tool
  would send, rebuilds the same story; all 19,672 BOTS v1 events export and re-import with 0 errors.

---

## Accounts, roles, audit log and HTTPS

* **Named accounts with roles.** An admin creates accounts on the **Admin** page (or `POST /api/admin/users`):
  * `viewer` reads everything;
  * `analyst` can also run investigations, decide on findings and add data;
  * `admin` can also manage accounts, read the audit log and clear data.

  The shared access code still works for the launcher, scripts and collectors and acts as an admin. Once named
  accounts exist it can be switched off with `PRISM_AUTH_ACCESS_CODE_ENABLED=false`.
* **Passwords and sessions.**
  * Passwords need at least 12 characters and are stored only as salted scrypt hashes.
  * Sessions are random tokens, stored hashed, and end after 12 hours.
  * Disabling an account, changing its role or changing its password signs it out everywhere.
  * Five failed sign-ins lock the account and the address for 15 minutes.
* **Audit log.** Sign-ins (including failures), account changes, every change made through the API and every
  refused request are recorded with who, what, when and from where.
  * Entries are hash-chained, so editing or deleting an earlier entry is detected by **Verify integrity**
    (`GET /api/admin/audit/verify`).
  * Removing the most recent entries is not detected. Stopping that needs write-once storage or a copy kept
    on a separate system.
* **HTTPS.** Run `scripts\make-tls-cert.ps1`, or copy your organisation's certificate to
  `backend\data\tls\prism.crt` and `prism.key`. `Start PRISM.bat` then serves PRISM over HTTPS.
  * Over HTTPS the session cookie is `Secure` and HSTS is sent.
  * Browser hardening headers (Content-Security-Policy, X-Frame-Options, nosniff) are always sent.
* **PostgreSQL (optional).** Storage and accounts use SQLite files by default. For larger deployments set
  `PRISM_STORAGE_URL` and/or `PRISM_AUTH_DB_URL` to `postgresql://user:password@host:5432/prism` and run
  `pip install -r backend/requirements-postgres.txt`. In local-only mode the database must be on the same
  computer.
  * Tested against PostgreSQL 16. 40,000 events at about 8,400 events/s were stored and kept across restarts,
    with accounts and the audit log working.
  * `backend/tests/test_postgres.py` runs when `PRISM_TEST_POSTGRES_URL` is set.
  * Back up PostgreSQL with `pg_dump`. PRISM's built-in backups cover the SQLite files only.

---

## Scale, monitoring and backups

* **Ingestion is a queue; analysis runs in the background.**
  * Live events are parsed, de-duplicated and saved to storage before the sender gets its answer, so a
    restart loses nothing.
  * Re-analysis runs in a worker thread, so the dashboard and API keep answering from the previous result
    meanwhile.
  * When more than `PRISM_LIVE_MAX_PENDING` events (50,000) are waiting:
    * the live API answers **429** with `Retry-After`;
    * the Splunk HEC endpoint answers `503`, code 9 ("server is busy");
    * syslog counts what it had to drop.
* **Metrics.** `GET /api/metrics` gives Prometheus-format counters: requests by route and status, a latency
  histogram, events, chains, queue size, analysis runs and duration. Scrape it with
  `Authorization: Bearer <access code>`.
* **Backups.**
  * PRISM backs up its SQLite databases every 24 hours (`PRISM_BACKUP_INTERVAL_HOURS`) into
    `backend/data/backups/` and keeps the newest 7. An admin can also start one with
    `POST /api/admin/backups`.
  * Backups are consistent while PRISM runs and carry SHA-256 checksums.
  * To restore, stop PRISM and run `python scripts/restore_backup.py <name>`. It refuses a damaged backup or
    a running PRISM, and keeps the replaced files as `*.before-restore`.
* **Retention.** `PRISM_STORAGE_RETENTION_DAYS` deletes stored events and investigations older than that many
  days. The default 0 keeps everything. The audit log is never trimmed.
* **Load test.** `python scripts/load_test.py --events 40000 --senders 4 --attack` sends realistic office
  activity, with the demo attack hidden in it, to a running PRISM. It reports the ingestion rate, API latency
  under load and the time for analysis to catch up.

  Measured on a laptop with 40,000 events from 4 senders:
  * about 12,700 events/s accepted;
  * analysis caught up 6 s after sending started;
  * API median latency 30 ms;
  * the attack was still found among the noise.

  The previous version, under the same load, answered the dashboard in a median of 3.1 s.

---

## Configuration

| Setting | Default | Meaning |
|---|---|---|
| `PRISM_LOCAL_ONLY` | `true` | Edge mode: refuse other machines, send nothing off this computer |
| `PRISM_AUTH_ENABLED` | `true` | Require the access code on `/api` |
| `PRISM_AUTH_TOKEN` | *(generated)* | Use a fixed code instead of `backend/data/.prism_token` |
| `PRISM_STORAGE_ENABLED` | `true` | Keep uploads, live events and investigations in SQLite |
| `PRISM_STORAGE_PATH` | `backend/data/prism.db` | Database file |
| `PRISM_STORAGE_URL` | *(empty)* | `postgresql://...` to store data in PostgreSQL instead |
| `PRISM_AUTH_DB_URL` | `backend/data/security.db` | Accounts, sessions and audit log (file or `postgresql://...`) |
| `PRISM_AUTH_ACCESS_CODE_ENABLED` | `true` | `false` allows named accounts only |
| `PRISM_AUTH_SESSION_HOURS` | `12` | Sessions end this long after sign-in |
| `PRISM_AUTH_MAX_FAILED_LOGINS` / `_LOCKOUT_MINUTES` | `5` / `15` | Sign-in lockout |
| `PRISM_LIVE_MAX_PENDING` | `50000` | Events waiting for analysis before senders get HTTP 429 |
| `PRISM_STORAGE_RETENTION_DAYS` | `0` | Delete stored events and investigations older than this (0 = keep) |
| `PRISM_BACKUP_INTERVAL_HOURS` / `PRISM_BACKUP_KEEP` | `24` / `7` | Automatic backups and how many to keep |
| `PRISM_LOCAL_NETWORKS` | `[]` | Extra networks treated as this computer (Docker's internal network) |
| `PRISM_TLS_CERT_FILE` / `PRISM_TLS_KEY_FILE` | `backend/data/tls/prism.crt` / `.key` | HTTPS certificate used by the launcher |
| `PRISM_SYSLOG_ENABLED` / `_HOST` / `_PORT` | `false` / `127.0.0.1` / `5514` | Syslog receiver |
| `PRISM_FORWARD_WEBHOOK_URL` | *(empty)* | Send attack-chain alerts to a webhook |
| `PRISM_FORWARD_SPLUNK_HEC_URL` / `_TOKEN` | *(empty)* | Send alerts to Splunk HEC |
| `PRISM_FORWARD_SYSLOG_TARGET` | *(empty)* | Send alerts as CEF over syslog (`host:port`) |
| `PRISM_FORWARD_FORMAT` | `prism` | `ocsf` sends alerts as OCSF Detection Findings |

Every threshold and weight is environment-overridable — see
[.env.example](.env.example). Nothing is hardcoded in the detection logic, and
`GET /api/config` returns the live values so the UI can show the engine's own
rules.

```bash
PRISM_CORRELATION_MIN_SCORE=0.80      # stricter chain membership
PRISM_LATERAL_WINDOW_SECONDS=300      # tighter movement window
PRISM_SIMULATION_TICK_SECONDS=0.6     # faster demo replay
```

There are no secrets in the codebase. Neo4j credentials, if you enable the
optional mirror, come from the environment.

---

## Neo4j (optional)

PRISM analyses on NetworkX in process, with no external dependency. To also
mirror the entity graph into Neo4j:

```bash
.venv/Scripts/python.exe -m pip install -r backend/requirements-neo4j.txt
```

```bash
cat docs/neo4j_schema.cypher | cypher-shell -u neo4j -p <password>
```

Then set `PRISM_NEO4J_ENABLED=true` and the connection variables. The schema,
labels, relationship kinds and some example queries are in
[docs/neo4j_schema.cypher](docs/neo4j_schema.cypher). A mirror failure is logged
and swallowed — persistence never breaks detection.

---

## Project layout

```
backend/
  app/
    core/        configuration, structured JSON logging
    models/      NormalizedEvent, inventory, analysis, graph, view models
    ingest/      parsers, indicator heuristics, file loader
    graph/       NetworkX builder, Cytoscape presenter, Neo4j mirror
    engine/      correlation, MITRE, lateral movement, prediction, chains
    agents/      the nine investigation agents, tool layer, orchestrator, LLM
    services/    SocState and InvestigationService
    api/         routes, aggregates, dependencies
  data/
    demo/        the three-feed demo dataset
    inventory/   hosts, accounts, entitlements, known domains
  tests/         98 tests
frontend/
  src/
    components/  graph, timeline, intel panel, agent panels, findings, badges
    pages/       dashboard, investigation, chains, events, MITRE, hosts, users
    lib/         API client, story layout, Cytoscape stylesheet, theme
    types/       TypeScript mirrors of the backend models
docs/            architecture, API reference, dataset notes, Neo4j schema
```

---

## Documentation

- **[docs/TECHNICAL_OVERVIEW.md](docs/TECHNICAL_OVERVIEW.md)** — code, architecture, algorithms, APIs,
  AI-generated components, models, data flow, design decisions, security considerations and
  technical implementation, in one place.
- [docs/AGENTS.md](docs/AGENTS.md) — the agent layer: what each agent decides,
  the tool interface, verification, and the optional LLM guardrail
- [docs/DEMO.md](docs/DEMO.md) — a five-minute walkthrough with the exact
  numbers you should see at each step
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — pipeline, module map, and the
  reasoning behind each design decision
- [docs/API.md](docs/API.md) — full endpoint reference with payloads
- [docs/DATASET.md](docs/DATASET.md) — what the demo data is, why it is
  synthetic, and how to swap in your own
- [docs/neo4j_schema.cypher](docs/neo4j_schema.cypher) — graph schema and
  example queries

---

## Status

This is a working prototype, not a production SOC platform. It holds state in
memory, has no authentication or multi-tenancy, and its indicator lists are
small enough to read in one sitting — which is deliberate, since every finding
has to be explainable.

The engines are real: the same code path handles the demo dataset and an
uploaded one, and nothing about the demo is special-cased.
