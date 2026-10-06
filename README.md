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

## Quick start

### One click (Windows)

Double-click **`Start PRISM.bat`**. The launcher (`scripts/start-prism.ps1`) runs in three steps:

1. **Checks this computer**: Windows 10 or newer (64-bit), processor, memory (4 GB minimum), free disk space
   (2 GB minimum) and whether port 8000 is free.
2. **Checks what PRISM needs**: Python 3.11+, Node.js 18+, the backend packages, the dashboard packages and
   the dashboard build.
3. **Asks before installing anything.** If something is missing it lists exactly what it will download, from
   where and where it will go, and waits for you to answer **Y**. Answering **N** installs nothing.

| Missing | What the launcher installs (with your permission) |
|---|---|
| Python 3.11+ | Python 3.12 for your user account, via winget or the official python.org installer |
| Node.js 18+ | A portable Node.js LTS from nodejs.org, unpacked into `.tools/node` |
| Backend packages | Creates `.venv` and installs `backend/requirements.txt` from pypi.org |
| Dashboard packages and build | `npm ci` from npmjs.org, then `npm run build` |

No administrator rights are needed, nothing is installed system-wide, and no security or antivirus settings
are changed. The first setup needs an internet connection; later launches skip every satisfied step and start
in seconds. Packages are reinstalled when `requirements.txt` or `package-lock.json` change, the dashboard is
rebuilt when its source changes (for example after `git pull`), and a `.venv` copied from another computer is
rebuilt. PRISM then runs on http://localhost:8000 in a minimised window; close that window to stop it.

### Manual setup

Requires Python 3.11+ and Node 18+.

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
docker compose up --build
```

UI on http://localhost:5173, API on http://localhost:8000. To also run the
optional Neo4j mirror: `docker compose --profile neo4j up --build`.

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

## Configuration

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
