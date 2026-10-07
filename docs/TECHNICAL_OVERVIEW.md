# PRISM – Technical Overview

**Team FORTZ · Byteathon · Problem statement BYT04**
*Reconstructing Multi-Stage Cyberattacks and Anticipating Lateral Movement by Correlating
Fragmented Security Telemetry Across Networked Systems.*

This document explains and justifies how PRISM is built: code, architecture, algorithms, APIs,
AI-generated components, models, data flow, design decisions, security considerations and the
technical implementation. Every number below comes from the code or from measurements on the
bundled data; limitations are stated where they exist.

---

## 1. Code

| Area | Location | Purpose |
|---|---|---|
| Ingestion | `backend/app/ingest/` | Parsers for Windows Security, Sysmon, Zeek DNS, native PRISM events and Splunk BOTS v1 exports; format auto-detection; cross-event enrichment |
| Engine | `backend/app/engine/` | `correlation.py`, `attack_chain.py`, `lateral.py`, `mitre.py`, `prediction.py` |
| Graph | `backend/app/graph/` | NetworkX entity graph, presentation graph for the UI, optional Neo4j mirror |
| Agents | `backend/app/agents/` | Nine investigation agents, tool layer, orchestrator, narrator, report renderer |
| Services | `backend/app/services/` | `soc_state.py` (owns events and analysis), `investigation_service.py`, `live_feed.py` |
| API | `backend/app/api/` | FastAPI routers: core, agents, live feed |
| Frontend | `frontend/src/` | React + TypeScript dashboard (Simple and Analyst views, Cytoscape.js graph) |
| Tests | `backend/tests/` | 109 automated tests (pytest) |
| Launcher | `Start PRISM.bat`, `scripts/start-prism.ps1` | System check, permission-based setup, start-up |
| Live feeders | `scripts/live_replay.py`, `scripts/live_windows_collector.ps1`, `Start Live Demo.bat` | Real-time data sources |

## 2. Architecture

```
 Log sources                         PRISM backend (FastAPI, Python)                    Dashboard (React)
 ───────────                         ───────────────────────────────                    ─────────────────
 Windows Security ─┐
 Sysmon ───────────┼─► Ingestion ─► Normalization ─► Entity graph ─► Correlation ─► Attack chains ─► REST API ─► Simple view
 Zeek DNS ─────────┤   (files,       + enrichment     (NetworkX)      engine          + lateral                  Analyst view
 BOTS v1 export ───┤    upload,                                                       movement                   Investigation
 Live feed ────────┘    live API,                                                     + MITRE                    Reports
                        watched folder)                                               + prediction
                                                                                         │
                                                                    Agent layer (9 agents, 17 tools) ─► findings + report
```

* **One state owner.** `SocState` holds all events and re-runs the whole pipeline in a single
  `recompute()` path, so the graph, chains and statistics can never disagree.
* **The UI polls** the REST API every 1.5–4 s instead of holding sockets open.
* **Single process.** When the dashboard is built, FastAPI also serves it, so the prototype runs
  as one process on one port (8000). Neo4j is an optional mirror, off by default.

## 3. Algorithms

All detection logic is **rule-based and additive, not learned**, so every result can be explained.

**Normalization and enrichment** (`ingest/`)
* Each source is mapped to one `NormalizedEvent` schema (time, type, action, user, source/destination
  host and IP, process, command line, domain, severity, tags).
* Aggregate findings no single line can show: **5+ lookups of one domain from one host within 600 s**
  become beaconing (`HIGH_VOLUME_DNS`); **3+ failed logons for one account within 600 s** become
  credential guessing.

**Correlation** (`engine/correlation.py`)
* Every pair of notable events within a **1,800 s** window is scored as a weighted sum of named factors:
  host pivot 0.40, same user 0.35, same host 0.25, suspicious coincidence 0.25, time proximity 0.25,
  shared IP 0.20, process on host 0.15, domain overlap 0.15.
* Links scoring at least **0.70** are kept, each with the factors that produced it.

**Attack chains** (`engine/attack_chain.py`)
* Chains are the **connected components** of the correlation graph (minimum 2 events).
* Each event's stage is its most confident MITRE tactic; stages are ordered by kill-chain order.
* Initial host = first compromised host; current host = latest endpoint execution. A failed logon
  counts as *targeted*, not *reached*.

**Lateral movement** (`engine/lateral.py`), written clause by clause:
```
IF   a host was recently associated with suspicious activity (within 600 s)
AND  that host is the source of authentication / network activity
AND  the activity reaches another host
AND  the same account is involved
AND  the correlation score is at least 0.70
THEN "Lateral Movement in Progress"   (every fired clause is recorded)
```

**MITRE ATT&CK mapping** (`engine/mitre.py`)
* **19 named rules.** Each has a predicate, an evidence string built from the actual event, and a
  plain-English reason. No keyword matching.

**Next-target prediction** (`engine/prediction.py`)
```
Score = User access (30) + Privilege (25) + Graph connectivity (20)
      + Host criticality (20) + Recent activity (15) + Attack-path proximity (20)
normalised to 0–100 against a ceiling of 140; top 4 reported
```
Every factor is shown with its points and reason. Results are always labelled **PREDICTED**.

**Agent investigation** (`agents/`)
* Nine agents run in order: Triage → Correlation → Investigation → Evidence → Graph → MITRE →
  Chain → Next-Target → Verification.
* They work only through **17 tools** (log searches, host neighbours, user access, attack path,
  related events, privileged users, host profile, MITRE lookups, next-target scoring, chain and
  lateral-movement lookups).
* **A finding cannot be created without at least one evidence id.**
* The Verification agent re-checks every finding and **downgrades** what does not hold, rather than
  silently dropping it.

## 4. APIs

REST, JSON, documented interactively at **`/docs`** (OpenAPI). Main groups:

| Group | Endpoints |
|---|---|
| System | `GET /api/health`, `GET /api/config` |
| Dashboard | `GET /api/stats`, `/api/attacks`, `/api/attacks/{id}`, `/api/events`, `/api/correlations`, `/api/graph`, `/api/hosts`, `/api/users`, `/api/mitre`, `/api/predictions` |
| Ingestion | `POST /api/logs/ingest` (file upload), `POST /api/logs/reset` |
| Simulation | `GET /api/simulation`, `POST /api/simulation/start · pause · resume · step · reset` |
| Agents | `GET /api/agents/roster`, `/api/agents/tools`; `POST/GET /api/agents/investigations`; `…/{id}`, `…/timeline`, `…/evidence`, `…/report?format=html\|md`; `POST …/findings/{finding_id}/decision`, `POST …/cancel` |
| Live feed | `POST /api/live/events`, `GET /api/live/status`, `POST /api/live/start`, `POST /api/live/flush` |

## 5. AI-generated components

* **At runtime, PRISM's detections are not produced by AI.** Correlation, chains, lateral movement,
  MITRE mapping and prediction are deterministic rules (section 3).
* **The nine "agents" are deterministic Python components.** They call tools and apply rules; no
  language model is needed or used by default (`narrator: deterministic`).
* **Optional language model** (`agents/llm.py`, off by default, `PRISM_LLM_PROVIDER=anthropic`, needs
  an API key). It is only allowed to re-phrase the summary of findings that are already verified.
  A faithfulness check rejects any text mentioning a host or technique id that is not in the verified
  set, and falls back to the deterministic text.
* **Development.** Much of the source code, tests and documentation was written with the help of an
  AI coding assistant, under the team's direction. The behaviour is verified by the automated test
  suite (section 10).
* The project's video and logo artwork were made with an AI image/video tool. They are not part of
  the software.

## 6. Models

* **No trained machine-learning model.** There is no training data, no learned weights and no model
  file; all thresholds and weights are visible in `backend/app/core/config.py` and can be changed with
  `PRISM_` environment variables.
* **Data models:** Pydantic v2 schemas in `backend/app/models/` (`NormalizedEvent`, `Correlation`,
  `AttackChain`, `LateralMovement`, `MitreMapping`, `TargetPrediction`, `Inventory`, graph and view
  models) and agent state in `backend/app/agents/state.py` (investigations, findings, evidence, steps).
* **Graph model:** a NetworkX `MultiDiGraph` of users, hosts, processes, domains, IPs and files, with
  events as edges.
* **Optional LLM:** the provider and model are configurable (`PRISM_LLM_PROVIDER`, `PRISM_LLM_MODEL`);
  it is used for wording only (section 5).

## 7. Data flow

1. **In:** log files (startup dataset or upload), the live push API, the watched folder
   `backend/data/live/`, or the Windows collector.
2. **Parse and normalize** each record to `NormalizedEvent`; malformed records are reported one by
   one instead of failing the batch.
3. **Enrich** across events (beaconing, credential guessing) and sort chronologically.
4. **Build** the entity graph, **score** correlations, **group** them into chains, **detect** lateral
   movement, **map** MITRE techniques, **score** next targets.
5. **Serve** the results through the API; the dashboard polls and redraws.
6. **On request,** agents investigate a chain through the tool layer, the Verification agent checks
   them, and an analyst approves, rejects or marks each finding as a false positive. Reports are
   produced as HTML (printable to PDF) or Markdown.

**Bundled demo result:** 56 events → 32 alerts → **1 attack chain** (HR-PC → FINANCE-PC, FILE01
reached, DC01 predicted at 92.9/100), 16 MITRE techniques, 2 lateral movements.

## 8. Design decisions

| Decision | Reason |
|---|---|
| Rule-based, additive scoring instead of a learned model | Every conclusion must be explainable and retunable by an analyst; no labelled training data was available |
| Assurance label on every statement: **observed / correlated / inferred / predicted** | A guess must never look like a fact |
| Agents must cite evidence; verification downgrades instead of deleting | Prevents unsupported AI-style conclusions while keeping them visible |
| LLM optional and limited to wording | Works fully offline; a model cannot invent hosts or techniques |
| Whole-pipeline recompute from one state owner | Graph, chains and statistics always agree; simpler to reason about |
| Polling instead of WebSockets | Simpler and robust for a prototype |
| Two views (Simple and Analyst) | Non-technical people and analysts both need to understand the same incident |
| Live feed re-analysis throttled (≥ 1 s, ≥ 2× last run time) | A fast sender gets an immediate answer without overloading the pipeline |
| Launcher asks before installing anything or collecting data | User consent; transparent to the user and to antivirus tools |

## 9. Security considerations

**In place**
* **Offline by default.** No external calls at runtime unless the optional LLM is enabled.
* **No secrets in the code.** Keys and passwords only come from environment variables
  (`.env` is git-ignored; `.env.example` has empty values).
* **CORS** is limited to local development origins.
* **Input handling.** Every record is parsed independently; malformed input returns an error instead
  of crashing. Live requests are capped at 5,000 records; stored live events are capped at 50,000.
* **Reports** HTML-escape all event-derived text.
* **The Windows collector only reads event logs,** sends them only to the PRISM address given, and
  starts only after the user agrees. Administrator rights are requested through Windows' own UAC
  prompt, which the user can refuse.
* **The launcher** installs only for the current user, from official sources, with no administrator
  rights, and asks first.

**Known limitations (prototype)**
* **No authentication or authorization on the API.** It is meant to run on `localhost`; it must not
  be exposed on a network as-is.
* **State is in memory.** A restart clears uploads, live events and investigations.
* **The live push endpoint accepts data from any local process.**
* **Not hardened against adversarial log injection** beyond per-record validation.

## 10. Technical implementation

| Layer | Technology |
|---|---|
| Backend | Python 3.11–3.14 (tested on 3.12 and 3.14), FastAPI 0.115, Uvicorn 0.34, Pydantic 2.12, pydantic-settings 2.11, NetworkX 3.4 |
| Frontend | React 18, TypeScript 5, Vite 6, Tailwind CSS 3, Cytoscape.js 3, React Router 6 |
| Optional | Neo4j (graph mirror), Anthropic API (narrative wording), Docker Compose |
| Data | Synthetic demo scenario (56 events); Splunk Boss of the SOC v1 (CC0) Cerber scenario |
| Tests | 109 pytest tests, passing on Python 3.12 and 3.14 |

**Measured on the bundled demo:**
* full analysis in about 20 ms per re-run
* server ready in 2.5 s
* about 68 MB of memory
* an agent investigation (43 tool calls, 37 evidence items, 87% confidence) computes in under 0.1 s
  (the UI paces it at about 0.5 s per step so it can be followed)

**Measured on BOTS v1 (19,672 events):**
* 64.8 s to analyse
* about 4 GB of memory
* 8 noisy chains
* the integration works, but is **not tuned yet**

**Accuracy:** on the labelled synthetic scenario, PRISM's chain matches the documented attack events
with 100% precision and recall. That scenario was written by the team, so this is **not** a claim
about real-world accuracy. No accuracy claim is made for real data yet.
