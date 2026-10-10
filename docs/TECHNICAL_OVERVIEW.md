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
| Ingestion | `backend/app/ingest/` | Parsers for Windows Security, Sysmon, Zeek DNS, native PRISM events, Splunk exports and Elastic Common Schema (Winlogbeat, Filebeat, Elastic Agent); format auto-detection; cross-event enrichment |
| Engine | `backend/app/engine/` | `correlation.py`, `attack_chain.py`, `lateral.py`, `mitre.py`, `prediction.py` |
| Graph | `backend/app/graph/` | NetworkX entity graph, presentation graph for the UI, optional Neo4j mirror |
| Agents | `backend/app/agents/` | Nine investigation agents, tool layer, orchestrator, narrator, report renderer |
| Services | `backend/app/services/` | `soc_state.py` (owns events and analysis), `investigation_service.py`, `live_feed.py`, `storage.py` (SQLite persistence) |
| Security | `backend/app/core/auth.py`, `backend/app/api/auth_routes.py` | API access code, sign-in cookie |
| Integrations | `backend/app/api/siem_routes.py`, `backend/app/services/syslog_receiver.py`, `backend/app/services/forwarder.py`, `scripts/siem_pull.py` | Splunk HEC endpoint, syslog receiver, alert forwarding (webhook, Splunk HEC, CEF), Splunk/Elastic pull connector |
| API | `backend/app/api/` | FastAPI routers: core, agents, live feed, sign-in |
| Frontend | `frontend/src/` | React + TypeScript dashboard (Simple and Analyst views, Cytoscape.js graph) |
| Tests | `backend/tests/` | 169 automated tests (pytest) |
| Launcher | `Start PRISM.bat`, `scripts/start-prism.ps1` | System check, permission-based setup, start-up |
| Live feeders | `scripts/live_replay.py`, `scripts/live_windows_collector.ps1` | Real-time data sources |

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

**Routine-event suppression** (`ingest/loader.py`)
* Windows writes a privileged-logon event (4672) for every administrator session and for its own
  service and computer accounts. These stay in the event list but are marked `suppressed` with the
  reason, and cannot start or extend a chain:
  * service accounts (SYSTEM, LOCAL/NETWORK SERVICE, DWM-*, UMFD-*, `HOST$`) and unattributed logons
  * repeats for the same account and host within 10 minutes (only the first counts)
  * the computer's own console user: a privileged logon for someone who signed in, unlocked or
    approved an administrator (UAC) prompt at that same computer (local logon types 2, 7, 11 from
    the computer itself). Privileged logons arriving remotely (for example over RDP) still count.
* Reverse-DNS (`*.in-addr.arpa`) and single-label local names are not treated as newly observed
  domains or beaconing.

**Correlation** (`engine/correlation.py`)
* Candidate pairs come from an index of shared entities (host, IP, account, domain), because a pair
  sharing none of them cannot reach the threshold. This gives exactly the same result as scoring
  every pair, at a fraction of the cost.
* Above 1,500 notable events (large real datasets), each event is compared with its 30 most recent
  neighbours per shared entity and keeps its 10 strongest links to earlier events. This keeps chains
  connected and memory linear.
* Every candidate pair of notable events within a **1,800 s** window is scored as a weighted sum of named factors:
  host pivot 0.40, same user 0.35, same host 0.25, suspicious coincidence 0.25, time proximity 0.25,
  shared IP 0.20, process on host 0.15, domain overlap 0.15.
* Links scoring at least **0.70** are kept, each with the factors that produced it.

**Attack chains** (`engine/attack_chain.py`)
* Chains are the **connected components** of the correlation graph (minimum 2 events).
* A cluster made only of sign-ins is not reported: a chain needs at least one piece of attack
  behaviour (an event a detection rule flagged as suspicious, or notable process, file or DNS
  activity) before any host is called compromised or any account is marked compromised.
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

REST, JSON, documented interactively at **`/docs`** (OpenAPI). Every `/api` call except `/api/health` and
sign-in needs the access code (section 9). Main groups:

| Group | Endpoints |
|---|---|
| System | `GET /api/health`, `GET /api/config` |
| Dashboard | `GET /api/stats`, `/api/attacks`, `/api/attacks/{id}`, `/api/events`, `/api/correlations`, `/api/graph`, `/api/hosts`, `/api/users`, `/api/mitre`, `/api/predictions` |
| Ingestion | `POST /api/logs/ingest` (file upload), `POST /api/logs/reset` |
| Simulation | `GET /api/simulation`, `POST /api/simulation/start · pause · resume · step · reset` |
| OCSF | `GET /api/ocsf/events` (`?chain_id=`, `?format=ndjson`), `GET /api/ocsf/findings`, `GET /api/ocsf/info` |
| Sign-in | `GET /api/auth/status`, `POST /api/auth/login`, `POST /api/auth/logout`, `POST /api/auth/password` |
| Admin | `GET/POST /api/admin/users`, `PATCH/DELETE /api/admin/users/{name}`, `GET /api/admin/audit`, `GET /api/admin/audit/verify` |
| Agents | `GET /api/agents/roster`, `/api/agents/tools`; `POST/GET /api/agents/investigations`; `…/{id}`, `…/timeline`, `…/evidence`, `…/report?format=html\|md`; `POST …/findings/{finding_id}/decision`, `POST …/cancel` |
| Live feed | `POST /api/live/events`, `GET /api/live/status`, `POST /api/live/start`, `POST /api/live/flush`, `GET /api/live/integrations` |
| Splunk HEC (compatible) | `POST /services/collector/event` (also `/services/collector`, `/event/1.0`), `GET /services/collector/health` |

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
* **Event schema:** PRISM's own normalized schema (custom JSON, below). **OCSF 1.3** is supported for
  import and export (`backend/app/ocsf.py`): Authentication 3002, Authorize Session 3003, Process Activity 1007,
  File System Activity 1001, DNS Activity 4003, and attack chains as Detection Finding 2004.
* **Data models:** Pydantic v2 schemas in `backend/app/models/` (`NormalizedEvent`, `Correlation`,
  `AttackChain`, `LateralMovement`, `MitreMapping`, `TargetPrediction`, `Inventory`, graph and view
  models) and agent state in `backend/app/agents/state.py` (investigations, findings, evidence, steps).
* **Graph model:** a NetworkX `MultiDiGraph` of users, hosts, processes, domains, IPs and files, with
  events as edges.
* **Optional LLM:** the provider and model are configurable (`PRISM_LLM_PROVIDER`, `PRISM_LLM_MODEL`);
  it is used for wording only (section 5).

## 7. Data flow

0. **Inventory:** the demo and BOTS datasets come with an inventory of their (fictional or recorded)
   organisation. Real-time mode starts with **no** inventory, so only computers and accounts actually
   seen on this machine appear; `PRISM_INVENTORY_FILE` can point at a real inventory for the site.
1. **In:** log files (startup dataset or upload), the live push API, the watched folder
   `backend/data/live/`, or the Windows collector. Uploaded and live events are also saved to
   SQLite, so they survive a restart.
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
| Access code instead of user accounts | Protects the API with no account management; one-click start still works |
| SQLite for persistence, stored per data choice | No server to install; demo, BOTS and live data never mix |
| Suppress routine Windows events instead of deleting them | Real networks are dominated by routine admin logons; keeping them visible preserves the record |

## 9. Security considerations

**In place**
* **Local-only (edge) mode, on by default and enforced in code.** Requests from any other machine are
  refused (403) even if the server listens on the network; alerts can only be forwarded to this computer;
  the optional language model is never used; syslog listens only on 127.0.0.1; the dashboard loads no
  outside resources; the collector and scripts refuse remote targets. A running server deliberately
  bound to 0.0.0.0 with outside alert targets and the language model configured opened **no** outgoing
  connections. `PRISM_LOCAL_ONLY=false` is the only way to switch this off.
* **API access code.** Every `/api` request except the health check and sign-in needs a code: a random
  32-character value generated on first start and stored in `backend/data/.prism_token` (git-ignored), or
  set with `PRISM_AUTH_TOKEN`. Scripts send it as `X-PRISM-Token` (or `Authorization: Bearer`); the
  dashboard exchanges it for an **HttpOnly, SameSite=Strict** session cookie. Codes are compared in
  constant time. `Start PRISM.bat` opens the dashboard signed in by passing the code in the URL
  fragment, which browsers never send to the server; the dashboard removes it from the address bar.
* **Named accounts and roles.**
  * Roles are viewer (read), analyst (also investigate and add data) and admin (also accounts, audit log and
    clearing data). They are enforced on every request: 401 when nobody is signed in, 403 when the role is
    too low.
  * Passwords are salted scrypt hashes and need at least 12 characters.
  * Session tokens are random and stored only as SHA-256 hashes. They expire after 12 h and are revoked when
    an account is disabled, deleted, changes role or changes password.
  * Five failed sign-ins per account or per address within 15 minutes give 429.
  * Admins cannot disable, demote or delete themselves.
* **Audit log.** Sign-ins, failed sign-ins, account changes, every change made through the API and every
  refused request are appended to a hash-chained log (`backend/app/core/security_store.py`).
  `GET /api/admin/audit/verify` recomputes the chain and names the first changed or missing entry.
  Truncating the newest entries is not detectable without write-once or external storage.
* **HTTPS and browser hardening.** With a certificate (`scripts/make-tls-cert.ps1` or the organisation's
  own) the launcher serves PRISM over HTTPS. The session cookie is then `Secure` and HSTS is sent.
  Content-Security-Policy, X-Frame-Options DENY, nosniff and Referrer-Policy are sent on every response.
* **Offline at runtime.** No external calls while PRISM runs; in local-only mode this is enforced.
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

* **Syslog has no authentication** (as the protocol defines): the receiver is off by default and binds
  to `localhost` unless network mode is chosen. The live API and Splunk HEC endpoint always need the
  access code, also in network mode.
* **Alert forwarding** only sends to targets the operator configured; no target is set by default.

**Known limitations (prototype)**
* **One shared access code, no individual user accounts or roles,** and no HTTPS of its own. Keep it on
  `localhost`, or put it behind HTTPS before exposing it on a network.
* **The database (`backend/data/prism.db`) is not encrypted.** It holds event data and investigations.
* **The access code file is readable by any program running as the same Windows user.**
* **Network mode sends logs and the access code over plain HTTP;** use it only on a trusted network, or
  put PRISM behind HTTPS.
* **The Splunk and Elastic connectors** were verified against real Splunk 10.6 and Elasticsearch 8.17
  running locally (single node, demo data), not yet against a large production deployment.
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

**Measured on BOTS v1 (19,672 events), after the Phase 2 work:**
* about 9 s from launch to ready (before: about 60 s)
* about 220 MB of server memory (before: about 4 GB)
* 100 alerts and 4 chains (before: 5,043 alerts and 8 noisy chains)
* the main chain on WE8105DESK (malicious attachment, script execution, the Cerber ransomware domain,
  admin-share access) is investigated at 74% confidence with 5 of 8 findings verified
* the triage agent declines two smaller chains on WE9041SRV (file-share access, repeated DNS lookups),
  because they show no escalating behaviour

**Accuracy:** on the labelled synthetic scenario, PRISM's chain matches the documented attack events
with 100% precision and recall. That scenario was written by the team, so this is **not** a claim
about real-world accuracy. No accuracy claim is made for real data yet.
