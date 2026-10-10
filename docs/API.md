# PRISM API

Base URL `http://localhost:8000/api`. Interactive documentation is generated
from the code at `/docs`; the OpenAPI schema is at `/openapi.json`.

All timestamps are ISO-8601 UTC. All responses are JSON.

## Assurance

Several payloads carry an `assurance` field. It is the contract that keeps a
prediction from being mistaken for a fact:

| Value | Meaning |
| --- | --- |
| `observed` | Taken directly from a source log record |
| `correlated` | Events grouped by shared identity, host, address or timing |
| `inferred` | Produced by the lateral-movement rule engine |
| `predicted` | Risk-based graph scoring, not observed attacker activity |

---

## System

### `GET /api/health`
Liveness plus a summary of what is loaded.

```json
{
  "status": "ok",
  "version": "0.1.0",
  "events": 56,
  "chains": 1,
  "sources": ["01_windows_security.csv", "02_sysmon.jsonl", "03_zeek_dns.jsonl"],
  "ingest_errors": [],
  "computed_at": "2026-09-30T10:21:31Z"
}
```

### `GET /api/config`
Every threshold and weight behind the detections, so the UI (or a reviewer) can
show the engine's own rules. Mirrors `app/core/config.py`.

---

## Dashboard

### `GET /api/stats`

```json
{
  "active_attack_chains": 1,
  "correlated_events": 29,
  "total_events": 56,
  "compromised_hosts": 3,
  "lateral_movements": 2,
  "potential_targets": 4,
  "mitre_techniques": 16,
  "raw_alert_count": 32,
  "alert_reduction_ratio": 0.9688
}
```

`raw_alert_count` is how many alerts a per-event console would have raised;
`active_attack_chains` is how many stories PRISM shows instead.
`alert_reduction_ratio` is `0.0` until something actually correlates.

---

## Attack chains

### `GET /api/attacks`
Every chain, highest risk first. Optional `?status=active`.

Each chain carries `initial_host`, `current_host`, `current_stage`, `users`,
`hosts` (reached), `targeted_hosts` (attempted, not reached), `stages`, `mitre`,
`lateral_movements`, `predictions` and `root_cause`.

### `GET /api/attacks/{chain_id}`
The chain plus the evidence behind it.

```json
{
  "chain": { "attack_chain_id": "ATTACK-001", "...": "..." },
  "events": [ { "event_id": "edr-0006", "...": "..." } ],
  "correlations": [
    {
      "source_event_id": "edr-0004",
      "target_event_id": "edr-0006",
      "score": 0.93,
      "time_delta_seconds": 53.0,
      "factors": [
        { "name": "same_user", "weight": 0.35, "detail": "Same account involved: john.doe" },
        { "name": "same_host", "weight": 0.25, "detail": "Shared host: HR-PC" }
      ]
    }
  ]
}
```

Returns `404` for an unknown chain id.

---

## Events

### `GET /api/events`
Normalized events, newest first.

| Query | Meaning |
| --- | --- |
| `event_type` | `authentication`, `dns` or `endpoint` |
| `host` | Matches source or destination host |
| `user` | Exact account match |
| `suspicious_only` | Only events the normalizer flagged |
| `chain_id` | Only events belonging to one chain |
| `limit` | 1-2000, default 500 |

Every event keeps its untouched `raw` record, so any finding can be traced back
to the original log line. Human-readable reasons are carried as `finding:` tags.

### `GET /api/correlations`
Scored links with their factors. Optional `event_id` returns only links touching
that event; `limit` defaults to 300.

---

## Graph

### `GET /api/graph`
The Cytoscape.js payload. Optional `chain_id` focuses one chain.

```json
{
  "nodes": [
    {
      "id": "host:FINANCE-PC",
      "label": "FINANCE-PC",
      "kind": "host",
      "state": "current_position",
      "assurance": "observed",
      "attack_chain_ids": ["ATTACK-001"],
      "stage_order": 6,
      "metadata": { "role": "workstation", "criticality": 0.5, "ip": "10.0.2.20" }
    }
  ],
  "edges": [
    {
      "id": "host:FINANCE-PC|PREDICTED_MOVE|host:DC01",
      "source": "host:FINANCE-PC",
      "target": "host:DC01",
      "kind": "PREDICTED_MOVE",
      "label": "Potential target (93/100)",
      "assurance": "predicted",
      "predicted": true,
      "event_ids": []
    }
  ],
  "stats": { "nodes": 22, "edges": 34, "predicted_edges": 4, "compromised_hosts": 3 }
}
```

Node `kind`: `user`, `host`, `ip`, `domain`, `process`, `file`, `event`, `attack`.
Node `state`: `normal`, `suspicious`, `compromised`, `current_position`,
`potential_target`.
Edge `kind`: `LOGGED_INTO`, `ACCESSES`, `RESOLVED`, `EXECUTED`, `CONNECTED_TO`,
`GENERATED`, `OCCURRED_ON`, `INVOLVES`, `PART_OF`, `DROPPED`, `LATERAL_MOVE`,
`PREDICTED_MOVE`.

`stage_order` is the timeline stage a node belongs to; the frontend uses it both
to highlight a stage and to lay the graph out in story order.

---

## Inventory

### `GET /api/hosts`
Inventory joined with observed activity: `state`, `event_count`,
`prediction_score`, `criticality`, `users`, `attack_chain_ids`.

### `GET /api/users`
Identities with `privilege`, `groups`, `accessible_hosts` (entitlements),
`hosts_observed`, `failed_logons` and `compromised`.

---

## MITRE

### `GET /api/mitre`
Techniques grouped by tactic in kill-chain order. Every technique lists its
`evidence`: one mapping per source event, each with the evidence string, the
rule's explanation and its confidence.

---

## Predictions

### `GET /api/predictions`
Potential next targets across all chains, highest score first.

```json
{
  "host": "DC01",
  "raw_score": 130.0,
  "score": 92.9,
  "confidence": "high",
  "assurance": "predicted",
  "is_critical_infrastructure": true,
  "factors": [
    {
      "name": "User Access",
      "points": 30.0,
      "max_points": 30.0,
      "detail": "Compromised account john.doe is entitled to DC01"
    }
  ],
  "narrative": "DC01 is a potential next target at 93/100, driven mainly by ..."
}
```

The six factors are User Access, Privilege, Connectivity, Criticality, Recent
Activity and Path Proximity. `points` always sum to `raw_score`, and `score` is
`raw_score` normalised against `prediction_normalisation_ceiling`.

---

## Ingestion

### `POST /api/logs/ingest`
`multipart/form-data` with one or more `files`. Accepts CSV, JSON, JSON-lines.

Optional `?log_format=` one of `windows_security`, `sysmon`, `zeek_dns`,
`prism`. Omit it and the format is detected per record.

```bash
curl -X POST http://localhost:8000/api/logs/ingest \
  -F "files=@backend/data/demo/02_sysmon.jsonl"
```

```json
{ "accepted": 17, "rejected": 0, "total_events": 73, "errors": [], "sources": ["..."] }
```

Malformed records are reported in `errors` rather than failing the whole upload.
The full pipeline re-runs before the response returns.

### `POST /api/logs/reset`
Discard ingested data and reload the configured dataset.

---

## Demo mode

| Endpoint | Effect |
| --- | --- |
| `GET /api/simulation` | Current replay progress |
| `POST /api/simulation/start` | Replay from the beginning |
| `POST /api/simulation/pause` | Freeze where it is |
| `POST /api/simulation/resume` | Continue a paused replay |
| `POST /api/simulation/step?count=N` | Reveal the next N events manually |
| `POST /api/simulation/reset?show_all=true` | Drop gating and show everything |

While the simulation is gating, the analysis only sees the revealed prefix of
the dataset, and the whole pipeline re-runs after each tick. The replay is the
real engine running on a growing event set, not a scripted animation.

---

## Agentic investigation layer

All paths below are under `/api/agents`. Reads are safe to poll: an
investigation in flight returns its partially complete state, which is what lets
the UI watch the agents work.

### `GET /api/agents/roster`
The agent line-up and the layer's configuration, including who narrates.

```json
{
  "enabled": true,
  "narrator": "deterministic",
  "llm_configured": false,
  "step_delay_seconds": 0.55,
  "agents": [
    { "agent": "triage", "label": "Triage Agent", "purpose": "...", "order": 1 }
  ]
}
```

`narrator` is `"deterministic"` when no LLM is configured. The UI displays it,
because an analyst reading a summary is entitled to know who wrote it.

### `GET /api/agents/tools`
The evidence-retrieval tools, with JSON schemas. This is the tool-calling
interface: the same catalogue an LLM provider would be handed if it were driving
the investigation directly.

### `POST /api/agents/investigations`
Open an investigation. Optional `?chain_id=`; defaults to the highest-risk
chain. Returns immediately with the roster laid out; the agents run in the
background. `400` if no chain exists or the id is unknown.

### `GET /api/agents/investigations`
Every investigation, newest first, as compact rows with `agents_complete` /
`agents_total` for progress.

### `GET /api/agents/investigations/latest`
The most recent investigation in full, or `null`.

### `GET /api/agents/investigations/{id}`
One investigation: agents, steps, findings, evidence, metrics and summary.

```json
{
  "investigation_id": "INV-8E82A1",
  "status": "complete",
  "initial_host": "HR-PC",
  "current_host": "FINANCE-PC",
  "current_stage": "Lateral Movement",
  "user": "john.doe",
  "observed_techniques": ["T1566.001", "T1059.001", "T1003.001"],
  "potential_targets": ["DC01", "IT-PC"],
  "evidence_count": 37,
  "confidence": 0.87,
  "metrics": {
    "raw_events": 56, "notable_events": 32, "correlated_events": 29,
    "suspicious_clusters": 1, "attack_chains": 1, "investigations": 1,
    "false_positive_candidates": 3, "tool_calls": 43,
    "evidence_items": 37, "investigation_seconds": 17.22
  }
}
```

Each **finding** carries `assurance`, `confidence`, `evidence_ids`, `verified`,
`verification_notes`, `confidence_before_verification` and any
`analyst_decision`. Each **evidence item** carries `source_tool`,
`source_call_id` and `event_ids`.

### `GET /api/agents/investigations/{id}/timeline`
The agent reasoning timeline: concise actions, the tool calls each one made with
their arguments and result counts, and the findings produced.

Private deliberation is not recorded and not exposed. What is here is what a
reviewer can disagree with.

### `GET /api/agents/investigations/{id}/evidence`
Evidence for the investigation, or for one finding via `?finding_id=`.

```json
{
  "investigation_id": "INV-8E82A1",
  "finding_id": "fi-2a9c41b0de",
  "count": 4,
  "evidence": [
    {
      "evidence_id": "ev-...",
      "summary": "john.doe is entitled to 5 host(s); reached HR-PC, FINANCE-PC, FILE01; attempted but not reached: DC01",
      "source_tool": "get_user_access",
      "source_call_id": "tc-...",
      "event_ids": ["auth-0011", "edr-0009"],
      "assurance": "observed"
    }
  ],
  "source_event_ids": ["auth-0011", "edr-0009"]
}
```

Every id in `source_event_ids` resolves through `GET /api/events`.

### `POST /api/agents/investigations/{id}/findings/{finding_id}/decision`
Record the analyst's verdict. `?decision=approved|rejected|false_positive`, with
an optional `{"note": "..."}` body.

A rejected finding is kept and excluded from the summary rather than deleted:
the disagreement is part of the record. Investigation confidence is recomputed
over the findings that survive.

### `POST /api/agents/investigations/{id}/cancel`
Stop an investigation that is still running.

## OCSF

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/ocsf/events` | Analysed events as OCSF 1.3. `chain_id` limits to one attack chain; `format=ndjson` gives one event per line |
| `GET` | `/api/ocsf/findings` | Attack chains as OCSF Detection Findings (class 2004) |
| `GET` | `/api/ocsf/info` | Supported classes and endpoints |

OCSF input needs no separate endpoint: events with a `class_uid` and `metadata` object are detected
automatically by every ingestion path (classes 3002, 3003, 1007, 1001, 4003).

## Sign-in

Every `/api` request except `GET /api/health` and the endpoints below needs the access code, sent as
`X-PRISM-Token: <code>`, `Authorization: Bearer <code>`, or the `prism_session` cookie. Without it
the API answers `401` with `WWW-Authenticate: Bearer`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/auth/status` | `enabled`, `authenticated`, `user`, `role`, `kind` (`user` or `access-code`) |
| `POST` | `/api/auth/login` | Body `{"username": "...", "password": "..."}` or `{"token": "<code>"}`; sets an HttpOnly, SameSite=Strict cookie (Secure over HTTPS). 401 if wrong, 429 after repeated failures |
| `POST` | `/api/auth/logout` | Ends the session |
| `POST` | `/api/auth/password` | Body `{"current_password", "new_password"}`; signs out your other sessions |

Roles: `viewer` may read; `analyst` may also use every other `POST`; `admin` may also use `/api/admin/*`,
`POST /api/logs/reset` and `POST /api/live/start`. A role that is too low gets `403`.

## Operations

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/metrics` | Prometheus text format: `prism_http_requests_total`, `prism_http_request_seconds` histogram, `prism_events`, `prism_attack_chains`, `prism_ingest_queue`, `prism_analysis_runs_total`, ... (any signed-in role) |
| `GET` | `/api/admin/backups` | Backups on this computer, newest first (admin) |
| `POST` | `/api/admin/backups` | Back up the databases now; returns the manifest with checksums (admin) |

`POST /api/live/events` answers `429` with `Retry-After` when more than `PRISM_LIVE_MAX_PENDING` events are
waiting for analysis; `GET /api/live/status` shows `queued` and `max_queued`.

## Admin (admin role)

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/admin/users` | Accounts: `username`, `role`, `disabled`, `created_at`, `last_login` |
| `POST` | `/api/admin/users` | Body `{"username", "password", "role"}` (201) |
| `PATCH` | `/api/admin/users/{username}` | Body with any of `role`, `disabled`, `password` |
| `DELETE` | `/api/admin/users/{username}` | Delete the account (204) |
| `GET` | `/api/admin/audit` | Newest entries first; `limit`, `actor`, `action` filters |
| `GET` | `/api/admin/audit/verify` | `{"ok", "entries", "first_broken", "reason"}` |

## Splunk HEC (compatible)

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/services/collector/event` | HEC events, back to back: `{"time": ..., "host": ..., "sourcetype": ..., "event": {...}}`. Auth: `Authorization: Splunk <access code>`. Replies with HEC codes: 0 Success, 2 Token is required (401), 4 Invalid token (403), 5 No data, 6 Invalid data format, 12 Event field is required. Plain-text events are counted as skipped. |
| `GET` | `/services/collector/health` | `{"text": "HEC is healthy", "code": 17}` |

## Live feed

Real-time ingestion. See "Real-time feed" in the README.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/live/events?source=<name>&format=<fmt>` | Push records as they happen: one JSON object, a JSON array, `{"records": [...]}`, JSON-lines, or CSV (`Content-Type: text/csv`). `format` is optional (`windows_security`, `sysmon`, `zeek_dns`, `prism`, `botsv1`). At most 5,000 records per request (413 above that). Returns `received`, `accepted`, `duplicates`, `rejected`, `errors`, `total_events`. |
| `GET` | `/api/live/status` | Events received per source, events per minute, whether events arrived in the last 30 s, and whether the analysis has caught up |
| `POST` | `/api/live/start?clear=true` | Switch to live analysis; with `clear=true` the bundled dataset is dropped (`POST /api/logs/reset` restores it) |
| `GET` | `/api/live/integrations` | Syslog receiver, alert forwarding, storage and authentication status |
| `POST` | `/api/live/flush` | Re-run the analysis now instead of waiting for the background loop (about 1 s) |

Event ids are prefixed with the source name (`edr-laptop:edr-0001`), so different senders never
collide, and a resent record is counted once.
