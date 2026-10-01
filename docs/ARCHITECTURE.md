# PRISM architecture

PRISM turns three independent log feeds into one attack story. This
document describes how, and why each stage is shaped the way it is.

## Two layers

PRISM is a rule-based correlation pipeline with an agentic investigation
layer on top of it. The division of labour is strict:

* the **pipeline** decides what happened, and
* the **agents** decide what to do about it, using only what the pipeline and
  the tool layer can tell them.

The agents never reimplement detection. When the Next-Target Agent reports a
score it called `score_next_targets`, which runs the same prediction engine the
dashboard uses; there is one implementation and therefore one answer. See
[AGENTS.md](AGENTS.md) for the agent layer in detail.

## Pipeline

```
 log files / uploads
        |
        v
 [1] Ingestion        parsers per vendor format  ->  NormalizedEvent
        |
        v
 [2] Enrichment       cross-event aggregates (beaconing, credential guessing)
        |
        v
 [3] Graph build      NetworkX entity graph + inventory context
        |
        v
 [4] Correlation      scored, explained event-to-event links
        |
        v
 [5] Chain detection  connected components -> AttackChain
        |             + MITRE mapping, stages, lateral movement
        v
 [6] Prediction       explainable next-target scoring
        |
        v
 [7] Presentation     trimmed Cytoscape payload + REST API
```

Every stage is a pure function of its input except stage 7, which reads the
shared analysis held by `SocState`. That single ownership point is why the
graph, the chain list and the statistics can never disagree: they are all
derived from one `Analysis` object produced by one `recompute()` call.

## Module map

| Stage | Module | Responsibility |
| --- | --- | --- |
| 1 | `app/ingest/parsers.py` | Vendor formats in, `NormalizedEvent` out |
| 1 | `app/ingest/indicators.py` | Readable heuristics that flag suspicious behaviour |
| 1-2 | `app/ingest/loader.py` | File decoding, directory ingest, cross-event enrichment |
| 3 | `app/graph/builder.py` | NetworkX entity graph, connectivity, path maths |
| 3 | `app/graph/neo4j_store.py` | Optional Neo4j mirror |
| 4 | `app/engine/correlation.py` | Pairwise scoring with named factors |
| 5 | `app/engine/attack_chain.py` | Components, stages, risk, root cause |
| 5 | `app/engine/mitre.py` | Technique rules with evidence and explanation |
| 5 | `app/engine/lateral.py` | The lateral-movement rule engine |
| 6 | `app/engine/prediction.py` | Six-factor target scoring |
| 7 | `app/graph/presenter.py` | The Cytoscape payload |
| 7 | `app/api/routes.py` | HTTP surface |
| - | `app/services/soc_state.py` | Owns state, ingestion and the demo simulation |
| - | `app/core/config.py` | Every threshold and weight, all environment-overridable |

### The agent layer

| Module | Responsibility |
| --- | --- |
| `app/agents/tools.py` | The 17 evidence-retrieval tools and the call recorder |
| `app/agents/base.py` | The workspace that makes evidence mandatory |
| `app/agents/triage.py` and the eight beside it | One specialised agent each |
| `app/agents/orchestrator.py` | Which agents run, in what order, and when to stop |
| `app/agents/llm.py` | Optional narrative provider, swappable |
| `app/agents/narrative.py` | The summary, and the faithfulness guard on it |
| `app/services/investigation_service.py` | Investigation lifecycle and analyst verdicts |

## Design decisions

### Normalization is the extension point
Adding Zeek `conn.log`, Okta, or CloudTrail means writing one parser and
registering it in `PARSERS`. Nothing downstream knows vendor field names, so no
engine changes. `detect_format` sniffs the shape, so uploads work without a
format hint.

### Only notable events enter chains
`correlate()` considers only events where `is_notable` holds: suspicious, or at
least medium severity, or a high-signal action. Routine business traffic is
still ingested, still queryable, and still available as context, but it cannot
drag an attack chain wider. This is the main false-positive control.

### Correlation is additive and named
Each dimension contributes a named, weighted factor with a sentence. Time
proximity alone is capped below the threshold, so two unrelated events one
second apart never link. The strongest single factor is `host_pivot`: a
compromised host being used as the source of activity against a new host. That
is precisely the signal a per-alert SIEM rule cannot see.

DNS records carry no account, so they would otherwise float free. The
`suspicious_coincidence` factor attaches them: two independently suspicious
events on one host inside the window reinforce each other.

### Chains are graph components, not rules
Correlations form a graph over notable events; each connected component above
`min_chain_events` becomes a chain. No rule enumerates "phishing then PowerShell
then RDP". The story emerges from the evidence, which is why the same engine
handles an attack path it has never seen.

### Reached versus targeted
A failed logon proves intent, not access. `_reached_and_targeted` puts the
destination of a failed authentication in `targeted_hosts`, never in `hosts`.
This is what keeps a predicted next target out of the compromised-host count --
and it is why DC01 can be both "actively targeted" and "not yet compromised".

### Current position means code execution
`_current_host` prefers the most recent endpoint event over the most recent
logon, because execution is stronger evidence of presence than an
authentication. An admin share mount moves a host into the chain without
claiming the attacker is operating from it.

### Prediction is arithmetic, not a model
Six weighted factors, each reporting its own points, ceiling and sentence,
normalised to 0-100. A deliberate choice: an analyst who cannot audit a
prediction will not act on it, and a black box cannot be tuned by the team that
has to live with its false positives.

### The frontend renders, it does not decide
`/api/graph` returns node states (`compromised`, `current_position`,
`potential_target`) and edge assurance. The UI maps those to shape, colour and
line style, and nothing else. Point it at a different dataset and the picture
changes with no frontend edits.

### Layout follows the story, not the topology
A hierarchical or force layout arranges a host/process graph by its edges, which
on a star-shaped graph produces a tangle. `frontend/src/lib/storyLayout.ts`
instead lays out one column per timeline stage: the graph reads left to right in
the order the attack actually happened.

### Agents may not assert what they did not retrieve

`AgentWorkspace.finding()` raises on an empty evidence list, and
`AgentWorkspace.evidence()` stamps each fact with the tool call that produced
it. The constraint lives in the code rather than in a prompt, which is what
makes it hold regardless of which agent is running, or whether a model is
involved at all.

### Verification is allowed to disagree

The Verification Agent re-derives each finding through the same tools and
downgrades what it cannot reproduce, recording why. A finding that fails is
annotated rather than deleted: removing it would hide the disagreement, which is
the one thing an analyst most needs to see.

### The model, if present, may only rephrase

An LLM is never asked for a fact. It receives findings that are already verified
and returns prose, which is then scanned for hosts and technique ids outside the
verified set and discarded if it introduces one. A model that cannot supply a
fact cannot fabricate one.

## Assurance labelling

Every statement PRISM makes carries how it was derived. This is enforced in
the models, not just the UI.

| Label | Meaning | Produced by |
| --- | --- | --- |
| `observed` | Straight from a source log record | parsers, MITRE mappings |
| `correlated` | Several events grouped by shared identity/host/address/time | correlation engine |
| `inferred` | Rule-engine conclusion no single record states | lateral movement |
| `predicted` | Risk-based graph scoring, not attacker activity | prediction engine |

## State and concurrency

`SocState` holds all mutable state and guards mutations with an `asyncio.Lock`.
The demo simulator is an asyncio task that reveals events one tick at a time and
recomputes after each, so the replay exercises the real pipeline rather than
animating a fixed picture. Recompute over the demo dataset takes a few
milliseconds, which is what makes per-tick recomputation practical.

## Persistence

Analysis always runs on NetworkX, in process, with no external dependency. When
`PRISM_NEO4J_ENABLED=true`, the entity graph is additionally mirrored into
Neo4j using the schema in `neo4j_schema.cypher`. A mirror failure is logged and
swallowed: persistence must never break detection.
