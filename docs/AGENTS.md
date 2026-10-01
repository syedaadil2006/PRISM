# The agentic investigation layer

PRISM's rule-based pipeline answers *what happened*. The agent layer
answers *what should I do about it*, by running an investigation the way an
analyst would: forming a hypothesis, deciding what would test it, retrieving the
records, and checking the conclusion before presenting it.

The difference from a chatbot bolted onto a dashboard is structural, and it
comes down to one rule:

> An agent cannot state anything it did not retrieve through a tool.

That is enforced in code, not in a prompt. `AgentWorkspace.finding()` raises if
handed an empty evidence list, and `AgentWorkspace.evidence()` stamps every fact
with the tool call that produced it. There is no path to an unsupported claim.

---

## What runs, and in what order

```
                        ORCHESTRATOR
                             |
      +----------------------+----------------------+
      v                      v                      v
   TRIAGE  ------------> CORRELATION ------> INVESTIGATION
   is this worth          are these one        what actually
   a human's time?        attack?              happened?
      |                      |                      |
      +----------------------+----------------------+
                             v
                          EVIDENCE
                   make every citation resolve
                             |
      +----------------------+----------------------+
      v                      v                      v
    GRAPH                  MITRE                  CHAIN
   reachability          techniques,            the story, in
   and access            with evidence          order
      |                      |                      |
      +----------------------+----------------------+
                             v
                        NEXT TARGET
                     where could this go
                             |
                             v
                        VERIFICATION
                   re-derive everything, downgrade
                   what does not hold
                             |
                             v
                       FINAL SOC STORY
```

Triage is the only agent that can end the investigation early. If it finds no
escalating behaviour, everything downstream is marked skipped with a reason, and
no case is opened. An agentic layer that opens a case for everything has moved
alert fatigue, not fixed it.

Each agent can also decline. `should_run()` returns a reason, which is recorded
on the agent's row, so a skipped agent is visible rather than absent.

---

## The nine agents

| Agent | Decides | Key tools |
| --- | --- | --- |
| **Triage** | Whether this warrants a human at all; severity; who and what is involved | `get_attack_chain`, `search_events` |
| **Correlation** | Whether separate alerts are one attack, and which factors carry the link | `get_related_events`, `get_lateral_movements` |
| **Investigation** | The plan: forms a hypothesis and branches on what it finds | `search_endpoint_logs`, `search_auth_logs`, `search_dns_logs`, `get_user_access` |
| **Evidence** | That every finding cites source events that actually resolve | `search_events` |
| **Graph Reasoning** | Reachability, entitlement, distance to critical infrastructure | `get_host_neighbors`, `get_attack_path`, `get_privileged_users` |
| **MITRE ATT&CK** | Which techniques the evidence supports, then re-checks each one | `map_event_techniques`, `lookup_mitre_technique` |
| **Attack Chain** | The chronological story, and whether it is internally consistent | `get_attack_chain`, `get_lateral_movements` |
| **Next-Target** | Where the attacker could go, and whether the score's premises hold | `score_next_targets`, `get_attack_path`, `get_user_access` |
| **Verification** | Whether any of the above survives re-derivation | all of them |

### The Investigation Agent branches

It does not run a fixed script. What it asks next depends on what came back:

1. Pull flagged endpoint activity on the origin host.
2. Form a hypothesis from the actions present (delivery? execution? credentials?).
3. **If an account is attached**, follow its entitlements and authentication
   history. **If not**, say so and work the process lineage instead.
4. Check outbound DNS, which carries no identity and would otherwise float free.
5. Trace where the activity reached.
6. Confirm, partially support, or reject the hypothesis, and say which.

The third step is where a report generator and an investigator diverge.

---

## The tool layer

Seventeen tools across four categories, in `app/agents/tools.py`. Every one
reads the same analysis the dashboard reads and wraps the same engines the
rule-based pipeline uses. `GET /api/agents/tools` returns their JSON schemas --
the same catalogue an LLM provider would be handed if it were driving.

```
logs      search_auth_logs      search_dns_logs       search_endpoint_logs
          search_events
graph     get_host_neighbors    get_user_access       get_attack_path
          get_related_events    get_recent_activity   get_privileged_users
          get_host_profile
mitre     lookup_mitre_technique  lookup_mitre_tactic  map_event_techniques
analysis  score_next_targets    get_attack_chain      get_lateral_movements
```

Two consequences of routing everything through here:

* **Traceability.** Every claim resolves to a tool call, to source event ids, to
  the original vendor log record.
* **No drift.** The agents cannot reach a different conclusion from the
  rule-based layer, because there is only one implementation of each piece of
  analysis. `test_scoring_tool_matches_the_prediction_engine` asserts this.

### Attempt is not access

`get_user_access` reports `activity_seen` and `access_succeeded` separately. In
the demo data `john.doe` is entitled to five hosts, reached three, and *attempted
but did not reach* DC01. A layer that collapsed those two into "observed on"
would report the domain controller as compromised on the strength of two failed
logons.

---

## Verification

The agent exists because the rest of the system is only as trustworthy as its
weakest claim. It re-derives what each finding rests on and compares:

* Does the finding cite any source event at all?
* Do those ids still resolve to records?
* Is the evidence span consistent with the correlation window?
* Is a predicted target actually reachable from the attacker's position?
* Is a causal claim being made where only correlation was established?
* Does a movement claim match a recorded detection?

A finding that fails is **downgraded and annotated, not deleted**. Silently
dropping a conclusion hides the disagreement; marking it surfaces it.
`test_verification_downgrades_a_finding_with_unresolvable_evidence` plants a
fabricated evidence item and asserts the check catches it.

---

## The optional LLM

**The agents do not need a model.** Configure none and everything above runs.

When `PRISM_LLM_PROVIDER` is set, a model may rephrase the summary
paragraph over findings that are *already verified*. It is never asked to supply
a fact. Its output then passes a faithfulness check that scans for host names
and technique ids outside the verified set; anything that introduces one is
discarded in favour of the deterministic text.

```
verified findings --> LLM rephrases --> faithfulness check --> display
                                              |
                                        fails: use deterministic text
```

The UI names the author in the summary footer, because an analyst reading a
conclusion is entitled to know who wrote it.

Swapping provider means adding a class to `app/agents/llm.py`. No agent changes.

---

## Investigation state

```json
{
  "investigation_id": "INV-8E82A1",
  "status": "complete",
  "initial_host": "HR-PC",
  "current_host": "FINANCE-PC",
  "current_stage": "Lateral Movement",
  "user": "john.doe",
  "observed_techniques": ["T1566.001", "T1059.001", "T1003.001", "T1021.001"],
  "evidence_count": 37,
  "confidence": 0.87,
  "potential_targets": ["DC01", "IT-PC"],
  "metrics": {
    "raw_events": 56,
    "notable_events": 32,
    "correlated_events": 29,
    "suspicious_clusters": 1,
    "attack_chains": 1,
    "investigations": 1,
    "false_positive_candidates": 3,
    "tool_calls": 43,
    "evidence_items": 37,
    "investigation_seconds": 17.22
  }
}
```

Each finding carries its assurance, confidence, verification verdict and
evidence ids. Each evidence item carries its source tool, call id and source
event ids.

---

## Human in the loop

The agents recommend. The analyst decides, and nothing here touches a host.

`POST /api/agents/investigations/{id}/findings/{finding_id}/decision` accepts
`approved`, `rejected` or `false_positive`. A rejected finding stays on the
record, leaves the summary, and the investigation confidence is recomputed over
what survives.

Recommended actions are phrased as recommendations and tested to stay that way:
`test_summary_recommends_and_never_acts` fails the build if the summary ever
claims an action was taken.

---

## The metrics are measured, not claimed

The funnel on the investigation page is counted from the data actually loaded:

```
56 raw events -> 32 would alert -> 29 correlated -> 1 cluster -> 1 chain -> 1 investigation
```

The three flagged events left out of the chain are named on the page. No
percentage improvement is asserted beyond what this dataset produced. On a
different dataset the numbers will differ, and the page will say so.

---

## What this layer does not do

* It does not act on hosts. There is no containment path in the code.
* It does not persist investigations. They live in memory and are capped at
  `PRISM_AGENTS_MAX_INVESTIGATIONS`.
* It does not learn. The scoring is arithmetic with published weights, on
  purpose: an analyst who cannot audit a conclusion will not act on it.
* It does not expose private deliberation. The timeline records actions, tool
  calls and conclusions -- the things a reviewer can disagree with.
