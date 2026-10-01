# Demo walkthrough

A five-minute script for showing PRISM, with the exact numbers you should
see at each step. Every figure below comes from the bundled dataset, so if one
does not match, something is wrong.

## Setup

Start the backend and the frontend (see the README), open
**http://localhost:5173**, and make sure the top-right status strip reads
`PIPELINE READY · 56 events · 1 chains`.

If a previous run left the simulation part-way through, press **Show full
dataset** first.

---

## 1. The opening frame (20 seconds)

Say nothing and let the headline do the work:

> **Active attack detected: HR-PC → FINANCE-PC**
> Lateral Movement in progress. DC01 is the highest-scoring potential next target.

Then the six cards:

| Card | Value |
| --- | --- |
| Active attack chains | **1** |
| Correlated events | **29** of 56 ingested |
| Compromised hosts | **3** |
| Lateral movements | **2** |
| Potential targets | **4** |
| Alert reduction | **97%** — 32 raw alerts to 1 chain |

**The point to make:** 32 things a per-event console would have paged someone
about. One story here.

---

## 2. The graph (60 seconds)

The board reads left to right in the order the attack happened, because the
layout follows the timeline stages rather than the graph topology.

Trace it out loud:

- `john.doe` and `ATTACK-001` on the far left
- **HR-PC** in red — compromised
- `OUTLOOK.EXE` → `Invoice_Q3_Statement.docm` → `WINWORD.EXE` → `powershell.exe`
- `update-svc-cdn.xyz` hanging off HR-PC — the C2 domain
- a thick **orange** line to **FINANCE-PC**, the cyan node — that is inferred
  lateral movement, and cyan means *this is where the attacker is now*
- `procdump.exe`, `reg.exe`, `psexec.exe` on FINANCE-PC
- a **pink dotted** line out to **DC01** — dotted and pink means predicted

Point at the legend: shape says what an entity is, colour says what state the
backend put it in, line style says how sure we are. Nothing on this board is
hardcoded in the frontend — it all comes from `/api/graph`.

---

## 3. The timeline (30 seconds)

Below the graph, eleven stages:

```
Initial Access → Execution → Command and Control → Discovery →
Credential Access → Lateral Movement → Privilege Escalation →
Execution → Command and Control → Credential Access → Lateral Movement
```

Click **Credential Access · HR-PC**. The graph dims everything except that
stage's entities. Click it again to clear.

---

## 4. Why this is one incident (45 seconds)

Go to **Attack Chains**. Scroll to *Why these events are one incident* and pick
the link between `edr-0009` and `auth-0011`:

```
edr-0009  ↔  auth-0011                              score 1.00
  +0.35  Same account involved: john.doe
  +0.25  Shared host: HR-PC
  +0.40  HR-PC was used as the source for activity against FINANCE-PC
  +0.20  Events are 6m 13s apart
```

**The point to make:** the 0.40 factor is the one a per-alert rule cannot see.
An RDP logon on its own is not an alert. An RDP logon *from a host that was
dumping credentials six minutes ago* is the whole story.

---

## 5. Root cause (30 seconds)

On the same page, the Root Cause panel states the origin, the initial evidence
with its source event id, the eleven-step progression, and then — the part worth
reading aloud — how each statement was derived:

- Stage sequence and host attribution are **OBSERVED**
- Grouping them into one chain is **CORRELATED**
- Lateral movement is **INFERRED** by the rule engine
- DC01 is **PREDICTED**; no attacker activity has been observed on it

---

## 6. The prediction (60 seconds)

In the right-hand panel, expand **DC01 · 93/100**:

| Factor | Points | Why |
| --- | --- | --- |
| User Access | +30.0 / 30 | Compromised account john.doe is entitled to DC01 |
| Privilege | +25.0 / 25 | 2 privileged accounts can reach DC01, including admin.k |
| Connectivity | +20.0 / 20 | DC01 is 100% of the most connected host |
| Criticality | +20.0 / 20 | Domain controller, criticality 1.0, critical infrastructure |
| Recent Activity | +15.0 / 15 | Failed logon attempt against DC01 from FINANCE-PC |
| Path Proximity | +20.0 / 20 | 1 hop from the current attacker position |

Raw 130.0, normalised to **92.9/100**.

**The point to make:** there is no model here. Six numbers, each with a sentence
an analyst can disagree with, and every weight is configurable. Also note DC01 is
in `targeted_hosts`, not `hosts` — two **failed** logons prove intent, not
access, so it is never counted as compromised.

---

## 7. The false positives it did not raise (30 seconds)

Go to **Events** and clear the filters. Three findings deliberately stayed out
of the chain:

| Time | What | Why it was left alone |
| --- | --- | --- |
| 09:31 | `admin.k` RDP to DC01 | A real administrator session. No shared account, host or timing with the attack |
| 10:09 | `vendor-portal-eu.net` from IT-PC | A newly observed domain, but nothing ties it to the chain |
| 10:24 | One failed logon for `sara.lee` | One failure is a mistyped password. Three in six minutes is credential guessing — and `john.doe`'s five *were* flagged |

**The point to make:** the goal was never to generate more alerts.

---

## 8. Live replay (60 seconds)

Back on the **Dashboard**, press **Start attack simulation**.

The backend rewinds to zero and replays the dataset one event at a time,
re-running the entire pipeline after each tick. Watch for:

1. **~6 events in** — still an empty board. The morning's routine traffic
   correlates into nothing, which is the correct answer.
2. **~13 events in** — a chain appears. Current host **HR-PC**, stage
   **Credential Access**, and the top prediction is **FILE01 at 87/100**.
3. **~20 events in** — the RDP hop lands. Current host flips to **FINANCE-PC**,
   stage becomes **Lateral Movement**.
4. **Complete** — the prediction has flipped to **DC01 at 92.9/100**, because
   the attacker moved closer to it and started probing it.

**The point to make:** that prediction changed because the graph changed. It is
recomputed from scratch on every tick, not scripted.

Use **Step** to advance one event at a time if you would rather narrate it.
**Rewind** returns to an empty board.

---

## Questions you should expect

**"Is this just a rules engine?"**
Correlation and prediction are scored and weighted, not pattern-matched. No rule
anywhere says "phishing then PowerShell then RDP" — chains are connected
components of the correlation graph, so an unseen attack path works the same way.

**"Why not machine learning for the prediction?"**
Because an analyst who cannot audit a prediction will not act on it, and a black
box cannot be tuned by the team living with its false positives. The scoring is
six weighted factors precisely so it can be argued with. Section 10 of the brief
asks for exactly this.

**"Would it work on real logs?"**
The demo data is synthetic but written in the real schemas — Windows Security
event IDs, Sysmon event IDs, Zeek `dns.log` fields. Uploading a real export goes
through the identical code path; nothing about the demo is special-cased. See
[DATASET.md](DATASET.md).

**"What would you do next?"**
Persist state (it is in memory today), add authentication, widen the indicator
lists, and add parsers for cloud identity logs — the parser registry is the
single extension point.

---

# Part two: the agentic investigation

Everything above is the correlation layer. This part is the agents investigating
it. Budget another four minutes.

## 9. Open the case (30 seconds)

Go to **Investigation** and press **Start investigation**.

The nine-agent roster is on screen from the first frame, all pending. That is
deliberate: the analyst sees the plan, not agents materialising one at a time.

**The point to make:** these agents have no knowledge. Everything they say comes
from a tool call against the same analysis the dashboard is showing.

## 10. Watch it work (90 seconds)

Agents turn from pending to running to complete, each reporting what it did:

| Agent | What you should see |
| --- | --- |
| Triage | `Investigation required, severity critical` |
| Correlation | `29 related events, joined by same host (40x), same user (30x), host pivot (25x)` |
| Investigation | `Attack hypothesis confirmed (5 evidence items)` |
| Evidence | `34 record(s) behind 3 finding(s) so far` |
| Graph Reasoning | `Reachability mapped from FINANCE-PC; 2 exposed host(s)` |
| MITRE ATT&CK | `16 technique(s) across 8 tactic(s)` |
| Attack Chain | `11 stage(s), 2 host crossing(s)` |
| Next-Target | `DC01 at 93/100; then IT-PC 68, BACKUP01 50` |
| Verification | `7/7 verified, confidence 87%` |

The footer counts tool calls as they happen — it should reach **43 tool calls,
37 evidence items**.

Watch the **agent reasoning timeline** on the right fill in. Expand any step to
see the actual calls:

```
get_related_events(event_id=auth-0011, limit=40)
  3 event(s) correlate with auth-0011 at score 0.90 or better · 3 row(s)
```

**The point to make:** that is not a model describing what it might do. That is
the call it made and what came back.

## 11. Follow one claim to its source (60 seconds)

Scroll to **Findings**, open **Graph exposure from FINANCE-PC**, press
**View evidence**.

```
✓ FINANCE-PC can reach 5 host(s): BACKUP01, DC01, FILE01, HR-PC, IT-PC
    via get_host_neighbors
✓ 2 critical host(s) adjacent to FINANCE-PC: BACKUP01, DC01
    via get_attack_path
✓ john.doe is entitled to 5 host(s); reached HR-PC, FINANCE-PC, FILE01;
  attempted but not reached: DC01
    via get_user_access
✓ 2 privileged account(s) able to reach BACKUP01: admin.k, svc-backup
    via get_privileged_users

VERIFICATION
✓ All 24 cited event(s) resolve.
✓ Timestamps are consistent (2045s span).
```

**The point to make:** read the third line aloud. *Attempted but not reached.*
Two failed logons against the domain controller are intent, not access — which
is why DC01 is the top prediction and is still not counted as compromised.

## 12. Disagree with it (30 seconds)

Press **Mark false positive** on any finding.

The finding dims and keeps a `FALSE POSITIVE` badge; it does not vanish. Scroll
up: it has left the **Observed** block of the summary, and confidence has been
recomputed over what survives.

**The point to make:** the agents recommend. The analyst decides, and the
disagreement stays on the record.

## 13. The conclusion (30 seconds)

The **Attack summary** keeps three blocks apart on purpose:

- **Observed** — established from source records
- **Inferred** — rule-engine conclusions no single record states
- **Predicted** — graph scoring, explicitly not attacker activity

and ends with **recommended actions** plus the line *"Recommendations only.
PRISM does not act on hosts."*

The footer names the author: **written by the deterministic narrator**.

---

## Questions you should expect about the agents

**"Is there actually an LLM in this?"**
Not by default, and that is the design rather than a shortcut. The agents are
tool-driven: a model is optional, is only allowed to rephrase findings that are
already verified, and its output is scanned for hosts and technique ids outside
the verified set before display. Set `PRISM_LLM_PROVIDER=anthropic` and a
key to enable it; the summary footer will then name the model instead.

**"So how is this agentic?"**
Each agent decides what it needs and goes and gets it. The Investigation Agent
branches on what comes back — if an account is attached to the cluster it
follows the identity, if not it follows the process lineage. The orchestrator
skips agents whose preconditions are not met, and Triage can end the case
before anything else runs.

**"What stops it inventing evidence?"**
`AgentWorkspace.finding()` raises if handed an empty evidence list, so there is
no code path to an unsupported claim. The Verification Agent then re-derives
each finding and downgrades what does not hold. The test suite plants fabricated
evidence and asserts it gets caught.

**"Could it be wrong?"**
Yes, and it says which parts could be. Predictions are labelled, confidence is
shown per finding, verification notes are visible, and anything the analyst
rejects leaves the conclusion.
