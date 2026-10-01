"""MITRE ATT&CK Agent: no technique without evidence.

The agent is not permitted to name a technique it likes the sound of. It runs
the mapping rules over the actual source events and reports only what fired,
then spot-checks its own output by looking each technique back up and asking
whether the cited event really satisfies that rule.

That second pass looks redundant until you consider what it defends against: a
technique that is plausible for the scenario but not actually supported by the
record in front of it. That is precisely the failure mode of an LLM asked to
"map this to ATT&CK", and it is why the mapping runs through the rule table.
"""

from __future__ import annotations

from app.agents.base import Agent, AgentWorkspace
from app.agents.state import AgentName, EvidenceKind, Investigation
from app.models.analysis import Assurance

_CONFIDENCE_WEIGHT = {"high": 0.9, "medium": 0.65, "low": 0.4}


class MitreAgent(Agent):
    name = AgentName.MITRE
    label = "MITRE ATT&CK Agent"
    purpose = "Maps observed behaviour to ATT&CK, with evidence."

    def should_run(self, investigation: Investigation) -> tuple[bool, str]:
        if not investigation.attack_chain_id:
            return False, "No chain to map"
        return True, ""

    async def run(self, workspace: AgentWorkspace) -> str:
        investigation = workspace.investigation

        chain = workspace.call("get_attack_chain", chain_id=investigation.attack_chain_id)
        if not chain.found:
            await workspace.step("Looked for events to map", "No chain available.")
            return "Nothing to map"

        event_ids = sorted({eid for stage in chain.rows for eid in stage["event_ids"]})
        mapped = workspace.call("map_event_techniques", event_ids=event_ids)
        if not mapped.found:
            await workspace.step(
                "Ran the mapping rules",
                "No technique rule fired on these events.",
            )
            return "No techniques supported"

        # Collapse to one entry per technique, keeping its strongest evidence.
        best: dict[str, dict] = {}
        for row in mapped.rows:
            current = best.get(row["technique_id"])
            if current is None or _CONFIDENCE_WEIGHT.get(
                row["confidence"], 0
            ) > _CONFIDENCE_WEIGHT.get(current["confidence"], 0):
                best[row["technique_id"]] = row

        tactics = sorted({row["tactic"] for row in best.values()})
        await workspace.step(
            "Ran the mapping rules over {} source event(s)".format(len(event_ids)),
            "{} technique(s) fired across {} tactic(s).".format(len(best), len(tactics)),
        )

        # Spot-check: does the cited event genuinely satisfy each rule?
        confirmed: list[dict] = []
        rejected: list[str] = []
        evidence_ids: list[str] = []

        for technique_id, row in sorted(best.items()):
            check = workspace.call(
                "lookup_mitre_technique",
                technique_id=technique_id,
                event_id=row["event_id"],
            )
            supported = bool(check.rows) and check.rows[0].get("supported_by_event")
            if not supported:
                rejected.append(technique_id)
                continue

            confirmed.append(row)
            evidence_ids.append(
                workspace.evidence(
                    "{} {} ({})".format(
                        row["technique_id"], row["technique_name"], row["tactic"]
                    ),
                    detail="{} | source {} | {}".format(
                        row["evidence"], row["event_id"], row["explanation"]
                    ),
                    kind=EvidenceKind.MITRE,
                    event_ids=[row["event_id"]],
                    assurance=Assurance.OBSERVED,
                )
            )

        await workspace.step(
            "Re-checked each technique against its source event",
            "{} confirmed{}".format(
                len(confirmed),
                "; {} dropped as unsupported: {}".format(
                    len(rejected), ", ".join(rejected)
                )
                if rejected
                else "",
            ),
            evidence_ids=evidence_ids[:5],
        )

        if not confirmed:
            return "No technique survived verification"

        investigation.observed_techniques = [row["technique_id"] for row in confirmed]

        ordered = sorted(confirmed, key=lambda r: r["tactic_id"])
        progression = " -> ".join(
            dict.fromkeys(row["tactic"] for row in ordered)
        )
        mean_confidence = sum(
            _CONFIDENCE_WEIGHT.get(row["confidence"], 0.5) for row in confirmed
        ) / len(confirmed)

        finding = workspace.finding(
            "{} ATT&CK techniques observed".format(len(confirmed)),
            "Observed progression: {}. Every technique is backed by a source "
            "event that satisfies its mapping rule.".format(progression),
            assurance=Assurance.OBSERVED,
            confidence=round(mean_confidence, 3),
            evidence_ids=evidence_ids,
        )
        await workspace.step(
            "Reported the ATT&CK progression",
            progression,
            finding_ids=[finding],
        )

        return "{} technique(s) across {} tactic(s)".format(
            len(confirmed), len({row["tactic"] for row in confirmed})
        )
