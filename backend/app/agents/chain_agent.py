"""Attack Chain Agent: turn events into a story a person can hold in their head.

The stages already exist -- the rule-based engine built them. What this agent
adds is the reading: which stage is the origin, where the story crosses from one
host to another, and which stage represents where the attacker is now rather
than merely the last thing that happened to be logged.

It also checks the story for the thing that most often breaks a reconstructed
timeline: stages that are out of order with respect to their own evidence.
"""

from __future__ import annotations

from datetime import datetime

from app.agents.base import Agent, AgentWorkspace
from app.agents.state import AgentName, EvidenceKind, Investigation
from app.models.analysis import Assurance


class AttackChainAgent(Agent):
    name = AgentName.CHAIN
    label = "Attack Chain Agent"
    purpose = "Reconstructs the chronological attack story."

    def should_run(self, investigation: Investigation) -> tuple[bool, str]:
        if not investigation.attack_chain_id:
            return False, "No chain to reconstruct"
        return True, ""

    async def run(self, workspace: AgentWorkspace) -> str:
        investigation = workspace.investigation

        chain = workspace.call("get_attack_chain", chain_id=investigation.attack_chain_id)
        if not chain.found:
            await workspace.step("Looked for a chain", "None available.")
            return "No chain to reconstruct"

        stages = chain.rows
        timeline = [
            "{} {} on {}".format(
                s["timestamp"][11:19], s["tactic"], s["host"] or "unknown host"
            )
            for s in stages
        ]
        story_evidence = workspace.evidence(
            chain.summary,
            detail=" | ".join(timeline),
            source=chain,
            assurance=Assurance.CORRELATED,
        )
        await workspace.step(
            "Ordered the stages chronologically",
            " -> ".join(s["tactic"] for s in stages),
            evidence_ids=[story_evidence],
        )

        # Check the ordering actually holds against the stage timestamps.
        times = [datetime.fromisoformat(s["timestamp"]) for s in stages]
        out_of_order = [
            i for i in range(1, len(times)) if times[i] < times[i - 1]
        ]
        if out_of_order:
            await workspace.step(
                "Checked chronological consistency",
                "{} stage(s) are out of order against their own timestamps.".format(
                    len(out_of_order)
                ),
            )
        else:
            await workspace.step(
                "Checked chronological consistency",
                "All {} stages are in timestamp order.".format(len(stages)),
            )

        # Where does the story cross hosts? That is the spine of the narrative.
        crossings: list[str] = []
        previous_host = None
        for stage in stages:
            host = stage["host"]
            if previous_host and host and host != previous_host:
                crossings.append("{} -> {}".format(previous_host, host))
            previous_host = host or previous_host

        movements = workspace.call(
            "get_lateral_movements", chain_id=investigation.attack_chain_id
        )
        movement_evidence = workspace.evidence(
            movements.summary,
            detail="; ".join(
                "{} via {} at {}".format(
                    "{} -> {}".format(m["source_host"], m["destination_host"]),
                    m["method"],
                    m["timestamp"][11:19],
                )
                for m in movements.rows
            ),
            source=movements,
            assurance=Assurance.INFERRED,
        )
        await workspace.step(
            "Identified where the story crosses hosts",
            "; ".join(crossings) or "the activity stays on one host",
            evidence_ids=[movement_evidence],
        )

        first, last = stages[0], stages[-1]
        investigation.initial_host = (
            chain.meta.get("initial_host") or investigation.initial_host or first["host"]
        )
        investigation.current_host = (
            chain.meta.get("current_host") or investigation.current_host or last["host"]
        )
        investigation.current_stage = (
            chain.meta.get("current_stage") or investigation.current_stage or last["tactic"]
        )

        statement = (
            "The chain runs {} across {} stage(s), beginning with {} on {} at {}. "
            "The attacker is currently operating from {}, at the {} stage."
        ).format(
            " -> ".join(dict.fromkeys(s["tactic"] for s in stages)),
            len(stages),
            first["tactic"],
            first["host"],
            first["timestamp"][11:19],
            investigation.current_host,
            chain.meta.get("current_stage") or last["tactic"],
        )
        if out_of_order:
            statement += " Note: some stages are not in timestamp order."

        finding = workspace.finding(
            "Attack chain reconstructed",
            statement,
            assurance=Assurance.CORRELATED,
            confidence=0.6 if out_of_order else 0.87,
            evidence_ids=[story_evidence, movement_evidence],
        )
        await workspace.step(
            "Published the reconstructed chain",
            statement,
            finding_ids=[finding],
        )

        return "{} stage(s), {} host crossing(s)".format(len(stages), len(crossings))
