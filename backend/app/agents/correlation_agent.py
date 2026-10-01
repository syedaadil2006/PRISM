"""Correlation Agent: do these separate alerts belong to one attack?

This agent does not re-derive correlation. The scoring engine already did that,
with named factors; re-implementing it here would give PRISM two answers to
the same question. Instead the agent interrogates the engine's output: it picks
the events that anchor the cluster, asks what correlates with them and why, and
reports which dimensions are actually carrying the link.

That distinction matters for trust. If the cluster only holds together on
timing, an analyst should know that before believing the story.
"""

from __future__ import annotations

from collections import Counter

from app.agents.base import Agent, AgentWorkspace
from app.agents.state import AgentName, EvidenceKind, Investigation
from app.models.analysis import Assurance

#: Factors that represent a real relationship rather than mere coincidence.
_SUBSTANTIVE = {
    "same_user",
    "same_host",
    "host_pivot",
    "shared_ip",
    "process_continuity",
    "domain_overlap",
}


class CorrelationAgent(Agent):
    name = AgentName.CORRELATION
    label = "Correlation Agent"
    purpose = "Tests whether separate alerts belong to one attack."

    def should_run(self, investigation: Investigation) -> tuple[bool, str]:
        if not investigation.attack_chain_id:
            return False, "No correlated cluster to examine"
        return True, ""

    async def run(self, workspace: AgentWorkspace) -> str:
        investigation = workspace.investigation
        chain = workspace.call("get_attack_chain", chain_id=investigation.attack_chain_id)
        if not chain.found:
            await workspace.step("Looked for a cluster", "Nothing to correlate.")
            return "No cluster to correlate"

        # Anchor on the pivot: the movement events are where a cluster either
        # holds together across hosts or falls apart into coincidence.
        movements = workspace.call(
            "get_lateral_movements", chain_id=investigation.attack_chain_id
        )
        anchors = [m["event_id"] for m in movements.rows]
        if not anchors:
            anchors = [chain.rows[-1]["event_ids"][0]] if chain.rows else []

        await workspace.step(
            "Selected correlation anchors",
            "Anchored on {} event(s) that join hosts: {}".format(
                len(anchors), ", ".join(anchors) or "none"
            ),
        )

        factor_counts: Counter[str] = Counter()
        linked_ids: set[str] = set()
        strongest: dict | None = None
        evidence_ids: list[str] = []

        for anchor in anchors:
            related = workspace.call("get_related_events", event_id=anchor, limit=40)
            if not related.found:
                continue
            for row in related.rows:
                linked_ids.add(row["related_event_id"])
                for factor in row["factors"]:
                    if factor["name"] in _SUBSTANTIVE:
                        factor_counts[factor["name"]] += 1
                if strongest is None or row["score"] > strongest["score"]:
                    strongest = dict(row, anchor=anchor)

            evidence_ids.append(
                workspace.evidence(
                    related.summary,
                    detail="Strongest link {:.2f} to {}".format(
                        related.rows[0]["score"], related.rows[0]["related_event_id"]
                    ),
                    source=related,
                    assurance=Assurance.CORRELATED,
                )
            )

        if strongest is None:
            await workspace.step(
                "Examined the correlation graph",
                "No scored links found; these events do not join up.",
            )
            return "No supporting correlation"

        pivot_factors = [
            f for f in strongest["factors"] if f["name"] == "host_pivot"
        ]
        detail = "; ".join(
            "{} (+{:.2f})".format(f["detail"], f["weight"]) for f in strongest["factors"]
        )
        strongest_evidence = workspace.evidence(
            "Strongest link: {} to {} at {:.2f}".format(
                strongest["anchor"], strongest["related_event_id"], strongest["score"]
            ),
            detail=detail,
            kind=EvidenceKind.CORRELATION,
            event_ids=[strongest["anchor"], strongest["related_event_id"]],
            assurance=Assurance.CORRELATED,
        )
        evidence_ids.append(strongest_evidence)

        await workspace.step(
            "Read the scoring factors behind each link",
            detail,
            evidence_ids=[strongest_evidence],
        )

        # State the conclusion, and be explicit about what is carrying it.
        carried_by = ", ".join(
            "{} ({}x)".format(name.replace("_", " "), count)
            for name, count in factor_counts.most_common(4)
        )
        if pivot_factors:
            statement = (
                "These events are one attack. {} is decisive: {}. "
                "Supporting dimensions: {}."
            ).format(
                "The host pivot",
                pivot_factors[0]["detail"],
                carried_by or "timing only",
            )
            confidence = min(0.95, 0.75 + 0.05 * len(factor_counts))
        elif factor_counts:
            statement = (
                "These events are likely one attack, joined by {}. "
                "No host pivot was observed, so the link is associative rather "
                "than causal."
            ).format(carried_by)
            confidence = 0.62
        else:
            statement = (
                "These events share only timing. That is not enough to call them "
                "one attack."
            )
            confidence = 0.3

        finding = workspace.finding(
            "Events belong to one attack chain"
            if factor_counts
            else "Correlation is weak",
            statement,
            assurance=Assurance.CORRELATED,
            confidence=confidence,
            evidence_ids=evidence_ids,
        )
        investigation.metrics.correlated_events = len(set(chain.event_ids))

        await workspace.step(
            "Concluded on cluster membership",
            statement,
            evidence_ids=evidence_ids[-1:],
            finding_ids=[finding],
        )
        return "{} related events, joined by {}".format(
            len(set(chain.event_ids)), carried_by or "timing alone"
        )
