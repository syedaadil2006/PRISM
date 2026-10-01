"""Next-Target Agent: where could this go, and how sure are we.

The scoring is not done here. It is done by the prediction engine, which the
agent calls; that keeps one set of numbers in the system. What the agent adds is
the checking: it takes the top candidate and independently confirms the two
claims the score rests on -- that the compromised account is entitled to that
host, and that the host is actually reachable from where the attacker is.

It also enforces the wording. The agent may say a host is the highest-scoring
candidate on current evidence. It may not say the attacker will go there.
"""

from __future__ import annotations

from app.agents.base import Agent, AgentWorkspace
from app.agents.state import AgentName, EvidenceKind, Investigation
from app.models.analysis import Assurance


class NextTargetAgent(Agent):
    name = AgentName.NEXT_TARGET
    label = "Next-Target Agent"
    purpose = "Scores where the attacker could go next."

    def should_run(self, investigation: Investigation) -> tuple[bool, str]:
        if not investigation.attack_chain_id:
            return False, "No chain to project forward"
        if not investigation.current_host:
            return False, "Attacker position unknown"
        return True, ""

    async def run(self, workspace: AgentWorkspace) -> str:
        investigation = workspace.investigation

        scored = workspace.call("score_next_targets", chain_id=investigation.attack_chain_id)
        if not scored.found:
            await workspace.step(
                "Scored reachable candidates",
                "No candidate scored above zero.",
            )
            return "No candidates"

        candidates = scored.rows
        top = candidates[0]
        investigation.potential_targets = [c["host"] for c in candidates]

        breakdown = "; ".join(
            "{} +{:.0f}/{:.0f}".format(f["name"], f["points"], f["max_points"])
            for f in top["factors"]
            if f["points"] > 0
        )
        score_evidence = workspace.evidence(
            "{} scores {:.0f}/100 (raw {:.1f})".format(
                top["host"], top["score"], top["raw_score"]
            ),
            detail=breakdown,
            source=scored,
            assurance=Assurance.PREDICTED,
        )
        await workspace.step(
            "Scored reachable candidates",
            "{} candidate(s); {} leads at {:.0f}/100.".format(
                len(candidates), top["host"], top["score"]
            ),
            evidence_ids=[score_evidence],
        )

        # Independently check the two claims the score depends on.
        reachable = workspace.call(
            "get_attack_path",
            source_host=investigation.current_host,
            target_host=top["host"],
        )
        path_ok = reachable.found
        path_evidence = workspace.evidence(
            reachable.summary,
            source=reachable,
            assurance=Assurance.OBSERVED,
        )

        entitled = False
        access_evidence = None
        if investigation.user:
            access = workspace.call("get_user_access", user=investigation.user)
            entitled = any(
                row["host"].upper() == top["host"].upper() and row["entitled"]
                for row in access.rows
            )
            access_evidence = workspace.evidence(
                "{} {} entitled to {}".format(
                    investigation.user, "is" if entitled else "is NOT", top["host"]
                ),
                source=access,
                assurance=Assurance.OBSERVED,
            )

        await workspace.step(
            "Checked the claims the score rests on",
            "Reachable: {}. Account entitled: {}.".format(
                "yes" if path_ok else "no", "yes" if entitled else "no"
            ),
            evidence_ids=[e for e in [path_evidence, access_evidence] if e],
        )

        # Confidence follows the checks, not the raw score.
        confidence = top["score"] / 100.0
        caveats: list[str] = []
        if not path_ok:
            confidence *= 0.5
            caveats.append("no path to it exists in the known topology")
        if investigation.user and not entitled:
            confidence *= 0.7
            caveats.append("the compromised account is not entitled to it")

        statement = (
            "{} is currently the highest-scoring potential next target at "
            "{:.0f}/100, based on {}. This is an inference from graph context, "
            "not observed attacker activity on {}."
        ).format(top["host"], top["score"], breakdown, top["host"])
        if caveats:
            statement += " Caveats: " + "; ".join(caveats) + "."

        evidence_ids = [score_evidence, path_evidence]
        if access_evidence:
            evidence_ids.append(access_evidence)

        finding = workspace.finding(
            "Potential next target: {}".format(top["host"]),
            statement,
            assurance=Assurance.PREDICTED,
            confidence=round(confidence, 3),
            evidence_ids=evidence_ids,
        )
        await workspace.step(
            "Reported the potential next target",
            statement,
            finding_ids=[finding],
        )

        runners_up = ", ".join(
            "{} {:.0f}".format(c["host"], c["score"]) for c in candidates[1:3]
        )
        return "{} at {:.0f}/100{}".format(
            top["host"], top["score"], "; then " + runners_up if runners_up else ""
        )
