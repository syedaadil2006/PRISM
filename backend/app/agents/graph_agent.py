"""Graph Reasoning Agent: the graph is the memory, not the conversation.

Every question this agent answers is answered by querying the graph, never by
recalling something an earlier agent said. That is deliberate. Facts that live
in a conversation drift; facts that live in the graph can be re-derived by
anyone, including the Verification Agent, which re-runs several of these same
queries later and compares.

The questions are the ones an analyst actually asks at this point in a case:
where can this account go, what does this host touch, and how far is the
attacker from something that matters.
"""

from __future__ import annotations

from app.agents.base import Agent, AgentWorkspace
from app.agents.state import AgentName, EvidenceKind, Investigation
from app.models.analysis import Assurance


class GraphReasoningAgent(Agent):
    name = AgentName.GRAPH
    label = "Graph Reasoning Agent"
    purpose = "Answers reachability and access questions from the graph."

    def should_run(self, investigation: Investigation) -> tuple[bool, str]:
        if not investigation.current_host and not investigation.initial_host:
            return False, "No host to reason about"
        return True, ""

    async def run(self, workspace: AgentWorkspace) -> str:
        investigation = workspace.investigation
        position = investigation.current_host or investigation.initial_host
        account = investigation.user
        evidence_ids: list[str] = []

        # Which hosts does the attacker's current position touch?
        neighbors = workspace.call("get_host_neighbors", host=position)
        neighbor_evidence = workspace.evidence(
            neighbors.summary,
            source=neighbors,
            assurance=Assurance.OBSERVED,
        )
        evidence_ids.append(neighbor_evidence)
        await workspace.step(
            "Queried reachability from {}".format(position),
            neighbors.summary,
            evidence_ids=[neighbor_evidence],
        )

        # Which of those matter?
        critical = [r for r in neighbors.rows if r["critical_infrastructure"]]
        if critical:
            names = [r["host"] for r in critical]
            paths: list[str] = []
            for name in names:
                path = workspace.call(
                    "get_attack_path", source_host=position, target_host=name
                )
                if path.found:
                    paths.append(path.rows[0]["path"])
            path_evidence = workspace.evidence(
                "{} critical host(s) adjacent to {}: {}".format(
                    len(critical), position, ", ".join(names)
                ),
                detail="; ".join(" -> ".join(p) for p in paths),
                kind=EvidenceKind.GRAPH,
                node_ids=neighbors.node_ids,
            )
            evidence_ids.append(path_evidence)
            await workspace.step(
                "Measured distance to critical infrastructure",
                "{} is adjacent to {}".format(position, ", ".join(names)),
                evidence_ids=[path_evidence],
            )
        else:
            names = []

        # Where could the compromised account go that it has not been yet?
        unreached: list[str] = []
        if account:
            access = workspace.call("get_user_access", user=account)
            unreached = [
                r["host"] for r in access.rows if not r["access_succeeded"]
            ]
            access_evidence = workspace.evidence(
                access.summary,
                detail="Entitled but not yet reached: "
                + (", ".join(unreached) or "none"),
                source=access,
            )
            evidence_ids.append(access_evidence)
            await workspace.step(
                "Mapped the account's remaining reach",
                "{} is entitled to {} host(s) it has not reached: {}".format(
                    account, len(unreached), ", ".join(unreached) or "none"
                ),
                evidence_ids=[access_evidence],
            )

        # Who else holds privilege on the infrastructure in question?
        if names:
            privileged = workspace.call("get_privileged_users", host=names[0])
            priv_evidence = workspace.evidence(
                privileged.summary,
                source=privileged,
            )
            evidence_ids.append(priv_evidence)
            await workspace.step(
                "Checked privileged relationships on {}".format(names[0]),
                privileged.summary,
                evidence_ids=[priv_evidence],
            )

        # State what the graph says, without overstating it.
        exposed = sorted(set(unreached) & {r["host"] for r in neighbors.rows})
        if exposed:
            statement = (
                "From {}, the compromised account can reach {} without further "
                "escalation. {} of those are critical infrastructure."
            ).format(
                position,
                ", ".join(exposed),
                len([h for h in exposed if h in names]) or "None",
            )
            confidence = 0.85
        elif names:
            statement = (
                "{} is adjacent to critical infrastructure ({}), but the "
                "compromised account is not entitled to it on current inventory."
            ).format(position, ", ".join(names))
            confidence = 0.6
        else:
            statement = (
                "{} has no adjacency to critical infrastructure in the known "
                "topology.".format(position)
            )
            confidence = 0.5

        finding = workspace.finding(
            "Graph exposure from {}".format(position),
            statement,
            assurance=Assurance.OBSERVED,
            confidence=confidence,
            evidence_ids=evidence_ids,
        )
        await workspace.step(
            "Summarised graph exposure",
            statement,
            finding_ids=[finding],
        )

        return "Reachability mapped from {}; {} exposed host(s)".format(
            position, len(exposed)
        )
