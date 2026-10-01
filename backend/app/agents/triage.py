"""Triage Agent: is there anything here worth a human's time?

Triage is the agent that is allowed to say no. Most of what arrives in a SOC
queue does not deserve an investigation, and an agentic layer that opens a case
for everything has moved the alert-fatigue problem rather than solved it.

So this agent looks for a coherent cluster with a shared subject, not merely a
pile of severe-looking events, and it reports the entities involved so the
orchestrator knows what the rest of the investigation is about.
"""

from __future__ import annotations

from app.agents.base import Agent, AgentWorkspace
from app.agents.state import AgentName, EvidenceKind, Investigation
from app.models.analysis import Assurance

#: Actions that on their own justify opening a case.
_ESCALATING_ACTIONS = {
    "CREDENTIAL_ACCESS",
    "MALICIOUS_ATTACHMENT",
    "SUSPICIOUS_DOMAIN",
    "REMOTE_SERVICE_EXEC",
}


class TriageAgent(Agent):
    name = AgentName.TRIAGE
    label = "Triage Agent"
    purpose = "Decides whether anything here is worth a human's time."

    async def run(self, workspace: AgentWorkspace) -> str:
        investigation = workspace.investigation
        chain_id = investigation.attack_chain_id

        chain = workspace.call("get_attack_chain", chain_id=chain_id)
        if not chain.found:
            await workspace.step(
                "Reviewed the current event set",
                "Nothing has correlated into a chain; no investigation opened.",
            )
            return "No correlated activity to investigate"

        stages = chain.rows
        # Take these from the engine rather than from the first and last stage.
        # The final stage is where the story ends; the current host is where the
        # attacker is running code. They are not always the same host.
        investigation.initial_host = chain.meta.get("initial_host") or stages[0].get("host")
        investigation.current_host = chain.meta.get("current_host") or stages[-1].get("host")
        investigation.attack_chain_id = chain.meta.get("attack_chain_id") or chain_id
        investigation.current_stage = chain.meta.get("current_stage")

        chain_evidence = workspace.evidence(
            chain.summary,
            detail="Stage sequence: "
            + " -> ".join("{} on {}".format(s["tactic"], s["host"]) for s in stages),
            source=chain,
            assurance=Assurance.CORRELATED,
        )
        await workspace.step(
            "Pulled the correlated cluster",
            chain.summary,
            evidence_ids=[chain_evidence],
        )

        # What is actually suspicious inside it, and who is the subject?
        flagged = workspace.call(
            "search_events", suspicious_only=True, limit=200, host=None
        )
        cluster_ids = {eid for stage in stages for eid in stage["event_ids"]}
        in_cluster = [r for r in flagged.rows if r["event_id"] in cluster_ids]

        accounts = chain.meta.get("users") or sorted(
            {r["user"] for r in in_cluster if r["user"]}
        )
        hosts = sorted(
            {h for r in in_cluster for h in (r["source_host"], r["destination_host"]) if h}
        )
        escalating = [r for r in in_cluster if r["action"] in _ESCALATING_ACTIONS]
        critical = [r for r in in_cluster if r["severity"] == "critical"]

        investigation.user = accounts[0] if accounts else None

        entity_evidence = workspace.evidence(
            "{} flagged event(s) involving {} across {}".format(
                len(in_cluster),
                ", ".join(accounts) or "no named account",
                ", ".join(hosts) or "no host",
            ),
            detail="Escalating actions present: "
            + (", ".join(sorted({r["action"] for r in escalating})) or "none"),
            kind=EvidenceKind.EVENT,
            event_ids=[r["event_id"] for r in in_cluster],
            source=flagged,
        )

        # The decision. A cluster spanning two hosts under one account is the
        # shape of an intrusion; a pile of unrelated noise is not.
        multi_host = len(hosts) > 1
        single_subject = len(accounts) == 1
        severity = self._severity(bool(critical), bool(escalating), multi_host)
        investigation.severity = severity

        if not escalating and not critical:
            await workspace.step(
                "Assessed the cluster",
                "No escalating behaviour found; this does not warrant an investigation.",
                evidence_ids=[entity_evidence],
            )
            return "No investigation required"

        reasons = []
        if escalating:
            reasons.append(
                "escalating behaviour ({})".format(
                    ", ".join(sorted({r["action"] for r in escalating}))
                )
            )
        if multi_host:
            reasons.append("activity spans {} hosts".format(len(hosts)))
        if single_subject and accounts:
            reasons.append("a single account ({}) runs through it".format(accounts[0]))

        finding = workspace.finding(
            "Investigation required",
            "This cluster warrants investigation: " + "; ".join(reasons) + ".",
            assurance=Assurance.CORRELATED,
            confidence=0.8 if (escalating and multi_host) else 0.65,
            evidence_ids=[chain_evidence, entity_evidence],
        )
        await workspace.step(
            "Opened an investigation",
            "Severity {}. {}".format(severity, "; ".join(reasons).capitalize() + "."),
            evidence_ids=[entity_evidence],
            finding_ids=[finding],
        )

        return "Investigation required, severity {}".format(severity)

    @staticmethod
    def _severity(critical: bool, escalating: bool, multi_host: bool) -> str:
        if critical and multi_host:
            return "critical"
        if critical or (escalating and multi_host):
            return "high"
        if escalating:
            return "medium"
        return "low"
