"""Investigation Agent: the autonomous investigator.

This is the agent that decides what to look at next. It does not answer from the
opening alert; it forms a hypothesis, works out which questions would separate
that hypothesis from the benign explanation, asks them through the tool layer,
and then either confirms or drops it.

The branching is the point. What it asks on step four depends on what step three
returned: if the account turns out to be the thread running through the cluster
it pulls the account's history, and if the cluster turns out to be one host with
no identity attached it goes down the process lineage instead. An investigator
that always runs the same seven queries is a report generator.
"""

from __future__ import annotations

from app.agents.base import Agent, AgentWorkspace
from app.agents.state import AgentName, EvidenceKind, Investigation
from app.models.analysis import Assurance


class InvestigationAgent(Agent):
    name = AgentName.INVESTIGATION
    label = "Investigation Agent"
    purpose = "Runs the investigation plan, step by step."

    def should_run(self, investigation: Investigation) -> tuple[bool, str]:
        if not investigation.attack_chain_id:
            return False, "Nothing triaged for investigation"
        return True, ""

    async def run(self, workspace: AgentWorkspace) -> str:
        investigation = workspace.investigation
        host = investigation.initial_host
        account = investigation.user
        evidence_ids: list[str] = []

        # --- step 1: what actually happened on the origin host -------------
        endpoint = workspace.call(
            "search_endpoint_logs", host=host, suspicious_only=True, limit=40
        )
        if not endpoint.found:
            await workspace.step(
                "Checked the origin host",
                "No flagged endpoint activity on {}.".format(host),
            )
            return "No endpoint activity to investigate"

        lineage = [
            "{} -> {}".format(r["parent_process"] or "?", r["process"] or "?")
            for r in endpoint.rows
            if r["process"]
        ]
        origin_evidence = workspace.evidence(
            endpoint.summary,
            detail="Process lineage: " + "; ".join(lineage[:6]),
            source=endpoint,
        )
        evidence_ids.append(origin_evidence)
        await workspace.step(
            "Checked prior activity on {}".format(host),
            endpoint.summary,
            evidence_ids=[origin_evidence],
        )

        # --- step 2: form a hypothesis from what came back -----------------
        actions = {r["action"] for r in endpoint.rows}
        has_execution = bool(actions & {"POWERSHELL_EXEC", "SCRIPT_EXEC", "COMMAND_EXEC"})
        has_delivery = "MALICIOUS_ATTACHMENT" in actions
        has_credentials = "CREDENTIAL_ACCESS" in actions

        if has_delivery and has_execution:
            hypothesis = (
                "A document delivered to {} executed a payload, which then went "
                "after credentials and moved to another host."
            ).format(host)
        elif has_credentials:
            hypothesis = (
                "Code running on {} went after credential material in order to "
                "move elsewhere."
            ).format(host)
        else:
            hypothesis = "Suspicious execution on {} with no clear delivery route.".format(host)

        await workspace.step(
            "Formed a hypothesis",
            hypothesis,
        )

        # --- step 3: follow the account, if there is one -------------------
        if account:
            access = workspace.call("get_user_access", user=account)
            access_evidence = workspace.evidence(
                access.summary,
                detail="Entitlements are inventory facts, not observed activity.",
                source=access,
                assurance=Assurance.OBSERVED,
            )
            evidence_ids.append(access_evidence)

            auth = workspace.call("search_auth_logs", user=account, limit=60)
            failures = [r for r in auth.rows if r["outcome"] == "failure"]
            successes = [
                r
                for r in auth.rows
                if r["outcome"] != "failure"
                and r["destination_host"]
                and r["destination_host"] != r["source_host"]
            ]
            auth_evidence = workspace.evidence(
                "{} authentication event(s) for {}: {} remote success(es), {} failure(s)".format(
                    len(auth.rows), account, len(successes), len(failures)
                ),
                detail="; ".join(
                    "{} {} -> {}".format(r["action"], r["source_host"], r["destination_host"])
                    for r in successes[:5]
                ),
                source=auth,
            )
            evidence_ids.append(auth_evidence)
            await workspace.step(
                "Followed the account {}".format(account),
                "{}. {} remote logon success(es), {} failure(s).".format(
                    access.summary, len(successes), len(failures)
                ),
                evidence_ids=[access_evidence, auth_evidence],
            )
        else:
            successes, failures = [], []
            await workspace.step(
                "Looked for an account to follow",
                "No named account is attached to this activity.",
            )

        # --- step 4: the network side, which carries no identity -----------
        dns = workspace.call("search_dns_logs", host=host, suspicious_only=True, limit=20)
        if dns.found:
            domains = sorted({r["domain"] for r in dns.rows if r["domain"]})
            dns_evidence = workspace.evidence(
                dns.summary,
                detail="Flagged domains: " + ", ".join(domains),
                source=dns,
            )
            evidence_ids.append(dns_evidence)
            await workspace.step(
                "Checked outbound DNS from {}".format(host),
                "Flagged: " + ", ".join(domains),
                evidence_ids=[dns_evidence],
            )

        # --- step 5: where the activity reached ----------------------------
        movements = workspace.call(
            "get_lateral_movements", chain_id=investigation.attack_chain_id
        )
        if movements.found:
            destinations = [m["destination_host"] for m in movements.rows]
            movement_evidence = workspace.evidence(
                movements.summary,
                detail="; ".join(
                    "{}: {}".format(m["method"], " / ".join(m["rule_evaluation"][:2]))
                    for m in movements.rows
                ),
                source=movements,
                assurance=Assurance.INFERRED,
            )
            evidence_ids.append(movement_evidence)
            await workspace.step(
                "Traced where the activity reached",
                movements.summary,
                evidence_ids=[movement_evidence],
            )
        else:
            destinations = []

        # --- step 6: confirm or drop the hypothesis ------------------------
        confirmed = has_execution and (bool(destinations) or bool(successes))
        if confirmed:
            statement = (
                "{} The hypothesis holds: execution on {} is followed by "
                "authenticated access to {}, under the same account."
            ).format(hypothesis, host, ", ".join(destinations) or "another host")
            confidence = 0.88 if has_credentials else 0.74
            title = "Attack hypothesis confirmed"
        elif has_execution:
            statement = (
                "{} Execution is present but nothing carried it to another host, "
                "so the intrusion appears contained to {} on current evidence."
            ).format(hypothesis, host)
            confidence = 0.55
            title = "Attack hypothesis partially supported"
        else:
            statement = (
                "The evidence does not support the hypothesis: no execution chain "
                "was found on {}.".format(host)
            )
            confidence = 0.3
            title = "Attack hypothesis rejected"

        finding = workspace.finding(
            title,
            statement,
            assurance=Assurance.INFERRED,
            confidence=confidence,
            evidence_ids=evidence_ids,
        )
        await workspace.step(
            "Tested the hypothesis against the evidence",
            statement,
            finding_ids=[finding],
        )

        investigation.evidence_count = len(investigation.evidence)
        return "{} ({} evidence items)".format(title, len(evidence_ids))
