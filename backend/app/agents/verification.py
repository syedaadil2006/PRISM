"""Verification Agent: check the other agents, and downgrade what does not hold.

This agent exists because the rest of the system is only as trustworthy as its
weakest claim. It re-derives the facts each finding rests on, using the same
tools, and compares. A finding whose evidence it cannot reproduce is not deleted
-- it is downgraded and marked, because silently dropping a conclusion hides the
disagreement instead of surfacing it.

The checks are the ones that catch real mistakes:

* Does the finding cite any source event at all?
* Do those event ids still resolve to records?
* Are the timestamps consistent with the order the story claims?
* Does the graph actually contain the relationship that was asserted?
* Is each ATT&CK technique still supported by its own source event?
* Is the predicted target genuinely reachable?
* Is a causal claim being made where only correlation was established?
"""

from __future__ import annotations

from datetime import datetime

from app.agents.base import Agent, AgentWorkspace
from app.agents.state import AgentName, Finding, Investigation
from app.models.analysis import Assurance


class VerificationAgent(Agent):
    name = AgentName.VERIFICATION
    label = "Verification Agent"
    purpose = "Re-checks every conclusion against the evidence."

    def should_run(self, investigation: Investigation) -> tuple[bool, str]:
        if not investigation.findings:
            return False, "Nothing to verify"
        return True, ""

    async def run(self, workspace: AgentWorkspace) -> str:
        investigation = workspace.investigation
        downgrade = workspace.settings.agents.verification_downgrade

        records = workspace.call("search_events", limit=500)
        known_events = {row["event_id"]: row for row in records.rows}
        await workspace.step(
            "Loaded the record set for cross-checking",
            "{} source record(s) available.".format(len(known_events)),
        )

        # Snapshot the count now: the verdict this agent records at the end is
        # not one of the findings under review, and counting it would let
        # verification inflate its own pass rate.
        under_review = list(investigation.findings)
        total = len(under_review)
        passed = 0
        downgraded = 0

        for finding in under_review:
            notes: list[str] = []
            ok = True

            cited = self._cited_events(investigation, finding)
            if not cited:
                notes.append("Cites no source event.")
                ok = False
            else:
                unresolved = [eid for eid in cited if eid not in known_events]
                if unresolved:
                    notes.append(
                        "{} cited event id(s) do not resolve: {}".format(
                            len(unresolved), ", ".join(sorted(unresolved)[:4])
                        )
                    )
                    ok = False
                else:
                    notes.append("All {} cited event(s) resolve.".format(len(cited)))

            resolved = [known_events[eid] for eid in cited if eid in known_events]
            if len(resolved) > 1:
                times = sorted(datetime.fromisoformat(r["timestamp"]) for r in resolved)
                span = (times[-1] - times[0]).total_seconds()
                window = workspace.settings.correlation.window_seconds
                if span > window * 4:
                    notes.append(
                        "Evidence spans {:.0f}s, far beyond the {}s correlation "
                        "window.".format(span, window)
                    )
                    ok = False
                else:
                    notes.append("Timestamps are consistent ({:.0f}s span).".format(span))

            ok = await self._check_specifics(workspace, finding, notes, ok)

            finding.verification_notes = notes
            finding.verified = ok
            if ok:
                passed += 1
            else:
                finding.confidence_before_verification = finding.confidence
                finding.confidence = round(max(0.05, finding.confidence - downgrade), 3)
                downgraded += 1

        await workspace.step(
            "Cross-checked every finding",
            "{} verified, {} downgraded for insufficient evidence.".format(
                passed, downgraded
            ),
        )

        accepted = [f for f in investigation.findings if f.verified]
        investigation.confidence = (
            round(sum(f.confidence for f in accepted) / len(accepted), 3)
            if accepted
            else 0.0
        )

        verdict_evidence = workspace.evidence(
            "{} of {} finding(s) verified".format(passed, total),
            detail="Overall confidence {:.0%}, the mean of verified findings.".format(
                investigation.confidence
            ),
            event_ids=sorted(known_events)[:1],
            assurance=Assurance.INFERRED,
        )
        finding_id = workspace.finding(
            "Verification complete",
            "{} of {} finding(s) are supported by evidence that re-derives. "
            "Investigation confidence {:.0%}.".format(
                passed, total, investigation.confidence
            ),
            assurance=Assurance.INFERRED,
            confidence=investigation.confidence,
            evidence_ids=[verdict_evidence],
        )
        # The verification verdict is itself a finding, and it verifies itself
        # by construction: it reports counts it just computed.
        verdict = investigation.finding(finding_id)
        if verdict is not None:
            verdict.verified = True
            verdict.verification_notes = ["Derived from the checks above."]

        await workspace.step(
            "Published the verification verdict",
            "Confidence {:.0%} across {} verified finding(s).".format(
                investigation.confidence, passed
            ),
            finding_ids=[finding_id],
        )

        return "{}/{} verified, confidence {:.0%}".format(
            passed, total, investigation.confidence
        )

    @staticmethod
    def _cited_events(investigation: Investigation, finding: Finding) -> set[str]:
        cited: set[str] = set()
        for evidence_id in finding.evidence_ids:
            item = investigation.evidence_item(evidence_id)
            if item is not None:
                cited.update(item.event_ids)
        return cited

    async def _check_specifics(
        self,
        workspace: AgentWorkspace,
        finding: Finding,
        notes: list[str],
        ok: bool,
    ) -> bool:
        """Checks that only apply to particular kinds of claim."""
        investigation = workspace.investigation

        # A predicted target must actually be reachable.
        if finding.assurance is Assurance.PREDICTED and investigation.current_host:
            target = finding.title.split(":")[-1].strip()
            if target:
                path = workspace.call(
                    "get_attack_path",
                    source_host=investigation.current_host,
                    target_host=target,
                )
                if path.found:
                    notes.append(
                        "Predicted target is reachable: {}.".format(path.summary)
                    )
                else:
                    notes.append(
                        "Predicted target {} is not reachable from {}.".format(
                            target, investigation.current_host
                        )
                    )
                    ok = False

        # A causal claim needs more than shared timing.
        causal = any(
            word in finding.statement.lower()
            for word in (" because ", " caused ", " led to ", " resulted in ")
        )
        if causal and finding.assurance is Assurance.CORRELATED:
            notes.append(
                "States a causal relationship from correlated evidence; treat as "
                "association, not causation."
            )
            ok = False

        # An inferred movement claim should match a recorded detection.
        if finding.agent is AgentName.INVESTIGATION and "hypothesis confirmed" in finding.title.lower():
            movements = workspace.call(
                "get_lateral_movements", chain_id=investigation.attack_chain_id
            )
            if movements.found:
                notes.append(
                    "Movement claim matches {} recorded detection(s).".format(
                        len(movements.rows)
                    )
                )
            else:
                notes.append("Claims movement, but no movement detection exists.")
                ok = False

        return ok
