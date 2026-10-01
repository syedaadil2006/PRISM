"""Evidence Agent: make sure every claim has a record behind it.

The other agents cite evidence as they go. This one closes the gaps: it walks
the findings recorded so far, checks that each cites at least one retrievable
source event, and pulls the raw records for anything referenced but never
actually fetched.

It is the difference between "the agent said there was credential dumping" and
"here is the event id, the host, the timestamp and the original Sysmon record".
"""

from __future__ import annotations

from app.agents.base import Agent, AgentWorkspace
from app.agents.state import AgentName, EvidenceKind, Investigation
from app.models.analysis import Assurance


class EvidenceAgent(Agent):
    name = AgentName.EVIDENCE
    label = "Evidence Agent"
    purpose = "Pulls the supporting records behind every claim."

    def should_run(self, investigation: Investigation) -> tuple[bool, str]:
        if not investigation.findings:
            return False, "No findings to substantiate"
        return True, ""

    async def run(self, workspace: AgentWorkspace) -> str:
        investigation = workspace.investigation

        # Which source events have the findings so far leaned on?
        cited: set[str] = set()
        unsupported: list[str] = []
        for finding in investigation.findings:
            events_for_finding: set[str] = set()
            for evidence_id in finding.evidence_ids:
                item = investigation.evidence_item(evidence_id)
                if item is not None:
                    events_for_finding.update(item.event_ids)
            if not events_for_finding:
                unsupported.append(finding.title)
            cited.update(events_for_finding)

        await workspace.step(
            "Indexed the evidence cited so far",
            "{} finding(s) cite {} distinct source event(s).".format(
                len(investigation.findings), len(cited)
            ),
        )

        if unsupported:
            await workspace.step(
                "Flagged findings with no source events",
                "; ".join(unsupported),
            )

        # Retrieve the records themselves, so the analyst can read them.
        records = workspace.call("search_events", limit=500)
        by_id = {row["event_id"]: row for row in records.rows}
        retrieved = [by_id[eid] for eid in sorted(cited) if eid in by_id]
        missing = sorted(cited - set(by_id))

        if retrieved:
            by_type: dict[str, int] = {}
            for row in retrieved:
                by_type[row["event_type"]] = by_type.get(row["event_type"], 0) + 1
            breakdown = ", ".join(
                "{} {}".format(count, name) for name, count in sorted(by_type.items())
            )
            evidence_id = workspace.evidence(
                "{} source record(s) retrieved: {}".format(len(retrieved), breakdown),
                detail="; ".join(
                    "{} {} on {}".format(
                        r["timestamp"][11:19], r["action"], r["source_host"] or "?"
                    )
                    for r in retrieved[:8]
                ),
                kind=EvidenceKind.EVENT,
                event_ids=[r["event_id"] for r in retrieved],
            )
            await workspace.step(
                "Retrieved the underlying records",
                breakdown,
                evidence_ids=[evidence_id],
            )
        else:
            await workspace.step(
                "Retrieved the underlying records",
                "No source records could be retrieved.",
            )

        if missing:
            # A cited event that cannot be fetched is exactly the kind of thing
            # verification needs to know about.
            await workspace.step(
                "Found citations that do not resolve",
                "{} cited event id(s) are not present in the current event set: {}".format(
                    len(missing), ", ".join(missing[:5])
                ),
            )

        investigation.evidence_count = len(investigation.evidence)
        investigation.metrics.evidence_items = investigation.evidence_count

        return "{} record(s) behind {} finding(s) so far".format(
            len(retrieved), len(investigation.findings)
        )
