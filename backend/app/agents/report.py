"""Investigation report generation.

Turns a completed investigation into a document an analyst can hand to someone
else: a manager, an incident-response lead, an auditor. Two formats:

* Markdown, for tickets and wikis, and
* standalone HTML, styled for print so "Save as PDF" in any browser produces a
  clean PDF with no extra dependency.

The report reuses the investigation's own records. It adds no new claims, keeps
the observed / inferred / predicted separation, and records the analyst's
verdict on each finding, including the ones that were rejected.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from app.agents.state import AnalystDecision, Investigation

_ASSURANCE_ORDER = ["observed", "correlated", "inferred", "predicted"]
_DECISION_TEXT = {
    AnalystDecision.APPROVED: "Approved by analyst",
    AnalystDecision.REJECTED: "Rejected by analyst",
    AnalystDecision.FALSE_POSITIVE: "Marked false positive by analyst",
}


def _stamp(value: datetime | None) -> str:
    if value is None:
        return "n/a"
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _sections(investigation: Investigation) -> list[tuple[str, list[str]]]:
    """The report as (heading, lines) pairs, shared by both output formats."""
    inv = investigation
    summary = inv.summary
    sections: list[tuple[str, list[str]]] = []

    sections.append(
        (
            "Overview",
            [
                "Investigation: {}".format(inv.investigation_id),
                "Attack chain: {}".format(inv.attack_chain_id or "n/a"),
                "Status: {}".format(summary.status if summary else inv.status),
                "Severity: {}".format(inv.severity),
                "Confidence: {:.0%}".format(inv.confidence),
                "Opened: {}".format(_stamp(inv.created_at)),
                "Completed: {}".format(_stamp(inv.completed_at)),
                "Summary written by: {}".format(
                    summary.generated_by if summary else "n/a"
                ),
            ],
        )
    )

    sections.append(
        (
            "Key facts",
            [
                "Root cause host: {}".format(inv.initial_host or "unknown"),
                "Current attacker position: {}".format(inv.current_host or "unknown"),
                "Current stage: {}".format(inv.current_stage or "unknown"),
                "Account involved: {}".format(inv.user or "unknown"),
                "Potential next targets (predicted): {}".format(
                    ", ".join(inv.potential_targets[:3]) or "none"
                ),
                "ATT&CK techniques observed: {}".format(
                    ", ".join(inv.observed_techniques) or "none"
                ),
            ],
        )
    )

    if summary:
        sections.append(("Summary", summary.narrative.split("\n\n")))
        if summary.observed:
            sections.append(("Observed (from source records)", summary.observed))
        if summary.inferred:
            sections.append(("Inferred (rule-engine conclusions)", summary.inferred))
        if summary.predicted:
            sections.append(
                ("Predicted (risk estimate, not observed activity)", summary.predicted)
            )
        if summary.recommended_actions:
            sections.append(
                (
                    "Recommended actions",
                    summary.recommended_actions
                    + ["These are recommendations. PRISM takes no action on hosts."],
                )
            )

    findings = sorted(
        inv.findings,
        key=lambda f: _ASSURANCE_ORDER.index(f.assurance.value)
        if f.assurance.value in _ASSURANCE_ORDER
        else 99,
    )
    finding_lines: list[str] = []
    for index, finding in enumerate(findings, start=1):
        verdict = (
            "verified"
            if finding.verified
            else "downgraded by verification"
            if finding.verified is False
            else "not verified"
        )
        decision = (
            _DECISION_TEXT[finding.analyst_decision]
            if finding.analyst_decision
            else "No analyst decision"
        )
        finding_lines.append(
            "{}. {} [{} | {:.0%} confidence | {} | {}]".format(
                index,
                finding.title,
                finding.assurance.value,
                finding.confidence,
                verdict,
                decision,
            )
        )
        finding_lines.append("   " + finding.statement)
        if finding.analyst_note:
            finding_lines.append("   Analyst note: " + finding.analyst_note)
        sources = sorted(
            {
                eid
                for ev_id in finding.evidence_ids
                for ev in [inv.evidence_item(ev_id)]
                if ev is not None
                for eid in ev.event_ids
            }
        )
        if sources:
            shown = ", ".join(sources[:8])
            extra = " (+{} more)".format(len(sources) - 8) if len(sources) > 8 else ""
            finding_lines.append("   Source events: " + shown + extra)
    sections.append(("Findings", finding_lines or ["No findings recorded."]))

    sections.append(
        (
            "Agent activity",
            [
                "{}: {} - {}".format(run.label, run.status.value, run.summary or run.skip_reason)
                for run in inv.agents
            ],
        )
    )

    m = inv.metrics
    sections.append(
        (
            "Alert reduction (measured on the loaded data)",
            [
                "Raw events: {}".format(m.raw_events),
                "Events that would raise an alert: {}".format(m.notable_events),
                "Correlated into chains: {}".format(m.correlated_events),
                "Attack chains: {}".format(m.attack_chains),
                "Flagged events left out as unrelated: {}".format(
                    m.false_positive_candidates
                ),
                "Findings dismissed by the analyst: {}".format(m.analyst_false_positives),
                "Tool calls made by agents: {}".format(m.tool_calls),
                "Evidence items gathered: {}".format(m.evidence_items),
            ],
        )
    )

    sections.append(
        (
            "How to read this report",
            [
                "OBSERVED statements come directly from log records.",
                "CORRELATED statements group several events by shared account, host or timing.",
                "INFERRED statements are rule-engine conclusions no single record states.",
                "PREDICTED statements are risk estimates from graph context, not attacker activity.",
            ],
        )
    )
    return sections


def _title(investigation: Investigation) -> str:
    return "PRISM Investigation Report - {}".format(investigation.investigation_id)


def render_markdown(investigation: Investigation) -> str:
    lines = ["# " + _title(investigation), ""]
    if investigation.summary:
        lines += ["**{}**".format(investigation.summary.headline), ""]
    for heading, body in _sections(investigation):
        lines += ["## " + heading, ""]
        for line in body:
            is_detail = line.startswith("   ")
            lines.append(line if is_detail or heading == "Summary" else "- " + line)
        lines.append("")
    lines.append(
        "_Generated {} by PRISM._".format(_stamp(datetime.now(tz=timezone.utc)))
    )
    return "\n".join(lines) + "\n"


_CSS = """
body{font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#111;max-width:860px;
margin:32px auto;padding:0 24px;line-height:1.5;font-size:14px}
h1{font-size:22px;border-bottom:3px solid #111;padding-bottom:8px;margin-bottom:4px}
.headline{font-size:16px;font-weight:600;color:#b91c1c;margin:8px 0 20px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:#333;
border-bottom:1px solid #ccc;padding-bottom:4px;margin-top:28px}
ul{padding-left:20px}li{margin:3px 0}.detail{color:#444;list-style:none;margin-left:-4px}
.foot{margin-top:36px;color:#777;font-size:12px;border-top:1px solid #ddd;padding-top:8px}
.print{position:fixed;top:16px;right:16px;padding:8px 14px;font-size:13px;cursor:pointer}
@media print{.print{display:none}body{margin:0}}
"""


def render_html(investigation: Investigation) -> str:
    esc = html.escape
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<title>{}</title><style>{}</style></head><body>".format(
            esc(_title(investigation)), _CSS
        ),
        "<button class='print' onclick='window.print()'>Print / Save as PDF</button>",
        "<h1>{}</h1>".format(esc(_title(investigation))),
    ]
    if investigation.summary:
        parts.append("<p class='headline'>{}</p>".format(esc(investigation.summary.headline)))
    for heading, body in _sections(investigation):
        parts.append("<h2>{}</h2>".format(esc(heading)))
        if heading == "Summary":
            parts += ["<p>{}</p>".format(esc(p)) for p in body]
            continue
        parts.append("<ul>")
        for line in body:
            if line.startswith("   "):
                parts.append("<li class='detail'>{}</li>".format(esc(line.strip())))
            else:
                parts.append("<li>{}</li>".format(esc(line)))
        parts.append("</ul>")
    parts.append(
        "<p class='foot'>Generated {} by PRISM.</p></body></html>".format(
            esc(_stamp(datetime.now(tz=timezone.utc)))
        )
    )
    return "".join(parts)
