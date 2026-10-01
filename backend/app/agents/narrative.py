"""The analyst-facing summary.

Built deterministically from verified findings. When an LLM provider is
configured it may rephrase that summary, but only within a guard: the result is
scanned for host names and technique ids that were not in the verified set, and
anything that introduces one is discarded in favour of the deterministic text.

The guard is the reason the provider is safe to enable. A model asked to write
prose over settled facts can still drift; a model whose output is checked
against those facts cannot smuggle a new one into the record.
"""

from __future__ import annotations

import re

from app.agents.llm import LLMProvider
from app.agents.state import AISummary, AnalystDecision, Investigation
from app.core.logging_config import get_logger
from app.models.analysis import Assurance

logger = get_logger(__name__)

_SYSTEM = (
    "You are writing the summary paragraph of a SOC investigation report. "
    "You will be given findings that have already been verified against "
    "evidence. Rephrase them into three or four short paragraphs for a SOC "
    "analyst. Use only the hosts, accounts, techniques and conclusions given. "
    "Do not add detail, do not speculate, and preserve the distinction between "
    "what was observed, what was inferred and what is predicted. Write plainly."
)

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_HOSTNAME_RE = re.compile(r"\b[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+\b")


def _bullets(investigation: Investigation) -> tuple[list[str], list[str], list[str]]:
    observed: list[str] = []
    inferred: list[str] = []
    predicted: list[str] = []

    for finding in investigation.accepted_findings():
        if finding.verified is False:
            continue
        line = finding.statement
        if finding.assurance in {Assurance.OBSERVED, Assurance.CORRELATED}:
            observed.append(line)
        elif finding.assurance is Assurance.INFERRED:
            inferred.append(line)
        else:
            predicted.append(line)
    return observed, inferred, predicted


def _headline(investigation: Investigation) -> str:
    if not investigation.initial_host:
        return "Investigation {}".format(investigation.investigation_id)
    return "{} to {}: {}".format(
        investigation.initial_host,
        investigation.current_host or "unknown",
        investigation.current_stage or "under investigation",
    )


def _recommended_actions(investigation: Investigation) -> list[str]:
    """Recommendations, never automatic action. The analyst decides."""
    actions: list[str] = []
    if investigation.current_host:
        actions.append(
            "Isolate {} and capture volatile memory before containment.".format(
                investigation.current_host
            )
        )
    if investigation.user:
        actions.append(
            "Reset credentials for {} and revoke active sessions.".format(
                investigation.user
            )
        )
    if investigation.potential_targets:
        actions.append(
            "Raise monitoring on {} and review recent authentication to it.".format(
                investigation.potential_targets[0]
            )
        )
    if investigation.initial_host:
        actions.append(
            "Preserve the delivery artefact on {} for analysis.".format(
                investigation.initial_host
            )
        )
    return actions


def _deterministic_narrative(investigation: Investigation) -> str:
    parts: list[str] = []

    if investigation.initial_host:
        opening = "The investigation identified a likely attack chain originating from {}".format(
            investigation.initial_host
        )
        if investigation.user:
            opening += " under the account {}".format(investigation.user)
        parts.append(opening + ".")

    if investigation.current_host and investigation.current_host != investigation.initial_host:
        parts.append(
            "The same account subsequently reached {}, where further activity was "
            "observed. This movement is inferred by the rule engine from "
            "correlated evidence; no single log record states it.".format(
                investigation.current_host
            )
        )

    if investigation.observed_techniques:
        parts.append(
            "Observed behaviour maps to {} ATT&CK technique(s): {}. Each is backed "
            "by a source event that satisfies its mapping rule.".format(
                len(investigation.observed_techniques),
                ", ".join(investigation.observed_techniques[:6]),
            )
        )

    if investigation.potential_targets:
        parts.append(
            "{} is currently the highest-scoring potential next target, because the "
            "compromised account has access to it and it occupies a privileged "
            "position in the graph. This is a prediction from graph context, not "
            "observed attacker activity.".format(investigation.potential_targets[0])
        )

    rejected = [
        f
        for f in investigation.findings
        if f.analyst_decision
        in {AnalystDecision.REJECTED, AnalystDecision.FALSE_POSITIVE}
    ]
    if rejected:
        parts.append(
            "{} finding(s) were dismissed by the analyst and are excluded from this "
            "summary.".format(len(rejected))
        )

    return "\n\n".join(parts) or "No verified findings were produced."


def _permitted_terms(investigation: Investigation) -> tuple[set[str], set[str]]:
    hosts = {h.upper() for h in investigation.potential_targets}
    for value in (investigation.initial_host, investigation.current_host):
        if value:
            hosts.add(value.upper())
    for item in investigation.evidence:
        for node in item.node_ids:
            if node.startswith("host:"):
                hosts.add(node.split(":", 1)[1].upper())
    return hosts, set(investigation.observed_techniques)


def _is_faithful(text: str, investigation: Investigation) -> tuple[bool, str]:
    """Reject prose that introduces a host or technique we never verified."""
    hosts, techniques = _permitted_terms(investigation)

    for match in _TECHNIQUE_RE.findall(text):
        if match not in techniques:
            return False, "introduced technique " + match
    for match in _HOSTNAME_RE.findall(text):
        if match.upper() not in hosts:
            return False, "introduced host " + match
    return True, ""


async def build_summary(
    investigation: Investigation, provider: LLMProvider
) -> AISummary:
    """Compose the summary, optionally letting a model phrase it."""
    observed, inferred, predicted = _bullets(investigation)
    narrative = _deterministic_narrative(investigation)
    generated_by = "deterministic"

    if provider.name != "deterministic":
        prompt = _build_prompt(investigation, observed, inferred, predicted)
        candidate = await provider.complete(_SYSTEM, prompt)
        if candidate:
            faithful, reason = _is_faithful(candidate, investigation)
            if faithful:
                narrative = candidate
                generated_by = provider.name
            else:
                logger.warning(
                    "llm summary rejected as unfaithful; using deterministic text",
                    extra={"reason": reason},
                )

    status = (
        "{} in progress on {}".format(
            investigation.current_stage or investigation.severity.capitalize(),
            investigation.current_host,
        )
        if investigation.current_host
        else investigation.status
    )

    return AISummary(
        headline=_headline(investigation),
        narrative=narrative,
        observed=observed,
        inferred=inferred,
        predicted=predicted,
        recommended_actions=_recommended_actions(investigation),
        evidence_count=investigation.evidence_count,
        technique_count=len(investigation.observed_techniques),
        confidence=investigation.confidence,
        status=status,
        generated_by=generated_by,
    )


def _build_prompt(
    investigation: Investigation,
    observed: list[str],
    inferred: list[str],
    predicted: list[str],
) -> str:
    lines = [
        "Investigation: {}".format(investigation.investigation_id),
        "Origin host: {}".format(investigation.initial_host or "unknown"),
        "Current host: {}".format(investigation.current_host or "unknown"),
        "Account: {}".format(investigation.user or "unknown"),
        "Techniques: {}".format(", ".join(investigation.observed_techniques) or "none"),
        "Evidence items: {}".format(investigation.evidence_count),
        "Confidence: {:.0%}".format(investigation.confidence),
        "",
        "OBSERVED (established from source records):",
    ]
    lines.extend("- " + line for line in observed or ["none"])
    lines.append("")
    lines.append("INFERRED (rule-engine conclusions):")
    lines.extend("- " + line for line in inferred or ["none"])
    lines.append("")
    lines.append("PREDICTED (graph scoring, not observed):")
    lines.extend("- " + line for line in predicted or ["none"])
    return "\n".join(lines)
