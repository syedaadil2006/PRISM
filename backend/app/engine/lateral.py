"""Explainable lateral-movement rule engine.

The rule is written out clause by clause, and every detection records which
clauses fired. There is deliberately no opaque scoring model here: an analyst
who disagrees with a detection must be able to see exactly which condition
they think is wrong.

    IF   a host has recently been associated with suspicious activity
    AND  that host is the source of authentication/network activity
    AND  the activity reaches another host
    AND  the same account is involved
    AND  the correlation score clears the configured minimum
    THEN raise "Lateral Movement in Progress"
"""

from __future__ import annotations

from app.core.config import CorrelationSettings, LateralMovementSettings
from app.engine.correlation import score_pair
from app.models.analysis import (
    Assurance,
    Correlation,
    LateralMovement,
    confidence_from_score,
)
from app.models.events import NormalizedEvent


def _movement_candidates(
    events: list[NormalizedEvent], settings: LateralMovementSettings
) -> list[NormalizedEvent]:
    """Successful authentication events that carry an identity to a new host."""
    allowed = set(settings.movement_actions)
    return [
        e
        for e in events
        if e.action.value in allowed
        and e.outcome != "failure"
        and e.source_host
        and e.destination_host
        and e.source_host != e.destination_host
    ]


def detect_lateral_movement(
    events: list[NormalizedEvent],
    correlations: list[Correlation],
    settings: LateralMovementSettings,
    correlation_settings: CorrelationSettings,
) -> list[LateralMovement]:
    """Apply the lateral-movement rule to a batch of events."""
    by_id = {e.event_id: e for e in events}
    scores: dict[tuple[str, str], Correlation] = {}
    for link in correlations:
        scores[(link.source_event_id, link.target_event_id)] = link
        scores[(link.target_event_id, link.source_event_id)] = link

    detections: list[LateralMovement] = []

    for movement in _movement_candidates(events, settings):
        source = movement.source_host
        assert source is not None  # guaranteed by _movement_candidates

        # Clause 1 + 2: prior suspicious activity on the host being moved *from*.
        prior = [
            e
            for e in events
            if e.suspicious
            and e.event_id != movement.event_id
            and e.timestamp <= movement.timestamp
            and (movement.timestamp - e.timestamp).total_seconds() <= settings.window_seconds
            and source in e.hosts()
        ]
        if not prior:
            continue

        # Clause 4 + 5: pick the best-corroborated supporting event.
        best_link: Correlation | None = None
        best_support: NormalizedEvent | None = None
        for candidate in prior:
            link = scores.get((candidate.event_id, movement.event_id))
            if link is None:
                link = score_pair(candidate, movement, correlation_settings)
            if link is None:
                continue
            if best_link is None or link.score > best_link.score:
                best_link, best_support = link, candidate

        if best_link is None or best_support is None:
            continue
        if best_link.score < settings.min_correlation_score:
            continue

        same_account = bool(movement.user) and best_support.user == movement.user
        host_continuity = source in best_support.hosts()
        if not same_account and not host_continuity:
            continue

        gap = (movement.timestamp - best_support.timestamp).total_seconds()
        rule_evaluation = [
            "Host {} showed suspicious activity {:.0f}s earlier: {}".format(
                source, gap, best_support.summary()
            ),
            "{} was then used as the source of {} activity".format(source, movement.action.value),
            "The activity reached {}".format(movement.destination_host),
        ]
        if same_account:
            rule_evaluation.append("The same account ({}) is involved in both events".format(movement.user))
        else:
            rule_evaluation.append(
                "No shared account, but both events are anchored to {}".format(source)
            )
        rule_evaluation.append(
            "Correlation score {:.2f} meets the configured minimum of {:.2f}".format(
                best_link.score, settings.min_correlation_score
            )
        )

        detections.append(
            LateralMovement(
                movement_id="lm-" + movement.event_id,
                timestamp=movement.timestamp,
                user=movement.user,
                source_host=source,
                destination_host=movement.destination_host or "",
                method=movement.action.value,
                event_id=movement.event_id,
                correlation_score=best_link.score,
                confidence=confidence_from_score(best_link.score),
                assurance=Assurance.INFERRED,
                rule_evaluation=rule_evaluation,
                explanation=(
                    "{} moved from {} to {} using {}. "
                    "{} was already associated with suspicious activity, so this "
                    "authentication is treated as attacker movement rather than "
                    "routine access."
                ).format(
                    movement.user or "An account",
                    source,
                    movement.destination_host,
                    movement.action.value,
                    source,
                ),
            )
        )

    return _deduplicate(detections)


def _deduplicate(detections: list[LateralMovement]) -> list[LateralMovement]:
    """Collapse one movement reported by several events.

    A single RDP hop usually produces both a logon and a privilege-assignment
    record. Reporting it twice would inflate the lateral-movement count without
    telling the analyst anything new, so the best-corroborated detection per
    (account, source, destination) wins.
    """
    best: dict[tuple[str, str, str], LateralMovement] = {}
    for detection in detections:
        key = (detection.user or "", detection.source_host, detection.destination_host)
        incumbent = best.get(key)
        if incumbent is None or (
            detection.correlation_score,
            -detection.timestamp.timestamp(),
        ) > (incumbent.correlation_score, -incumbent.timestamp.timestamp()):
            best[key] = detection
    return sorted(best.values(), key=lambda d: d.timestamp)
