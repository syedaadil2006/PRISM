"""The correlation engine.

Given a list of normalized events, score every plausible pair and keep the
links that clear the configured threshold. Each link carries the factors that
produced its score so the UI can answer "why are these two events related?".

The engine is intentionally rule-based and additive rather than learned: an
analyst has to be able to read the reasoning, and an operator has to be able to
retune it from configuration.
"""

from __future__ import annotations

from app.core.config import CorrelationSettings
from app.models.analysis import Correlation, CorrelationFactor
from app.models.events import EventType, NormalizedEvent


def _shared_hosts(a: NormalizedEvent, b: NormalizedEvent) -> set[str]:
    return a.hosts() & b.hosts()


def _is_pivot(a: NormalizedEvent, b: NormalizedEvent) -> str | None:
    """True when b uses a's host as the launch point for reaching a new host.

    This is the single strongest correlation signal: it is what turns two
    isolated alerts on two machines into one attack path.
    """
    a_host = a.primary_host
    if not a_host or not b.source_host or not b.destination_host:
        return None
    if b.source_host != a_host or b.destination_host == b.source_host:
        return None
    return b.destination_host


def score_pair(
    a: NormalizedEvent,
    b: NormalizedEvent,
    settings: CorrelationSettings,
) -> Correlation | None:
    """Score one ordered pair of events (a no later than b).

    Returns None when the pair is outside the time window or scores zero on
    every substantive dimension.
    """
    delta = (b.timestamp - a.timestamp).total_seconds()
    if delta < 0:
        a, b = b, a
        delta = -delta
    if delta > settings.window_seconds:
        return None

    factors: list[CorrelationFactor] = []

    # Temporal proximity: decays linearly across the window.
    proximity = 1.0 - (delta / settings.window_seconds)
    time_weight = settings.weight_time_proximity * proximity
    factors.append(
        CorrelationFactor(
            name="time_proximity",
            weight=round(time_weight, 4),
            detail="Events are {} apart".format(_format_delta(delta)),
        )
    )

    substantive = 0.0

    if a.user and b.user and a.user == b.user:
        substantive += settings.weight_same_user
        factors.append(
            CorrelationFactor(
                name="same_user",
                weight=settings.weight_same_user,
                detail="Same account involved: " + a.user,
            )
        )

    shared = _shared_hosts(a, b)
    if shared:
        substantive += settings.weight_same_host
        factors.append(
            CorrelationFactor(
                name="same_host",
                weight=settings.weight_same_host,
                detail="Shared host: " + ", ".join(sorted(shared)),
            )
        )

    pivot_target = _is_pivot(a, b)
    if pivot_target:
        substantive += settings.weight_host_pivot
        factors.append(
            CorrelationFactor(
                name="host_pivot",
                weight=settings.weight_host_pivot,
                detail="{} was used as the source for activity against {}".format(
                    a.primary_host, pivot_target
                ),
            )
        )

    shared_ips = a.ips() & b.ips()
    if shared_ips:
        substantive += settings.weight_shared_ip
        factors.append(
            CorrelationFactor(
                name="shared_ip",
                weight=settings.weight_shared_ip,
                detail="Shared address: " + ", ".join(sorted(shared_ips)),
            )
        )

    if a.process and b.process and a.process.lower() == b.process.lower() and shared:
        substantive += settings.weight_process_host
        factors.append(
            CorrelationFactor(
                name="process_continuity",
                weight=settings.weight_process_host,
                detail="Same process {} active on the same host".format(a.process),
            )
        )

    if a.domain and b.domain and a.domain == b.domain:
        substantive += settings.weight_domain_overlap
        factors.append(
            CorrelationFactor(
                name="domain_overlap",
                weight=settings.weight_domain_overlap,
                detail="Both events reference " + a.domain,
            )
        )

    # Two independently suspicious events on the same machine within the window
    # is itself evidence, and it is how DNS records (which carry no user) get
    # attached to the process activity that generated them.
    if shared and a.suspicious and b.suspicious:
        substantive += settings.weight_suspicious_coincidence
        factors.append(
            CorrelationFactor(
                name="suspicious_coincidence",
                weight=settings.weight_suspicious_coincidence,
                detail="Two independently suspicious events on {} inside the window".format(
                    ", ".join(sorted(shared))
                ),
            )
        )

    if substantive <= 0:
        return None

    score = min(1.0, substantive + time_weight)
    return Correlation(
        source_event_id=a.event_id,
        target_event_id=b.event_id,
        score=round(score, 4),
        time_delta_seconds=round(delta, 3),
        factors=factors,
    )


def _format_delta(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 60:
        return "{}s".format(seconds)
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return "{}m {}s".format(minutes, secs)
    hours, minutes = divmod(minutes, 60)
    return "{}h {}m".format(hours, minutes)


def correlate(
    events: list[NormalizedEvent],
    settings: CorrelationSettings,
) -> list[Correlation]:
    """Correlate the notable events in a batch.

    Only notable events are considered, which is what keeps routine business
    traffic out of attack chains. The scan is windowed, so cost stays close to
    linear in the number of events rather than quadratic.
    """
    notable = sorted(
        (e for e in events if e.is_notable),
        key=lambda e: (e.timestamp, e.event_id),
    )
    correlations: list[Correlation] = []

    for index, event in enumerate(notable):
        for other in notable[index + 1 :]:
            delta = (other.timestamp - event.timestamp).total_seconds()
            if delta > settings.window_seconds:
                break  # sorted, so nothing further can be in window
            link = score_pair(event, other, settings)
            if link and link.score >= settings.min_score:
                correlations.append(link)

    correlations.sort(key=lambda c: c.score, reverse=True)
    return correlations
