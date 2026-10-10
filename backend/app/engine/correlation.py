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


def _quick_score(a: NormalizedEvent, b: NormalizedEvent, settings: CorrelationSettings) -> float:
    """The score score_pair() would give, without building its explanation.

    Mirrors score_pair() exactly; used to skip building factor objects for the
    great majority of pairs that do not clear the threshold.
    """
    delta = abs((b.timestamp - a.timestamp).total_seconds())
    if delta > settings.window_seconds:
        return 0.0
    if b.timestamp < a.timestamp:
        a, b = b, a
    substantive = 0.0
    if a.user and b.user and a.user == b.user:
        substantive += settings.weight_same_user
    shared = _shared_hosts(a, b)
    if shared:
        substantive += settings.weight_same_host
    if _is_pivot(a, b):
        substantive += settings.weight_host_pivot
    if a.ips() & b.ips():
        substantive += settings.weight_shared_ip
    if a.process and b.process and a.process.lower() == b.process.lower() and shared:
        substantive += settings.weight_process_host
    if a.domain and b.domain and a.domain == b.domain:
        substantive += settings.weight_domain_overlap
    if shared and a.suspicious and b.suspicious:
        substantive += settings.weight_suspicious_coincidence
    if substantive <= 0:
        return 0.0
    return min(1.0, substantive + settings.weight_time_proximity * (1.0 - delta / settings.window_seconds))


def _keys(event: NormalizedEvent) -> list[tuple[str, str]]:
    """The entities an event can share with another. Two events that share none
    of these cannot score anything but time proximity, so they are never paired."""
    keys = [("host", h) for h in event.hosts()]
    keys += [("ip", ip) for ip in event.ips()]
    if event.user:
        keys.append(("user", event.user))
    if event.domain:
        keys.append(("domain", event.domain))
    return keys


def correlate(
    events: list[NormalizedEvent],
    settings: CorrelationSettings,
) -> list[Correlation]:
    """Correlate the notable events in a batch.

    Only notable events are considered, which is what keeps routine business
    traffic out of attack chains. Candidate pairs come from an index of shared
    entities (host, address, account, domain) inside the time window, because a
    pair sharing none of them can never reach the threshold. Up to
    ``exact_pair_limit`` notable events the result is identical to scoring every
    pair in the window.

    Above that size (large real datasets) the work is bounded: each event is
    compared with its ``max_neighbors_per_key`` most recent neighbours per shared
    entity, and keeps its ``max_links_per_event`` strongest links to earlier
    events. That is enough to keep a chain connected, and keeps memory linear
    in the number of events instead of quadratic.
    """
    notable = sorted(
        (e for e in events if e.is_notable),
        key=lambda e: (e.timestamp, e.event_id),
    )
    bounded = len(notable) > settings.exact_pair_limit
    neighbours = settings.max_neighbors_per_key if bounded else None
    window = settings.window_seconds

    buckets: dict[tuple[str, str], list[NormalizedEvent]] = {}
    correlations: list[Correlation] = []

    for event in notable:
        candidates: dict[str, NormalizedEvent] = {}
        for key in _keys(event):
            bucket = buckets.setdefault(key, [])
            # Drop neighbours that have left the window (bucket is time ordered).
            cut = 0
            while cut < len(bucket) and (event.timestamp - bucket[cut].timestamp).total_seconds() > window:
                cut += 1
            if cut:
                del bucket[:cut]
            recent = bucket if neighbours is None else bucket[-neighbours:]
            for other in recent:
                candidates[other.event_id] = other
            bucket.append(event)

        links: list[Correlation] = []
        for other in candidates.values():
            if _quick_score(other, event, settings) < settings.min_score:
                continue
            link = score_pair(other, event, settings)
            if link and link.score >= settings.min_score:
                links.append(link)
        if bounded and len(links) > settings.max_links_per_event:
            links.sort(key=lambda c: c.score, reverse=True)
            links = links[: settings.max_links_per_event]
        correlations.extend(links)

    correlations.sort(key=lambda c: c.score, reverse=True)
    return correlations
