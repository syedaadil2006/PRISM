"""Behaviour baselines (UEBA): what is normal for each account and computer.

PRISM learns, in time order, which computers each account signs in to, at what
hours, and which programs run on each computer. Once an account or computer
has enough history - at least ``min_history`` events over at least
``learning_hours`` since PRISM first saw it - a departure is recorded as an
**anomaly** with a plain explanation, for example:

* "first sign-in by maria.gomez to FILE01 (usually: FINANCE-PC, HR-PC)";
* "sign-in by john.doe at 03:00, outside their usual hours (08:00-18:00)";
* "procdump.exe ran on HR-PC for the first time (never seen on any computer)".

The same history also recognises **routine work**: a low-risk pattern (the
same account doing the same kind of sign-in or discovery command against the
same computer) seen on ``routine_days`` or more different days, for example an
IT administrator who signs in to the file server over remote desktop every
morning. Routine events stay in the record with the reason, but cannot start or
extend an attack chain. Anything a rule flagged (Sigma, threat intel,
credential access, high severity) is never treated as routine.

Anomalies are evidence, not verdicts: they are attached to the event (shown
with its findings, counted on the chain) but on their own they never create an
attack chain, because people do new things all the time. They make a chain
that already shows attack behaviour more convincing, and they surface the
quiet steps an attacker takes with valid credentials.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from app.models.events import MOVEMENT_ACTIONS, Action, EventType, NormalizedEvent, Severity

ROUTINE_REASON = "routine: "
#: Low-signal actions that a daily habit can explain.
ROUTINE_ACTIONS = MOVEMENT_ACTIONS | {Action.LOGIN_SUCCESS, Action.DISCOVERY_COMMAND}
ANOMALY_PREFIX = "anomaly:"
FINDING_PREFIX = "finding:Baseline: "


def _clear(event: NormalizedEvent) -> None:
    if any(t.startswith((ANOMALY_PREFIX, FINDING_PREFIX)) for t in event.tags):
        event.tags[:] = [t for t in event.tags if not t.startswith((ANOMALY_PREFIX, FINDING_PREFIX))]


def _flag(event: NormalizedEvent, kind: str, text: str) -> None:
    event.tags.append(ANOMALY_PREFIX + kind)
    event.tags.append(FINDING_PREFIX + text)


def _hours(hours: set[int]) -> str:
    ordered = sorted(hours)
    return f"{ordered[0]:02d}:00-{ordered[-1] + 1:02d}:00" if ordered else "none yet"


def apply_baselines(events: list[NormalizedEvent], min_history: int = 20, learning_hours: float = 24.0) -> int:
    """Tag anomalies on ``events`` (which must be in time order). Returns how many."""
    learning = timedelta(hours=learning_hours)
    first_seen: dict[str, datetime] = {}

    def learned(key: str, count: int, when: datetime) -> bool:
        start = first_seen.setdefault(key, when)
        return count >= min_history and when - start >= learning

    user_events: dict[str, int] = defaultdict(int)
    user_hosts: dict[str, set[str]] = defaultdict(set)
    user_hours: dict[str, set[int]] = defaultdict(set)
    host_events: dict[str, int] = defaultdict(int)
    host_processes: dict[str, set[str]] = defaultdict(set)
    process_hosts: dict[str, set[str]] = defaultdict(set)
    found = 0

    for event in events:
        _clear(event)
        user = (event.user or "").lower()
        host = (event.primary_host or "").upper()
        is_logon = event.event_type is EventType.AUTHENTICATION and event.action is not Action.LOGIN_FAILURE

        if is_logon and user and host and not event.suppressed:
            if learned("u:" + user, user_events[user], event.timestamp):
                if host not in user_hosts[user] and (event.action in MOVEMENT_ACTIONS or event.action is Action.LOGIN_SUCCESS):
                    usual = ", ".join(sorted(user_hosts[user])[:4]) or "none"
                    _flag(event, "new-host", f"first sign-in by {event.user} to {event.primary_host} (usually: {usual})")
                    found += 1
                hour = event.timestamp.hour
                if user_hours[user] and not ({hour - 1, hour, hour + 1} & user_hours[user]):
                    _flag(event, "unusual-hour",
                          f"sign-in by {event.user} at {hour:02d}:00, outside their usual hours ({_hours(user_hours[user])})")
                    found += 1
            user_hosts[user].add(host)
            if event.source_host:
                user_hosts[user].add(event.source_host.upper())
            user_hours[user].add(event.timestamp.hour)

        if event.event_type is EventType.ENDPOINT and event.process and host:
            process = event.process.lower()
            if learned("h:" + host, host_events[host], event.timestamp) and process not in host_processes[host]:
                elsewhere = process_hosts[process] - {host}
                if not elsewhere:
                    _flag(event, "new-process",
                          f"{event.process} ran on {event.primary_host} for the first time (never seen on any computer)")
                    found += 1
            host_processes[host].add(process)
            process_hosts[process].add(host)
            host_events[host] += 1

        if user:
            first_seen.setdefault("u:" + user, event.timestamp)
            user_events[user] += 1
        if host:
            first_seen.setdefault("h:" + host, event.timestamp)
            if event.event_type is not EventType.ENDPOINT:
                host_events[host] += 1
    return found


def anomalies(event: NormalizedEvent) -> list[str]:
    return [t[len(FINDING_PREFIX):] for t in event.tags if t.startswith(FINDING_PREFIX)]


def _routine_key(event: NormalizedEvent) -> tuple[str, str, str, str] | None:
    if event.action not in ROUTINE_ACTIONS or not event.user:
        return None
    if event.severity.rank >= Severity.HIGH.rank or any(t.startswith(("sigma:", "intel:")) for t in event.tags):
        return None
    detail = " ".join((event.command_line or event.process or "").lower().split())
    return (event.user.lower(), event.action.value, (event.primary_host or "").upper(), detail)


def mark_routine(events: list[NormalizedEvent], routine_days: int = 3) -> int:
    """Suppress low-risk patterns repeated on ``routine_days`` or more days. Returns how many events."""
    for event in events:
        if event.suppressed and event.suppressed.startswith(ROUTINE_REASON + "same"):
            event.suppressed = None  # recomputed from scratch on every pass
    if routine_days <= 0:
        return 0
    days: dict[tuple[str, str, str, str], set] = defaultdict(set)
    for event in events:
        key = _routine_key(event)
        if key:
            days[key].add(event.timestamp.date())
    marked = 0
    for event in events:
        key = _routine_key(event)
        if key and not event.suppressed and len(days[key]) >= routine_days:
            event.suppressed = (f"{ROUTINE_REASON}same activity by {event.user} on {len(days[key])} different days "
                                "(behaviour baseline)")
            marked += 1
    return marked
