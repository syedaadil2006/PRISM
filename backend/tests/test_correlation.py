"""Correlation engine behaviour."""

from __future__ import annotations

from app.engine.correlation import correlate, score_pair
from app.models.events import Action, Severity
from tests.conftest import make_event


def test_events_outside_the_window_are_not_correlated(settings):
    first = make_event(Action.POWERSHELL_EXEC, user="john.doe", source_host="HR-PC", suspicious=True)
    later = make_event(
        Action.CREDENTIAL_ACCESS,
        offset_seconds=settings.correlation.window_seconds + 60,
        user="john.doe",
        source_host="HR-PC",
        suspicious=True,
    )
    assert score_pair(first, later, settings.correlation) is None


def test_time_proximity_alone_never_links_two_events(settings):
    """Two unrelated events one second apart must not become an attack chain."""
    a = make_event(Action.POWERSHELL_EXEC, user="john.doe", source_host="HR-PC", suspicious=True)
    b = make_event(
        Action.POWERSHELL_EXEC,
        offset_seconds=1,
        user="sara.lee",
        source_host="MKTG-PC",
        suspicious=True,
    )
    assert score_pair(a, b, settings.correlation) is None


def test_same_user_and_host_clears_the_threshold(settings):
    a = make_event(Action.MALICIOUS_ATTACHMENT, user="john.doe", source_host="HR-PC", suspicious=True)
    b = make_event(
        Action.POWERSHELL_EXEC,
        offset_seconds=53,
        user="john.doe",
        source_host="HR-PC",
        suspicious=True,
    )
    link = score_pair(a, b, settings.correlation)
    assert link is not None
    assert link.score >= settings.correlation.min_score
    names = {f.name for f in link.factors}
    assert {"same_user", "same_host", "time_proximity"} <= names


def test_host_pivot_is_the_strongest_single_factor(settings):
    """An account moving off a compromised host must score above the threshold."""
    creds = make_event(
        Action.CREDENTIAL_ACCESS,
        user="john.doe",
        source_host="HR-PC",
        destination_host="HR-PC",
        suspicious=True,
        severity=Severity.CRITICAL,
    )
    rdp = make_event(
        Action.RDP_LOGIN,
        offset_seconds=323,
        user="john.doe",
        source_host="HR-PC",
        destination_host="FINANCE-PC",
    )
    link = score_pair(creds, rdp, settings.correlation)
    assert link is not None
    pivot = next(f for f in link.factors if f.name == "host_pivot")
    assert pivot.weight == settings.correlation.weight_host_pivot
    assert "FINANCE-PC" in pivot.detail
    assert link.score >= settings.correlation.min_score


def test_dns_without_a_user_still_attaches_via_suspicious_coincidence(settings):
    """DNS records carry no account, so host plus suspicion has to carry them."""
    powershell = make_event(
        Action.POWERSHELL_EXEC, user="john.doe", source_host="HR-PC", suspicious=True
    )
    beacon = make_event(
        Action.SUSPICIOUS_DOMAIN,
        offset_seconds=17,
        source_host="HR-PC",
        domain="update-svc-cdn.xyz",
        suspicious=True,
    )
    link = score_pair(powershell, beacon, settings.correlation)
    assert link is not None
    assert link.score >= settings.correlation.min_score
    assert any(f.name == "suspicious_coincidence" for f in link.factors)


def test_routine_activity_is_excluded_before_scoring(settings):
    """correlate() only considers notable events, which is the noise filter."""
    routine = make_event(
        Action.LOGIN_SUCCESS,
        user="john.doe",
        source_host="HR-PC",
        destination_host="HR-PC",
        severity=Severity.INFO,
    )
    other_routine = make_event(
        Action.PROCESS_CREATE,
        offset_seconds=30,
        user="john.doe",
        source_host="HR-PC",
        process="chrome.exe",
        severity=Severity.INFO,
    )
    assert correlate([routine, other_routine], settings.correlation) == []


def test_every_correlation_carries_its_reasons(settings):
    a = make_event(Action.MALICIOUS_ATTACHMENT, user="john.doe", source_host="HR-PC", suspicious=True)
    b = make_event(
        Action.POWERSHELL_EXEC, offset_seconds=36, user="john.doe", source_host="HR-PC", suspicious=True
    )
    links = correlate([a, b], settings.correlation)
    assert len(links) == 1
    assert links[0].reasons
    assert all(reason for reason in links[0].reasons)


def test_scores_are_capped_at_one(settings):
    a = make_event(
        Action.CREDENTIAL_ACCESS,
        user="john.doe",
        source_host="HR-PC",
        source_ip="10.0.1.15",
        process="powershell.exe",
        suspicious=True,
    )
    b = make_event(
        Action.RDP_LOGIN,
        offset_seconds=5,
        user="john.doe",
        source_host="HR-PC",
        destination_host="FINANCE-PC",
        source_ip="10.0.1.15",
        process="powershell.exe",
        suspicious=True,
    )
    link = score_pair(a, b, settings.correlation)
    assert link is not None
    assert link.score == 1.0
