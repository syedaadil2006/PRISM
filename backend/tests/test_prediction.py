"""Next-target scoring behaviour."""

from __future__ import annotations

from app.engine.prediction import build_context, predict_next_targets
from app.graph.builder import build_entity_graph, connectivity_scores, host_subgraph
from app.models.events import Action, Severity
from tests.conftest import make_event


def _scenario(inventory):
    """HR-PC compromised, attacker on FINANCE-PC, two failed attempts at DC01."""
    events = [
        make_event(
            Action.CREDENTIAL_ACCESS,
            user="john.doe",
            source_host="HR-PC",
            destination_host="HR-PC",
            process="powershell.exe",
            suspicious=True,
            severity=Severity.CRITICAL,
        ),
        make_event(
            Action.RDP_LOGIN,
            offset_seconds=300,
            user="john.doe",
            source_host="HR-PC",
            destination_host="FINANCE-PC",
        ),
        make_event(
            Action.LOGIN_FAILURE,
            offset_seconds=600,
            user="john.doe",
            source_host="FINANCE-PC",
            destination_host="DC01",
            outcome="failure",
            suspicious=True,
        ),
    ]
    graph = build_entity_graph(events, inventory)
    ctx = build_context(
        events=events,
        compromised_hosts={"HR-PC", "FINANCE-PC"},
        current_host="FINANCE-PC",
        users={"john.doe"},
        connectivity=connectivity_scores(graph),
        known_hosts=inventory.host_names(),
        attack_chain_id="ATTACK-001",
    )
    return events, host_subgraph(graph), ctx


def test_domain_controller_outranks_the_file_server(inventory, settings):
    _, projection, ctx = _scenario(inventory)
    predictions = predict_next_targets(inventory, projection, ctx, settings.prediction)

    assert predictions, "expected at least one prediction"
    assert predictions[0].host == "DC01"
    assert predictions[0].score > 0
    hosts = [p.host for p in predictions]
    assert hosts.index("DC01") < hosts.index("FILE01")


def test_compromised_hosts_are_never_predicted(inventory, settings):
    _, projection, ctx = _scenario(inventory)
    predictions = predict_next_targets(inventory, projection, ctx, settings.prediction)
    hosts = {p.host.upper() for p in predictions}
    assert "HR-PC" not in hosts
    assert "FINANCE-PC" not in hosts


def test_every_prediction_is_labelled_and_explained(inventory, settings):
    _, projection, ctx = _scenario(inventory)
    for prediction in predict_next_targets(inventory, projection, ctx, settings.prediction):
        assert prediction.assurance.value == "predicted"
        assert prediction.reasons, "a prediction without reasons is not shippable"
        assert "prediction" in prediction.narrative.lower()
        assert len(prediction.factors) == 6
        for factor in prediction.factors:
            assert factor.detail
            assert 0.0 <= factor.points <= factor.max_points


def test_scores_are_normalised_into_the_zero_hundred_range(inventory, settings):
    _, projection, ctx = _scenario(inventory)
    for prediction in predict_next_targets(inventory, projection, ctx, settings.prediction):
        assert 0.0 <= prediction.score <= 100.0
        assert prediction.raw_score > 0


def test_factor_points_sum_to_the_raw_score(inventory, settings):
    _, projection, ctx = _scenario(inventory)
    for prediction in predict_next_targets(inventory, projection, ctx, settings.prediction):
        total = sum(f.points for f in prediction.factors)
        assert abs(total - prediction.raw_score) < 0.01


def test_recent_failed_logons_credit_the_targeted_host(inventory, settings):
    _, projection, ctx = _scenario(inventory)
    predictions = predict_next_targets(inventory, projection, ctx, settings.prediction)
    dc01 = next(p for p in predictions if p.host == "DC01")
    recent = next(f for f in dc01.factors if f.name == "Recent Activity")
    assert recent.points > 0
    assert "DC01" in recent.detail


def test_an_uninvolved_account_removes_the_access_factor(inventory, settings):
    events, projection, ctx = _scenario(inventory)
    ctx.users = {"nobody"}
    predictions = predict_next_targets(inventory, projection, ctx, settings.prediction)
    dc01 = next(p for p in predictions if p.host == "DC01")
    access = next(f for f in dc01.factors if f.name == "User Access")
    assert access.points == 0.0
    assert "No compromised account" in access.detail


def test_weights_are_configurable(inventory, settings):
    _, projection, ctx = _scenario(inventory)
    baseline = predict_next_targets(inventory, projection, ctx, settings.prediction)
    dc01_before = next(p for p in baseline if p.host == "DC01").raw_score

    tuned = settings.prediction.model_copy(update={"weight_criticality": 0.0})
    after = predict_next_targets(inventory, projection, ctx, tuned)
    dc01_after = next(p for p in after if p.host == "DC01").raw_score

    assert dc01_after < dc01_before
