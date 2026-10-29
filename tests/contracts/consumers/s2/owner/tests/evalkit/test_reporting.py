"""Private/frozen versus comparable populations, absent methods and public canaries."""

import pytest
from test_statistics import outcome

from issue_triage.shared.evalkit.models import MetricSpec, PublicProjectionPolicy
from issue_triage.shared.evalkit.reporting import metric_row, not_measured_row, public_aggregate
from issue_triage.shared.evalkit.statistics import accuracy


@pytest.mark.parametrize(
    "change",
    [
        {"field": "foreign"},
        {"class_name": "foreign"},
        {"dataset": "foreign"},
    ],
    ids=["field", "class", "dataset"],
)
def test_mixed_or_relabelled_metric_axes_refuse(change):
    rows = (outcome(0, True, True), outcome(1, False, False))
    rows = (rows[0].model_copy(update=change), rows[1])
    with pytest.raises(ValueError, match="metric_axis_mismatch"):
        metric_row(
            rows,
            ("0", "1"),
            spec(),
            accuracy,
            method="baseline",
            dataset_alias="public-tiny",
            split="dev",
            config_ref="config/1",
        )


def spec(population="as_frozen"):
    return MetricSpec(
        metric="accuracy",
        statistic_version="tiny/1",
        population=population,
        denominator_policy="all-eligible/1",
        zero_denominator_reason="zero_support",
        averaging="none",
    )


def test_frozen_comparable_answered_stale_error_unlabelled_denominators_stay_distinct():
    rows = (
        outcome(0, True, True),
        outcome(1, False, True),
        outcome(2, True, None, status="stale"),
        outcome(3, True, None, status="provider_error"),
        outcome(4, None, None, eligibility="unlabelled"),
    )
    kwargs = {
        "method": "baseline",
        "dataset_alias": "public-tiny",
        "split": "dev",
        "config_ref": "config/1",
    }
    expected = tuple(row.item_id for row in rows)
    frozen = metric_row(rows, expected, spec(), accuracy, **kwargs)
    assert (
        frozen.corpus_N,
        frozen.eligible_N,
        frozen.answered_N,
        frozen.comparable_N,
        frozen.stale_N,
        frozen.error_N,
    ) == (5, 4, 2, 3, 1, 1)
    assert frozen.value == 0.25 and frozen.denominator == 4
    comparable = metric_row(rows, expected, spec("comparable"), accuracy, **kwargs)
    answered = metric_row(rows, expected, spec("answered_only"), accuracy, **kwargs)
    assert comparable.value == pytest.approx(1 / 3) and answered.value == 0.5
    with pytest.raises(ValueError):
        metric_row(rows[:-1], expected, spec(), accuracy, **kwargs)


def test_not_measured_keeps_expected_eligible_metadata_without_fake_perfect_or_live():
    row = not_measured_row(
        ("one", "two", "unlabelled"),
        ("one", "two"),
        spec(),
        method="never-run",
        dataset_alias="tiny",
        split="dev",
        config_ref="config/1",
    )
    assert row.corpus_N == 3 and row.eligible_N == 2 and row.answered_N == 0
    assert row.value is None and row.numerator is None and row.denominator is None
    assert row.evidence_origin == "not_run" and row.measurement_status == "not_measured"


def test_closed_public_values_count_projection_and_private_source_canary_refusal():
    rows = (outcome(0, True, True),)
    row = metric_row(
        rows,
        ("0",),
        spec(),
        accuracy,
        method="baseline",
        dataset_alias="tiny",
        split="dev",
        config_ref="config/1",
    )
    policy = PublicProjectionPolicy(
        mode="aggregate_only",
        allowed_dimensions=("method", "dataset_alias"),
        allowed_value_sets={"method": ("baseline",), "dataset_alias": ("tiny",)},
        allowed_numeric_metrics=("value", "corpus_N", "eligible_N"),
        synthetic_example_refs=(),
    )
    assert public_aggregate(row, policy) == {
        "method": "baseline",
        "dataset_alias": "tiny",
        "value": 1.0,
        "corpus_N": 1,
        "eligible_N": 1,
    }
    with pytest.raises(ValueError):
        public_aggregate(rows[0], policy)
    with pytest.raises(ValueError):
        public_aggregate(row.model_copy(update={"dataset_alias": "private-org-CANARY"}), policy)


def test_public_not_measured_keeps_explicit_null_value_without_fake_zero():
    row = not_measured_row(
        ("one",),
        ("one",),
        spec(),
        method="absent",
        dataset_alias="tiny",
        split="dev",
        config_ref="config/1",
    )
    policy = PublicProjectionPolicy(
        mode="aggregate_only",
        allowed_dimensions=("method", "null_reason"),
        allowed_value_sets={"method": ("absent",), "null_reason": ("not_run",)},
        allowed_numeric_metrics=("value", "eligible_N", "low", "high"),
        synthetic_example_refs=(),
    )
    public = public_aggregate(row, policy)
    assert public["value"] is None and public["low"] is None and public["high"] is None
    assert public["null_reason"] == "not_run" and public["eligible_N"] == 1
