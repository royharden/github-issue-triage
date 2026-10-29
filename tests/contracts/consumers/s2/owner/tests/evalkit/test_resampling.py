"""Paired clusters retain their cells; draw provenance, undefined support and strata controls."""

import pytest
from test_statistics import outcome

from issue_triage.shared.evalkit.models import ResamplingSpec
from issue_triage.shared.evalkit.resampling import paired_group_resample, percentile
from issue_triage.shared.evalkit.statistics import Statistic, accuracy


def spec(**changes):
    value = {
        "version": "paired/1",
        "unit": "group_id",
        "seed": 37,
        "draws": 2000,
        "level": 0.95,
        "method": "percentile",
        "group_order": ("g0", "g1"),
        "stratum_map": None,
        "min_support": 1,
        "min_valid_draws": 1900,
        "statistic_version": "tiny-accuracy/1",
        "rng_version": "Python3.12/random",
    }
    return ResamplingSpec.model_validate(value | changes)


def test_whole_group_cells_stay_together_and_same_draws_pair_identical_methods():
    baseline = (
        outcome(0, True, True),
        outcome(1, False, True),
        outcome(2, True, False),
        outcome(3, False, False),
    )
    other = tuple(row.model_copy(update={"method": "other"}) for row in baseline)

    def callback(rows):
        for group in {r.group_id for r in rows}:
            members = [r.item_id for r in rows if r.group_id == group]
            assert (
                members.count("0") == members.count("1")
                if group == "g0"
                else members.count("2") == members.count("3")
            )
        return accuracy(rows)

    first = paired_group_resample({"baseline": baseline, "other": other}, spec(), callback)
    again = paired_group_resample({"baseline": baseline, "other": other}, spec(), callback)
    assert first.draws_sha256 == again.draws_sha256
    assert first.methods["baseline"].valid_draws == 2000
    delta = first.differences["baseline", "other"]
    assert delta.point.value == 0 and delta.interval.low == delta.interval.high == 0
    assert (
        first.methods["baseline"].interval.draw_ids_sha256
        == first.methods["other"].interval.draw_ids_sha256
    )
    changed = paired_group_resample({"baseline": baseline}, spec(seed=38), accuracy)
    assert changed.draws_sha256 != first.draws_sha256


def test_undefined_draws_not_redrawn_or_invented_intervals_and_support_minimum_frozen():
    rows = (outcome(0, True, True), outcome(2, False, False))

    def callback(sample):
        if all(r.group_id == "g0" for r in sample):
            return Statistic(None, len(sample), "undefined-example")
        return accuracy(sample)

    result = paired_group_resample({"baseline": rows}, spec(min_valid_draws=2000), callback)
    assert 0 < result.methods["baseline"].valid_draws < 2000
    assert result.methods["baseline"].interval is None
    assert result.methods["baseline"].null_reason == "insufficient_valid_draws"
    unsupported = paired_group_resample({"baseline": rows}, spec(min_support=3), accuracy)
    assert unsupported.methods["baseline"].null_reason == "insufficient_support"


def test_single_group_no_independence_strata_and_missing_group_rejects():
    rows = (outcome(0, True, True), outcome(2, False, False))
    single = paired_group_resample({"baseline": rows[:1]}, spec(group_order=("g0",)), accuracy)
    assert single.methods["baseline"].null_reason == "insufficient_independent_groups"
    stratified = paired_group_resample(
        {"baseline": rows}, spec(stratum_map={"g0": "mixed", "g1": "month2"}), accuracy
    )
    assert stratified.methods["baseline"].valid_draws == 2000
    with pytest.raises(ValueError):
        paired_group_resample({"baseline": rows[:1]}, spec(), accuracy)
    with pytest.raises(ValueError):
        paired_group_resample({"baseline": rows}, spec(rng_version="other"), accuracy)


def test_percentile_interpolation_and_nonfinite_controls():
    assert percentile((0.0, 10.0), 0.25) == 2.5
    for values, p in (((), 0.5), ((0.0, float("nan")), 0.5), ((1.0,), True), ((1.0,), -1)):
        with pytest.raises(ValueError):
            percentile(values, p)


@pytest.mark.parametrize(
    "change",
    [
        {"item_id": "foreign"},
        {"field": "foreign"},
        {"class_name": "foreign"},
        {"expected": "different-gold"},
        {"eligibility": "unlabelled", "correct": None},
        {"dataset": "foreign"},
        {"split": "heldout"},
    ],
    ids=["item", "field", "class", "gold", "eligibility", "dataset", "split"],
)
def test_paired_population_identity_and_gold_cannot_change_before_draws(change):
    rows = (outcome(0, True, True), outcome(2, False, False))
    other = tuple(r.model_copy(update={"method": "other"}) for r in rows)
    other = (other[0].model_copy(update=change), other[1])
    calls = []

    def no_callback(sample):
        calls.append(sample)
        raise AssertionError("invalid paired populations reached callback")

    with pytest.raises(ValueError, match="paired_population"):
        paired_group_resample({"baseline": rows, "other": other}, spec(), no_callback)
    assert calls == []


def test_missing_axis_or_duplicate_axis_inside_same_declared_groups_refuses():
    rows = (outcome(0, True, True), outcome(1, False, False), outcome(2, True, False))
    other = tuple(r.model_copy(update={"method": "other"}) for r in rows)
    for bad in ((other[0], other[2]), (*other, other[0])):
        with pytest.raises(ValueError, match="paired_population"):
            paired_group_resample({"baseline": rows, "other": bad}, spec(), accuracy)
