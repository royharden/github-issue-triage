"""Independent hand counts, failure denominators and declared uncertainty methods."""

import math

import pytest

from issue_triage.shared.evalkit.models import ConfusionCounts, Outcome
from issue_triage.shared.evalkit.statistics import (
    accuracy,
    agreement,
    classification_rates,
    classification_summary,
    confusion_counts,
    exact_set_accuracy,
    rate,
    typed_equal,
    wilson_interval,
)


def outcome(item, expected, predicted, *, status="ok", eligibility="eligible", human=False):
    return Outcome(
        item_id=str(item),
        group_id="g" + str(item // 2),
        dataset="synthetic",
        split="dev",
        method="baseline",
        field=None,
        **{"class": None},
        eligibility=eligibility,
        status=status,
        correct=typed_equal(expected, predicted)
        if status == "ok" and eligibility == "eligible"
        else None,
        predicted=predicted,
        expected=expected,
        human_touched_prediction=human,
        evidence_origin="synthetic",
        issues=(),
        ledger_refs=(),
    )


def test_adopted_six_eligible_seven_corpus_five_answered_three_correct_microcase():
    gold = (True, True, False, False, "not_stated", "not_stated")
    predicted = (True, False, False, "not_stated", "not_stated", None)
    rows = tuple(
        outcome(i, a, b, status="provider_error" if i == 5 else "ok")
        for i, (a, b) in enumerate(zip(gold, predicted, strict=True))
    )
    rows = rows + (outcome(6, None, None, eligibility="unlabelled"),)
    true = classification_rates(confusion_counts(rows, True))
    false = classification_rates(confusion_counts(rows, False))
    unstated = classification_rates(confusion_counts(rows, "not_stated"))
    assert (
        true.precision.value == 1
        and true.recall.value == 0.5
        and true.f1.value == pytest.approx(2 / 3)
    )
    for stats in (false, unstated):
        assert stats.precision.value == stats.recall.value == stats.f1.value == 0.5
    assert accuracy(rows).value == 0.5 and accuracy(rows).denominator == 6
    assert (
        accuracy(rows, answered_only=True).value == 0.6
        and accuracy(rows, answered_only=True).denominator == 5
    )
    assert len(rows) == 7


def test_supported_false_is_not_integer_zero_and_none_string_not_absence():
    assert not typed_equal(False, 0) and not typed_equal(True, 1)
    assert not typed_equal("none", None) and not typed_equal("é", "e\u0301")
    rows = (outcome(0, False, False), outcome(1, False, 0))
    assert confusion_counts(rows, False).true_positive == 1
    assert confusion_counts(rows, False).false_negative == 1


def test_no_answer_all_positive_f1_zero_precision_undefined_unsupported_class_na():
    rows = (outcome(0, True, None, status="blocked"), outcome(1, True, None, status="stale"))
    stats = classification_rates(confusion_counts(rows, True))
    assert stats.precision.value is None and stats.recall.value == 0 and stats.f1.value == 0
    unsupported = classification_rates(confusion_counts(rows, False))
    assert unsupported.f1.value is None and unsupported.f1.null_reason == "unsupported_class"
    assert rate(0, 0).value is None and wilson_interval(0, 0) is None


@pytest.mark.parametrize("num,den", [(True, 1), (0, False), (-1, 1), (2, 1), (1.0, 2)])
def test_rate_invalid_and_boolean_counts_refuse(num, den):
    with pytest.raises(ValueError):
        rate(num, den)


def test_macro_weighted_and_micro_handcounts_do_not_erase_undefined_supported_class():
    counts = {
        "a": ConfusionCounts(true_positive=1, false_positive=0, false_negative=1, true_negative=2),
        "b": ConfusionCounts(true_positive=2, false_positive=1, false_negative=0, true_negative=1),
    }
    micro = classification_summary(counts, "micro")
    assert micro.precision.value == 0.75 and micro.recall.value == 0.75
    macro = classification_summary(counts, "macro")
    assert macro.precision.value == pytest.approx((1 + 2 / 3) / 2)
    assert macro.recall.value == 0.75
    missing = counts | {
        "c": ConfusionCounts(true_positive=0, false_positive=0, false_negative=2, true_negative=2)
    }
    assert classification_summary(missing, "macro").precision.value is None
    assert classification_summary(counts, "weighted").f1.value == pytest.approx((2 / 3 + 0.8) / 2)


def test_human_effective_predictions_not_substituted_for_machine_reference_scoring():
    raw = (outcome(0, True, False, human=True), outcome(1, True, True))
    assert accuracy(raw).value == 0.5
    assert accuracy(raw, machine_automation_only=True).value == 1
    assert accuracy(raw, machine_automation_only=True).denominator == 1


def test_exact_sets_empty_negative_and_failure_denominator():
    rows = (
        outcome(0, ["a", "b"], ["b", "a"]),
        outcome(1, [], []),
        outcome(2, ["a"], None, status="provider_error"),
    )
    assert exact_set_accuracy(rows).value == pytest.approx(2 / 3)
    with pytest.raises(ValueError):
        exact_set_accuracy((outcome(0, ["a", "a"], ["a"]),))


def test_wilson_known_values_and_small_all_correct_is_not_precision_gate():
    low, high = wilson_interval(3, 6)
    assert low == pytest.approx(0.18761280689940868) and high == pytest.approx(0.8123871931005913)
    low, high = wilson_interval(40, 40)
    assert low < 0.95 and high == pytest.approx(1.0)
    assert wilson_interval(100, 100)[0] > 0.95
    for args in ((True, 1), (2, 1), (1, 2, float("nan")), (1, 2, 0)):
        with pytest.raises(ValueError):
            wilson_interval(*args)


def test_paired_actual_label_agreement_counts_kappa_and_degenerate_no_fake_humans():
    stats = agreement((True, True, False, False), (True, False, False, False))
    assert stats["agreement"].value == 0.75 and stats["disagreement"].value == 0.25
    assert stats["kappa"].value == 0.5
    assert agreement((True,), (True,))["kappa"].value is None
    assert agreement((), ())["kappa"].null_reason == "no_paired_labels"
    with pytest.raises(ValueError):
        agreement((True,), ())
    assert math.isfinite(stats["kappa"].value)
