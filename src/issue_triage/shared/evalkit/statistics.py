"""Generic hand-checkable statistics over private outcomes. No domain or model calls."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass

from .identity import canonical_bytes
from .models import ConfusionCounts, Outcome


@dataclass(frozen=True)
class Statistic:
    value: float | None
    support: int
    null_reason: str | None = None
    numerator: int | None = None
    denominator: int | None = None

    def __post_init__(self):
        if type(self.support) is not int or self.support < 0:
            raise ValueError("support must be a nonnegative integer")
        if self.value is None:
            if not self.null_reason:
                raise ValueError("undefined statistic needs a reason")
        elif (
            type(self.value) not in (float, int)
            or not math.isfinite(self.value)
            or self.null_reason
        ):
            raise ValueError("finite measured statistic or explicit undefined value required")


@dataclass(frozen=True)
class ClassificationStats:
    precision: Statistic
    recall: Statistic
    f1: Statistic
    actual_support: int
    predicted_support: int


def _count(value: int) -> None:
    if type(value) is not int or value < 0:
        raise ValueError("nonnegative integer count required")


def rate(numerator: int, denominator: int) -> Statistic:
    _count(numerator)
    _count(denominator)
    if numerator > denominator:
        raise ValueError("rate numerator exceeds denominator")
    return (
        Statistic(
            numerator / denominator, denominator, numerator=numerator, denominator=denominator
        )
        if denominator
        else Statistic(None, 0, "zero_denominator", numerator, denominator)
    )


def typed_equal(left: object, right: object) -> bool:
    """JSONfalse differs from0; strings retain codepoints/whitespace without normalization."""
    return canonical_bytes(left) == canonical_bytes(right)


def confusion_counts(
    outcomes: tuple[Outcome, ...], label: object, eligibility: str = "eligible"
) -> ConfusionCounts:
    tp = fp = fn = tn = 0
    for outcome in outcomes:
        if outcome.eligibility != eligibility or outcome.status == "not_run":
            continue
        actual = typed_equal(outcome.expected, label)
        predicted = outcome.status == "ok" and typed_equal(outcome.predicted, label)
        if actual and predicted:
            tp += 1
        elif predicted:
            fp += 1
        elif actual:
            fn += 1  # eligible failures, abstentions and stale rows remain end-to-end misses
        else:
            tn += 1
    return ConfusionCounts(true_positive=tp, false_positive=fp, false_negative=fn, true_negative=tn)


def classification_rates(counts: ConfusionCounts) -> ClassificationStats:
    tp, fp, fn = counts.true_positive, counts.false_positive, counts.false_negative
    actual, predicted = tp + fn, tp + fp
    precision = rate(tp, predicted)
    recall = rate(tp, actual)
    if actual == 0:
        f1 = Statistic(None, 0, "unsupported_class", 2 * tp, 2 * tp + fp + fn)
    else:
        f1 = Statistic(
            2 * tp / (2 * tp + fp + fn), actual, numerator=2 * tp, denominator=2 * tp + fp + fn
        )
    return ClassificationStats(precision, recall, f1, actual, predicted)


def classification_summary(
    confusions: Mapping[str, ConfusionCounts], declared_averaging: str
) -> ClassificationStats:
    if declared_averaging == "micro":
        keys = ("true_positive", "false_positive", "false_negative", "true_negative")
        total = ConfusionCounts(
            **{key: sum(getattr(c, key) for c in confusions.values()) for key in keys}
        )
        return classification_rates(total)
    if declared_averaging not in ("macro", "weighted"):
        raise ValueError("declared averaging must be micro, macro or weighted")
    stats = [classification_rates(c) for c in confusions.values()]
    outputs = []
    for metric in ("precision", "recall", "f1"):
        # Keep supported-but-undefined metrics NA instead of dropping difficult classes.
        supported = [s for s in stats if s.actual_support > 0]
        if any(getattr(s, metric).value is None for s in supported):
            outputs.append(
                Statistic(
                    None, sum(s.actual_support for s in supported), "undefined_supported_class"
                )
            )
            continue
        measured = [
            (getattr(s, metric).value, s.actual_support)
            for s in stats
            if s.actual_support > 0 and getattr(s, metric).value is not None
        ]
        weights = [n if declared_averaging == "weighted" else 1 for _, n in measured]
        denominator = sum(weights)
        value = (
            sum(v * w for (v, _), w in zip(measured, weights, strict=True)) / denominator
            if denominator
            else None
        )
        outputs.append(
            Statistic(
                value,
                sum(n for _, n in measured),
                None if value is not None else "unsupported_classes",
            )
        )
    return ClassificationStats(
        *outputs, sum(s.actual_support for s in stats), sum(s.predicted_support for s in stats)
    )


def accuracy(
    outcomes: tuple[Outcome, ...],
    *,
    answered_only: bool = False,
    machine_automation_only: bool = False,
) -> Statistic:
    eligible = [
        o
        for o in outcomes
        if o.eligibility == "eligible"
        and o.status != "not_run"
        and (not machine_automation_only or not o.human_touched_prediction)
    ]
    if answered_only:
        eligible = [o for o in eligible if o.status == "ok"]
    correct = sum(o.status == "ok" and o.correct is True for o in eligible)
    return rate(correct, len(eligible))


def exact_set_accuracy(outcomes: tuple[Outcome, ...]) -> Statistic:
    eligible = [o for o in outcomes if o.eligibility == "eligible" and o.status != "not_run"]
    count = 0
    for outcome in eligible:
        if outcome.status != "ok":
            continue
        if type(outcome.expected) is not list or type(outcome.predicted) is not list:
            raise ValueError("exact-set inputs must be adapter-validated JSON arrays")
        expected = {canonical_bytes(v) for v in outcome.expected}
        predicted = {canonical_bytes(v) for v in outcome.predicted}
        if len(expected) != len(outcome.expected) or len(predicted) != len(outcome.predicted):
            raise ValueError("duplicate set member")
        count += expected == predicted
    return rate(count, len(eligible))


def wilson_interval(correct: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    _count(correct)
    _count(n)
    if correct > n or type(z) not in (float, int) or not math.isfinite(z) or z <= 0:
        raise ValueError("valid correct/n and finite positive z required")
    if n == 0:
        return None
    p = correct / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, center - half), min(1.0, center + half)


def agreement(left: tuple[object, ...], right: tuple[object, ...]) -> dict[str, Statistic]:
    """Actual paired label values supplied by consumer; this does not create human provenance."""
    if len(left) != len(right):
        raise ValueError("paired label counts differ")
    n = len(left)
    matches = sum(typed_equal(a, b) for a, b in zip(left, right, strict=True))
    observed = rate(matches, n)
    disagreement = rate(n - matches, n)
    if not n:
        return {
            "agreement": observed,
            "disagreement": disagreement,
            "kappa": Statistic(None, 0, "no_paired_labels"),
        }
    labels = {canonical_bytes(v) for v in (*left, *right)}
    a_counts = {label: sum(canonical_bytes(v) == label for v in left) for label in labels}
    b_counts = {label: sum(canonical_bytes(v) == label for v in right) for label in labels}
    expected = sum(a_counts[label] * b_counts[label] for label in labels) / (n * n)
    kappa = (
        Statistic((observed.value - expected) / (1 - expected), n)
        if expected < 1
        else Statistic(None, n, "degenerate_marginals")
    )
    return {"agreement": observed, "disagreement": disagreement, "kappa": kappa}
