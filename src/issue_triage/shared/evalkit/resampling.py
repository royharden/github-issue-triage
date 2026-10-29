"""Paired whole-group bootstrap; fixed draw stream shared across every method."""

from __future__ import annotations

import hashlib
import math
import random
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from .identity import canonical_bytes
from .models import Interval, Outcome, ResamplingSpec
from .statistics import Statistic


@dataclass(frozen=True)
class ResampledEstimate:
    point: Statistic
    interval: Interval | None
    valid_draws: int
    null_reason: str | None


@dataclass(frozen=True)
class PairedResampling:
    methods: dict[str, ResampledEstimate]
    differences: dict[tuple[str, str], ResampledEstimate]
    draws_sha256: str
    group_count: int
    rng_version: str
    python_version: str
    support_policy: str


def percentile(values: tuple[float, ...], probability: float) -> float:
    if (
        not values
        or type(probability) not in (float, int)
        or not math.isfinite(probability)
        or not 0 <= probability <= 1
    ):
        raise ValueError("finite percentile inputs required")
    if any(type(v) not in (float, int) or not math.isfinite(v) for v in values):
        raise ValueError("nonfinite percentile value")
    ordered = sorted(values)
    index = probability * (len(ordered) - 1)
    low, high = math.floor(index), math.ceil(index)
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def paired_group_resample(
    outcomes_by_method: Mapping[str, tuple[Outcome, ...]],
    spec: ResamplingSpec,
    statistic_callback: Callable[[tuple[Outcome, ...]], Statistic],
) -> PairedResampling:
    """min_support is callback-reported target support; minimum2 whole independent groups.

    Consumer pins its support meaning in statistic_version and freezes the policy before tuning.
    Undefined/insufficient-support draws are recorded; they are not redrawn until a score appears.
    """
    if spec.rng_version != "Python3.12/random" or sys.version_info[:2] != (3, 12):
        raise ValueError("unsupported pinned RNG profile")
    if not outcomes_by_method:
        raise ValueError("named methods required")
    group_order = spec.group_order
    grouped = {}
    points = {}
    reference_population = None
    for method, outcomes in outcomes_by_method.items():
        buckets: dict[str, list[Outcome]] = {}
        population = {}
        for outcome in outcomes:
            if outcome.method != method or outcome.status == "not_run":
                raise ValueError("wrong method or never-run method has no measured resampling")
            buckets.setdefault(outcome.group_id, []).append(outcome)
            axis = (outcome.item_id, outcome.field, outcome.class_name)
            if axis in population:
                raise ValueError("paired_population_duplicate_axis")
            population[axis] = (
                outcome.dataset,
                outcome.group_id,
                outcome.split,
                outcome.eligibility,
                canonical_bytes(outcome.expected),
            )
        if set(buckets) != set(group_order):
            raise ValueError("paired methods must cover identical declared whole groups")
        grouped[method] = buckets
        if reference_population is None:
            reference_population = population
        elif population != reference_population:
            raise ValueError("paired_population_changed")
    # All fixed reference axes are admitted before any callback or RNG draw can have effects.
    for method, outcomes in outcomes_by_method.items():
        point = statistic_callback(outcomes)
        if not isinstance(point, Statistic):
            raise ValueError("callback must return value/support/undefined metadata")
        points[method] = point
    strata: dict[str, list[str]] = {}
    for group in group_order:
        stratum = spec.stratum_map[group] if spec.stratum_map is not None else "all"
        strata.setdefault(stratum, []).append(group)
    rng = random.Random(spec.seed)
    digest = hashlib.sha256()
    draw_values: dict[str, list[float | None]] = {method: [] for method in outcomes_by_method}
    for _ in range(spec.draws):
        draw = tuple(rng.choice(pool) for pool in strata.values() for _ in pool)
        digest.update(canonical_bytes(draw) + b"\n")
        for method, buckets in grouped.items():
            sample = tuple(row for group in draw for row in buckets[group])
            statistic = statistic_callback(sample)
            if not isinstance(statistic, Statistic):
                raise ValueError("callback must preserve its explicit support/undefined shape")
            draw_values[method].append(
                statistic.value if statistic.support >= spec.min_support else None
            )
    draw_digest = digest.hexdigest()

    def estimate(point: Statistic, values: tuple[float, ...]) -> ResampledEstimate:
        reason = (
            "insufficient_independent_groups"
            if len(group_order) < 2
            else point.null_reason
            if point.value is None
            else "insufficient_support"
            if point.support < spec.min_support
            else "insufficient_valid_draws"
            if len(values) < spec.min_valid_draws
            else None
        )
        if reason:
            return ResampledEstimate(point, None, len(values), reason)
        alpha = (1 - spec.level) / 2
        interval = Interval(
            method="paired_group_percentile",
            low=percentile(values, alpha),
            high=percentile(values, 1 - alpha),
            level=spec.level,
            valid_draws=len(values),
            draw_ids_sha256=draw_digest,
        )
        return ResampledEstimate(point, interval, len(values), None)

    methods = {
        method: estimate(points[method], tuple(v for v in values if v is not None))
        for method, values in draw_values.items()
    }
    differences = {}
    names = tuple(outcomes_by_method)
    for i, left in enumerate(names):
        for right in names[i + 1 :]:
            a, b = points[left], points[right]
            point = (
                Statistic(a.value - b.value, min(a.support, b.support))
                if a.value is not None and b.value is not None
                else Statistic(None, min(a.support, b.support), "undefined_paired_statistic")
            )
            paired = tuple(
                a - b
                for a, b in zip(draw_values[left], draw_values[right], strict=True)
                if a is not None and b is not None
            )
            differences[left, right] = estimate(point, paired)
    return PairedResampling(
        methods,
        differences,
        draw_digest,
        len(group_order),
        spec.rng_version,
        sys.version,
        "callback target support; minimum2 independent groups",
    )
