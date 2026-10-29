"""Explicit private metric populations and allowlisted aggregate serialization."""

from __future__ import annotations

from collections.abc import Callable

from .identity import validate_public_projection
from .models import MetricRow, MetricSpec, Outcome, PublicProjectionPolicy
from .statistics import Statistic


def metric_row(
    outcomes: tuple[Outcome, ...],
    expected_item_ids: tuple[str, ...],
    spec: MetricSpec,
    statistic_callback: Callable[[tuple[Outcome, ...]], Statistic],
    *,
    method: str,
    dataset_alias: str,
    split: str,
    config_ref: str,
    field: str | None = None,
    class_name: str | None = None,
) -> MetricRow:
    """One declared metric axis; case IDs must be unique after consumer axis selection."""
    if len(set(expected_item_ids)) != len(expected_item_ids):
        raise ValueError("duplicate frozen item ID")
    ids = tuple(row.item_id for row in outcomes)
    if len(set(ids)) != len(ids) or set(ids) != set(expected_item_ids):
        raise ValueError("metric omitted/duplicated/unrequested fixed cases")
    if any(row.method != method or row.split != split for row in outcomes):
        raise ValueError("metric method/split mismatch")
    if len({row.dataset for row in outcomes}) != 1 or any(
        row.field != field or row.class_name != class_name for row in outcomes
    ):
        raise ValueError("metric_axis_mismatch")
    origins = {row.evidence_origin for row in outcomes}
    if len(origins) != 1 or "not_run" in origins:
        raise ValueError("explicit one-origin executed population required")
    eligible = tuple(row for row in outcomes if row.eligibility == "eligible")
    answered = tuple(row for row in eligible if row.status == "ok")
    comparable = tuple(row for row in eligible if row.status not in ("stale", "unavailable"))
    population = (
        answered
        if spec.population == "answered_only"
        else comparable
        if spec.population == "comparable"
        else eligible
    )
    statistic = statistic_callback(population)
    if not isinstance(statistic, Statistic):
        raise ValueError("callback value/support/reason required")
    counts = {
        "corpus_N": len(outcomes),
        "eligible_N": len(eligible),
        "answered_N": len(answered),
        "comparable_N": len(comparable),
        "error_N": sum(
            row.status in ("invalid", "provider_error", "unavailable") for row in eligible
        ),
        "abstention_N": sum(row.status in ("abstained", "blocked") for row in eligible),
        "stale_N": sum(row.status == "stale" for row in eligible),
    }
    return MetricRow.model_validate(
        {
            "schema_version": 1,
            "dataset_alias": dataset_alias,
            "split": split,
            "method": method,
            "config_ref": config_ref,
            "field": field,
            "class": class_name,
            "metric": spec.metric,
            "statistic_version": spec.statistic_version,
            "measurement_status": "measured",
            "numerator": statistic.numerator,
            "denominator": statistic.denominator,
            "confusion_counts": None,
            "supports": {"statistic_support": statistic.support},
            **counts,
            "value": statistic.value,
            "null_reason": statistic.null_reason,
            "interval": None,
            "evidence_origin": next(iter(origins)),
        }
    )


def not_measured_row(
    expected_item_ids: tuple[str, ...],
    eligible_item_ids: tuple[str, ...],
    spec: MetricSpec,
    *,
    method: str,
    dataset_alias: str,
    split: str,
    config_ref: str,
) -> MetricRow:
    """Explicit consumer eligibility of a never-run method, without fabricated predictions/cost."""
    if len(set(expected_item_ids)) != len(expected_item_ids) or len(set(eligible_item_ids)) != len(
        eligible_item_ids
    ):
        raise ValueError("duplicate expected population")
    if not set(eligible_item_ids) <= set(expected_item_ids):
        raise ValueError("eligibility outside fixed population")
    return MetricRow.model_validate(
        {
            "schema_version": 1,
            "dataset_alias": dataset_alias,
            "split": split,
            "method": method,
            "config_ref": config_ref,
            "field": None,
            "class": None,
            "metric": spec.metric,
            "statistic_version": spec.statistic_version,
            "measurement_status": "not_measured",
            "numerator": None,
            "denominator": None,
            "confusion_counts": None,
            "supports": {"declared_eligible": len(eligible_item_ids)},
            "corpus_N": len(expected_item_ids),
            "eligible_N": len(eligible_item_ids),
            "answered_N": 0,
            "comparable_N": 0,
            "error_N": 0,
            "abstention_N": 0,
            "stale_N": 0,
            "value": None,
            "null_reason": "not_run",
            "interval": None,
            "evidence_origin": "not_run",
        }
    )


def public_aggregate(row: MetricRow, policy: PublicProjectionPolicy) -> dict[str, object]:
    """Do not pass private per-item outcomes or arbitrary metadata to this exporter."""
    if not isinstance(row, MetricRow):
        raise ValueError("aggregate MetricRow required, no private outcome")
    data = row.model_dump(mode="json")
    data["low"] = row.interval.low if row.interval else None
    data["high"] = row.interval.high if row.interval else None
    result = {
        key: data[key]
        for key in (*policy.allowed_dimensions, *policy.allowed_numeric_metrics)
        if key in data and (key in policy.allowed_numeric_metrics or data[key] is not None)
    }
    # Requested dimensions cannot quietly disappear as a different private-name spelling.
    if any(key not in data for key in policy.allowed_dimensions):
        raise ValueError("unknown aggregate dimension")
    validate_public_projection(result, policy)
    return result
