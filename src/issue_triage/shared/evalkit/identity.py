"""Exact ordered-ID and JSON preimages; no split generation or filesystem access."""

import hashlib
import json


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def ordered_ids_digest(ids: tuple[str, ...]) -> str:
    if type(ids) is not tuple or any(type(item) is not str or not item for item in ids):
        raise ValueError("ordered opaque string IDs required")
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate ordered ID")
    return hashlib.sha256(canonical_bytes(ids)).hexdigest()


def validate_public_projection(row: dict[str, object], policy: object) -> None:
    """Closed aggregate admission only; not a report writer or de-identification guarantee."""
    from .models import PublicProjectionPolicy

    if not isinstance(policy, PublicProjectionPolicy) or type(row) is not dict:
        raise ValueError("closed row and explicit policy required")
    for key, value in row.items():
        if key in policy.allowed_dimensions:
            if type(value) is not str or value not in policy.allowed_value_sets[key]:
                raise ValueError("unapproved public string dimension")
        elif key in policy.allowed_numeric_metrics:
            if key.endswith("_N") and (type(value) is not int or value < 0):
                raise ValueError("public population counts must remain nonnegative integers")
            if value is not None:
                import math

                if type(value) not in (int, float) or not math.isfinite(value):
                    raise ValueError("finite aggregate number/null required")
        else:
            raise ValueError("private/unknown field in public aggregate projection")


def validate_expected_predictions(
    expected_ids: tuple[str, ...], predictions: tuple[object, ...]
) -> None:
    """Admit response IDs; missing cases remain explicit runner obligations."""
    from .models import Prediction

    ordered_ids_digest(expected_ids)
    seen: set[str] = set()
    for prediction in predictions:
        if not isinstance(prediction, Prediction):
            raise ValueError("Prediction wire required")
        if prediction.item_id not in expected_ids or prediction.item_id in seen:
            raise ValueError("duplicate/unrequested prediction")
        seen.add(prediction.item_id)
