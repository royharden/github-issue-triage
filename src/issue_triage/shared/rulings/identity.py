"""Canonical identity and complete intent preimages. Raw row validation is injected."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import RulingIntent


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def canonical_pair(refs: tuple[dict[str, str], dict[str, str]]) -> tuple[dict[str, str], ...]:
    from .models import RecordIdentity

    validated = [RecordIdentity.model_validate(ref).model_dump() for ref in refs]
    if len(validated) != 2 or validated[0] == validated[1]:
        raise ValueError("two distinct record identities required")
    return tuple(sorted(validated, key=canonical_bytes))


def pair_key(refs: tuple[dict[str, str], dict[str, str]]) -> str:
    preimage = {"algorithm_version": 1, "kind": "pair", "refs": canonical_pair(refs)}
    return "pk1:" + hashlib.sha256(canonical_bytes(preimage)).hexdigest()


def pair_generation(key: str, aligned_raw_fingerprints: tuple[str, str]) -> str:
    from pydantic import TypeAdapter

    from .models import PairKey, Sha256

    TypeAdapter(PairKey, config={"strict": True}).validate_python(key)
    TypeAdapter(tuple[Sha256, Sha256], config={"strict": True}).validate_python(
        aligned_raw_fingerprints
    )
    preimage = {
        "algorithm_version": 1,
        "pair_key": key,
        "raw_fingerprints": aligned_raw_fingerprints,
    }
    return "pg1:" + hashlib.sha256(canonical_bytes(preimage)).hexdigest()


def intent_bytes(intent: RulingIntent) -> bytes:
    """All client fields participate, including actor/time/reason/context and nulls."""
    return canonical_bytes(intent.model_dump(mode="json", exclude={"sequence"}))
