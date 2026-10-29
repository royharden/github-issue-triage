"""Bounded, closed deterministic JSON preimages; no binary floats or surrogate strings."""

import hashlib
import json


class CodeIndexError(ValueError):
    """Closed code only; no untrusted input or arbitrary exception text."""


def canonical_bytes(value) -> bytes:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 64 or count > 200000:
            raise CodeIndexError("canonical_structure_limit")
        if type(item) is str:
            try:
                item.encode("utf-8", errors="strict")
            except UnicodeError:
                raise CodeIndexError("invalid_utf8") from None
        elif type(item) is dict:
            if any(type(key) is not str for key in item):
                raise CodeIndexError("invalid_canonical_key")
            pending.extend((key, depth + 1) for key in item)
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in (int, bool):
            raise CodeIndexError("invalid_canonical_scalar")
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def digest(value) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def decode_canonical(data: bytes, *, max_bytes: int):
    if type(data) is not bytes or len(data) > max_bytes:
        raise CodeIndexError("canonical_byte_limit")

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise CodeIndexError("duplicate_json_key")
            result[key] = value
        return result

    def unsupported(_):
        raise CodeIndexError("invalid_canonical_scalar")

    try:
        value = json.loads(
            data, object_pairs_hook=pairs, parse_float=unsupported, parse_constant=unsupported
        )
        if canonical_bytes(value) != data:
            raise CodeIndexError("noncanonical_bytes")
        return value
    except CodeIndexError:
        raise
    except Exception:
        raise CodeIndexError("invalid_canonical_json") from None
