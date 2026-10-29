"""Bounded whole-source preparation with conservative original UTF-8 interval maps."""

import re
import secrets
import unicodedata
from types import MappingProxyType

from .models import (
    HeldInput,
    OffsetSegment,
    PreparedText,
    ScreenPolicy,
    ScreenValidationError,
    UntrustedText,
    WrappedData,
    canonical_digest,
    digest_text,
)

MARKER = re.compile(r"<!--|-->|</?details\b[^>]*>", re.IGNORECASE)


def prepare_text(source: UntrustedText, policy: ScreenPolicy) -> PreparedText | HeldInput:
    if type(source) is not UntrustedText or type(policy) is not ScreenPolicy:
        raise ScreenValidationError()
    try:
        original = source.text.encode("utf-8", errors="strict")
    except UnicodeError:
        return HeldInput(source, None, None, policy.sha256, "invalid_encoding")
    original_sha = digest_text(source.text)
    if len(original) > policy.max_input_bytes:
        return HeldInput(source, original_sha, None, policy.sha256, "input_too_large")
    units: list[tuple[str, int, int, str]] = []
    text = source.text
    i = offset = 0
    notices: set[str] = set()
    while i < len(text):
        marker = MARKER.match(text, i)
        if marker:
            value = marker.group()
            size = len(value.encode("utf-8"))
            units.append(("", offset, offset + size, "html_marker_removed"))
            notices.add("hidden_markup_surfaced")
            i = marker.end()
            offset += size
            continue
        char = text[i]
        if unicodedata.category(char) == "Cf" or (
            unicodedata.category(char) == "Cc" and char not in "\t\r\n"
        ):
            size = len(char.encode("utf-8"))
            units.append(("", offset, offset + size, "control_removed"))
            notices.add("controls_removed")
            i += 1
            offset += size
            continue
        end = i + 1
        while end < len(text) and unicodedata.combining(text[end]):
            end += 1
        cluster = text[i:end]
        normalized = unicodedata.normalize("NFKC", cluster)
        size = len(cluster.encode("utf-8"))
        transform = "identity" if normalized == cluster else "nfkc"
        if transform == "nfkc":
            notices.add("normalization_changed")
        units.append((normalized, offset, offset + size, transform))
        i = end
        offset += size
    rendered = "".join(unit[0] for unit in units)
    expected = unicodedata.normalize("NFKC", rendered)
    normalized_sha = digest_text(expected)
    if len(expected.encode("utf-8")) > policy.max_input_bytes:
        return HeldInput(
            source, original_sha, normalized_sha, policy.sha256, "normalized_too_large"
        )
    segments = []
    cursor = 0
    for value, start, end, transform in units:
        following = cursor + len(value.encode("utf-8"))
        segments.append(OffsetSegment(cursor, following, start, end, transform))
        cursor = following
    if expected != rendered:
        # Hold unsupported cross-cluster compositions rather than invent offsets.
        return HeldInput(
            source,
            original_sha,
            normalized_sha,
            policy.sha256,
            "ambiguous_normalization",
            ("ambiguous_normalization",),
        )
    return PreparedText(
        source,
        original_sha,
        normalized_sha,
        len(original),
        len(expected.encode("utf-8")),
        expected,
        tuple(segments),
        policy.normalization_version,
        policy.sha256,
        tuple(sorted(notices)),
    )


def wrap_untrusted(prepared: PreparedText, nonce_source=secrets.token_hex) -> WrappedData:
    if type(prepared) is not PreparedText or prepared.coverage != "complete":
        raise ScreenValidationError()
    original, normalized = prepared.source.text, prepared.normalized_text
    for _ in range(8):
        nonce = nonce_source(16)
        if type(nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
            raise ScreenValidationError("invalid_nonce")
        if nonce not in original and nonce not in normalized:
            break
    else:
        raise ScreenValidationError("nonce_collision")

    def wrapped(value: str) -> str:
        # Escaping markers preserves source text and the original digest; it never drops a suffix.
        value = value.replace("<", "\\u003c").replace(">", "\\u003e")
        return f"<untrusted-{nonce}>\n{value}\n</untrusted-{nonce}>"

    state = MappingProxyType(
        {"original_text": wrapped(original), "normalized_text": wrapped(normalized)}
    )
    return WrappedData(state, canonical_digest(dict(state)))


def validate_captured_wrapper(prepared: PreparedText, wrapped: WrappedData) -> bool:
    """Validate exact current DATA, not permission to read a path or contact a provider."""
    if type(wrapped) is not WrappedData:
        return False
    state = dict(wrapped.state)
    if canonical_digest(state) != wrapped.sha256:
        return False
    match = re.match(r"<untrusted-([0-9a-f]{32})>\n", state["original_text"])
    if match is None:
        return False
    nonce = match.group(1)
    if nonce in prepared.source.text or nonce in prepared.normalized_text:
        return False
    expected = wrap_untrusted(prepared, nonce_source=lambda _: nonce)
    return state == dict(expected.state) and wrapped.sha256 == expected.sha256
