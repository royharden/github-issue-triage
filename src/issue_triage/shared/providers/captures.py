"""Exact immutable fixture lookup and optional caller-owned safe projection protocol."""

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal, Protocol

from pydantic import JsonValue

from ..callledger.models import (
    CallContext,
    Digest,
    Identifier,
    Money,
    NormalizedUsage,
    WireModel,
    canonical_digest,
    decode_wire_json,
)
from .adapters import Outcome, PreparedRequest
from .models import SafeError, SourceCaptureRef, TypedJudgmentResult


class CaptureError(ValueError):
    """Closed codes: no response body, source text, key or path in diagnostics."""


class CaptureContent(WireModel):
    kind: Literal["generated", "typed"]
    status: Literal["ok", "refused", "invalid_output", "provider_error", "unknown"]
    text: str | None
    parsed: JsonValue
    typed: TypedJudgmentResult | None
    model_reported: str | None
    usage_raw: dict[str, JsonValue] | None
    normalized_usage: NormalizedUsage
    error: SafeError | None


@dataclass(frozen=True)
class FixtureRecord:
    content_json: bytes = field(repr=False)
    source: SourceCaptureRef
    namespace: str
    source_generation: str | None
    consumer_context_sha256: str
    dispatched_envelope_sha256: str
    review_receipt_sha256: str


class LiveCaptureReceipt(WireModel):
    receipt_sha256: Digest
    capture_sha256: Digest
    source_ref_sha256: Digest
    namespace: Identifier


def synthetic_capture(
    prepared: PreparedRequest,
    *,
    context: CallContext,
    outcome: Outcome,
    capture_id: str,
    review_receipt_sha256: str,
    indicative_source_cost_usd: str | None = None,
) -> FixtureRecord:
    """Author an explicitly synthetic fixture. There is no live-origin override."""
    content = CaptureContent(
        kind="typed" if prepared.request.kind == "typed_judgment" else "generated",
        status=outcome.status,
        text=outcome.text,
        parsed=outcome.parsed,
        typed=outcome.typed,
        model_reported=outcome.model_reported,
        usage_raw=outcome.usage_raw,
        normalized_usage=outcome.normalized_usage,
        error=None,
    )
    data = json.dumps(
        content.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    source = SourceCaptureRef(
        capture_id=capture_id,
        capture_sha256=hashlib.sha256(data).hexdigest(),
        origin="synthetic",
        source_run_id="authored-fixture",
        request_identity_sha256=prepared.request_identity_sha256,
        model_requested=prepared.request.model,
        model_reported=outcome.model_reported,
        usage_ref=canonical_digest(outcome.normalized_usage.model_dump(mode="json")),
        price_ref=None,
        cost_usd=indicative_source_cost_usd,
        latency_ms=None,
        first_output_kind="unavailable",
        first_output_ms=None,
    )
    return FixtureRecord(
        data,
        source,
        context.consumer_namespace,
        context.source_generation,
        context.consumer_context_sha256,
        prepared.dispatched_envelope_sha256,
        review_receipt_sha256,
    )


class FixtureIndex:
    """Only supplied reviewed bytes; no implicit cache files, put, network or fallback."""

    def __init__(
        self,
        records: Iterable[FixtureRecord],
        *,
        verified_live_receipts: Mapping[str, LiveCaptureReceipt] | None = None,
    ):
        index = {}
        receipts = verified_live_receipts or {}
        for record in records:
            if type(record.content_json) is not bytes:
                raise CaptureError("invalid_capture")
            source = SourceCaptureRef.model_validate(record.source.model_dump(mode="json"))
            if source.capture_sha256 != hashlib.sha256(record.content_json).hexdigest():
                raise CaptureError("capture_hash")
            if (
                not isinstance(record.review_receipt_sha256, str)
                or len(record.review_receipt_sha256) != 64
                or any(c not in "0123456789abcdef" for c in record.review_receipt_sha256)
            ):
                raise CaptureError("unreviewed_capture")
            if source.origin == "live":
                receipt = receipts.get(record.review_receipt_sha256)
                if receipt is None or (
                    receipt.capture_sha256,
                    receipt.source_ref_sha256,
                    receipt.namespace,
                ) != (
                    source.capture_sha256,
                    canonical_digest(source.model_dump(mode="json")),
                    record.namespace,
                ):
                    raise CaptureError("unverified_live_capture")
            CaptureContent.model_validate(decode_wire_json(record.content_json.decode("utf-8")))
            key = (
                source.request_identity_sha256,
                record.namespace,
                record.source_generation,
                record.consumer_context_sha256,
            )
            if key in index:
                raise CaptureError("duplicate_capture")
            index[key] = FixtureRecord(
                record.content_json,
                source,
                record.namespace,
                record.source_generation,
                record.consumer_context_sha256,
                record.dispatched_envelope_sha256,
                record.review_receipt_sha256,
            )
        self._index = MappingProxyType(index)

    def lookup(
        self, prepared: PreparedRequest, *, context: CallContext
    ) -> tuple[CaptureContent, SourceCaptureRef] | None:
        key = (
            prepared.request_identity_sha256,
            context.consumer_namespace,
            context.source_generation,
            context.consumer_context_sha256,
        )
        record = self._index.get(key)
        if (
            record is None
            or record.dispatched_envelope_sha256 != prepared.dispatched_envelope_sha256
        ):
            return None
        if record.source.model_requested != prepared.request.model:
            raise CaptureError("capture_model")
        # Recheck immutable content and return fresh model instances, not mutable stored state.
        if hashlib.sha256(record.content_json).hexdigest() != record.source.capture_sha256:
            raise CaptureError("capture_hash")
        return CaptureContent.model_validate(
            decode_wire_json(record.content_json.decode("utf-8"))
        ), SourceCaptureRef.model_validate(record.source.model_dump(mode="json"))


class SafeCaptureProjection(WireModel):
    namespace: Identifier
    request_identity_sha256: Digest
    source_generation: Identifier | None
    dependency_ids: list[Identifier]
    expected_generation_sha256: Digest
    status: Literal["ok", "refused", "invalid_output", "unknown"]
    capture_sha256: Digest
    current_external_cost_usd: Money | None


class SafeProjectionStore(Protocol):
    def put_safe(
        self, projection: SafeCaptureProjection, *, expected_generation_sha256: str
    ) -> bool:
        """Atomically reject stale generation before committing; caller owns retention/deletion."""


def put_safe_projection(store: SafeProjectionStore, projection: SafeCaptureProjection) -> bool:
    """Explicit optional metadata-only hook, separate from run and disabled by default."""
    projection = SafeCaptureProjection.model_validate(projection.model_dump(mode="json"))
    return (
        store.put_safe(projection, expected_generation_sha256=projection.expected_generation_sha256)
        is True
    )
