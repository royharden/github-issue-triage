"""One offline controller: actual Ledger calls, immutable fixtures or injected test transport.

There is intentionally no HTTP/SDK client, credential lookup or live mode here.
"""

import hashlib
import math
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal, localcontext
from email.utils import parsedate_to_datetime
from types import MappingProxyType
from typing import Literal, Protocol

from ..callledger import AdmissionView, Ledger
from ..callledger.ledger import ReuseAccounting
from ..callledger.models import (
    Allocation,
    BudgetAuthority,
    CallContext,
    Limits,
    MetadataRecord,
    MetadataUsage,
    NormalizedUsage,
    OperationPlan,
    canonical_digest,
    decode_wire_json,
)
from ..callledger.pricing import PricePolicy, RequestEvidence
from ..callledger.projection import project_usage
from .adapters import (
    Outcome,
    PreparedRequest,
    ProviderConfig,
    decode_outcome,
    normalize_usage,
    prepare_request,
)
from .captures import FixtureIndex
from .models import (
    ExecutionEnvelope,
    GenerateRequest,
    ImagePart,
    Result,
    SafeError,
    SourceCaptureRef,
)
from .schema import validate_output


class ProviderError(ValueError):
    """Closed code only. Callers must not log underlying provider/validation exceptions."""


@dataclass(frozen=True)
class TransportReply:
    status_code: int
    body: bytes = field(repr=False)
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    first_output_kind: Literal["token", "chunk", "answer", "unavailable"] = "unavailable"
    first_output_ms: float | None = None


class TransportFailure(Exception):
    def __init__(
        self,
        code: Literal["unknown_dispatch", "deadline", "auth"],
        *,
        usage_raw: dict | None = None,
        first_output_kind="unavailable",
        first_output_ms=None,
    ):
        if code not in {"unknown_dispatch", "deadline", "auth"}:
            raise ValueError("transport_code")
        super().__init__(code)
        self.code = code
        self.usage_raw = usage_raw
        self.first_output_kind = first_output_kind
        self.first_output_ms = first_output_ms


class InjectedTransport(Protocol):
    is_test_transport: bool

    def send(
        self, payload_json: bytes, *, timeout_s: float, max_retries: int, max_response_bytes: int
    ) -> TransportReply:
        """One injected test dispatch. A future installed client needs genuine retry proof."""


def _aggregate(usages):
    result = {}
    for key in NormalizedUsage.model_fields:
        values = [getattr(usage, key) for usage in usages]
        result[key] = sum(values) if values and all(value is not None for value in values) else None
    return NormalizedUsage.model_validate(result)


class Provider:
    def __init__(
        self,
        config: ProviderConfig,
        *,
        mode: Literal["mock", "strict_replay", "injected_simulation"],
        request_evidence: Iterable[RequestEvidence],
        fixtures: FixtureIndex | None = None,
        transport: InjectedTransport | None = None,
        images: Mapping[str, bytes] | None = None,
        capture_mode: Literal["disabled", "fixture_replay"] = "disabled",
        clock=None,
        sleep=None,
    ):
        if mode not in {"mock", "strict_replay", "injected_simulation"}:
            raise ProviderError("unsupported_live_transport")
        if capture_mode not in {"disabled", "fixture_replay"}:
            raise ProviderError("unsupported_capture_mode")
        self.config = ProviderConfig.model_validate(config.model_dump(mode="json"))
        self.mode = mode
        self.capture_mode = capture_mode
        self.fixtures = fixtures
        self.transport = transport
        self.images = MappingProxyType(dict(images or {}))
        self.evidence = MappingProxyType(
            {
                (
                    item.request_identity_sha256,
                    item.dispatched_envelope_sha256,
                ): RequestEvidence.model_validate(item.model_dump(mode="json"))
                for item in request_evidence
            }
        )
        self.clock = clock or time.monotonic
        self.sleep = sleep or time.sleep

    def prepare(self, request, *, context: CallContext, limits: Limits) -> PreparedRequest:
        return prepare_request(
            request, config=self.config, context=context, limits=limits, images=self.images
        )

    def admit_operation(
        self,
        plan: OperationPlan,
        *,
        ledger: Ledger,
        budget: BudgetAuthority,
        context: CallContext,
        limits: Limits,
    ) -> Allocation:
        self._budget(ledger, budget)
        return ledger.admit_operation(
            plan,
            context=context,
            limits=limits,
            mode="simulation" if self.mode == "injected_simulation" else "offline",
        )

    @staticmethod
    def _budget(ledger, budget):
        if not isinstance(ledger, Ledger) or budget.model_dump(
            mode="json"
        ) != ledger.authority.model_dump(mode="json"):
            raise ProviderError("budget_mismatch")

    def _bound(self, request, *, purpose, ledger, budget, context, limits, allocation):
        self._budget(ledger, budget)
        prepared = self.prepare(request, context=context, limits=limits)
        envelope = ExecutionEnvelope(
            schema_version=1,
            request=prepared.request,
            provider_config_sha256=self.config.sha256,
            purpose=purpose,
            ledger_ref=canonical_digest(str(ledger.db_path.resolve())),
            budget=budget,
            context=context,
            limits=limits,
            allocation=allocation,
            capture_mode=self.capture_mode,
        )
        if envelope.request_identity_sha256 != prepared.request_identity_sha256:
            raise ProviderError("request_identity")
        evidence = self.evidence.get(
            (prepared.request_identity_sha256, prepared.dispatched_envelope_sha256)
        )
        if evidence is None:
            raise ProviderError("untrusted_request")
        view = ledger.validate_allocation(
            allocation,
            context=context,
            limits=limits,
            request=evidence,
            require_zero_dispatch=self.mode != "injected_simulation",
        )
        if (view.provider_config_sha256, view.model, view.bound_evidence_sha256) != (
            self.config.sha256,
            prepared.request.model,
            evidence.bound_evidence_sha256,
        ):
            raise ProviderError("provider_binding")
        if view.mode != ("simulation" if self.mode == "injected_simulation" else "offline"):
            raise ProviderError("mode_mismatch")
        return prepared, evidence, view

    def validate_replay_allocation(
        self,
        request,
        *,
        purpose: str,
        ledger: Ledger,
        budget: BudgetAuthority,
        context: CallContext,
        limits: Limits,
        allocation: Allocation,
    ) -> AdmissionView:
        """S6 seam: read-only observation before lookup; reuse rechecks atomically.

        Requires actual offline child max/remaining/used0 AND explicit outbound0.
        It creates no capture, allocation, dispatch marker, funding or fallback.
        """
        if self.mode not in {"mock", "strict_replay"}:
            raise ProviderError("unsupported_replay_mode")
        return self._bound(
            request,
            purpose=purpose,
            ledger=ledger,
            budget=budget,
            context=context,
            limits=limits,
            allocation=allocation,
        )[2]

    def run(
        self,
        request,
        *,
        purpose: str,
        ledger: Ledger,
        budget: BudgetAuthority,
        context: CallContext,
        limits: Limits,
        allocation: Allocation,
    ) -> Result:
        started = self.clock()
        prepared, evidence, view = self._bound(
            request,
            purpose=purpose,
            ledger=ledger,
            budget=budget,
            context=context,
            limits=limits,
            allocation=allocation,
        )
        if self.mode != "injected_simulation":
            return self._reuse(
                prepared,
                evidence,
                view,
                started=started,
                ledger=ledger,
                context=context,
                limits=limits,
                allocation=allocation,
            )
        if (
            self.transport is None
            or getattr(self.transport, "is_test_transport", False) is not True
        ):
            raise ProviderError("unsupported_live_transport")
        if isinstance(prepared.request, GenerateRequest) and any(
            isinstance(part, ImagePart)
            for message in prepared.request.messages
            for part in message.content
        ):
            # In-memory image payload construction is supported. A real paid image's
            # token/detail/rendition billing proof is deliberately not established here.
            raise ProviderError("unsupported_image_billing_proof")
        return self._injected(
            prepared,
            evidence,
            started=started,
            ledger=ledger,
            context=context,
            limits=limits,
            allocation=allocation,
        )

    def complete(
        self,
        messages,
        schema=None,
        *,
        model: str,
        purpose: str,
        ledger: Ledger,
        budget: BudgetAuthority,
        context: CallContext,
        limits: Limits,
        allocation: Allocation,
        max_output_tokens: int = 512,
        stream: bool = False,
        reasoning_effort: str | None = None,
        temperature: float | None = None,
    ) -> Result:
        request = GenerateRequest.model_validate(
            dict(
                schema_version=1,
                kind="generate",
                model=model,
                messages=messages,
                schema=schema,
                max_output_tokens=max_output_tokens,
                stream=stream,
                reasoning_effort=reasoning_effort,
                temperature=temperature,
            )
        )
        return self.run(
            request,
            purpose=purpose,
            ledger=ledger,
            budget=budget,
            context=context,
            limits=limits,
            allocation=allocation,
        )

    def _reuse(self, prepared, evidence, view, *, started, ledger, context, limits, allocation):
        if self.capture_mode != "fixture_replay" or self.fixtures is None:
            return self._offline_failure(
                prepared,
                started=started,
                allocation=allocation,
                status="unsupported",
                code="unsupported_capability",
            )
        if view.child_state != "pending" or view.operation_state != "pending":
            raise ProviderError("completion_conflict")
        found = self.fixtures.lookup(prepared, context=context)
        if found is None:
            # A miss is closed and never invents a synthetic output/capture or calls send.
            proof = canonical_digest(
                {
                    "allocation_id": allocation.allocation_id,
                    "child_id": context.child_id,
                    "undispatched": True,
                }
            )
            ledger.finish_child(
                allocation,
                child_id=context.child_id,
                outcome="cancelled_before_dispatch",
                proof_sha256=proof,
            )
            return self._offline_failure(
                prepared,
                started=started,
                allocation=allocation,
                status="cache_miss",
                code="cache_miss",
            )
        content, source = found
        origin = "mock" if source.origin == "synthetic" else "replay"
        if self.mode == "mock" and origin != "mock":
            raise ProviderError("capture_origin")
        result = Result(
            schema_version=1,
            kind=content.kind,
            status=content.status,
            text=content.text,
            parsed=content.parsed,
            typed=content.typed,
            error=content.error,
            model_requested=prepared.request.model,
            model_reported=content.model_reported,
            usage_raw=content.usage_raw,
            normalized_usage=content.normalized_usage,
            accounting_ref=allocation.allocation_id,
            attempt_ids=[],
            origin=origin,
            source_capture=source,
            latency_ms=max((self.clock() - started) * 1000, 0),
            first_output_ms=None,
            first_output_kind="unavailable",
            current_external_cost_usd="0",
        ).validate_for(prepared.request)
        if (
            isinstance(prepared.request, GenerateRequest)
            and prepared.request.output_schema is not None
            and result.status == "ok"
        ):
            validate_output(result.parsed, prepared.request.output_schema)
        ledger.record_reuse(
            allocation,
            context=context,
            request=evidence,
            caller_limits=limits,
            provenance=ReuseAccounting(
                schema_version=1,
                origin=origin,
                capture_sha256=source.capture_sha256,
                request_identity_sha256=source.request_identity_sha256,
                source_run_id=source.source_run_id,
                source_model=source.model_reported,
                source_cost_usd=source.cost_usd,
                source_usage_sha256=source.usage_ref,
                source_price_sha256=source.price_ref,
                current_external_cost_usd="0",
            ),
        )
        return result

    def _offline_failure(self, prepared, *, started, allocation, status, code):
        """Called only after actual offline child/outbound0 validation; never a fallback."""
        return Result(
            schema_version=1,
            kind="typed" if prepared.request.kind == "typed_judgment" else "generated",
            status=status,
            text=None,
            parsed=None,
            typed=None,
            error=SafeError(code=code),
            model_requested=prepared.request.model,
            model_reported=None,
            usage_raw=None,
            normalized_usage=NormalizedUsage(),
            accounting_ref=allocation.allocation_id,
            attempt_ids=[],
            origin="replay" if self.mode == "strict_replay" else "mock",
            source_capture=None,
            latency_ms=max((self.clock() - started) * 1000, 0),
            first_output_ms=None,
            first_output_kind="unavailable",
            current_external_cost_usd="0",
        ).validate_for(prepared.request)

    @staticmethod
    def _metadata(outcome, *, context, request_sha256, duration_ms, error_code=None):
        projection, redacted, _ = project_usage(outcome.usage_raw or {})
        values = projection.model_dump(mode="json")
        values["details"] = outcome.normalized_usage.model_dump(mode="json")
        projection = MetadataUsage.model_validate(values)
        return MetadataRecord(
            schema_version=1,
            context=context,
            request_identity_sha256=request_sha256,
            usage=projection,
            usage_projection_sha256=canonical_digest(projection.model_dump(mode="json")),
            usage_redacted_fields=redacted,
            status=outcome.status,
            duration_ms=duration_ms,
            error_code=error_code
            or ("invalid_output" if outcome.status == "invalid_output" else None),
        )

    def _retry_delay(self, headers, *, used):
        normalized = {str(key).lower(): value for key, value in headers.items()}
        if "retry-after-ms" in normalized:
            try:
                delay = float(normalized["retry-after-ms"]) / 1000
            except (ValueError, TypeError):
                raise ProviderError("retry_header") from None
        elif "retry-after" in normalized:
            try:
                delay = float(normalized["retry-after"])
            except (ValueError, TypeError):
                try:
                    delay = (
                        parsedate_to_datetime(normalized["retry-after"]) - self._wall_now()
                    ).total_seconds()
                except (ValueError, TypeError, OverflowError):
                    raise ProviderError("retry_header") from None
        else:
            delay = min(0.1 * 2 ** max(used - 1, 0), 1.0)
        if not math.isfinite(delay) or delay < 0:
            raise ProviderError("retry_header")
        return delay

    @staticmethod
    def _wall_now():
        from datetime import UTC, datetime

        return datetime.now(UTC)

    def _injected(self, prepared, evidence, *, started, ledger, context, limits, allocation):
        attempts = []
        usages = []
        costs = []
        last_body = None
        first_ms = None
        first_kind = "unavailable"
        proof = None
        last_error_code = None
        outcome = Outcome("unknown", None, NormalizedUsage(), None)
        while True:
            view = ledger.validate_allocation(
                allocation, context=context, limits=limits, request=evidence
            )
            if (
                view.used_attempts >= view.max_attempts
                or not view.remaining_attempts
                or view.cumulative_dispatched >= view.outbound_ceiling
            ):
                raise ProviderError("attempt_limit")
            timeout = min(limits.attempt_timeout_s, view.deadline_remaining_s)
            attempt = ledger.begin_attempt(
                allocation, context=context, request=evidence, caller_limits=limits
            )
            attempts.append(attempt)
            try:
                # Commit/lock delay can consume the precheck's headroom. Observe it
                # again before handing a timeout to even the injected transport.
                after_transfer = ledger.validate_allocation(
                    allocation, context=context, limits=limits, request=evidence
                )
                timeout = min(limits.attempt_timeout_s, after_transfer.deadline_remaining_s)
            except ValueError:
                # The durable dispatch marker is conservative after this point.
                proof = ledger.mark_unknown(attempt)
                ledger.finish_child(
                    allocation, child_id=context.child_id, outcome="failed", proof_sha256=proof
                )
                raise ProviderError("deadline") from None
            call_started = self.clock()
            reply = None
            retryable = False
            last_error_code = None
            try:
                reply = self.transport.send(
                    prepared.payload_json,
                    timeout_s=timeout,
                    max_retries=0,
                    max_response_bytes=limits.max_response_bytes,
                )
                if (
                    not isinstance(reply, TransportReply)
                    or type(reply.body) is not bytes
                    or type(reply.status_code) is not int
                    or len(reply.body) > limits.max_response_bytes
                ):
                    raise TransportFailure("unknown_dispatch")
                last_body = reply.body
                raw = None
                try:
                    data = decode_wire_json(
                        reply.body.decode("utf-8"), max_bytes=limits.max_response_bytes
                    )
                    raw = (
                        data.get("usage")
                        if isinstance(data, dict) and isinstance(data.get("usage"), dict)
                        else None
                    )
                except (ValueError, UnicodeError):
                    pass
                if 200 <= reply.status_code < 300:
                    try:
                        outcome = decode_outcome(
                            reply.body,
                            prepared=prepared,
                            config=self.config,
                            max_bytes=limits.max_response_bytes,
                        )
                    except (ValueError, UnicodeError):
                        outcome = Outcome(
                            "invalid_output", None, normalize_usage(raw, self.config.flavor), raw
                        )
                else:
                    outcome = Outcome(
                        "provider_error", None, normalize_usage(raw, self.config.flavor), raw
                    )
                    if reply.status_code in {401, 403}:
                        last_error_code = "auth"
                    retryable = reply.status_code in {429, 500, 502, 503, 504, 529}
                first_kind, first_ms = reply.first_output_kind, reply.first_output_ms
            except TransportFailure as failure:
                last_error_code = failure.code
                outcome = Outcome(
                    "deadline_exceeded" if failure.code == "deadline" else "unknown",
                    None,
                    normalize_usage(failure.usage_raw, self.config.flavor),
                    failure.usage_raw,
                )
                first_kind, first_ms = failure.first_output_kind, failure.first_output_ms
            except Exception:
                # Never log raw exceptions. The active reservation is accounted below.
                outcome = Outcome("unknown", None, NormalizedUsage(), None)
            elapsed = max((self.clock() - call_started) * 1000, 0)
            if (
                outcome.model_reported is not None
                and outcome.model_reported
                not in self.config.models[prepared.request.model].reported_models
            ):
                outcome = Outcome(
                    "invalid_output",
                    outcome.model_reported,
                    outcome.normalized_usage,
                    outcome.usage_raw,
                )
            if (
                (first_kind == "unavailable" and first_ms is not None)
                or (
                    first_kind != "unavailable"
                    and (
                        type(first_ms) not in {int, float}
                        or not math.isfinite(first_ms)
                        or first_ms < 0
                        or first_ms > elapsed
                    )
                )
                or first_kind not in {"token", "chunk", "answer", "unavailable"}
            ):
                outcome = Outcome(
                    "invalid_output",
                    outcome.model_reported,
                    outcome.normalized_usage,
                    outcome.usage_raw,
                )
                first_kind = "unavailable"
                first_ms = None
            if elapsed > timeout * 1000:
                outcome = Outcome(
                    "deadline_exceeded",
                    outcome.model_reported,
                    outcome.normalized_usage,
                    outcome.usage_raw,
                )
                retryable = False
            metadata = self._metadata(
                outcome,
                context=context,
                request_sha256=prepared.request_identity_sha256,
                duration_ms=elapsed,
                error_code=last_error_code,
            )
            proof = ledger.settle(attempt, metadata=metadata, usage=outcome.normalized_usage)
            policy = PricePolicy.model_validate(decode_wire_json(view.price_policy_json))
            observation = policy.price(
                outcome.normalized_usage, reservation_usd=view.reservation_usd
            )
            usages.append(outcome.normalized_usage)
            costs.append(observation.computed_cost_usd)
            if ledger.totals()["halted"]:
                outcome = Outcome(
                    "budget_rejected",
                    outcome.model_reported,
                    outcome.normalized_usage,
                    outcome.usage_raw,
                )
                retryable = False
            if retryable:
                try:
                    delay = self._retry_delay(reply.headers, used=view.used_attempts + 1)
                    current = ledger.validate_allocation(
                        allocation, context=context, limits=limits, request=evidence
                    )
                    retryable = (
                        current.used_attempts < current.max_attempts
                        and current.remaining_attempts > 0
                        and delay < current.deadline_remaining_s
                        and ledger.retry_fits(allocation, retry_after_s=delay)
                    )
                except ValueError:
                    retryable = False
                if retryable:
                    if delay:
                        self.sleep(delay)
                    continue
            break
        ledger.finish_child(
            allocation,
            child_id=context.child_id,
            outcome="complete" if outcome.status == "ok" else "failed",
            proof_sha256=proof,
        )
        if last_body is None:
            raise ProviderError(
                "auth"
                if last_error_code == "auth"
                else ("deadline" if outcome.status == "deadline_exceeded" else "unknown_dispatch")
            )
        usage = _aggregate(usages)
        with localcontext() as decimal_context:
            decimal_context.prec = 150
            source_cost = (
                format(sum((Decimal(cost) for cost in costs), Decimal(0)), "f")
                if all(cost is not None for cost in costs)
                else None
            )
        source = SourceCaptureRef(
            capture_id=attempts[-1],
            capture_sha256=hashlib.sha256(last_body).hexdigest(),
            origin="synthetic",
            source_run_id=context.run_id,
            request_identity_sha256=prepared.request_identity_sha256,
            model_requested=prepared.request.model,
            model_reported=outcome.model_reported,
            usage_ref=canonical_digest(usage.model_dump(mode="json")),
            price_ref=view.price_snapshot_sha256,
            cost_usd=source_cost,
            latency_ms=None,
            first_output_kind="unavailable",
            first_output_ms=None,
        )
        code = (
            "invalid_output"
            if outcome.status == "invalid_output"
            else (
                "budget_rejected"
                if outcome.status == "budget_rejected"
                else ("deadline" if outcome.status == "deadline_exceeded" else "unknown_dispatch")
            )
        )
        return Result(
            schema_version=1,
            kind="typed" if prepared.request.kind == "typed_judgment" else "generated",
            status=outcome.status,
            text=outcome.text if outcome.status == "ok" else None,
            parsed=outcome.parsed if outcome.status == "ok" else None,
            typed=outcome.typed if outcome.status == "ok" else None,
            error=(
                SafeError(code="auth")
                if last_error_code == "auth"
                else (
                    None
                    if outcome.status in {"ok", "refused", "provider_error"}
                    else SafeError(code=code)
                )
            ),
            model_requested=prepared.request.model,
            model_reported=outcome.model_reported,
            usage_raw=outcome.usage_raw,
            normalized_usage=usage,
            accounting_ref=allocation.allocation_id,
            attempt_ids=attempts,
            origin="mock",
            source_capture=source,
            latency_ms=max((self.clock() - started) * 1000, 0),
            first_output_ms=first_ms,
            first_output_kind=first_kind,
            current_external_cost_usd="0",
        ).validate_for(prepared.request)
