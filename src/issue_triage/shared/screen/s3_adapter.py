"""Explicit native S3 request binding; admission and accounting stay with the caller."""

import re
from dataclasses import dataclass, field

from ..callledger.models import canonical_digest
from ..providers.controller import Provider
from ..providers.models import TypedJudgmentRequest
from .models import PreparedText, ScreenResult, ScreenValidationError, WrappedData
from .prepare import prepare_text, wrap_untrusted
from .questions import screen_questions


@dataclass(frozen=True, slots=True)
class ScreenRequestBinding:
    """One original pair, checked again because native nested mappings are mutable."""

    wrapped: WrappedData = field(repr=False)
    request: TypedJudgmentRequest = field(repr=False)
    source_id: str
    source_generation: str
    original_sha256: str
    normalized_sha256: str
    policy_sha256: str
    model: str = field(repr=False)
    request_sha256: str
    question_spec_sha256: str
    captured: bool


def _exact_wrapper(prepared, wrapped):
    if type(wrapped) is not WrappedData:
        return False
    state = dict(wrapped.state)
    if canonical_digest(state) != wrapped.sha256:
        return False
    match = re.match(r"<untrusted-([0-9a-f]{32})>\n", state["original_text"])
    if match is None:
        return False
    nonce = match.group(1)
    for key, text in (
        ("original_text", prepared.source.text),
        ("normalized_text", prepared.normalized_text),
    ):
        if nonce in text:
            return False
        escaped = text.replace("<", "\\u003c").replace(">", "\\u003e")
        if state[key] != f"<untrusted-{nonce}>\n{escaped}\n</untrusted-{nonce}>":
            return False
    return True


def bind_native_request(prepared: PreparedText, *, model: str, captured_wrapped=None):
    """Create once, before external prepare/admit. A capture supplies its original DATA."""
    if type(prepared) is not PreparedText or prepared.coverage != "complete":
        raise ScreenValidationError("invalid_prepared_input")
    wrapped = wrap_untrusted(prepared) if captured_wrapped is None else captured_wrapped
    if not _exact_wrapper(prepared, wrapped):
        raise ScreenValidationError("invalid_capture")
    request = TypedJudgmentRequest(
        schema_version=1,
        kind="typed_judgment",
        model=model,
        state=dict(wrapped.state),
        questions=screen_questions(),
    )
    return ScreenRequestBinding(
        wrapped=wrapped,
        request=request,
        source_id=prepared.source.source_id,
        source_generation=prepared.source.source_generation,
        original_sha256=prepared.original_sha256,
        normalized_sha256=prepared.normalized_sha256,
        policy_sha256=prepared.policy_sha256,
        model=model,
        request_sha256=canonical_digest(request.identity_payload()),
        question_spec_sha256=request.question_spec_sha256,
        captured=captured_wrapped is not None,
    )


def _validate_pair(binding, prepared, model):
    if type(binding) is not ScreenRequestBinding or type(prepared) is not PreparedText:
        raise ScreenValidationError("invalid_capture")
    request = binding.request
    if (
        type(request) is not TypedJudgmentRequest
        or type(binding.captured) is not bool
        or (
            binding.source_id,
            binding.source_generation,
            binding.original_sha256,
            binding.normalized_sha256,
            binding.policy_sha256,
            binding.model,
        )
        != (
            prepared.source.source_id,
            prepared.source.source_generation,
            prepared.original_sha256,
            prepared.normalized_sha256,
            prepared.policy_sha256,
            model,
        )
        or request.model != model
        or request.kind != "typed_judgment"
        or request.schema_version != 1
        or not _exact_wrapper(prepared, binding.wrapped)
        or request.state != dict(binding.wrapped.state)
        or canonical_digest(request.identity_payload()) != binding.request_sha256
        or request.question_spec_sha256 != binding.question_spec_sha256
        or list(request.questions) != list(screen_questions())
        or {
            key: value.model_dump(mode="json", exclude_unset=True)
            for key, value in request.questions.items()
        }
        != screen_questions()
    ):
        raise ScreenValidationError("invalid_capture")
    return request


def native_binding_permits_model_input(binding, result, current_source, current_policy):
    """Current-source guard for native consumers; caller must check atomically before saving.

    Does not write a cache, prevent a later concurrent edit, or grant an external effect.
    """
    try:
        prepared = prepare_text(current_source, current_policy)
        _validate_pair(binding, prepared, binding.model)
        return (
            type(result) is ScreenResult
            and result.permits_model_input(current_source, current_policy)
            and result.model_requested == binding.model
            and result.wrapped_state_sha256 == binding.wrapped.sha256
            and result.question_set_sha256 == binding.question_spec_sha256
            and result.request_identity_sha256 is not None
            and result.actual_dispatched_envelope_sha256 is not None
        )
    except Exception:
        return False


def observe_native_binding(
    binding,
    prepared,
    *,
    model,
    captured_wrapped,
    gateway,
    purpose,
    ledger,
    budget,
    context,
    limits,
    allocation,
):
    """Read-only validation; returns prepared native identity, never an allocation."""
    request = _validate_pair(binding, prepared, model)
    if not isinstance(gateway, Provider):
        raise ScreenValidationError("invalid_capture")
    if binding.captured:
        if captured_wrapped is not binding.wrapped or gateway.mode != "strict_replay":
            raise ScreenValidationError("invalid_capture")
    elif captured_wrapped is not None or gateway.mode != "mock":
        raise ScreenValidationError("invalid_capture")
    if type(limits.max_outbound_attempts) is not int or limits.max_outbound_attempts != 0:
        raise ScreenValidationError("replay_dispatch_forbidden")
    # These are the actual same caller-owned objects. Observation never settles/resets them.
    view = gateway.validate_replay_allocation(
        request,
        purpose=purpose,
        ledger=ledger,
        budget=budget,
        context=context,
        limits=limits,
        allocation=allocation,
    )
    if (
        view.mode != "offline"
        or view.operation_state != "pending"
        or view.child_state != "pending"
        or any(
            (
                view.used_attempts,
                view.remaining_attempts,
                view.repairs_used,
                view.max_attempts,
                view.max_repairs,
                view.outbound_ceiling,
            )
        )
        or view.deadline_remaining_s <= 0
    ):
        raise ScreenValidationError("invalid_capture")
    return gateway.prepare(request, context=context, limits=limits)
