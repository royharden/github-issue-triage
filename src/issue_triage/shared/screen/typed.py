"""Compose one injected S3 protocol call; never implement transport or accounting."""

import json
import math
from collections.abc import Mapping

from .models import HAZARDS, HeldInput, PreparedText, ScreenPolicy, ScreenValidationError
from .prepare import prepare_text, validate_captured_wrapper, wrap_untrusted
from .questions import QUESTION_SET_SHA256, screen_questions
from .rules import result_for, safety_flags


def _field(obj, name, default=None):
    return obj.get(name, default) if isinstance(obj, Mapping) else getattr(obj, name, default)


def _answer_mapping(answer):
    if isinstance(answer, Mapping):
        return answer
    # Accept S3 Pydantic answer values without importing its package or SDK.
    dump = getattr(answer, "model_dump", None)
    return dump(mode="python") if callable(dump) else None


def screen_typed(
    prepared,
    *,
    model,
    typed_gateway,
    ledger,
    budget,
    purpose,
    context,
    limits,
    allocation,
    policy: ScreenPolicy,
    captured_wrapped=None,
    request_binding=None,
):
    if isinstance(prepared, HeldInput):
        return result_for(prepared, policy)
    if type(prepared) is not PreparedText:
        raise ScreenValidationError("invalid_prepared_input")
    checked = prepare_text(prepared.source, policy)
    if not isinstance(checked, PreparedText) or checked != prepared:
        return result_for(
            checked, policy, decision="needs_human", reason_codes=("stale_preparation",)
        )
    flags = safety_flags(prepared)
    if flags:
        return result_for(
            prepared, policy, decision="needs_human", reason_codes=flags, deterministic_flags=flags
        )
    if policy.required_method != "typed":
        return result_for(
            prepared, policy, decision="needs_human", reason_codes=("method_mismatch",)
        )
    if policy.thresholds is None or policy.threshold_provenance == "not_applicable":
        return result_for(
            prepared, policy, decision="needs_human", reason_codes=("typed_policy_unavailable",)
        )
    if (
        policy.threshold_provenance == "exploratory_seed"
        and "synthetic-smoke" not in policy.profile_id
    ):
        return result_for(
            prepared, policy, decision="needs_human", reason_codes=("typed_policy_unavailable",)
        )
    if (
        any(v is None for v in (typed_gateway, ledger, budget, context, limits, allocation))
        or type(model) is not str
        or not model
        or type(purpose) is not str
        or not purpose
        or _field(context, "purpose") != purpose
        or _field(context, "policy_sha256") != policy.sha256
        or _field(context, "source_generation") != prepared.source.source_generation
        or not _field(context, "authority_id")
    ):
        return result_for(
            prepared,
            policy,
            decision="needs_human",
            reason_codes=("accounting_context_unavailable",),
        )
    native_prepared = None
    if request_binding is not None:
        from .s3_adapter import observe_native_binding

        try:
            native_prepared = observe_native_binding(
                request_binding,
                prepared,
                model=model,
                captured_wrapped=captured_wrapped,
                gateway=typed_gateway,
                purpose=purpose,
                ledger=ledger,
                budget=budget,
                context=context,
                limits=limits,
                allocation=allocation,
            )
        except Exception:
            return result_for(
                prepared, policy, decision="needs_human", reason_codes=("invalid_capture",)
            )
        wrapped = request_binding.wrapped
        request = request_binding.request
        question_sha256 = request_binding.question_spec_sha256
    elif captured_wrapped is not None:
        if not validate_captured_wrapper(prepared, captured_wrapped):
            return result_for(
                prepared, policy, decision="needs_human", reason_codes=("invalid_capture",)
            )
        if (
            type(_field(limits, "max_outbound_attempts")) is not int
            or _field(limits, "max_outbound_attempts") != 0
        ):
            return result_for(
                prepared,
                policy,
                decision="needs_human",
                reason_codes=("replay_dispatch_forbidden",),
            )
        # Actual S3 OperationPlan/allocation admission source remains unpublished.
        # A wrapper and zero limit alone cannot establish replay authority.
        return result_for(
            prepared,
            policy,
            decision="needs_human",
            reason_codes=("capture_allocation_unavailable",),
        )
    else:
        try:
            wrapped = wrap_untrusted(prepared)
        except ScreenValidationError:
            return result_for(
                prepared, policy, decision="needs_human", reason_codes=("wrapper_unavailable",)
            )
        request = {
            "schema_version": 1,
            "kind": "typed_judgment",
            "model": model,
            "state": dict(wrapped.state),
            "questions": screen_questions(),
        }
        question_sha256 = QUESTION_SET_SHA256
        request_bound = _field(limits, "max_request_bytes")
        if type(request_bound) is not int or request_bound < 1:
            return result_for(
                prepared,
                policy,
                decision="needs_human",
                reason_codes=("accounting_context_unavailable",),
            )
        request_bytes = json.dumps(request, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(request_bytes) > request_bound:
            return result_for(
                prepared, policy, decision="needs_human", reason_codes=("request_too_large",)
            )
    common = {
        "decision": "needs_human",
        "model_requested": model,
        "question_set_sha256": question_sha256,
        "wrapped_state_sha256": wrapped.sha256,
    }
    if native_prepared is not None:
        common.update(
            request_identity_sha256=native_prepared.request_identity_sha256,
            actual_dispatched_envelope_sha256=native_prepared.dispatched_envelope_sha256,
        )
    try:
        response = typed_gateway.run(
            request,
            purpose=purpose,
            ledger=ledger,
            budget=budget,
            context=context,
            limits=limits,
            allocation=allocation,
        )
    except Exception:
        # No settle/release/refund: injected S3 retains dispatched liability.
        return result_for(
            prepared,
            policy,
            reason_codes=("provider_error",),
            adapter_status="provider_error",
            **common,
        )
    refs = {"accounting_ref": None, "attempt_ids": (), "source_capture_ref": None}
    try:
        origin = _field(response, "origin")
        method = (
            {"mock": "typed_mock", "replay": "typed_replay", "live": "typed_live"}.get(origin)
            if type(origin) is str
            else None
        )
        refs["accounting_ref"] = _field(response, "accounting_ref")
        refs["source_capture_ref"] = _field(response, "source_capture")
        attempts = _field(response, "attempt_ids", ())
        if isinstance(attempts, (list, tuple)) and all(type(v) is str for v in attempts):
            refs["attempt_ids"] = tuple(attempts)
        if method:
            common["method"] = method
        status = _field(response, "status")
        if status != "ok":
            allowed = (
                "refused",
                "invalid_output",
                "provider_error",
                "unknown",
                "budget_rejected",
                "unsupported",
                "cache_miss",
                "deadline_exceeded",
                "cancelled",
            )
            status = status if type(status) is str and status in allowed else "invalid_output"
            return result_for(
                prepared, policy, reason_codes=(status,), adapter_status=status, **common, **refs
            )
        typed = _field(response, "typed")
        # Fresh requests cannot become replay merely by returned origin.
        allowed_methods = (
            ("typed_mock", "typed_replay") if native_prepared else ("typed_mock", "typed_live")
        )
        if method not in allowed_methods or _field(response, "kind") != "typed":
            raise ValueError
        if _field(response, "text") is not None or _field(response, "parsed") is not None:
            raise ValueError
        reported = _field(typed, "model_reported")
        if (
            type(reported) is not str
            or not reported
            or _field(response, "model_reported") != reported
        ):
            raise ValueError
        if (
            _field(response, "model_requested") != model
            or type(_field(typed, "schema_version")) is not int
            or _field(typed, "schema_version") != 1
        ):
            raise ValueError
        if _field(typed, "question_spec_sha256") != question_sha256:
            raise ValueError
        answers = _field(typed, "answers")
        if not isinstance(answers, Mapping) or set(answers) != set(HAZARDS):
            raise ValueError
        probabilities = {}
        for key in HAZARDS:
            answer = _answer_mapping(answers[key])
            if (
                not isinstance(answer, Mapping)
                or set(answer) != {"type", "noul"}
                or answer["type"] != "noul"
            ):
                raise ValueError
            value = answer["noul"]
            if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError
            probabilities[key] = value
    except Exception:
        return result_for(
            prepared,
            policy,
            reason_codes=("invalid_output",),
            adapter_status="invalid_output",
            **common,
            **refs,
        )
    holds = tuple(key for key in HAZARDS if probabilities[key] >= policy.thresholds[key])
    common.update(decision="needs_human" if holds else "pass", model_reported=reported)
    return result_for(
        prepared,
        policy,
        reason_codes=holds,
        hazard_probabilities=probabilities,
        adapter_status="ok",
        **common,
        **refs,
    )
