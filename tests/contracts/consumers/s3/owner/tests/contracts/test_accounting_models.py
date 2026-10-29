"""what_bug_this_catches: schemas accepting incomplete billing or unfunded declarations."""

import copy

import pytest
from pydantic import ValidationError

from issue_triage.shared.callledger import models as wire


def policy(fields):
    return dict(
        schema_version=1,
        policy_sha256=wire.canonical_digest("synthetic-price-policy"),
        required_usage_fields=fields,
        fee_context_known=True,
    )


def test_input_only_cost_can_be_known_with_output_null():
    value = wire.CostObservation.model_validate(
        dict(
            schema_version=1,
            usage={"input_tokens": 1000, "output_tokens": None},
            billing_policy=policy(["input_tokens"]),
            status="known",
            computed_cost_usd="0.000042",
            unresolved_liability_usd="0",
        )
    )
    assert value.usage.output_tokens is None
    assert value.computed_cost_usd == "0.000042"


@pytest.mark.parametrize("field", ["input_tokens", "output_tokens"])
def test_missing_billed_component_cannot_be_known_cost(field):
    usage = {"input_tokens": 100, "output_tokens": 50, field: None}
    data = dict(
        schema_version=1,
        usage=usage,
        billing_policy=policy(["input_tokens", "output_tokens"]),
        status="known",
        computed_cost_usd="0.01",
        unresolved_liability_usd="0",
    )
    with pytest.raises(ValidationError):
        wire.CostObservation.model_validate(data)
    data.update(status="unknown", computed_cost_usd=None, unresolved_liability_usd="0.10")
    value = wire.CostObservation.model_validate(data)
    assert value.unresolved_liability_usd == "0.10"
    assert value.computed_cost_usd is None


@pytest.mark.parametrize("bad", [True, -1, "100", 1.5])
def test_usage_is_reported_nonnegative_integer_or_null(bad):
    with pytest.raises(ValidationError):
        wire.NormalizedUsage(input_tokens=bad)


@pytest.mark.parametrize(
    "data",
    [
        {"input_tokens": 10, "cache_read_input_tokens": 8, "cache_write_input_tokens": 5},
        {"output_tokens": 10, "reasoning_output_tokens": 11},
    ],
)
def test_inclusive_partitions_cannot_exceed_total(data):
    with pytest.raises(ValidationError):
        wire.NormalizedUsage.model_validate(data)


def child(child_id, amount, attempts=2):
    digest = wire.canonical_digest("synthetic-bound")
    return dict(
        child_id=child_id,
        purpose="schema.test",
        provider_config_sha256=digest,
        model="synthetic-mock",
        bound_evidence_sha256=digest,
        max_attempts=attempts,
        max_repairs=0,
        input_token_maximum=1000,
        output_token_maximum=512,
        fee_maximum_usd="0",
        reserved_usd_per_attempt=amount,
        request_shape_limit_sha256=digest,
        conditional=False,
    )


def funding(authority_data, amounts):
    plan = wire.OperationPlan.model_validate(
        dict(
            schema_version=1,
            operation_id="op1",
            authority_id="fixture",
            context_sha256=wire.canonical_digest("synthetic-context"),
            children=[child(str(index), amount) for index, amount in enumerate(amounts)],
        )
    )
    allocation = dict(
        schema_version=1,
        allocation_id="alloc1",
        authority_id="fixture",
        operation_id="op1",
        plan_sha256=plan.plan_sha256,
    )
    return dict(
        schema_version=1,
        authority=authority_data,
        plan=plan,
        allocation=allocation,
        known_spend_usd="0",
        other_held_exposure_usd="0",
        already_dispatched_attempts=0,
    )


def test_full_declared_fanout_rejected_when_first_attempt_would_fit(authority_data):
    data = funding(authority_data, ["0.30", "0.10"])
    assert data["plan"].declared_worst_case_usd == wire.Decimal("0.80")
    with pytest.raises(ValidationError, match="complete declared operation exceeds cap"):
        wire.FundingDeclaration.model_validate(data)


def test_declared_funding_boundary_is_inclusive(authority_data):
    data = funding(authority_data, ["0.10", "0.10"])
    data["known_spend_usd"] = "0.10"
    assert wire.FundingDeclaration.model_validate(
        data
    ).plan.declared_worst_case_usd == wire.Decimal("0.40")
    data["other_held_exposure_usd"] = "0.000001"
    with pytest.raises(ValidationError):
        wire.FundingDeclaration.model_validate(data)


@pytest.mark.parametrize("mutation", ["authority", "operation", "digest", "quota", "duplicate"])
def test_funding_and_allocation_identity_cannot_be_forged(authority_data, mutation):
    data = funding(authority_data, ["0.10", "0.10"])
    if mutation == "authority":
        data["allocation"]["authority_id"] = "other"
    elif mutation == "operation":
        data["allocation"]["operation_id"] = "other"
    elif mutation == "digest":
        data["allocation"]["plan_sha256"] = "a" * 64
    elif mutation == "quota":
        data["already_dispatched_attempts"] = 9
    else:
        plan = data["plan"].model_dump(mode="python")
        plan["children"][1]["child_id"] = plan["children"][0]["child_id"]
        data["plan"] = plan
    with pytest.raises(ValidationError):
        wire.FundingDeclaration.model_validate(data)


def test_zero_dispatch_fixture_declaration_needs_no_paid_quota(authority_data):
    authority_data.update(cap_usd="0", max_outbound_attempts=0)
    plan = wire.OperationPlan.model_validate(
        dict(
            schema_version=1,
            operation_id="op1",
            authority_id="fixture",
            context_sha256=wire.canonical_digest("synthetic-context"),
            children=[child("offline", "0", attempts=0)],
        )
    )
    data = funding(authority_data, ["0"])
    data["plan"] = plan
    data["allocation"]["plan_sha256"] = plan.plan_sha256
    assert wire.FundingDeclaration.model_validate(data).authority.cap_usd == "0"


@pytest.mark.parametrize("mutation", ["attempts", "repairs", "deadline", "count_string"])
def test_limits_enforce_tighter_caller_bounds(limits_data, mutation):
    data = copy.deepcopy(limits_data)
    if mutation == "attempts":
        data["max_attempts_total"] = 4
    elif mutation == "repairs":
        data.update(max_attempts_total=1, max_content_repairs=1)
    elif mutation == "deadline":
        data["run_deadline_utc"] = "2026-99-99T23:00:00Z"
    else:
        data["max_outbound_attempts"] = "10"
    with pytest.raises(ValidationError):
        wire.Limits.model_validate(data)
    valid = wire.Limits.model_validate(limits_data)
    assert valid.max_attempts_total == 2 and valid.max_content_repairs == 0


def test_metadata_only_projection_rejects_payload_and_secret_text(context_data):
    data = dict(
        schema_version=1,
        context=context_data,
        request_identity_sha256=wire.canonical_digest("synthetic-request"),
        usage={"input_tokens": 100},
        usage_projection_sha256=wire.canonical_digest("usage"),
        usage_redacted_fields=False,
        status="invalid_output",
        duration_ms=1.0,
        error_code="invalid_output",
    )
    assert wire.MetadataRecord.model_validate(data).usage.input_tokens == 100
    for extra in [
        {"request_body": "PRIVACY_CANARY"},
        {"error_message": "PRIVACY_CANARY"},
        {"usage": {"input_tokens": 100, "secret": "PRIVACY_CANARY"}},
        {"error_code": "PRIVACY_CANARY"},
    ]:
        with pytest.raises(ValidationError) as error:
            wire.MetadataRecord.model_validate({**data, **extra})
        assert "PRIVACY_CANARY" not in str(error.value)


def test_nonmodel_span_never_invents_tokens_or_runtime_cost(context_data):
    span = wire.NonModelSpan.model_validate(
        dict(
            schema_version=1, kind="non_model", context=context_data, duration_ms=12.5, status="ok"
        )
    )
    assert span.resource_cost_usd is None and span.input_tokens is None
    with pytest.raises(ValidationError):
        wire.NonModelSpan.model_validate({**span.model_dump(), "input_tokens": 0})
