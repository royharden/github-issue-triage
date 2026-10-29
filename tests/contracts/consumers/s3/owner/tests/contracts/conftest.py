"""Synthetic schema inputs, not provider captures or funded-operation evidence."""

import pytest

from issue_triage.shared.callledger import models as ledger
from issue_triage.shared.providers import models as providers


def digest(name="synthetic"):
    return ledger.canonical_digest(name)


@pytest.fixture
def context_data():
    return dict(
        schema_version=1,
        authority_id="fixture",
        run_id="run1",
        operation_id="op1",
        child_id="child1",
        task_id="task1",
        span_id="span1",
        parent_span_id=None,
        consumer_namespace="synthetic",
        purpose="schema.test",
        source_generation="g1",
        consumer_context_sha256=digest(),
        policy_sha256=digest("policy"),
        template_sha256=digest("template"),
        config_sha256=digest("config"),
    )


@pytest.fixture
def limits_data():
    return dict(
        schema_version=1,
        max_attempts_total=2,
        max_content_repairs=0,
        operation_deadline_s=30.0,
        attempt_timeout_s=20.0,
        run_deadline_utc="2026-10-14T23:00:00Z",
        max_outbound_attempts=10,
        max_concurrent_operations=1,
        max_total_input_tokens=4000,
        max_state_plus_longest_question_tokens=2000,
        max_request_bytes=32000,
        max_response_bytes=64000,
        max_questions=32,
        max_choice_options=64,
        max_total_output_tokens=512,
    )


@pytest.fixture
def authority_data():
    return dict(
        schema_version=1,
        authority_id="fixture",
        scope_sha256=digest("authority"),
        cap_usd="0.50",
        max_outbound_attempts=10,
        run_deadline_utc="2026-10-14T23:00:00Z",
    )


@pytest.fixture
def typed_request():
    return providers.TypedJudgmentRequest.model_validate(
        dict(
            schema_version=1,
            kind="typed_judgment",
            model="jev-1.13.0",
            state="Synthetic input",
            questions={
                "category": {
                    "type": "choice",
                    "instructions": "Choose category",
                    "criteria": {"a": None, "b": None},
                },
                "condition": {"type": "noul", "instructions": "Does condition hold?"},
            },
        )
    )


@pytest.fixture
def typed_result_data(typed_request):
    return dict(
        schema_version=1,
        model_reported="jev-1.13.0",
        question_spec_sha256=typed_request.question_spec_sha256,
        answers={
            "category": {
                "type": "choice",
                "choice": "a",
                "probabilities": {"a": 0.8, "b": 0.2},
                "confidence": 0.6,
            },
            "condition": {"type": "noul", "noul": 0.7},
        },
    )


@pytest.fixture
def envelope_data(context_data, limits_data, authority_data, typed_request):
    return dict(
        schema_version=1,
        request=typed_request.model_dump(mode="json"),
        provider_config_sha256=digest("provider"),
        purpose="schema.test",
        ledger_ref="fixture-ledger",
        budget=authority_data,
        context=context_data,
        limits=limits_data,
        capture_mode="disabled",
        allocation=dict(
            schema_version=1,
            allocation_id="alloc1",
            authority_id="fixture",
            operation_id="op1",
            plan_sha256=digest("plan"),
        ),
    )


@pytest.fixture
def image_data():
    return dict(
        type="local_image",
        execution_ref="C:/synthetic/one.png",
        content_sha256=digest("image bytes"),
        media_type="image/png",
        byte_length=100,
        decoded_width=10,
        decoded_height=10,
        rendition_sha256=digest("rendition"),
        source_generation="source1",
        transform_sha256=digest("transform"),
        detail="low",
    )
