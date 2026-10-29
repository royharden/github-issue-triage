"""Authored synthetic controller fixtures. No actual model/capture/token proof is claimed."""

import json
from datetime import UTC, datetime

import pytest

from issue_triage.shared.callledger import Ledger
from issue_triage.shared.callledger.models import (
    BudgetAuthority,
    CallContext,
    ChildBound,
    Limits,
    OperationPlan,
)
from issue_triage.shared.callledger.models import (
    canonical_digest as digest,
)
from issue_triage.shared.callledger.pricing import (
    FundingEvidence,
    PricePolicy,
    PriceProvenance,
    PriceSnapshot,
    RequestEvidence,
)
from issue_triage.shared.providers.adapters import (
    ModelSupport,
    ProviderConfig,
    decode_outcome,
    prepare_request,
)
from issue_triage.shared.providers.captures import synthetic_capture
from issue_triage.shared.providers.controller import Provider, TransportReply
from issue_triage.shared.providers.models import GenerateRequest, TypedJudgmentRequest


class Rig:
    def __init__(self, path, flavor="openai_responses", typed=False):
        self.path = path
        self.tick = 100.0
        self.now = datetime(2026, 10, 14, 23, 0, tzinfo=UTC)
        self.reservation = "0.1"
        self.config = ProviderConfig(
            schema_version=1,
            flavor=flavor,
            endpoint_id="synthetic-endpoint",
            revision_sha256=digest("offline-doc-contract"),
            models={
                "fixture-model": ModelSupport(
                    generation=not typed,
                    typed_judgment=typed,
                    structured_output=not typed,
                    image_input=not typed,
                    streaming=not typed,
                    temperature=False,
                    reasoning_efforts=["low"],
                    reported_models=["fixture-model-reported"],
                )
            },
        )
        self.authority = BudgetAuthority(
            schema_version=1,
            authority_id="fixture-authority",
            scope_sha256=digest("fixture-scope"),
            cap_usd="0.50",
            max_outbound_attempts=10,
            run_deadline_utc="2026-10-15T00:00:00Z",
        )
        self.limits = Limits(
            schema_version=1,
            max_attempts_total=2,
            max_content_repairs=0,
            operation_deadline_s=30.0,
            attempt_timeout_s=20.0,
            run_deadline_utc="2026-10-15T00:00:00Z",
            max_outbound_attempts=10,
            max_concurrent_operations=2,
            max_total_input_tokens=4000,
            max_state_plus_longest_question_tokens=2000,
            max_request_bytes=32000,
            max_response_bytes=64000,
            max_questions=32,
            max_choice_options=64,
            max_total_output_tokens=512,
        )
        if typed:
            self.request = TypedJudgmentRequest.model_validate(
                dict(
                    schema_version=1,
                    kind="typed_judgment",
                    model="fixture-model",
                    state={"text": "SYNTHETIC_PAYLOAD_CANARY", "nonce": "nonce-1"},
                    questions={
                        "condition": {
                            "type": "noul",
                            "instructions": "A synthetic condition?",
                            "criteria": {"true": {"means": "present"}, "false": ["absent"]},
                        },
                        "category": {
                            "type": "choice",
                            "instructions": "Synthetic category",
                            "criteria": {"a": None, "b": None},
                        },
                        "score": {
                            "type": "score",
                            "instructions": {"task": "Synthetic relation"},
                            "criteria": ["unrelated", {"description": "related"}, ["same size"]],
                        },
                    },
                )
            )
        else:
            self.request = GenerateRequest.model_validate(
                dict(
                    schema_version=1,
                    kind="generate",
                    model="fixture-model",
                    messages=[
                        {
                            "role": "user",
                            "content": [{"type": "text", "text": "SYNTHETIC_PAYLOAD_CANARY"}],
                        }
                    ],
                    schema={
                        "type": "object",
                        "properties": {"tier": {"type": "string", "enum": ["cheap", "review"]}},
                        "required": ["tier"],
                        "additionalProperties": False,
                    },
                    max_output_tokens=32,
                    stream=False,
                )
            )
        self.policy = PricePolicy(
            schema_version=1,
            provider="synthetic",
            model="fixture-model",
            context_sha256=digest("synthetic-price-context"),
            cache_mode="flat_inclusive",
            input_usd_per_million="100",
            cache_read_usd_per_million=None,
            cache_write_usd_per_million=None,
            output_usd_per_million=None,
            fee_usd="0",
        )
        self.snapshot = PriceSnapshot(
            schema_version=1,
            provenance=PriceProvenance(
                origin="synthetic",
                source_url=None,
                retrieved_at="2026-10-14T00:00:00Z",
                official_verified_at=None,
                source_commit=None,
            ),
            policies=[self.policy],
            data_sha256=digest([self.policy.model_dump(mode="json")]),
        )
        self.bound = FundingEvidence(
            schema_version=1,
            snapshot_sha256=self.snapshot.snapshot_sha256,
            policy_sha256=self.policy.policy_sha256,
            provider_config_sha256=self.config.sha256,
            model="fixture-model",
            request_shape_limit_sha256=digest("synthetic-shape"),
            input_token_maximum=1000,
            output_token_maximum=None if typed else 512,
            bound_kind="synthetic_fixture",
            proof_sha256=digest("authored-count-bound"),
        )
        self.evidence = []
        self.register(self.request)

    def context(self, operation="op1", child="group", run="run1"):
        return CallContext(
            schema_version=1,
            authority_id=self.authority.authority_id,
            run_id=run,
            operation_id=operation,
            child_id=child,
            task_id="task1",
            span_id="span1",
            consumer_namespace="synthetic",
            purpose="synthetic.route",
            source_generation="g1",
            consumer_context_sha256=digest("public-context"),
            policy_sha256=digest("consumer-policy"),
            template_sha256=digest("public-template"),
            config_sha256=digest("consumer-config"),
        )

    def prepared(self, request=None):
        return prepare_request(
            request or self.request, config=self.config, context=self.context(), limits=self.limits
        )

    def register(self, request):
        prepared = self.prepared(request)
        evidence = RequestEvidence(
            schema_version=1,
            bound_evidence_sha256=self.bound.evidence_sha256,
            request_identity_sha256=prepared.request_identity_sha256,
            dispatched_envelope_sha256=prepared.dispatched_envelope_sha256,
            input_token_count=100,
            output_token_maximum=request.max_output_tokens
            if isinstance(request, GenerateRequest)
            else None,
            proof_sha256=digest("authored-request-count"),
        )
        self.evidence.append(evidence)
        return evidence

    def plan(self, *, offline=False, operation="op1", count=1, attempts=2):
        return OperationPlan(
            schema_version=1,
            operation_id=operation,
            authority_id=self.authority.authority_id,
            context_sha256=digest(self.context(operation).model_dump(mode="json")),
            children=[
                ChildBound(
                    child_id=f"child{i}",
                    purpose="synthetic.route",
                    provider_config_sha256=self.config.sha256,
                    model="fixture-model",
                    bound_evidence_sha256=self.bound.evidence_sha256,
                    max_attempts=0 if offline else attempts,
                    max_repairs=0,
                    input_token_maximum=1000,
                    output_token_maximum=self.bound.output_token_maximum,
                    fee_maximum_usd="0",
                    reserved_usd_per_attempt="0" if offline else self.reservation,
                    request_shape_limit_sha256=self.bound.request_shape_limit_sha256,
                    conditional=False,
                )
                for i in range(count)
            ],
        )

    def open(self, *, offline=False):
        return Ledger(
            self.path,
            authority=self.authority,
            price_snapshot=None if offline else self.snapshot,
            trusted_bounds=[] if offline else [self.bound],
            trusted_requests=self.evidence,
            clock=lambda: self.now,
            monotonic=lambda: self.tick,
        )

    def provider(self, mode="injected_simulation", **kwargs):
        return Provider(
            self.config,
            mode=mode,
            request_evidence=self.evidence,
            clock=lambda: self.tick,
            sleep=self.sleep,
            **kwargs,
        )

    def sleep(self, seconds):
        self.tick += seconds

    def kwargs(self, ledger, allocation, *, offline=False, operation="op1", child="child0"):
        return dict(
            purpose="synthetic.route",
            ledger=ledger,
            budget=self.authority,
            context=self.context(operation, child),
            limits=self.limits.model_copy(update={"max_outbound_attempts": 0})
            if offline
            else self.limits,
            allocation=allocation,
        )

    def body(self):
        usage = {"input_tokens": 100, "output_tokens": None}
        if self.config.flavor == "typesafe":
            return dict(
                model="fixture-model-reported",
                answers={
                    "condition": {"type": "noul", "noul": 0.8},
                    "category": {
                        "type": "choice",
                        "choice": "a",
                        "probabilities": {"a": 0.8, "b": 0.2},
                        "confidence": 0.6,
                    },
                    "score": {
                        "type": "score",
                        "score": 1.6,
                        "legend": {"0": "unrelated", "1": "related", "2": "same size"},
                        "probabilities": {"0": 0.1, "1": 0.2, "2": 0.7},
                        "confidence": 0.8,
                    },
                },
                usage=usage,
            )
        if self.config.flavor == "openai_chat":
            return dict(
                model="fixture-model-reported",
                choices=[{"finish_reason": "stop", "message": {"content": '{"tier":"cheap"}'}}],
                usage={"prompt_tokens": 100, "completion_tokens": None},
            )
        if self.config.flavor == "anthropic":
            return dict(
                model="fixture-model-reported",
                content=[{"type": "text", "text": '{"tier":"cheap"}'}],
                stop_reason="end_turn",
                usage={
                    "input_tokens": 100,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "output_tokens": None,
                },
            )
        return dict(
            model="fixture-model-reported",
            status="completed",
            output=[
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": '{"tier":"cheap"}'}],
                }
            ],
            usage=usage,
        )

    def capture(self):
        prepared = self.prepared()
        outcome = decode_outcome(
            json.dumps(self.body()).encode(), prepared=prepared, config=self.config, max_bytes=64000
        )
        return synthetic_capture(
            prepared,
            context=self.context(),
            outcome=outcome,
            capture_id="authored-capture",
            review_receipt_sha256=digest("authored-fixture-review"),
        )


class Spy:
    is_test_transport = True

    def __init__(self, rig, replies):
        self.rig = rig
        self.replies = list(replies)
        self.calls = []

    def send(self, payload_json, **kwargs):
        self.calls.append((payload_json, kwargs))
        self.rig.tick += 0.010
        response = self.replies.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path / "provider.sqlite3")


@pytest.fixture
def factory():
    return Rig


@pytest.fixture
def spy():
    return Spy


@pytest.fixture
def reply():
    return response


def response(body, status=200, **kwargs):
    return TransportReply(status, json.dumps(body).encode(), **kwargs)
