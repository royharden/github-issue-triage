"""Synthetic prices/bounds explicitly simulate accounting, never provider access."""

from datetime import UTC, datetime

import pytest

from issue_triage.shared.callledger.ledger import Ledger
from issue_triage.shared.callledger.models import (
    BudgetAuthority,
    CallContext,
    ChildBound,
    Limits,
    MetadataRecord,
    MetadataUsage,
    NormalizedUsage,
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


class Fixture:
    def __init__(self, path):
        self.path = path
        self.now = datetime(2026, 10, 14, 22, 30, tzinfo=UTC)
        self.tick = 100.0
        self.authority = BudgetAuthority(
            schema_version=1,
            authority_id="synthetic-authority",
            scope_sha256=digest("scope"),
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
            max_request_bytes=32000,
            max_response_bytes=64000,
            max_questions=32,
            max_choice_options=64,
        )
        self.policy = PricePolicy(
            schema_version=1,
            provider="synthetic",
            model="fixture-model",
            context_sha256=digest("price-context"),
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
            provider_config_sha256=digest("provider"),
            model="fixture-model",
            request_shape_limit_sha256=digest("shape"),
            input_token_maximum=1000,
            output_token_maximum=None,
            bound_kind="synthetic_fixture",
            proof_sha256=digest("synthetic-count-proof"),
        )
        self.request = RequestEvidence(
            schema_version=1,
            bound_evidence_sha256=self.bound.evidence_sha256,
            request_identity_sha256=digest("synthetic-request"),
            dispatched_envelope_sha256=digest("synthetic-dispatch"),
            input_token_count=100,
            output_token_maximum=None,
            proof_sha256=digest("synthetic-actual-count"),
        )

    def open(self, **kwargs):
        return Ledger(
            self.path,
            authority=self.authority,
            price_snapshot=self.snapshot,
            trusted_bounds=[self.bound],
            trusted_requests=[self.request],
            clock=lambda: self.now,
            monotonic=lambda: self.tick,
            **kwargs,
        )

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
            purpose="synthetic.test",
            source_generation="g1",
            consumer_context_sha256=digest("public-context"),
            policy_sha256=digest("consumer-policy"),
            template_sha256=digest("template"),
            config_sha256=digest("config"),
        )

    def plan(self, operation="op1", *, count=1, conditional=False, attempts=2, run="run1"):
        context = self.context(operation, run=run)
        children = [
            ChildBound(
                child_id=f"child{i}",
                purpose=context.purpose,
                provider_config_sha256=self.bound.provider_config_sha256,
                model=self.bound.model,
                bound_evidence_sha256=self.bound.evidence_sha256,
                max_attempts=attempts,
                max_repairs=0,
                input_token_maximum=1000,
                output_token_maximum=None,
                fee_maximum_usd="0",
                reserved_usd_per_attempt="0.1" if attempts else "0",
                request_shape_limit_sha256=self.bound.request_shape_limit_sha256,
                conditional=conditional,
            )
            for i in range(count)
        ]
        return OperationPlan(
            schema_version=1,
            operation_id=operation,
            authority_id=self.authority.authority_id,
            context_sha256=digest(context.model_dump(mode="json")),
            children=children,
        )

    def admit(self, ledger, operation="op1", **kwargs):
        return ledger.admit_operation(
            self.plan(operation, **kwargs),
            context=self.context(operation, run=kwargs.get("run", "run1")),
            limits=self.limits,
            mode="simulation",
        )

    def begin(self, ledger, allocation, child="child0", run="run1", **kwargs):
        return ledger.begin_attempt(
            allocation,
            context=self.context(allocation.operation_id, child, run),
            request=self.request,
            **kwargs,
        )

    def metadata(self, allocation, child="child0", *, count=100, status="ok", run="run1"):
        usage = NormalizedUsage(input_tokens=count)
        projection = MetadataUsage(input_tokens=count, details=usage)
        metadata = MetadataRecord(
            schema_version=1,
            context=self.context(allocation.operation_id, child, run),
            request_identity_sha256=self.request.request_identity_sha256,
            usage=projection,
            usage_projection_sha256=digest(projection.model_dump(mode="json")),
            usage_redacted_fields=False,
            status=status,
            duration_ms=1.0,
        )
        return dict(metadata=metadata, usage=usage)


@pytest.fixture
def factory(tmp_path):
    return Fixture(tmp_path / "ledger.sqlite3")
