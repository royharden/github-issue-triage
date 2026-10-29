"""what_bug_this_catches: lost/doubled holds, counter resets and invalid settlement releases."""

from datetime import timedelta
from decimal import Decimal

import pytest

from issue_triage.shared.callledger.ledger import LedgerError, ReuseAccounting
from issue_triage.shared.callledger.models import NonModelSpan
from issue_triage.shared.callledger.models import canonical_digest as digest


def money(totals, name):
    return Decimal(totals[name + "_usd"])


def test_full_fanout_rejected_before_any_attempt(factory):
    with factory.open() as ledger:
        with pytest.raises(LedgerError, match="budget_rejected"):
            factory.admit(ledger, count=3)
        assert ledger.totals()["dispatched_attempts"] == 0
        assert money(ledger.totals(), "total_exposure") == 0


def test_conserved_transfer_known_unknown_and_conditional_release(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger, count=2, conditional=True)
        assert money(ledger.totals(), "future_holds") == Decimal("0.4")
        first = factory.begin(ledger, allocation)
        totals = ledger.totals()
        assert money(totals, "future_holds") == Decimal("0.3")
        assert money(totals, "active_holds") == Decimal("0.1")
        assert money(totals, "total_exposure") == Decimal("0.4")
        settled = ledger.settle(first, **factory.metadata(allocation))
        ledger.finish_child(allocation, child_id="child0", outcome="complete", proof_sha256=settled)
        assert money(ledger.totals(), "known_spend") == Decimal("0.01")
        second = factory.begin(ledger, allocation, "child1")
        unknown = ledger.mark_unknown(second)
        ledger.finish_child(allocation, child_id="child1", outcome="failed", proof_sha256=unknown)
        totals = ledger.totals()
        assert money(totals, "unknown_liability") == Decimal("0.1")
        assert money(totals, "future_holds") == 0
        assert money(totals, "total_exposure") == Decimal("0.11")
        assert ledger.operation_state(allocation) == "partial"
    with factory.open() as restarted:
        assert restarted.totals() == totals


def test_duplicate_admission_settlement_and_completion_are_idempotent(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        assert allocation == factory.admit(ledger)
        attempt = factory.begin(ledger, allocation)
        metadata = factory.metadata(allocation)
        proof = ledger.settle(attempt, **metadata)
        before = ledger.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert ledger.settle(attempt, **metadata) == proof
        assert ledger.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before
        with pytest.raises(LedgerError, match="settlement_conflict"):
            ledger.settle(attempt, **factory.metadata(allocation, count=200))
        ledger.finish_child(allocation, child_id="child0", outcome="complete", proof_sha256=proof)
        ledger.finish_child(allocation, child_id="child0", outcome="complete", proof_sha256=proof)
        assert ledger.operation_state(allocation) == "complete"


def test_active_and_unknown_never_release_as_undispatched(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger, conditional=True)
        attempt = factory.begin(ledger, allocation)
        with pytest.raises(LedgerError, match="active_attempt"):
            ledger.finish_child(
                allocation, child_id="child0", outcome="skipped", proof_sha256=digest("fake")
            )
        proof = ledger.mark_unknown(attempt)
        with pytest.raises(LedgerError, match="completion_proof"):
            ledger.finish_child(
                allocation, child_id="child0", outcome="skipped", proof_sha256=proof
            )
        with pytest.raises(LedgerError, match="settlement_conflict"):
            ledger.settle(attempt, **factory.metadata(allocation))
        assert money(ledger.totals(), "unknown_liability") == Decimal("0.1")


def test_conditional_skip_requires_database_undispatched_proof(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger, conditional=True)
        with pytest.raises(LedgerError, match="completion_proof"):
            ledger.finish_child(
                allocation, child_id="child0", outcome="skipped", proof_sha256=digest("wrong")
            )
        proof = digest(
            {"allocation_id": allocation.allocation_id, "child_id": "child0", "undispatched": True}
        )
        ledger.finish_child(allocation, child_id="child0", outcome="skipped", proof_sha256=proof)
        assert money(ledger.totals(), "total_exposure") == 0
        assert ledger.totals()["dispatched_attempts"] == 0


def test_invalid_paid_attempt_settles_and_cannot_claim_child_success(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        attempt = factory.begin(ledger, allocation)
        proof = ledger.settle(attempt, **factory.metadata(allocation, status="invalid_output"))
        assert money(ledger.totals(), "known_spend") == Decimal("0.01")
        with pytest.raises(LedgerError, match="completion_proof"):
            ledger.finish_child(
                allocation, child_id="child0", outcome="complete", proof_sha256=proof
            )
        ledger.finish_child(allocation, child_id="child0", outcome="failed", proof_sha256=proof)
        assert ledger.operation_state(allocation) == "partial"


@pytest.mark.parametrize("count", [2000, 6000])
def test_above_bound_is_recorded_and_halts_without_clamping(factory, count):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        attempt = factory.begin(ledger, allocation)
        ledger.settle(attempt, **factory.metadata(allocation, count=count))
        totals = ledger.totals()
        assert totals["halted"] is True
        assert money(totals, "known_spend") == Decimal(count) / 10000
        with pytest.raises(LedgerError, match="halted"):
            factory.begin(ledger, allocation)
    with factory.open() as restarted:
        assert restarted.totals()["halted"] is True


def test_authority_identity_and_counters_survive_new_run(factory):
    factory.authority = factory.authority.model_copy(update={"max_outbound_attempts": 2})
    factory.limits = factory.limits.model_copy(update={"max_outbound_attempts": 2})
    with factory.open() as ledger:
        allocation = factory.admit(ledger, attempts=1)
        attempt = factory.begin(ledger, allocation)
        proof = ledger.settle(attempt, **factory.metadata(allocation))
        ledger.finish_child(allocation, child_id="child0", outcome="complete", proof_sha256=proof)
    with factory.open() as ledger:
        new = factory.admit(ledger, "op2", attempts=1, run="run2")
        attempt = factory.begin(ledger, new, run="run2")
        proof = ledger.mark_unknown(attempt)
        ledger.finish_child(new, child_id="child0", outcome="failed", proof_sha256=proof)
        with pytest.raises(LedgerError, match="attempt_limit"):
            factory.admit(ledger, "op3", attempts=1, run="run3")
        assert ledger.totals()["dispatched_attempts"] == 2
    factory.authority = factory.authority.model_copy(update={"cap_usd": "9"})
    with pytest.raises(LedgerError, match="authority_conflict"):
        factory.open()


def test_two_attempt_no_repair_and_cumulative_limits(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        with pytest.raises(LedgerError, match="repair_limit"):
            factory.begin(ledger, allocation, content_repair=True)
        for _ in range(2):
            attempt = factory.begin(ledger, allocation)
            ledger.mark_unknown(attempt)
        with pytest.raises(LedgerError, match="attempt_limit"):
            factory.begin(ledger, allocation)
        assert ledger.totals()["dispatched_attempts"] == 2


def test_monotonic_and_persisted_deadlines_refuse_backoff_and_clock_rollback(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        assert ledger.retry_fits(allocation, retry_after_s=29.0)
        assert not ledger.retry_fits(allocation, retry_after_s=30.0)
        factory.tick += 31
        with pytest.raises(LedgerError, match="deadline"):
            factory.begin(ledger, allocation)
    factory.now += timedelta(seconds=31)
    with factory.open() as ledger:
        with pytest.raises(LedgerError, match="deadline"):
            factory.begin(ledger, allocation)
    factory.now -= timedelta(seconds=32)
    with factory.open() as ledger:
        with pytest.raises(LedgerError, match="clock_rollback"):
            factory.begin(ledger, allocation)


@pytest.mark.parametrize("mutation", ["allocation", "context", "request", "bound", "external"])
def test_untrusted_or_changed_bindings_refuse_without_dispatch(factory, mutation):
    with factory.open() as ledger:
        if mutation in {"bound", "external"}:
            plan = factory.plan()
            if mutation == "bound":
                data = plan.model_dump()
                data["children"][0]["bound_evidence_sha256"] = digest("unregistered")
                plan = type(plan).model_validate(data)
            with pytest.raises(LedgerError):
                ledger.admit_operation(
                    plan,
                    context=factory.context(),
                    limits=factory.limits,
                    mode="external" if mutation == "external" else "simulation",
                )
        else:
            allocation = factory.admit(ledger)
            context = factory.context(child="child0")
            request = factory.request
            if mutation == "allocation":
                allocation = allocation.model_copy(update={"allocation_id": "fake"})
            elif mutation == "context":
                context = context.model_copy(update={"purpose": "fake"})
            else:
                request = request.model_copy(
                    update={"dispatched_envelope_sha256": digest("changed")}
                )
            with pytest.raises(LedgerError):
                ledger.begin_attempt(allocation, context=context, request=request)
        assert ledger.totals()["dispatched_attempts"] == 0


@pytest.mark.parametrize("origin,cost", [("mock", None), ("replay", None), ("replay", "0.12")])
def test_reuse_current_zero_separate_source_cost_and_nonmodel_null(factory, origin, cost):
    with factory.open() as ledger:
        allocation = ledger.admit_operation(
            factory.plan(attempts=0),
            context=factory.context(),
            limits=factory.limits,
            mode="offline",
        )
        provenance = ReuseAccounting(
            schema_version=1,
            origin=origin,
            capture_sha256=digest("capture"),
            request_identity_sha256=factory.request.request_identity_sha256,
            source_run_id="source-run",
            source_model="fixture-model",
            source_cost_usd=cost,
            source_usage_sha256=None,
            source_price_sha256=None,
            current_external_cost_usd="0",
        )
        ledger.record_reuse(
            allocation,
            context=factory.context(child="child0"),
            request=factory.request,
            provenance=provenance,
        )
        ledger.record_non_model(
            NonModelSpan(
                schema_version=1,
                kind="non_model",
                context=factory.context(),
                duration_ms=1.0,
                status="ok",
            )
        )
        assert ledger.operation_state(allocation) == "complete"
        assert money(ledger.totals(), "total_exposure") == 0
        assert ledger.totals()["dispatched_attempts"] == 0
        text = ledger.connection.execute(
            "SELECT payload FROM events WHERE payload LIKE '%reuse_accounted%'"
        ).fetchone()[0]
        assert '"source_cost_usd":' + ("null" if cost is None else '"0.12"') in text
