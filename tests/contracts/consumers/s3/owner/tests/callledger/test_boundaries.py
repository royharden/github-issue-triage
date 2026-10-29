"""what_bug_this_catches: underfunded evidence, deadline extensions and repriced history."""

import json
import sqlite3
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from issue_triage.shared.callledger.ledger import Ledger, LedgerError, ReuseAccounting
from issue_triage.shared.callledger.models import OperationPlan
from issue_triage.shared.callledger.models import canonical_digest as digest
from issue_triage.shared.callledger.pricing import PriceSnapshot


def test_unknown_billed_input_holds_liability_but_real_zero_settles(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        first = factory.begin(ledger, allocation)
        ledger.settle(first, **factory.metadata(allocation, count=None, status="invalid_output"))
        assert Decimal(ledger.totals()["unknown_liability_usd"]) == Decimal("0.1")
        assert ledger.totals()["known_spend_usd"] == "0"
        second = factory.begin(ledger, allocation)
        proof = ledger.settle(second, **factory.metadata(allocation, count=0))
        ledger.finish_child(allocation, child_id="child0", outcome="complete", proof_sha256=proof)
        assert Decimal(ledger.totals()["known_spend_usd"]) == 0
        assert Decimal(ledger.totals()["unknown_liability_usd"]) == Decimal("0.1")


@pytest.mark.parametrize("mutation", ["reservation", "shape", "input", "policy_registry"])
def test_unauthenticated_or_underfunded_plan_evidence_never_holds_or_dispatches(factory, mutation):
    plan = factory.plan().model_dump()
    child = plan["children"][0]
    if mutation == "reservation":
        child["reserved_usd_per_attempt"] = "0.09"
    elif mutation == "shape":
        child["request_shape_limit_sha256"] = digest("changed-shape")
    elif mutation == "input":
        child["input_token_maximum"] = 1001
    else:
        child["bound_evidence_sha256"] = digest("unregistered-schema-valid-evidence")
    with factory.open() as ledger:
        with pytest.raises(LedgerError):
            ledger.admit_operation(
                OperationPlan.model_validate(plan),
                context=factory.context(),
                limits=factory.limits,
                mode="simulation",
            )
        assert ledger.totals()["dispatched_attempts"] == 0
        assert Decimal(ledger.totals()["total_exposure_usd"]) == 0


def test_registered_request_count_still_must_fit_funded_shape(factory):
    factory.request = factory.request.model_copy(update={"input_token_count": 1001})
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        with pytest.raises(LedgerError, match="request_bound"):
            factory.begin(ledger, allocation)
        assert ledger.totals()["dispatched_attempts"] == 0


def test_monotonic_deadline_starts_before_first_attempt_not_first_check(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        factory.tick += 31
        with pytest.raises(LedgerError, match="deadline"):
            factory.begin(ledger, allocation)
        assert ledger.totals()["dispatched_attempts"] == 0


def test_expired_or_clock_rollback_authority_still_accepts_paid_settlement(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        attempt = factory.begin(ledger, allocation)
        factory.now -= timedelta(days=1)
        proof = ledger.settle(attempt, **factory.metadata(allocation))
        assert proof and Decimal(ledger.totals()["known_spend_usd"]) == Decimal("0.01")
        with pytest.raises(LedgerError, match="clock_rollback"):
            factory.begin(ledger, allocation)


def test_completed_child_rejects_conflicting_duplicate_proof(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        attempt = factory.begin(ledger, allocation)
        proof = ledger.settle(attempt, **factory.metadata(allocation))
        ledger.finish_child(allocation, child_id="child0", outcome="complete", proof_sha256=proof)
        with pytest.raises(LedgerError, match="completion_conflict"):
            ledger.finish_child(
                allocation, child_id="child0", outcome="complete", proof_sha256=digest("fake")
            )


def test_reopening_with_new_snapshot_does_not_reprice_existing_attempt(factory):
    original_snapshot = factory.snapshot.snapshot_sha256
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        attempt = factory.begin(ledger, allocation)
    changed = factory.snapshot.model_dump(mode="json")
    changed["policies"][0]["input_usd_per_million"] = "900"
    changed["data_sha256"] = digest(changed["policies"])
    factory.snapshot = PriceSnapshot.model_validate(changed)
    with factory.open() as ledger:
        ledger.settle(attempt, **factory.metadata(allocation))
        assert Decimal(ledger.totals()["known_spend_usd"]) == Decimal("0.01")
        row = json.loads(ledger.connection.execute("SELECT settlement FROM attempts").fetchone()[0])
        assert row["price_snapshot_sha256"] == original_snapshot
        assert ledger.connection.execute("SELECT COUNT(*) FROM price_snapshots").fetchone()[0] == 2


def test_offline_reuse_needs_no_price_snapshot_and_rejects_changed_capture_binding(factory):
    with Ledger(
        factory.path,
        authority=factory.authority,
        trusted_requests=[factory.request],
        clock=lambda: factory.now,
        monotonic=lambda: factory.tick,
    ) as ledger:
        allocation = ledger.admit_operation(
            factory.plan(attempts=0),
            context=factory.context(),
            limits=factory.limits,
            mode="offline",
        )
        data = dict(
            schema_version=1,
            origin="replay",
            capture_sha256=digest("capture"),
            request_identity_sha256=digest("wrong"),
            source_run_id="source",
            source_model=None,
            source_cost_usd=None,
            source_usage_sha256=None,
            source_price_sha256=None,
            current_external_cost_usd="0",
        )
        with pytest.raises(LedgerError, match="untrusted_request"):
            ledger.record_reuse(
                allocation,
                context=factory.context(child="child0"),
                request=factory.request,
                provenance=ReuseAccounting.model_validate(data),
            )
        assert ledger.operation_state(allocation) == "pending"


@pytest.mark.parametrize("suffix", ["", "-wal", "-shm", "-journal"])
def test_export_cannot_overwrite_sqlite_or_its_recovery_files(factory, suffix):
    with factory.open() as ledger:
        with pytest.raises(LedgerError, match="unsafe_projection"):
            ledger.export_jsonl(Path(str(factory.path) + suffix))
        assert ledger.totals()["dispatched_attempts"] == 0


def test_future_ledger_schema_refuses_without_dropping_existing_data(factory):
    connection = sqlite3.connect(factory.path)
    connection.execute("PRAGMA user_version=99")
    connection.execute("CREATE TABLE untouched (data TEXT)")
    connection.execute("INSERT INTO untouched VALUES('sentinel')")
    connection.commit()
    connection.close()
    with pytest.raises(LedgerError, match="schema_version"):
        factory.open()
    connection = sqlite3.connect(factory.path)
    assert connection.execute("SELECT data FROM untouched").fetchone()[0] == "sentinel"
    connection.close()
