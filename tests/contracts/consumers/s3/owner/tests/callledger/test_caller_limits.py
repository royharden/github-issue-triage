"""what_bug_this_catches: a read-only precheck or restarted loop bypassing tighter atomic limits."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from decimal import Decimal
from threading import Barrier

import pytest

from issue_triage.shared.callledger import LedgerError
from issue_triage.shared.callledger.models import OperationPlan


def admit_three(factory, ledger):
    factory.limits = factory.limits.model_copy(
        update={"max_attempts_total": 3, "max_content_repairs": 1}
    )
    data = factory.plan(attempts=3).model_dump(mode="json")
    data["children"][0]["max_repairs"] = 1
    return ledger.admit_operation(
        OperationPlan.model_validate(data),
        context=factory.context(),
        limits=factory.limits,
        mode="simulation",
    )


def test_validation_is_read_only_and_tighter_limits_persist_across_restart(factory):
    with factory.open() as ledger:
        allocation = admit_three(factory, ledger)
        strict = factory.limits.model_copy(
            update={"max_attempts_total": 2, "max_content_repairs": 0}
        )
        before = ledger.connection.total_changes
        view = ledger.validate_allocation(
            allocation,
            context=factory.context(child="child0"),
            limits=strict,
            request=factory.request,
        )
        assert (
            ledger.connection.total_changes == before
            and view.used_attempts == 0
            and view.max_attempts == 2
        )
        with pytest.raises(FrozenInstanceError):
            view.max_attempts = 3
        first = factory.begin(ledger, allocation, caller_limits=strict)
        ledger.mark_unknown(first)
    with factory.open() as ledger:
        with pytest.raises(LedgerError, match="repair_limit"):
            factory.begin(ledger, allocation, content_repair=True)
        second = factory.begin(ledger, allocation)
        proof = ledger.mark_unknown(second)
        with pytest.raises(LedgerError, match="attempt_limit"):
            factory.begin(ledger, allocation)
        with pytest.raises(LedgerError, match="caller_limits"):
            factory.begin(ledger, allocation, caller_limits=factory.limits)
        assert ledger.totals()["dispatched_attempts"] == 2
        assert Decimal(ledger.totals()["future_holds_usd"]) == Decimal("0.1")  # no silent release
        ledger.finish_child(allocation, child_id="child0", outcome="failed", proof_sha256=proof)
        assert Decimal(ledger.totals()["unknown_liability_usd"]) == Decimal("0.2")


def test_two_observed_views_do_not_authorize_two_tighter_transfers(factory):
    with factory.open() as ledger:
        allocation = admit_three(factory, ledger)
        strict = factory.limits.model_copy(
            update={"max_attempts_total": 2, "max_content_repairs": 0}
        )
        first = factory.begin(ledger, allocation, caller_limits=strict)
        ledger.mark_unknown(first)
    barrier = Barrier(2)

    def transfer(_):
        with factory.open() as ledger:
            view = ledger.validate_allocation(
                allocation,
                context=factory.context(child="child0"),
                limits=strict,
                request=factory.request,
            )
            assert view.used_attempts == 1
            barrier.wait(timeout=10)
            try:
                return factory.begin(ledger, allocation, caller_limits=strict)
            except LedgerError as error:
                return str(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(transfer, range(2)))
    assert results.count("attempt_limit") == 1
    winner = next(result for result in results if result != "attempt_limit")
    with factory.open() as ledger:
        ledger.mark_unknown(winner)
        assert ledger.totals()["dispatched_attempts"] == 2
        with pytest.raises(LedgerError, match="attempt_limit"):
            factory.begin(ledger, allocation)


@pytest.mark.parametrize(
    "field,value", [("operation_deadline_s", 20.0), ("max_concurrent_operations", 1)]
)
def test_unsupported_retroactive_scheduling_tightening_refuses_explicitly(factory, field, value):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        strict = factory.limits.model_copy(update={field: value})
        with pytest.raises(LedgerError, match="strict_limits_unsupported"):
            ledger.validate_allocation(
                allocation,
                context=factory.context(child="child0"),
                limits=strict,
                request=factory.request,
            )
        assert ledger.totals()["dispatched_attempts"] == 0


def test_paid_child_cannot_become_zero_dispatch_by_lowering_a_label(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        zero = factory.limits.model_copy(update={"max_outbound_attempts": 0})
        with pytest.raises(LedgerError, match="zero_quota_required"):
            ledger.validate_allocation(
                allocation,
                context=factory.context(child="child0"),
                limits=zero,
                request=factory.request,
                require_zero_dispatch=True,
            )
        assert ledger.totals()["dispatched_attempts"] == 0
