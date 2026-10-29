"""Declared offline child purposes remain distinct from the root operation purpose."""

import pytest

from issue_triage.shared.callledger.ledger import LedgerError, ReuseAccounting
from issue_triage.shared.callledger.models import canonical_digest as h


@pytest.fixture(autouse=True)
def purpose_bug_metadata(request):
    request.node.user_properties.append(("what_bug_this_catches", request.node.function.__doc__))


def offline_plan(factory):
    root = factory.context().model_copy(update={"purpose": "synthetic.operation"})
    original = factory.plan(count=2, attempts=0)
    children = [
        child.model_copy(update={"purpose": f"synthetic.stage{index}"})
        for index, child in enumerate(original.children)
    ]
    plan = original.model_copy(
        update={"context_sha256": h(root.model_dump(mode="json")), "children": children}
    )
    limits = factory.limits.model_copy(update={"max_outbound_attempts": 0})
    return root, plan, limits


def provenance(factory):
    return ReuseAccounting(
        schema_version=1,
        origin="mock",
        capture_sha256=h("authored body"),
        request_identity_sha256=factory.request.request_identity_sha256,
        source_run_id="synthetic-source",
        source_model="fixture-model",
        source_cost_usd=None,
        source_usage_sha256=None,
        source_price_sha256=None,
        current_external_cost_usd="0",
    )


@pytest.mark.parametrize("with_limits", [False, True])
def test_declared_child_purposes_complete_group_with_or_without_optional_limits(
    factory, with_limits
):
    """what_bug_this_catches: valid child purposes are compared to root and cannot record reuse."""
    root, plan, limits = offline_plan(factory)
    with factory.open() as ledger:
        allocation = ledger.admit_operation(plan, context=root, limits=limits, mode="offline")
        for index, child in enumerate(plan.children):
            context = factory.context(child=child.child_id).model_copy(
                update={"purpose": child.purpose}
            )
            options = {"caller_limits": limits} if with_limits else {}
            ledger.record_reuse(
                allocation,
                context=context,
                request=factory.request,
                provenance=provenance(factory),
                **options,
            )
            assert ledger.operation_state(allocation) == ("pending" if index == 0 else "complete")
        assert ledger.totals()["dispatched_attempts"] == 0
        assert ledger.totals()["known_spend_usd"] == ledger.totals()["total_exposure_usd"] == "0"
    with factory.open() as restarted:
        assert restarted.operation_state(allocation) == "complete"
        assert restarted.totals()["dispatched_attempts"] == 0


@pytest.mark.parametrize("with_limits", [False, True])
def test_root_purpose_cannot_impersonate_undeclared_child_even_without_limits(factory, with_limits):
    """what_bug_this_catches: removing root-purpose comparison opens an optional-limits bypass."""
    root, plan, limits = offline_plan(factory)
    with factory.open() as ledger:
        allocation = ledger.admit_operation(plan, context=root, limits=limits, mode="offline")
        bad = root.model_copy(update={"child_id": "child0"})
        before = ledger.connection.total_changes
        events = ledger.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        options = {"caller_limits": limits} if with_limits else {}
        with pytest.raises(LedgerError, match="context_mismatch"):
            ledger.record_reuse(
                allocation,
                context=bad,
                request=factory.request,
                provenance=provenance(factory),
                **options,
            )
        assert ledger.connection.total_changes == before
        assert ledger.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == events
        assert ledger.operation_state(allocation) == "pending"
        assert ledger.totals()["dispatched_attempts"] == 0
