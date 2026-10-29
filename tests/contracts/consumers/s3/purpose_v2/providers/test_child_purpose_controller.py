"""Actual controller/ledger fixture hits with different declared per-child purposes."""

import json

import pytest

from issue_triage.shared.callledger.ledger import LedgerError
from issue_triage.shared.callledger.models import canonical_digest as h
from issue_triage.shared.providers.adapters import decode_outcome, prepare_request
from issue_triage.shared.providers.captures import FixtureIndex, synthetic_capture


@pytest.fixture(autouse=True)
def purpose_bug_metadata(request):
    request.node.user_properties.append(("what_bug_this_catches", request.node.function.__doc__))


def scenario(rig):
    limits = rig.limits.model_copy(update={"max_outbound_attempts": 0})
    root = rig.context().model_copy(update={"purpose": "synthetic.operation"})
    plan = rig.plan(offline=True, count=2)
    children = [
        child.model_copy(update={"purpose": f"synthetic.stage{index}"})
        for index, child in enumerate(plan.children)
    ]
    plan = plan.model_copy(
        update={"context_sha256": h(root.model_dump(mode="json")), "children": children}
    )
    contexts = []
    captures = []
    for index, child in enumerate(children):
        context = rig.context(child=child.child_id).model_copy(update={"purpose": child.purpose})
        contexts.append(context)
        prepared = prepare_request(rig.request, config=rig.config, context=context, limits=limits)
        evidence = rig.evidence[0].model_copy(
            update={
                "request_identity_sha256": prepared.request_identity_sha256,
                "dispatched_envelope_sha256": prepared.dispatched_envelope_sha256,
                "proof_sha256": h(["authored purpose request", index]),
            }
        )
        rig.evidence.append(evidence)
        outcome = decode_outcome(
            json.dumps(rig.body()).encode(), prepared=prepared, config=rig.config, max_bytes=64000
        )
        captures.append(
            synthetic_capture(
                prepared,
                context=context,
                outcome=outcome,
                capture_id=f"purpose-control-{index}",
                review_receipt_sha256=h("authored purpose control"),
            )
        )
    return root, plan, limits, contexts, captures


def test_actual_provider_declared_purposes_hit_without_transport_or_paid_attempt(rig):
    """what_bug_this_catches: valid readonly admission followed by a false purpose rejection."""
    root, plan, limits, contexts, captures = scenario(rig)
    provider = rig.provider(
        mode="mock", fixtures=FixtureIndex(captures), capture_mode="fixture_replay"
    )
    with rig.open(offline=True) as ledger:
        allocation = provider.admit_operation(
            plan, ledger=ledger, budget=rig.authority, context=root, limits=limits
        )
        for index, context in enumerate(contexts):
            options = dict(
                purpose=context.purpose,
                ledger=ledger,
                budget=rig.authority,
                context=context,
                limits=limits,
                allocation=allocation,
            )
            before = ledger.connection.total_changes
            view = provider.validate_replay_allocation(rig.request, **options)
            assert (
                ledger.connection.total_changes == before
                and view.max_attempts == view.remaining_attempts == view.used_attempts == 0
            )
            result = provider.run(rig.request, **options)
            assert (
                result.status == "ok"
                and result.origin == "mock"
                and result.current_external_cost_usd == "0"
            )
            assert result.attempt_ids == [] and result.source_capture.origin == "synthetic"
            assert ledger.operation_state(allocation) == ("pending" if index == 0 else "complete")
        assert ledger.totals()["dispatched_attempts"] == 0


def test_actual_readonly_provider_rejects_unlisted_child_purpose_before_lookup(rig):
    """what_bug_this_catches: an undeclared purpose passes the actual prelookup seam."""
    root, plan, limits, contexts, captures = scenario(rig)
    bad = contexts[0].model_copy(update={"purpose": root.purpose})
    prepared = prepare_request(rig.request, config=rig.config, context=bad, limits=limits)
    rig.evidence.append(
        rig.evidence[0].model_copy(
            update={
                "request_identity_sha256": prepared.request_identity_sha256,
                "dispatched_envelope_sha256": prepared.dispatched_envelope_sha256,
                "proof_sha256": h("adverse purpose evidence"),
            }
        )
    )
    provider = rig.provider(
        mode="mock", fixtures=FixtureIndex(captures), capture_mode="fixture_replay"
    )
    with rig.open(offline=True) as ledger:
        allocation = provider.admit_operation(
            plan, ledger=ledger, budget=rig.authority, context=root, limits=limits
        )
        before = ledger.connection.total_changes
        with pytest.raises(LedgerError, match="context_mismatch"):
            provider.validate_replay_allocation(
                rig.request,
                purpose=bad.purpose,
                ledger=ledger,
                budget=rig.authority,
                context=bad,
                limits=limits,
                allocation=allocation,
            )
        assert (
            ledger.connection.total_changes == before
            and ledger.totals()["dispatched_attempts"] == 0
        )
