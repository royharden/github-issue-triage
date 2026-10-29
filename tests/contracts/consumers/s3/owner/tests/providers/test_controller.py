"""what_bug_this_catches: mocked accounting, hidden fanout/retries and misrepresented provenance."""

import json
from dataclasses import replace
from decimal import Decimal

import pytest

from issue_triage.shared.callledger.models import canonical_digest as digest
from issue_triage.shared.callledger.pricing import PriceSnapshot
from issue_triage.shared.providers.captures import CaptureError, FixtureIndex
from issue_triage.shared.providers.controller import (
    ProviderError,
    TransportFailure,
)


def admit(rig, provider, ledger, *, offline=False):
    limits = rig.limits.model_copy(update={"max_outbound_attempts": 0}) if offline else rig.limits
    return provider.admit_operation(
        rig.plan(offline=offline),
        ledger=ledger,
        budget=rig.authority,
        context=rig.context(),
        limits=limits,
    )


@pytest.mark.parametrize(
    "flavor,typed",
    [("openai_responses", False), ("openai_chat", False), ("typesafe", True), ("anthropic", False)],
)
def test_real_ledger_one_dispatch_actual_typed_or_structured_output(
    factory, spy, reply, tmp_path, flavor, typed
):
    rig = factory(tmp_path / "ledger.sqlite3", flavor, typed)
    transport = spy(rig, [reply(rig.body())])
    provider = rig.provider(transport=transport)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        result = provider.run(rig.request, **rig.kwargs(ledger, allocation))
        assert (
            result.status == "ok"
            and result.origin == "mock"
            and result.current_external_cost_usd == "0"
        )
        assert (
            result.model_reported == "fixture-model-reported"
            and result.source_capture.origin == "synthetic"
        )
        assert result.source_capture.cost_usd == "0.01"
        if typed:
            assert result.typed.answers["score"].score == 1.6 and result.text is None
            assert set(json.loads(transport.calls[0][0])["questions"]) == {
                "condition",
                "category",
                "score",
            }
        else:
            assert result.parsed == {"tier": "cheap"}
        assert (
            len(transport.calls)
            == len(result.attempt_ids)
            == ledger.totals()["dispatched_attempts"]
            == 1
        )
        assert transport.calls[0][1]["max_retries"] == 0
        assert Decimal(ledger.totals()["known_spend_usd"]) == Decimal("0.01")
        assert Decimal(ledger.totals()["future_holds_usd"]) == 0
        assert ledger.operation_state(allocation) == "complete"


def test_complete_forwards_exact_accounting_and_payload_binding(rig, spy, reply):
    transport = spy(rig, [reply(rig.body())])
    provider = rig.provider(transport=transport)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        result = provider.complete(
            [m.model_dump(mode="json") for m in rig.request.messages],
            schema=rig.request.output_schema,
            model=rig.request.model,
            max_output_tokens=32,
            **rig.kwargs(ledger, allocation),
        )
        assert result.status == "ok"
        assert transport.calls[0][0] == rig.prepared().payload_json
        with pytest.raises(TypeError):
            provider.complete([], model="fixture-model")


@pytest.mark.parametrize("mode", ["mock", "strict_replay"])
def test_zero_quota_real_admission_before_strict_lookup_no_transport(rig, spy, mode):
    transport = spy(rig, [])
    provider = rig.provider(
        mode=mode,
        fixtures=FixtureIndex([rig.capture()]),
        capture_mode="fixture_replay",
        transport=transport,
    )
    with rig.open(offline=True) as ledger:
        allocation = admit(rig, provider, ledger, offline=True)
        kwargs = rig.kwargs(ledger, allocation, offline=True)
        before = ledger.connection.total_changes
        view = provider.validate_replay_allocation(rig.request, **kwargs)
        assert ledger.connection.total_changes == before
        assert (
            view.mode == "offline"
            and view.used_attempts == view.remaining_attempts == view.max_attempts == 0
        )
        result = provider.run(rig.request, **kwargs)
        assert (
            result.status == "ok" and result.origin == "mock"
        )  # authored fixture remains synthetic
        assert result.source_capture.cost_usd is None and result.source_capture.latency_ms is None
        assert result.first_output_ms is None and result.first_output_kind == "unavailable"
        assert (
            result.attempt_ids == []
            and result.current_external_cost_usd == "0"
            and not transport.calls
        )
        assert ledger.totals()["dispatched_attempts"] == 0
        assert Decimal(ledger.totals()["total_exposure_usd"]) == 0


def test_changed_nonce_strict_miss_has_no_capture_no_fallback(factory, spy, tmp_path):
    rig = factory(tmp_path / "ledger.sqlite3", "typesafe", True)
    original = rig.capture()
    request = rig.request.model_copy(
        update={"state": {"text": "SYNTHETIC_PAYLOAD_CANARY", "nonce": "nonce-2"}}
    )
    rig.register(request)
    transport = spy(rig, [])
    provider = rig.provider(
        "strict_replay",
        fixtures=FixtureIndex([original]),
        capture_mode="fixture_replay",
        transport=transport,
    )
    with rig.open(offline=True) as ledger:
        allocation = admit(rig, provider, ledger, offline=True)
        result = provider.run(request, **rig.kwargs(ledger, allocation, offline=True))
        assert result.status == "cache_miss" and result.error.code == "cache_miss"
        assert result.source_capture is None and result.model_reported is None
        assert result.typed is None and result.parsed is None and result.text is None
        assert (
            result.attempt_ids == []
            and result.current_external_cost_usd == "0"
            and not transport.calls
        )
        assert ledger.operation_state(allocation) == "partial"
        assert ledger.totals()["dispatched_attempts"] == 0


def test_replay_needs_actual_zero_child_and_explicit_zero_outbound(rig):
    provider = rig.provider(
        "strict_replay", fixtures=FixtureIndex([rig.capture()]), capture_mode="fixture_replay"
    )
    with rig.open(offline=True) as ledger:
        allocation = ledger.admit_operation(
            rig.plan(offline=True), context=rig.context(), limits=rig.limits, mode="offline"
        )
        with pytest.raises(ValueError, match="zero_quota_required"):
            provider.validate_replay_allocation(rig.request, **rig.kwargs(ledger, allocation))
        forged = allocation.model_copy(update={"allocation_id": "fake"})
        with pytest.raises(ValueError, match="allocation_mismatch"):
            provider.run(rig.request, **rig.kwargs(ledger, forged, offline=True))
        assert ledger.totals()["dispatched_attempts"] == 0


def test_capture_flag_cannot_turn_authored_fixture_into_live_observation(rig):
    record = rig.capture()
    fake = replace(record, source=record.source.model_copy(update={"origin": "live"}))
    with pytest.raises(CaptureError, match="unverified_live_capture"):
        FixtureIndex([fake])
    changed = replace(record, content_json=record.content_json + b" ")
    with pytest.raises(CaptureError, match="capture_hash"):
        FixtureIndex([changed])


def test_429_then_invalid_output_uses_only_two_no_content_repair(rig, spy, reply):
    bad = rig.body()
    bad["output"][0]["content"][0]["text"] = '{"tier":"invented"}'
    transport = spy(
        rig, [reply({}, 429, headers={"Retry-After": "0"}), reply(bad), reply(rig.body())]
    )
    provider = rig.provider(transport=transport)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        result = provider.run(rig.request, **rig.kwargs(ledger, allocation))
        assert result.status == "invalid_output" and result.parsed is None
        assert len(transport.calls) == ledger.totals()["dispatched_attempts"] == 2
        assert len(transport.replies) == 1  # no third repair or hidden request
        assert Decimal(ledger.totals()["unknown_liability_usd"]) == Decimal("0.1")
        assert Decimal(ledger.totals()["known_spend_usd"]) == Decimal("0.01")
        assert result.source_capture.cost_usd is None


def test_retry_after_beyond_remaining_deadline_does_not_send_again(rig, spy, reply):
    transport = spy(rig, [reply({}, 429, headers={"Retry-After": "60"}), reply(rig.body())])
    provider = rig.provider(transport=transport)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        result = provider.run(rig.request, **rig.kwargs(ledger, allocation))
        assert result.status == "provider_error" and len(transport.calls) == 1
        assert Decimal(ledger.totals()["unknown_liability_usd"]) == Decimal("0.1")
        assert Decimal(ledger.totals()["future_holds_usd"]) == 0


def test_lost_response_retains_actual_reserved_liability_and_no_faux_capture(rig, spy):
    transport = spy(rig, [TransportFailure("unknown_dispatch")])
    provider = rig.provider(transport=transport)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        with pytest.raises(ProviderError, match="unknown_dispatch"):
            provider.run(rig.request, **rig.kwargs(ledger, allocation))
        assert ledger.totals()["dispatched_attempts"] == 1
        assert Decimal(ledger.totals()["unknown_liability_usd"]) == Decimal("0.1")
        assert Decimal(ledger.totals()["future_holds_usd"]) == 0
    with rig.open() as restarted:
        assert Decimal(restarted.totals()["unknown_liability_usd"]) == Decimal("0.1")


def test_streamed_incomplete_billed_output_retains_liability_without_fake_ttft(rig, spy, reply):
    rig.policy = rig.policy.model_copy(update={"output_usd_per_million": "1"})
    data = rig.snapshot.model_dump(mode="json")
    data["policies"] = [rig.policy.model_dump(mode="json")]
    data["data_sha256"] = digest(data["policies"])
    rig.snapshot = PriceSnapshot.model_validate(data)
    rig.bound = rig.bound.model_copy(
        update={
            "snapshot_sha256": rig.snapshot.snapshot_sha256,
            "policy_sha256": rig.policy.policy_sha256,
        }
    )
    rig.evidence = []
    rig.register(rig.request)
    rig.reservation = "0.11"
    body = rig.body()
    body["status"] = "incomplete"
    transport = spy(rig, [reply(body, first_output_kind="chunk", first_output_ms=2.0)])
    provider = rig.provider(transport=transport)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        result = provider.run(rig.request, **rig.kwargs(ledger, allocation))
        assert (
            result.status == "invalid_output"
            and result.first_output_kind == "chunk"
            and result.first_output_ms == 2.0
        )
        assert (
            result.latency_ms > result.first_output_ms
            and result.normalized_usage.output_tokens is None
        )
        assert Decimal(ledger.totals()["unknown_liability_usd"]) == Decimal("0.11")
        assert result.source_capture.cost_usd is None


def test_missing_explicit_accounting_and_payload_mutation_fail_before_transport(rig, spy, reply):
    transport = spy(rig, [reply(rig.body())])
    provider = rig.provider(transport=transport)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        kwargs = rig.kwargs(ledger, allocation)
        for key in ["purpose", "ledger", "budget", "context", "limits", "allocation"]:
            bad = {**kwargs}
            del bad[key]
            with pytest.raises(TypeError):
                provider.run(rig.request, **bad)
        changed = rig.request.model_copy(update={"max_output_tokens": 31})
        with pytest.raises(ProviderError, match="untrusted_request"):
            provider.run(changed, **kwargs)
        assert not transport.calls and ledger.totals()["dispatched_attempts"] == 0


@pytest.mark.parametrize("transfer_delay", [25.0, 31.0])
def test_transfer_delay_cannot_reuse_stale_timeout_headroom(
    rig, spy, reply, monkeypatch, transfer_delay
):
    """what_bug_this_catches: lock/commit delay extending the actual operation deadline."""
    transport = spy(rig, [reply(rig.body())])
    provider = rig.provider(transport=transport)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        original = ledger.begin_attempt

        def delayed(*args, **kwargs):
            attempt = original(*args, **kwargs)
            rig.tick += transfer_delay
            return attempt

        monkeypatch.setattr(ledger, "begin_attempt", delayed)
        if transfer_delay == 25.0:
            assert provider.run(rig.request, **rig.kwargs(ledger, allocation)).status == "ok"
            assert transport.calls[0][1]["timeout_s"] == pytest.approx(5.0)
        else:
            with pytest.raises(ProviderError, match="deadline"):
                provider.run(rig.request, **rig.kwargs(ledger, allocation))
            assert not transport.calls
            assert Decimal(ledger.totals()["unknown_liability_usd"]) == Decimal("0.1")


@pytest.mark.parametrize("status", [401, 403])
def test_auth_response_has_closed_auth_code_and_no_retry(rig, spy, reply, status):
    """what_bug_this_catches: a generic error hiding the batch's mandatory auth-stop signal."""
    transport = spy(
        rig, [reply({"error": {"message": "SYNTHETIC_AUTH_CANARY"}}, status), reply(rig.body())]
    )
    provider = rig.provider(transport=transport)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        result = provider.run(rig.request, **rig.kwargs(ledger, allocation))
        assert result.status == "provider_error" and result.error.code == "auth"
        assert len(transport.calls) == 1 and len(transport.replies) == 1
        assert Decimal(ledger.totals()["unknown_liability_usd"]) == Decimal("0.1")
        assert "SYNTHETIC_AUTH_CANARY" not in str(result.error)
        assert (
            '"error_code":"auth"'
            in ledger.connection.execute("SELECT settlement FROM attempts").fetchone()[0]
        )
