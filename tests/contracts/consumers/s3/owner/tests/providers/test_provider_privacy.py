"""what_bug_this_catches: provider paths persisting payloads or contacting live."""

import socket
from decimal import Decimal

import pytest
from pydantic import ValidationError

from issue_triage.shared.callledger.models import canonical_digest as digest
from issue_triage.shared.providers.captures import (
    FixtureIndex,
    SafeCaptureProjection,
    put_safe_projection,
)


def test_controller_network_denial_and_payload_canary_positive_control(
    rig, spy, reply, tmp_path, monkeypatch
):
    def blocked(*_args, **_kwargs):
        raise RuntimeError("Network positive control")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    with pytest.raises(RuntimeError, match="positive control"):
        socket.socket()
    body = rig.body()
    body["usage"]["headers"] = {"Authorization": "SYNTHETIC_PAYLOAD_CANARY"}
    body["usage"]["error"] = "SYNTHETIC_PAYLOAD_CANARY"
    transport = spy(rig, [reply(body)])
    provider = rig.provider(transport=transport)
    with rig.open() as ledger:
        allocation = provider.admit_operation(
            rig.plan(),
            ledger=ledger,
            budget=rig.authority,
            context=rig.context(),
            limits=rig.limits,
        )
        result = provider.run(rig.request, **rig.kwargs(ledger, allocation))
        assert result.status == "ok" and provider.capture_mode == "disabled"
        target = tmp_path / "events.jsonl"
        ledger.export_jsonl(target)
        files = [p for p in tmp_path.iterdir() if p.is_file()]
        assert not any(b"SYNTHETIC_PAYLOAD_CANARY" in path.read_bytes() for path in files)
        assert b'"usage_redacted_fields":true' in target.read_bytes()
        target.write_bytes(target.read_bytes() + b"SYNTHETIC_PAYLOAD_CANARY")
        assert any(
            b"SYNTHETIC_PAYLOAD_CANARY" in path.read_bytes() for path in files
        )  # planted leak detected
        ledger.export_jsonl(target)
        assert not any(b"SYNTHETIC_PAYLOAD_CANARY" in path.read_bytes() for path in files)
        assert Decimal(ledger.totals()["known_spend_usd"]) == Decimal("0.01")


def test_strict_fixture_path_with_network_disabled_and_no_fallback(rig, monkeypatch):
    def blocked(*_args, **_kwargs):
        raise RuntimeError("Network positive control")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    with pytest.raises(RuntimeError):
        socket.socket()
    provider = rig.provider(
        "strict_replay", fixtures=FixtureIndex([rig.capture()]), capture_mode="fixture_replay"
    )
    zero = rig.limits.model_copy(update={"max_outbound_attempts": 0})
    with rig.open(offline=True) as ledger:
        allocation = provider.admit_operation(
            rig.plan(offline=True),
            ledger=ledger,
            budget=rig.authority,
            context=rig.context(),
            limits=zero,
        )
        assert (
            provider.run(rig.request, **rig.kwargs(ledger, allocation, offline=True)).origin
            == "mock"
        )
        assert ledger.totals()["dispatched_attempts"] == 0


def test_optional_safe_projection_hook_rejects_payload_and_stale_generation():
    projection = SafeCaptureProjection(
        namespace="synthetic",
        request_identity_sha256=digest("request"),
        source_generation="g1",
        dependency_ids=["dep1"],
        expected_generation_sha256=digest("generation-1"),
        status="ok",
        capture_sha256=digest("capture"),
        current_external_cost_usd="0",
    )

    class Store:
        def __init__(self):
            self.generation = digest("generation-1")
            self.saved = []

        def put_safe(self, value, *, expected_generation_sha256):
            if self.generation != expected_generation_sha256:
                return False
            self.saved.append(value)
            return True

    store = Store()
    assert put_safe_projection(store, projection) is True
    store.saved.clear()
    store.generation = digest("deleted-generation")
    assert put_safe_projection(store, projection) is False and not store.saved
    with pytest.raises(ValidationError):
        SafeCaptureProjection.model_validate(
            {**projection.model_dump(), "caption": "SYNTHETIC_PAYLOAD_CANARY"}
        )
