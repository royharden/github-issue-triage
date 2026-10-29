"""Durability, replay and intent controls against actual owned temporary journals."""

import hashlib
import os

import pytest
from _s2_rulings_synthetic_intents import CurrentGeneration, pair, scalar

from issue_triage.shared.rulings.identity import canonical_bytes
from issue_triage.shared.rulings.models import RulingEvent, RulingIntent
from issue_triage.shared.rulings.store import (
    AppendUncertain,
    GenerationConflict,
    IntentConflict,
    JournalError,
    JournalReadOnly,
    JournalStore,
    PriorConflict,
    subject_key,
)


def test_real_append_restart_replay_and_exact_canonical_utf8_lf(tmp_path):
    store = JournalStore(tmp_path)
    intent = scalar(item="café  Ω", field="é")
    receipt = store.append(intent, CurrentGeneration(intent.generation_identity))
    assert receipt.sequence == 1 and receipt.outcome == "appended"
    data = store.path.read_bytes()
    assert data.endswith(b"\n") and b"\r" not in data
    assert "café  Ω".encode() in data
    restarted = JournalStore(tmp_path).replay()
    assert restarted.status == "clean" and len(restarted.events) == 1
    assert data == canonical_bytes(restarted.events[0].model_dump(mode="json")) + b"\n"


def test_retry_before_stale_head_and_changed_current_generation_is_historical(tmp_path):
    store = JournalStore(tmp_path)
    first = scalar()
    validator = CurrentGeneration(first.generation_identity)
    store.append(first, validator)
    next_intent = scalar("event-2", prior="event-1", raw="raw-2", old=True, new=False)
    validator.generation = next_intent.generation_identity
    store.append(next_intent, validator)
    before = store.path.read_bytes()
    calls = validator.calls
    retry = store.append(first, validator)
    assert (
        retry.sequence,
        retry.outcome,
        retry.historical,
        retry.current_generation_authority,
    ) == (1, "exact_retry", True, False)
    assert validator.calls == calls and store.path.read_bytes() == before
    assert store.replay().stable_head(first.namespace, first.subject).event_id == "event-2"


@pytest.mark.parametrize(
    "field,value",
    [
        ("reason", "changed"),
        ("actor_label", "other"),
        ("context_refs", ("other",)),
        ("at_utc", "2026-01-02T00:00:00Z"),
        ("expected_prior_event_id", "changed-head"),
    ],
)
def test_event_id_reuse_with_changed_complete_intent_refuses_without_bytes(field, value, tmp_path):
    store = JournalStore(tmp_path)
    original = scalar()
    store.append(original, CurrentGeneration(original.generation_identity))
    before = store.path.read_bytes()
    changed = RulingIntent.model_validate(original.model_dump() | {field: value})
    with pytest.raises(IntentConflict):
        store.append(changed, CurrentGeneration(changed.generation_identity))
    assert store.path.read_bytes() == before


def test_stale_head_source_or_evidence_refuses_before_any_event_bytes(tmp_path):
    store = JournalStore(tmp_path)
    first = scalar()
    current = CurrentGeneration(first.generation_identity)
    store.append(first, current)
    before = store.path.read_bytes()
    with pytest.raises(PriorConflict):
        store.append(scalar("event-2"), current)
    current.generation = scalar(raw="raw-2").generation_identity
    with pytest.raises(GenerationConflict) as error:
        store.append(scalar("event-2", prior="event-1"), current)
    assert str(error.value) == "current_generation_conflict" and "PRIVATE" not in str(error.value)
    current.generation = scalar(evidence="artifact-2").generation_identity
    with pytest.raises(GenerationConflict):
        store.append(scalar("event-2", prior="event-1"), current)
    assert store.path.read_bytes() == before


def test_fsync_failure_has_no_receipt_or_projection_then_unknown_retry_flushes_once(
    tmp_path, monkeypatch
):
    store = JournalStore(tmp_path)
    first = scalar()
    calls = []
    receipt = store._receipt
    monkeypatch.setattr(
        store, "_receipt", lambda *a, **kw: calls.append("receipt") or receipt(*a, **kw)
    )

    def fail(fd):
        raise OSError("synthetic disk fault")

    monkeypatch.setattr(store, "_sync", fail)
    with pytest.raises(AppendUncertain):
        store.append(first, CurrentGeneration(first.generation_identity))
    assert calls == [] and store.path.read_bytes().endswith(b"\n")
    with pytest.raises(AppendUncertain):
        store.replay()
    ordered = []

    def sync(fd):
        os.fsync(fd)
        ordered.append("synced")

    monkeypatch.setattr(store, "_sync", sync)
    monkeypatch.setattr(
        store, "_receipt", lambda *a, **kw: ordered.append("receipt") or receipt(*a, **kw)
    )
    retry = store.append(first, CurrentGeneration(scalar(raw="changed").generation_identity))
    assert ordered == ["synced", "receipt"] and retry.outcome == "exact_retry"
    assert len(store.replay().events) == 1


@pytest.mark.parametrize(
    "tail",
    [b'{"torn":', b"bad JSON\n", b"\n", b"x" * 65537],
    ids=["torn-json", "malformed", "empty-line", "oversized-line"],
)
def test_damaged_tail_prefix_replay_readonly_preserves_all_bytes_and_digest(tmp_path, tail):
    store = JournalStore(tmp_path)
    first = scalar()
    store.append(first, CurrentGeneration(first.generation_identity))
    prefix = store.path.read_bytes()
    store.path.write_bytes(prefix + tail)
    snapshot = store.replay()
    assert snapshot.status == "repair_required" and not snapshot.can_append
    assert snapshot.valid_prefix_bytes == len(prefix) and len(snapshot.events) == 1
    assert snapshot.damaged_tail_sha256 == hashlib.sha256(tail).hexdigest()
    assert snapshot.damaged_tail_bytes == len(tail)
    with pytest.raises(JournalReadOnly):
        store.append(
            scalar("event-2", prior="event-1"), CurrentGeneration(first.generation_identity)
        )
    assert store.path.read_bytes() == prefix + tail


def test_duplicate_sequence_or_impossible_historical_predecessor_is_preserved_not_repaired(
    tmp_path,
):
    store = JournalStore(tmp_path)
    first = scalar()
    store.append(first, CurrentGeneration(first.generation_identity))
    prefix = store.path.read_bytes()
    for event in (
        RulingEvent.model_validate(first.model_dump() | {"sequence": 2}),
        RulingEvent.model_validate(scalar("event-2").model_dump() | {"sequence": 2}),
    ):
        bad = canonical_bytes(event.model_dump(mode="json")) + b"\n"
        store.path.write_bytes(prefix + bad)
        assert JournalStore(tmp_path).replay().status == "repair_required"
        assert store.path.read_bytes() == prefix + bad


def test_partial_write_failure_keeps_torn_bytes_and_blocks_future_appends(tmp_path, monkeypatch):
    store = JournalStore(tmp_path)
    first = scalar()
    store.append(first, CurrentGeneration(first.generation_identity))
    real = os.write
    writes = []

    def partial(fd, value):
        if not writes:
            writes.append(1)
            return real(fd, value[:17])
        raise OSError("synthetic partial write")

    monkeypatch.setattr(os, "write", partial)
    with pytest.raises(AppendUncertain):
        store.append(
            scalar("event-2", prior="event-1"), CurrentGeneration(first.generation_identity)
        )
    broken = store.path.read_bytes()
    monkeypatch.setattr(os, "write", real)
    assert store.replay().status == "repair_required"
    assert store.path.read_bytes() == broken


def test_event_cap_before_append_and_journal_bounds_preserve_existing_bytes(tmp_path):
    store = JournalStore(tmp_path, max_events=1)
    first = scalar()
    huge = RulingIntent.model_validate(first.model_dump() | {"reason": "Ω" * 32768})
    with pytest.raises(ValueError):
        store.append(huge, CurrentGeneration(first.generation_identity))
    assert not store.path.exists()
    store.append(first, CurrentGeneration(first.generation_identity))
    before = store.path.read_bytes()
    with pytest.raises(JournalReadOnly):
        store.append(
            scalar("event-2", prior="event-1"), CurrentGeneration(first.generation_identity)
        )
    limited = JournalStore(tmp_path, max_journal_bytes=len(before) - 1).replay()
    assert limited.status == "limit_exceeded" and store.path.read_bytes() == before


def test_imported_sequence_and_reentrant_validation_never_self_deadlock(tmp_path):
    store = JournalStore(tmp_path, lock_deadline_s=0.1)
    intent = scalar()
    event = RulingEvent.model_validate(intent.model_dump() | {"sequence": 99})
    with pytest.raises(ValueError):
        store.append(event, CurrentGeneration(intent.generation_identity))

    class Reentrant:
        def validate(self, subject, generation):
            store.replay()

    with pytest.raises(JournalError, match="reentrant_journal_access"):
        store.append(intent, Reentrant())
    assert not store.path.exists()


def test_namespace_field_and_row_identity_head_separation_and_pair_target_rules(tmp_path):
    store = JournalStore(tmp_path)
    intents = (
        scalar("n1", namespace="a:b", item="c"),
        scalar("n2", namespace="a", item="b:c"),
        pair("p1"),
    )
    for intent in intents:
        store.append(intent, CurrentGeneration(intent.generation_identity))
    snapshot = store.replay()
    assert len({subject_key(i.namespace, i.subject) for i in intents}) == 3
    assert snapshot.stable_head(intents[0].namespace, intents[0].subject).event_id == "n1"
    for target in ("missing", "n1"):
        with pytest.raises(IntentConflict):
            intent = pair("p2", prior="p1", target=target)
            store.append(intent, CurrentGeneration(intent.generation_identity))
    assert len(store.replay().events) == 3


def test_same_client_id_new_generation_or_typed_payload_conflicts_not_retargeted(tmp_path):
    store = JournalStore(tmp_path)
    original = scalar()
    store.append(original, CurrentGeneration(original.generation_identity))
    before = store.path.read_bytes()
    for changed in (scalar(raw="raw-2"), scalar(new=False), scalar(actor="human")):
        with pytest.raises(IntentConflict):
            store.append(changed, CurrentGeneration(changed.generation_identity))
    assert store.path.read_bytes() == before


def test_historical_pair_retraction_wrong_generation_is_invalid_with_no_bytes(tmp_path):
    store = JournalStore(tmp_path)
    first = pair("p1")
    current = pair("p2", prior="p1", second_hash="c" * 64, verdict="negative")
    for intent in (first, current):
        store.append(intent, CurrentGeneration(intent.generation_identity))
    before = store.path.read_bytes()
    retraction = pair("p3", prior="p2", second_hash="c" * 64, target="p1")
    with pytest.raises(IntentConflict):
        store.append(retraction, CurrentGeneration(current.generation_identity))
    assert store.path.read_bytes() == before
    assert store.replay().stable_head(first.namespace, first.subject).event_id == "p2"


def test_noncanonical_and_duplicate_key_packets_never_enter_valid_prefix(tmp_path):
    store = JournalStore(tmp_path)
    intent = scalar()
    event = RulingEvent.model_validate(intent.model_dump() | {"sequence": 1})
    valid = canonical_bytes(event.model_dump(mode="json"))
    packets = (b" " + valid + b"\n", b'{"sequence":999,' + valid[1:] + b"\n")
    for packet in packets:
        store.path.write_bytes(packet)
        snapshot = store.replay()
        assert snapshot.status == "repair_required" and snapshot.events == ()
        assert store.path.read_bytes() == packet
