"""Recorded scalar/pair barriers and provenance, without real human or graph claims."""

from _s2_rulings_synthetic_intents import CurrentGeneration, pair, scalar

from issue_triage.shared.rulings.projection import export_labels, project
from issue_triage.shared.rulings.store import JournalStore, subject_key


def append(store, intent):
    store.append(intent, CurrentGeneration(intent.generation_identity))


def test_scalar_correct_confirm_reopen_never_revives_prior_value(tmp_path):
    store = JournalStore(tmp_path)
    intents = (
        scalar(new=False),
        scalar("event-2", prior="event-1", action="confirm", old=False, new=False),
        scalar("event-3", prior="event-2", action="reopen", old=False, new=None),
    )
    for intent in intents:
        append(store, intent)
    key = subject_key(intents[0].namespace, intents[0].subject)
    view = project(store.replay(), {key: intents[0].generation_identity})[key]
    assert view.state == "needs_review" and view.value is None and view.effective_event_id is None
    assert view.head_event_id == "event-3" and view.reason_code == "reopened"


def test_scalar_false_null_and_actual_human_evidence_gate_are_separate(tmp_path):
    store = JournalStore(tmp_path)
    first = scalar(new=False, actor="human")
    append(store, first)
    key = subject_key(first.namespace, first.subject)
    snapshot = store.replay()
    current = {key: first.generation_identity}
    unverified = export_labels(snapshot, current)[0]
    assert unverified.value is False and unverified.presence == "present"
    assert unverified.label_source == "unverified_human"

    class FixtureEvidence:
        def validate_human(self, event):
            assert event.actor_provenance_ref == "synthetic-not-real-human"

    assert (
        export_labels(snapshot, current, human_evidence=FixtureEvidence())[0].label_source
        == "human"
    )
    # The injected fixture validates a protocol only; it is not real human/gold evidence.
    absent = scalar("event-2", prior="event-1", action="waive_absent", old=False, new=None)
    append(store, absent)
    label = export_labels(store.replay(), current)[0]
    assert (
        label.presence == "absent"
        and label.value is None
        and label.label_source == "agent_provisional"
    )


def test_raw_evidence_change_or_tombstone_preserves_stable_head_but_no_old_correction(tmp_path):
    store = JournalStore(tmp_path)
    first = scalar()
    append(store, first)
    key = subject_key(first.namespace, first.subject)
    for current in (
        scalar(raw="raw-2").generation_identity,
        scalar(evidence="artifact-2").generation_identity,
        None,
    ):
        view = project(store.replay(), {key: current})[key]
        assert (
            view.state == "needs_review"
            and view.effective_event_id is None
            and view.head_event_id == "event-1"
        )
    newer = scalar("event-2", prior="event-1", raw="raw-2", new=False)
    append(store, newer)
    view = project(store.replay(), {key: newer.generation_identity})[key]
    assert view.value is False and view.effective_event_id == "event-2"


def test_effective_pair_retraction_barrier_and_non_effective_history_annotation(tmp_path):
    store = JournalStore(tmp_path)
    positive = pair("p1")
    negative = pair("p2", prior="p1", verdict="negative")
    retract = pair("p3", prior="p2", target="p2")
    for intent in (positive, negative, retract):
        append(store, intent)
    key = subject_key(positive.namespace, positive.subject)
    current = {key: positive.generation_identity}
    view = project(store.replay(), current)[key]
    assert view.state == "needs_review" and view.value is None and view.effective_event_id is None
    newer = pair("p4", prior="p3", verdict="negative")
    history = pair("p5", prior="p4", target="p1")
    for intent in (newer, history):
        append(store, intent)
    view = project(store.replay(), current)[key]
    assert (
        view.value == "negative" and view.effective_event_id == "p4" and view.head_event_id == "p5"
    )
    assert (
        export_labels(store.replay(), current) == ()
    )  # no pair graph/cluster/label implementation


def test_dirty_prefix_or_agent_provenance_never_becomes_real_human_gold(tmp_path):
    store = JournalStore(tmp_path)
    first = scalar()
    append(store, first)
    key = subject_key(first.namespace, first.subject)
    current = {key: first.generation_identity}
    assert export_labels(store.replay(), current)[0].label_source == "agent_provisional"
    store.path.write_bytes(store.path.read_bytes() + b"torn")
    label = export_labels(store.replay(), current)[0]
    assert label.presence == "unlabelled" and label.label_source == "unlabelled"
