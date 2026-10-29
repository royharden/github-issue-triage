"""Synthetic attribution only; no actual human label, source file or receipt data."""

from issue_triage.shared.rulings.identity import canonical_pair, pair_generation, pair_key
from issue_triage.shared.rulings.models import RulingIntent


def scalar(
    event_id="event-1",
    *,
    prior=None,
    raw="raw-1",
    evidence="artifact-1",
    item="opaque-item",
    field="label",
    action="correct",
    old=False,
    new=True,
    namespace="fixture",
    actor="agent_provisional",
):
    return RulingIntent.model_validate(
        {
            "event_id": event_id,
            "namespace": namespace,
            "subject": {"kind": "field", "item_id": item, "field_id": field},
            "generation_identity": {
                "kind": "scalar",
                "profile": "fixture/1",
                "source_sha256": "a" * 64,
                "raw_source_revision": raw,
                "evidence_revision": evidence,
            },
            "event_kind": "scalar_decision",
            "payload": {
                "action": action,
                "old_value": old,
                "new_value": new,
                "issue_dispositions": (),
            },
            "expected_source_revision": raw,
            "expected_evidence_revision": evidence,
            "expected_prior_event_id": prior,
            "actor_label": "synthetic-actor",
            "actor_provenance": actor,
            "actor_provenance_ref": "synthetic-not-real-human" if actor == "human" else None,
            "at_utc": "2026-01-01T00:00:00Z",
            "reason": "authored synthetic contract",
            "context_refs": (),
        }
    )


def pair(
    event_id="event-1",
    *,
    prior=None,
    verdict="positive",
    target=None,
    second_hash="b" * 64,
    namespace="fixture",
):
    refs = canonical_pair(
        ({"dataset_id": "left", "record_id": "123"}, {"dataset_id": "right", "record_id": "123"})
    )
    key = pair_key(refs)
    generation = pair_generation(key, ("a" * 64, second_hash))
    values = scalar(event_id, prior=prior, namespace=namespace).model_dump() | {
        "subject": {"kind": "pair", "pair_key": key, "refs": refs},
        "generation_identity": {
            "kind": "pair",
            "profile": "product-raw-fields-v1",
            "pair_generation": generation,
            "raw_fingerprints": ("a" * 64, second_hash),
        },
        "event_kind": "pair_decision",
        "expected_source_revision": generation,
        "expected_evidence_revision": None,
        "payload": {"action": "retract", "target_event_id": target}
        if target
        else {"action": "decide", "verdict": verdict},
    }
    return RulingIntent.model_validate(values)


class CurrentGeneration:
    def __init__(self, generation):
        self.generation = generation
        self.calls = 0

    def validate(self, subject, generation):
        self.calls += 1
        if generation != self.generation:
            raise ValueError("PRIVATE synthetic source mismatch must not leak")
