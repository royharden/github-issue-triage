"""Rebuildable scalar labels and pair decision barriers, without matching/components."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

from pydantic import JsonValue

from .models import (
    Generation,
    PairDecision,
    PairRetraction,
    RulingEvent,
    ScalarPayload,
    ScalarSubject,
)
from .store import JournalSnapshot, subject_key


@dataclass(frozen=True)
class DecisionView:
    subject_key: str
    head_event_id: str
    state: Literal["effective", "waived_absent", "needs_review"]
    value: JsonValue
    effective_event_id: str | None
    actor_provenance: Literal["human", "agent_provisional"] | None
    actor_provenance_ref: str | None
    reason_code: str | None


@dataclass(frozen=True)
class ScalarLabel:
    namespace: str
    item_id: str
    field_id: str
    row_key: str | None
    presence: Literal["present", "absent", "unlabelled"]
    value: JsonValue
    label_source: Literal["human", "agent_provisional", "unverified_human", "unlabelled"]
    label_provenance_ref: str | None
    event_id: str | None
    head_event_id: str
    source_revision: str | None
    evidence_revision: str | None
    state: str


class HumanEvidenceValidator(Protocol):
    """Consumer-owned actual evidence. Actor strings/ref syntax alone are insufficient."""

    def validate_human(self, event: RulingEvent) -> None: ...


def project(
    snapshot: JournalSnapshot, current_generations: Mapping[str, Generation | None]
) -> dict[str, DecisionView]:
    groups: dict[str, list[RulingEvent]] = {}
    for event in snapshot.events:
        groups.setdefault(subject_key(event.namespace, event.subject), []).append(event)
    views = {}
    for key, history in groups.items():
        head = history[-1]
        generation = current_generations.get(key)
        reason = (
            "journal_not_clean"
            if not snapshot.can_append
            else "source_missing_or_tombstoned"
            if generation is None
            else None
        )
        active: RulingEvent | None = None
        state: Literal["effective", "waived_absent", "needs_review"] = "needs_review"
        value: JsonValue = None
        if reason is None:
            for event in history:
                if event.generation_identity != generation:
                    continue
                payload = event.payload
                if isinstance(payload, ScalarPayload):
                    if payload.action == "reopen":
                        active, state, value = None, "needs_review", None
                        reason = "reopened"
                    else:
                        active, value = event, payload.new_value
                        state = "waived_absent" if payload.action == "waive_absent" else "effective"
                        reason = None
                elif isinstance(payload, PairDecision):
                    active, value = event, payload.verdict
                    state = "needs_review" if payload.verdict == "unsure" else "effective"
                    reason = "human_unsure" if payload.verdict == "unsure" else None
                elif isinstance(payload, PairRetraction) and active is not None:
                    if payload.target_event_id == active.event_id:
                        active, state, value = None, "needs_review", None
                        reason = "effective_decision_retracted"
            if active is None and reason is None:
                reason = "generation_changed"
        views[key] = DecisionView(
            key,
            head.event_id,
            state,
            value,
            active.event_id if active else None,
            active.actor_provenance if active else None,
            active.actor_provenance_ref if active else None,
            reason,
        )
    return views


def export_labels(
    snapshot: JournalSnapshot,
    current_generations: Mapping[str, Generation | None],
    *,
    human_evidence: HumanEvidenceValidator | None = None,
) -> tuple[ScalarLabel, ...]:
    """Private scalar annotations, not a published gold manifest or human authentication service."""
    views = project(snapshot, current_generations)
    by_id = {event.event_id: event for event in snapshot.events}
    labels = []
    for key, view in views.items():
        head = by_id[view.head_event_id]
        if not isinstance(head.subject, ScalarSubject):
            continue
        event = by_id.get(view.effective_event_id) if view.effective_event_id else None
        source: Literal["human", "agent_provisional", "unverified_human", "unlabelled"] = (
            "unlabelled"
        )
        if event is not None:
            source = (
                "agent_provisional"
                if event.actor_provenance == "agent_provisional"
                else "unverified_human"
            )
            if event.actor_provenance == "human" and human_evidence is not None:
                try:
                    if human_evidence.validate_human(event) is None:
                        source = "human"
                except Exception:
                    # Keep attribution provisional; never put underlying private errors in labels.
                    pass
        presence: Literal["present", "absent", "unlabelled"] = "unlabelled"
        if view.state != "needs_review":
            presence = "absent" if view.value is None else "present"
        generation = current_generations.get(key)
        labels.append(
            ScalarLabel(
                head.namespace,
                head.subject.item_id,
                head.subject.field_id,
                head.subject.row_key,
                presence,
                view.value,
                source,
                event.actor_provenance_ref if event else None,
                view.effective_event_id,
                view.head_event_id,
                event.expected_source_revision if event and generation else None,
                event.expected_evidence_revision if event and generation else None,
                view.state,
            )
        )
    return tuple(labels)
