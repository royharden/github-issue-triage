"""An explicit rehearsal, without a human-authentication claim or remote permission."""

from typing import Annotated, Literal, Self

from pydantic import Field, JsonValue, field_validator, model_validator

from ..contracts.domain import Digest, utc_epoch_us
from ..ingest.labels import LabelWire
from ..shared.rulings.models import RulingIntent, ScalarGeneration, ScalarSubject
from ..shared.rulings.projection import project
from ..shared.rulings.store import subject_key
from ..suggest.envelope import ProposedField
from ..worker.local import WorkflowError

NAMESPACE = "s6-local-provisional-review/1"


class DecisionRequest(LabelWire):
    event_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")]
    issue_key: Annotated[str, Field(pattern=r"^[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*$")]
    field: Literal["labels", "type", "priority", "comment"]
    expected_revision: Digest
    expected_prior_event_id: str | None
    disposition: Literal["accept", "edit", "reject", "reopen"]
    value: JsonValue = None
    actor_label: Annotated[str, Field(min_length=1, max_length=128)]
    at_utc: str
    reason: Annotated[str, Field(max_length=2000)]

    @field_validator("at_utc")
    @classmethod
    def utc(cls, value):
        utc_epoch_us(value)
        return value

    @model_validator(mode="after")
    def no_unused_value(self) -> Self:
        if self.disposition != "edit" and self.value is not None:
            raise ValueError("only_edit_has_value")
        return self


def field_context(suggestions, field):
    proposed = next(item for item in suggestions.fields if item.field == field)
    subject = ScalarSubject(kind="field", item_id=suggestions.key.stable_id, field_id=proposed.id)
    generation = ScalarGeneration(
        kind="scalar",
        profile="s6-proposal-field/1",
        source_sha256=suggestions.issue_sha256,
        raw_source_revision="proposal:" + suggestions.revision_sha256,
        evidence_revision="field-evidence:" + proposed.evidence_sha256,
    )
    return proposed, subject, generation


def validate_value(bundle, proposed, value):
    try:
        checked = ProposedField(
            field=proposed.field,
            id=proposed.id,
            status="proposal",
            value=value,
            evidence_sha256=proposed.evidence_sha256,
        )
        if proposed.field == "labels":
            allowed = {
                label.name for label in bundle.labels.labels if label.archival_state == "active"
            }
            if not set(checked.value) <= allowed:
                raise ValueError
        return checked.model_dump(mode="json")["value"]
    except Exception:
        raise WorkflowError("invalid_current_field_value") from None


def record_provisional(workflow, request):
    request = DecisionRequest.parse_json(request.canonical_bytes())
    with workflow.jobs.transaction():
        bundle, _, result = workflow.current(request.issue_key)
        suggestions = result.suggestions
        if request.expected_revision != suggestions.revision_sha256:
            raise WorkflowError("stale_proposal_revision")
        proposed, subject, generation = field_context(suggestions, request.field)
        old = proposed.model_dump(mode="json")["value"]
        action, new = {
            "accept": ("confirm", old),
            "edit": ("correct", request.value),
            "reject": ("waive_absent", None),
            "reopen": ("reopen", None),
        }[request.disposition]
        if request.disposition == "accept" and proposed.status != "proposal":
            raise WorkflowError("held_field_cannot_be_accepted")
        if action in {"confirm", "correct"}:
            new = validate_value(bundle, proposed, new)
        intent = RulingIntent.model_validate(
            {
                "event_id": request.event_id,
                "namespace": NAMESPACE,
                "subject": subject,
                "generation_identity": generation,
                "event_kind": "scalar_decision",
                "payload": {
                    "action": action,
                    "old_value": old,
                    "new_value": new,
                    "issue_dispositions": (),
                },
                "expected_source_revision": generation.raw_source_revision,
                "expected_evidence_revision": generation.evidence_revision,
                "expected_prior_event_id": request.expected_prior_event_id,
                "actor_label": request.actor_label,
                "actor_provenance": "agent_provisional",
                "actor_provenance_ref": None,
                "at_utc": request.at_utc,
                "reason": request.reason,
                "context_refs": ("s6-provisional-request/1:" + request.sha256,),
            }
        )

        class Current:
            def validate(self, actual_subject, actual_generation):
                if (
                    actual_subject != subject
                    or actual_generation != generation
                    or not workflow.intake.is_current(bundle.issue)
                ):
                    raise ValueError("stale_current_generation")

        return workflow.journal.append(intent, Current())


def current_views(workflow, suggestions):
    generations = {}
    for field in suggestions.fields:
        _, subject, generation = field_context(suggestions, field.field)
        generations[subject_key(NAMESPACE, subject)] = generation
    snapshot = workflow.journal.replay()
    if not snapshot.can_append:
        raise WorkflowError("journal_requires_explicit_repair")
    return snapshot, project(snapshot, generations)
