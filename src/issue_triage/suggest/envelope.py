"""Stable field identity and current proposal revision; no decision, approval or effect."""

from typing import Literal, Self

from pydantic import field_validator, model_validator

from ..contracts.domain import Digest, IssueKey
from ..ingest.labels import LabelInventory, LabelWire
from ..judges.contracts import DEFAULT_JUDGMENT_POLICY, TYPE_NAMES, JudgeHold
from ..shared.codeindex.canonical import digest
from .comments import CommentDraft, canonical_comment, validate_current_judgment
from .labels import LabelProposal

FIELDS = ("labels", "type", "priority", "comment")


def field_id(key, field):
    if type(key) is not IssueKey or field not in FIELDS:
        raise JudgeHold("invalid_proposal_field")
    return digest({"field_identity_schema_version": 1, "issue_key": key.stable_id, "field": field})


class ProposedField(LabelWire):
    field: Literal["labels", "type", "priority", "comment"]
    id: Digest
    status: Literal["proposal", "needs_human"]
    value: str | int | tuple[str, ...] | None = None
    evidence_sha256: Digest

    @model_validator(mode="before")
    @classmethod
    def immutable_label_value(cls, value):
        if (
            type(value) is dict
            and value.get("field") == "labels"
            and type(value.get("value")) is list
        ):
            return value | {"value": tuple(value["value"])}
        return value

    @model_validator(mode="after")
    def typed_value(self) -> Self:
        if self.status == "needs_human":
            if self.value is not None:
                raise ValueError("held_field_has_no_value")
            return self
        value = self.value
        if self.field == "labels":
            if (
                type(value) is not tuple
                or len(value) > 5
                or len(value) != len(set(value))
                or any(type(name) is not str for name in value)
            ):
                raise ValueError("invalid_label_field")
        elif self.field == "type":
            if type(value) is not str or value not in TYPE_NAMES:
                raise ValueError("invalid_type_field")
        elif self.field == "priority":
            if type(value) is not int or value not in range(4):
                raise ValueError("invalid_priority_field")
        elif type(value) is not str or canonical_comment(value) != value:
            raise ValueError("invalid_comment_field")
        return self


class SuggestionSet(LabelWire):
    key: IssueKey
    issue_sha256: Digest
    report_sha256: Digest
    raw_snapshot_sha256: Digest
    judgment_sha256: Digest
    label_set_sha256: Digest
    label_map_sha256: Digest
    judgment_policy_sha256: Digest
    screen_policy_sha256: Digest
    fields: tuple[ProposedField, ...]
    revision_sha256: Digest

    @field_validator("fields", mode="before")
    @classmethod
    def immutable_fields(cls, value):
        return tuple(value) if type(value) is list else value

    def revision_preimage(self):
        return self.model_dump(mode="json", exclude={"revision_sha256"})

    @model_validator(mode="after")
    def exact_fields_and_revision(self) -> Self:
        if tuple(item.field for item in self.fields) != FIELDS or any(
            item.id != field_id(self.key, item.field) for item in self.fields
        ):
            raise ValueError("invalid_suggestion_fields")
        if digest(self.revision_preimage()) != self.revision_sha256:
            raise ValueError("invalid_suggestion_revision")
        return self


def build_suggestions(
    context, judgment, inventory, labels, comment, *, policy=DEFAULT_JUDGMENT_POLICY
):
    _, judgment = validate_current_judgment(context, judgment, policy)
    try:
        inventory = LabelInventory.model_validate(inventory.model_dump(mode="python"))
        labels = LabelProposal.model_validate(labels.model_dump(mode="python"))
        comment = CommentDraft.model_validate(comment.model_dump(mode="python"))
    except Exception:
        raise JudgeHold("invalid_proposal_components") from None
    if (
        inventory.repository_id != context.issue.key.repository_id
        or labels.issue_sha256 != context.issue.sha256
        or comment.issue_sha256 != context.issue.sha256
        or labels.judgment_sha256 != judgment.sha256
        or comment.judgment_sha256 != judgment.sha256
        or labels.label_set_sha256 != inventory.label_set_sha256
        or comment.report_sha256 != context.report.sha256
    ):
        raise JudgeHold("stale_proposal_components")
    by_name = {label.name: label for label in inventory.labels}
    if any(
        by_name.get(label.name) != label or label.archival_state != "active"
        for label in labels.labels
    ):
        raise JudgeHold("label_component_not_allowlisted")
    ready = judgment.status == "proposal"
    values = [
        ("labels", labels.status, [label.name for label in labels.labels], labels.sha256),
        ("type", judgment.status, judgment.type_decision, judgment.sha256),
        ("priority", judgment.status, judgment.priority, judgment.sha256),
        ("comment", comment.status, comment.text, comment.sha256),
    ]
    fields = tuple(
        ProposedField(
            field=name,
            id=field_id(context.issue.key, name),
            status=status if ready else "needs_human",
            value=value if ready and status == "proposal" else None,
            evidence_sha256=evidence,
        )
        for name, status, value, evidence in values
    )
    snapshot = context.index.snapshot
    value = {
        "schema_version": 1,
        "key": context.issue.key.model_dump(mode="json"),
        "issue_sha256": context.issue.sha256,
        "report_sha256": context.report.sha256,
        "raw_snapshot_sha256": digest(
            {
                key: getattr(snapshot, key)
                for key in ("repository_id", "source_kind", "snapshot_id", "inventory_sha256")
            }
        ),
        "judgment_sha256": judgment.sha256,
        "label_set_sha256": inventory.label_set_sha256,
        "label_map_sha256": labels.label_map_sha256,
        "judgment_policy_sha256": policy.sha256,
        "screen_policy_sha256": context.screen_policy.sha256,
        "fields": [item.model_dump(mode="json") for item in fields],
    }
    return SuggestionSet.model_validate(value | {"revision_sha256": digest(value)})
