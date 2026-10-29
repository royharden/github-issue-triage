"""Exact current active-label allowlists; no label creation or fuzzy case aliases."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal, Self

from pydantic import field_validator, model_validator

from ..contracts.domain import Digest, IssueInput
from ..ingest.labels import LabelError, LabelInventory, LabelWire, RepositoryLabel
from ..judges.contracts import TYPE_NAMES, JudgmentRecord
from ..shared.codeindex.canonical import digest


def _names(value):
    if type(value) is str:
        value = (value,)
    elif type(value) is list:
        value = tuple(value)
    if (
        type(value) is not tuple
        or len(value) > 5
        or any(type(name) is not str or not name for name in value)
    ):
        raise LabelError("invalid_label_mapping")
    return value


@dataclass(frozen=True, slots=True)
class LabelMap:
    type_labels: Mapping = field(repr=False)
    priority_labels: Mapping = field(repr=False)
    common_labels: tuple[str, ...] = ()
    version: str = "s6-label-map/1"

    def __post_init__(self):
        if (
            self.version != "s6-label-map/1"
            or not isinstance(self.type_labels, Mapping)
            or not isinstance(self.priority_labels, Mapping)
        ):
            raise LabelError("invalid_label_mapping")
        if any(type(key) is not str or key not in TYPE_NAMES for key in self.type_labels):
            raise LabelError("invalid_label_mapping_type")
        if any(type(key) is not int or key not in range(4) for key in self.priority_labels):
            raise LabelError("invalid_label_mapping_priority")
        object.__setattr__(
            self,
            "type_labels",
            MappingProxyType({key: _names(value) for key, value in self.type_labels.items()}),
        )
        object.__setattr__(
            self,
            "priority_labels",
            MappingProxyType({key: _names(value) for key, value in self.priority_labels.items()}),
        )
        object.__setattr__(self, "common_labels", _names(self.common_labels))

    @property
    def sha256(self):
        return digest(
            {
                "version": self.version,
                "type_labels": {key: list(value) for key, value in self.type_labels.items()},
                "priority_labels": {
                    str(key): list(value) for key, value in self.priority_labels.items()
                },
                "common_labels": list(self.common_labels),
            }
        )


class LabelProposal(LabelWire):
    status: Literal["proposal", "needs_human"]
    issue_sha256: Digest
    judgment_sha256: Digest
    label_set_sha256: Digest
    label_map_sha256: Digest
    labels: tuple[RepositoryLabel, ...]
    reason_codes: tuple[str, ...]

    @field_validator("labels", "reason_codes", mode="before")
    @classmethod
    def immutable_arrays(cls, value):
        return tuple(value) if type(value) is list else value

    @model_validator(mode="after")
    def no_partial_hold(self) -> Self:
        if self.status == "needs_human" and self.labels:
            raise ValueError("held_label_proposal_has_no_labels")
        ids = [label.id for label in self.labels]
        if (
            len(ids) > 5
            or ids != sorted(set(ids))
            or any(label.archival_state != "active" for label in self.labels)
        ):
            raise ValueError("invalid_label_proposal")
        return self


def propose_labels(issue, judgment, inventory, mapping):
    try:
        issue = IssueInput.model_validate(issue.model_dump(mode="python"))
        judgment = JudgmentRecord.model_validate(judgment.model_dump(mode="python"))
        inventory = LabelInventory.model_validate(inventory.model_dump(mode="python"))
        if type(mapping) is not LabelMap:
            raise ValueError
    except Exception:
        raise LabelError("invalid_label_proposal_context") from None
    if judgment.issue_sha256 != issue.sha256 or inventory.repository_id != issue.key.repository_id:
        raise LabelError("stale_label_proposal_context")
    common = dict(
        issue_sha256=issue.sha256,
        judgment_sha256=judgment.sha256,
        label_set_sha256=inventory.label_set_sha256,
        label_map_sha256=mapping.sha256,
    )

    def hold(reason):
        return LabelProposal(status="needs_human", labels=(), reason_codes=(reason,), **common)

    if judgment.status != "proposal":
        return hold("judgment_needs_human")
    if (
        judgment.type_decision not in mapping.type_labels
        or judgment.priority not in mapping.priority_labels
    ):
        return hold("label_mapping_missing")
    wanted = (
        *mapping.type_labels[judgment.type_decision],
        *mapping.priority_labels[judgment.priority],
        *mapping.common_labels,
    )
    by_name, selected = {label.name: label for label in inventory.labels}, {}
    for name in wanted:
        if name not in by_name:
            return hold("mapped_label_missing")
        label = by_name[name]
        if label.archival_state != "active":
            return hold("mapped_label_not_active")
        selected[label.id] = label
    if len(selected) > 5:
        return hold("label_proposal_limit")
    return LabelProposal(
        status="proposal",
        labels=tuple(selected[key] for key in sorted(selected)),
        reason_codes=("human_disposition_required",),
        **common,
    )
