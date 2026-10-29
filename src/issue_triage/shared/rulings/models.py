"""Closed scalar/pair envelopes. Shapes do not prove source freshness or human authority."""

from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictInt,
    field_validator,
    model_validator,
)

OpaqueId = Annotated[str, Field(min_length=1, max_length=512)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
PairKey = Annotated[str, Field(pattern=r"^pk1:[0-9a-f]{64}$")]
PairGenerationId = Annotated[str, Field(pattern=r"^pg1:[0-9a-f]{64}$")]


class Wire(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)
    schema_version: Literal[1] = 1

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("integer schema_version required")
        return value


class RecordIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    dataset_id: OpaqueId
    record_id: OpaqueId


class ScalarSubject(Wire):
    kind: Literal["field"]
    item_id: OpaqueId
    field_id: OpaqueId
    row_key: OpaqueId | None = None


class PairSubject(Wire):
    kind: Literal["pair"]
    pair_key: PairKey
    refs: tuple[RecordIdentity, RecordIdentity]

    @model_validator(mode="after")
    def identity_order(self) -> Self:
        from .identity import canonical_pair, pair_key

        refs = tuple(ref.model_dump() for ref in self.refs)
        if refs != canonical_pair(refs) or self.pair_key != pair_key(refs):
            raise ValueError("pair key or canonical orientation mismatch")
        return self


class ScalarGeneration(Wire):
    kind: Literal["scalar"]
    profile: OpaqueId
    source_sha256: Sha256
    raw_source_revision: OpaqueId
    evidence_revision: OpaqueId | None


class PairGeneration(Wire):
    kind: Literal["pair"]
    profile: OpaqueId
    pair_generation: PairGenerationId
    raw_fingerprints: tuple[Sha256, Sha256]


class IssueDisposition(Wire):
    issue_id: OpaqueId
    disposition: Literal["resolved", "waived", "reopened"]
    reason: str


class ScalarPayload(Wire):
    action: Literal["correct", "confirm", "waive_absent", "reopen"]
    old_value: JsonValue
    new_value: JsonValue
    issue_dispositions: tuple[IssueDisposition, ...]

    @model_validator(mode="after")
    def branch(self) -> Self:
        from .identity import canonical_bytes

        if self.action in ("waive_absent", "reopen") and self.new_value is not None:
            raise ValueError("absence/reopen cannot introduce an approved value")
        if self.action == "confirm" and canonical_bytes(self.old_value) != canonical_bytes(
            self.new_value
        ):
            raise ValueError("confirm must preserve exact typed value")
        if len({i.issue_id for i in self.issue_dispositions}) != len(self.issue_dispositions):
            raise ValueError("duplicate issue disposition")
        return self


class PairDecision(Wire):
    action: Literal["decide"]
    verdict: Literal["positive", "negative", "unsure"]


class PairRetraction(Wire):
    action: Literal["retract"]
    target_event_id: OpaqueId


Subject = Annotated[ScalarSubject | PairSubject, Field(discriminator="kind")]
Generation = Annotated[ScalarGeneration | PairGeneration, Field(discriminator="kind")]
Payload = ScalarPayload | Annotated[PairDecision | PairRetraction, Field(discriminator="action")]


class RulingIntent(Wire):
    event_id: OpaqueId
    namespace: OpaqueId
    subject: Subject
    generation_identity: Generation
    event_kind: Literal["scalar_decision", "pair_decision"]
    payload: Payload
    expected_source_revision: OpaqueId
    expected_evidence_revision: OpaqueId | None
    expected_prior_event_id: OpaqueId | None
    actor_label: OpaqueId
    actor_provenance: Literal["human", "agent_provisional"]
    actor_provenance_ref: OpaqueId | None
    at_utc: str
    reason: str
    context_refs: tuple[OpaqueId, ...]

    @field_validator("at_utc")
    @classmethod
    def utc(cls, value: str) -> str:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.utcoffset() is None or dt.utcoffset().total_seconds() != 0:
            raise ValueError("explicit UTC timestamp required")
        return value

    @model_validator(mode="after")
    def registered_branch(self) -> Self:
        from .identity import pair_generation

        if self.actor_provenance == "human" and self.actor_provenance_ref is None:
            raise ValueError("human attribution requires actual provenance reference")
        if isinstance(self.subject, ScalarSubject):
            if (
                not isinstance(self.generation_identity, ScalarGeneration)
                or not isinstance(self.payload, ScalarPayload)
                or self.event_kind != "scalar_decision"
            ):
                raise ValueError("scalar branch mismatch")
            generation = self.generation_identity
            if (self.expected_source_revision, self.expected_evidence_revision) != (
                generation.raw_source_revision,
                generation.evidence_revision,
            ):
                raise ValueError("scalar generation/CAS wire mismatch")
        else:
            if (
                not isinstance(self.generation_identity, PairGeneration)
                or not isinstance(self.payload, (PairDecision, PairRetraction))
                or self.event_kind != "pair_decision"
            ):
                raise ValueError("pair branch mismatch")
            generation = self.generation_identity
            if (
                generation.pair_generation
                != pair_generation(self.subject.pair_key, generation.raw_fingerprints)
                or self.expected_source_revision != generation.pair_generation
            ):
                raise ValueError("pair raw generation mismatch")
            if self.expected_evidence_revision is not None:
                raise ValueError("pair human raw authority does not use processing revision")
            if (
                isinstance(self.payload, PairRetraction)
                and self.payload.target_event_id == self.event_id
            ):
                raise ValueError("event cannot retract itself")
        return self


class RulingEvent(RulingIntent):
    sequence: Annotated[StrictInt, Field(gt=0)]


class AppendReceipt(Wire):
    event_id: OpaqueId
    sequence: Annotated[StrictInt, Field(gt=0)]
    intent_sha256: Sha256
    outcome: Literal["appended", "exact_retry"]
    historical: bool
    current_generation_authority: Literal[False] = False

    @model_validator(mode="after")
    def retry_is_historical(self) -> Self:
        if self.outcome == "exact_retry" and not self.historical:
            raise ValueError("exact retry is a historical receipt, not present authority")
        return self


WIRE_MODELS = (
    RecordIdentity,
    ScalarSubject,
    PairSubject,
    ScalarGeneration,
    PairGeneration,
    RulingIntent,
    RulingEvent,
    AppendReceipt,
)
