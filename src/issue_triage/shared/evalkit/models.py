"""Private gold/outcomes, public method inputs and fixed-manifest schema admission."""

from datetime import datetime
from pathlib import PurePosixPath, PureWindowsPath
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
Count = Annotated[StrictInt, Field(ge=0)]
Split = Literal["dev", "heldout"]
Origin = Literal["live", "recorded_replay", "synthetic", "agent_provisional", "not_run"]
Status = Literal[
    "ok", "abstained", "blocked", "invalid", "provider_error", "stale", "unavailable", "not_run"
]
Dimension = Literal[
    "dataset_alias",
    "split",
    "method",
    "config_ref",
    "field",
    "class",
    "metric",
    "statistic_version",
    "null_reason",
    "evidence_origin",
]
NumericMetric = Literal[
    "value",
    "numerator",
    "denominator",
    "corpus_N",
    "eligible_N",
    "answered_N",
    "comparable_N",
    "error_N",
    "abstention_N",
    "stale_N",
    "low",
    "high",
]


class Wire(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)
    schema_version: Literal[1] = 1

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("integer schema_version required")
        return value


def utc_timestamp(value: str) -> str:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.utcoffset() is None or dt.utcoffset().total_seconds() != 0:
        raise ValueError("explicit UTC freeze required")
    return value


class FieldLabel(Wire):
    presence: Literal["present", "absent", "unlabelled"]
    value: JsonValue

    @model_validator(mode="after")
    def presence_value(self) -> Self:
        if self.presence != "present" and self.value is not None:
            raise ValueError("absent/unlabelled reference must be null")
        if self.presence == "present" and self.value is None:
            raise ValueError("present reference requires an actual typed value")
        return self


class FieldLabels(Wire):
    kind: Literal["field_labels"]
    labels: dict[OpaqueId, FieldLabel]


class DomainLabels(Wire):
    kind: Literal["domain_labels"]
    payload: dict[str, JsonValue]


class SourceRef(Wire):
    handle: OpaqueId
    sha256: Sha256 | None


class GoldRecord(Wire):
    item_id: OpaqueId
    dataset: OpaqueId
    group_id: OpaqueId
    split: Split
    label_version: OpaqueId
    source_ref: SourceRef
    input_sha256: Sha256
    label_source: Literal["human", "human_corrected", "agent_provisional", "synthetic"]
    label_provenance_ref: OpaqueId | None
    domain_kind: OpaqueId
    label_payload: Annotated[FieldLabels | DomainLabels, Field(discriminator="kind")]

    @model_validator(mode="after")
    def real_human_reference(self) -> Self:
        if self.label_source in ("human", "human_corrected") and self.label_provenance_ref is None:
            raise ValueError(
                "human reference needs actual provenance; agent labels are provisional"
            )
        return self


class PublicMethodInput(Wire):
    item_id: OpaqueId
    public_payload: dict[str, JsonValue]
    input_sha256: Sha256
    public_config_refs: tuple[OpaqueId, ...]


MethodInput = PublicMethodInput


class Prediction(Wire):
    item_id: OpaqueId
    method: OpaqueId
    method_version: OpaqueId
    config_sha256: Sha256
    model: OpaqueId | None
    origin: Origin
    status: Status
    domain_payload: dict[str, JsonValue] | None
    machine_output: JsonValue
    human_effective_output: JsonValue
    human_provenance_ref: OpaqueId | None
    issues: tuple[OpaqueId, ...]
    ledger_refs: tuple[OpaqueId, ...]
    source_refs: tuple[SourceRef, ...]

    @model_validator(mode="after")
    def execution_branches(self) -> Self:
        if (self.status == "not_run") != (self.origin == "not_run"):
            raise ValueError("not-run status/origin must agree")
        if self.status == "not_run" and (
            self.machine_output is not None
            or self.domain_payload is not None
            or self.human_effective_output is not None
            or self.human_provenance_ref is not None
            or self.ledger_refs
            or self.model is not None
        ):
            raise ValueError("not-run cannot fabricate outputs, calls or model observation")
        if self.status == "ok" and self.domain_payload is None:
            raise ValueError("ok requires adapter-validated domain output")
        if self.human_effective_output is not None and self.human_provenance_ref is None:
            raise ValueError("effective human prediction needs provenance")
        return self


class PinnedReference(Wire):
    status: Literal["available", "unsupported", "not_available"]
    ref: OpaqueId
    sha256: Sha256 | None

    @model_validator(mode="after")
    def actual_hash(self) -> Self:
        if (self.status == "available") != (self.sha256 is not None):
            raise ValueError("only available actual reference has a hash")
        return self


class SplitEntry(Wire):
    split: Split
    items_file: str
    item_count: Count
    ordered_item_ids: tuple[OpaqueId, ...]
    items_sha256: Sha256
    ordered_ids_sha256: Sha256
    group_ids: tuple[OpaqueId, ...]

    @field_validator("items_file")
    @classmethod
    def relative_path(cls, value: str) -> str:
        p = PurePosixPath(value)
        if not value or "\\" in value or p.is_absolute() or PureWindowsPath(value).drive:
            raise ValueError("portable relative corpus path required")
        if any(part in ("", ".", "..") for part in value.split("/")):
            raise ValueError("relative corpus path escapes/aliases")
        return value

    @model_validator(mode="after")
    def ordered_counts(self) -> Self:
        from .identity import ordered_ids_digest

        if self.item_count != len(self.ordered_item_ids):
            raise ValueError("item count differs from frozen IDs")
        if self.ordered_ids_sha256 != ordered_ids_digest(self.ordered_item_ids):
            raise ValueError("ordered ID digest mismatch")
        if len(set(self.group_ids)) != len(self.group_ids):
            raise ValueError("duplicate group")
        return self


class SourceArtifact(Wire):
    namespace: OpaqueId
    status: Literal["available", "unavailable", "unsupported"]
    sha256: Sha256 | None
    count: Count
    member_ids: tuple[OpaqueId, ...]

    @model_validator(mode="after")
    def actual_members(self) -> Self:
        if self.status == "available" and self.sha256 is None:
            raise ValueError("available source checksum required")
        if self.count != len(self.member_ids) or len(set(self.member_ids)) != self.count:
            raise ValueError("source member counts/IDs differ")
        return self


class PublicProjectionPolicy(Wire):
    mode: Literal["aggregate_only", "synthetic_named_examples"]
    allowed_dimensions: tuple[Dimension, ...]
    allowed_value_sets: dict[Dimension, tuple[str, ...]]
    allowed_numeric_metrics: tuple[NumericMetric, ...]
    synthetic_example_refs: tuple[OpaqueId, ...]

    @model_validator(mode="after")
    def explicit_closed_allowlist(self) -> Self:
        if set(self.allowed_dimensions) != self.allowed_value_sets.keys():
            raise ValueError("every public string dimension requires its exact allowed values")
        for names in (self.allowed_dimensions, self.allowed_numeric_metrics):
            if len(set(names)) != len(names):
                raise ValueError("duplicate projection field")
        if self.mode == "aggregate_only" and self.synthetic_example_refs:
            raise ValueError("aggregate mode cannot emit named examples")
        return self


class Manifest(Wire):
    manifest_id: OpaqueId
    parent_manifest_sha256: Sha256 | None
    split_seed: StrictInt | None
    partition_provenance: Literal["seeded", "published_canonical"]
    frozen_at: str
    scorer_version: OpaqueId
    comparator_config: PinnedReference
    domain_adapter_ref: PinnedReference
    experiment_refs: dict[OpaqueId, PinnedReference]
    splits: tuple[SplitEntry, ...]
    group_split_map: dict[OpaqueId, Split]
    group_members: dict[OpaqueId, tuple[OpaqueId, ...]]
    source_artifacts: tuple[SourceArtifact, ...]
    publication_policy: PublicProjectionPolicy
    run_history_ref: OpaqueId

    _utc = field_validator("frozen_at")(utc_timestamp)

    @model_validator(mode="after")
    def frozen_groups(self) -> Self:
        if self.split_seed is None and self.partition_provenance != "published_canonical":
            raise ValueError("null seed needs explicit published partition provenance")
        if self.group_members.keys() != self.group_split_map.keys():
            raise ValueError("group membership/split map mismatch")
        member_group: dict[str, str] = {}
        for group, members in self.group_members.items():
            if not members or len(set(members)) != len(members):
                raise ValueError("empty/duplicate group membership")
            for member in members:
                if member in member_group:
                    raise ValueError("member/near-duplicate group crosses partitions")
                member_group[member] = group
        if len({entry.split for entry in self.splits}) != len(self.splits):
            raise ValueError("duplicate split entry")
        all_items: set[str] = set()
        represented_groups: set[str] = set()
        for entry in self.splits:
            if all_items.intersection(entry.ordered_item_ids):
                raise ValueError("case crosses splits")
            all_items.update(entry.ordered_item_ids)
            actual_groups = {member_group.get(item) for item in entry.ordered_item_ids}
            if None in actual_groups or actual_groups != set(entry.group_ids):
                raise ValueError("case/group declaration mismatch")
            if any(self.group_split_map[group] != entry.split for group in entry.group_ids):
                raise ValueError("group crosses dev/heldout")
            represented_groups.update(entry.group_ids)
        if represented_groups != self.group_members.keys():
            raise ValueError("unrepresented group in canonical manifest")
        return self


class S1MinimalManifest(BaseModel):
    """A partial manifest view; it must never masquerade as enriched canonical gold."""

    model_config = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False, serialize_by_alias=True
    )
    schema_id: Literal[1] = Field(alias="schema")
    split: Split
    seed: StrictInt | None
    frozen_at: str
    items_file: str
    item_count: Count

    @field_validator("schema_id", mode="before")
    @classmethod
    def exact_schema(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("minimal schema is the integer1")
        return value

    _utc = field_validator("frozen_at")(utc_timestamp)
    _relative = field_validator("items_file")(SplitEntry.relative_path.__func__)


class ManifestEnrichmentResult(Wire):
    status: Literal["ready", "needs_owner_metadata"]
    canonical_manifest: Manifest | None
    missing_metadata: tuple[OpaqueId, ...]

    @model_validator(mode="after")
    def no_partial_canonical_output(self) -> Self:
        if self.status == "ready" and (self.canonical_manifest is None or self.missing_metadata):
            raise ValueError("ready needs full canonical manifest and no missing metadata")
        if self.status == "needs_owner_metadata" and (
            self.canonical_manifest is not None or not self.missing_metadata
        ):
            raise ValueError("partial view cannot emit canonical output")
        return self


class Outcome(Wire):
    model_config = ConfigDict(
        serialize_by_alias=True, validate_by_name=False, validate_by_alias=True
    )
    item_id: OpaqueId
    group_id: OpaqueId
    dataset: OpaqueId
    split: Split
    method: OpaqueId
    field: OpaqueId | None
    class_name: OpaqueId | None = Field(alias="class")
    eligibility: Literal["eligible", "ineligible", "unlabelled"]
    status: Status
    correct: bool | None
    predicted: JsonValue
    expected: JsonValue
    human_touched_prediction: bool
    evidence_origin: Origin
    issues: tuple[OpaqueId, ...]
    ledger_refs: tuple[OpaqueId, ...]

    @model_validator(mode="after")
    def measured_branch(self) -> Self:
        if self.eligibility != "eligible" and self.correct is not None:
            raise ValueError("ineligible/unlabelled has no correctness")
        if (self.status == "not_run") != (self.evidence_origin == "not_run"):
            raise ValueError("not-run identity mismatch")
        if self.status == "not_run" and (
            self.correct is not None or self.predicted is not None or self.ledger_refs
        ):
            raise ValueError("not-run outcome is not measured")
        if self.status != "ok" and self.correct is True:
            raise ValueError("blocked/error/stale outcome cannot be a success")
        return self


class ConfusionCounts(Wire):
    true_positive: Count
    false_positive: Count
    false_negative: Count
    true_negative: Count


class Interval(Wire):
    method: Literal["wilson", "paired_group_percentile"]
    low: float
    high: float
    level: Annotated[float, Field(gt=0, lt=1)]
    valid_draws: Count | None
    draw_ids_sha256: Sha256 | None

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.low > self.high:
            raise ValueError("inverted interval")
        if self.method == "wilson" and (self.valid_draws is not None or self.draw_ids_sha256):
            raise ValueError("Wilson is not a group bootstrap")
        if self.method == "paired_group_percentile" and (
            self.valid_draws is None or self.draw_ids_sha256 is None
        ):
            raise ValueError("bootstrap needs actual draw metadata")
        return self


class MetricRow(Wire):
    model_config = ConfigDict(
        serialize_by_alias=True, validate_by_name=False, validate_by_alias=True
    )
    dataset_alias: OpaqueId
    split: Split
    method: OpaqueId
    config_ref: OpaqueId
    field: OpaqueId | None
    class_name: OpaqueId | None = Field(alias="class")
    metric: OpaqueId
    statistic_version: OpaqueId
    measurement_status: Literal["measured", "unsupported", "not_measured"]
    numerator: Annotated[float, Field(ge=0)] | None
    denominator: Annotated[float, Field(ge=0)] | None
    confusion_counts: ConfusionCounts | None
    supports: dict[OpaqueId, Count]
    corpus_N: Count
    eligible_N: Count
    answered_N: Count
    comparable_N: Count
    error_N: Count
    abstention_N: Count
    stale_N: Count
    value: float | None
    null_reason: OpaqueId | None
    interval: Interval | None
    evidence_origin: Origin

    @model_validator(mode="after")
    def counts_and_na(self) -> Self:
        if not 0 <= self.eligible_N <= self.corpus_N:
            raise ValueError("eligible count exceeds corpus")
        if any(
            n > self.eligible_N
            for n in (
                self.answered_N,
                self.comparable_N,
                self.error_N,
                self.abstention_N,
                self.stale_N,
            )
        ):
            raise ValueError("population count exceeds fixed eligible population")
        if (self.value is None) != (self.null_reason is not None):
            raise ValueError("undefined value needs explicit null reason")
        if self.denominator == 0 and self.value is not None:
            raise ValueError("zero denominator is not a perfect result")
        if self.measurement_status != "measured" and (self.value is not None or self.interval):
            raise ValueError("not-measured/unsupported cannot supply a measurement")
        if self.evidence_origin == "not_run" and (
            self.measurement_status != "not_measured"
            or self.answered_N
            or self.numerator is not None
            or self.denominator is not None
            or self.confusion_counts is not None
        ):
            raise ValueError("missing method cannot fabricate scores/calls")
        return self


class ResamplingSpec(Wire):
    version: OpaqueId
    unit: Literal["group_id"]
    seed: StrictInt
    draws: Annotated[StrictInt, Field(ge=1)]
    level: Annotated[float, Field(gt=0, lt=1)]
    method: Literal["percentile"]
    group_order: tuple[OpaqueId, ...]
    stratum_map: dict[OpaqueId, OpaqueId] | None
    min_support: Annotated[StrictInt, Field(gt=0)]
    min_valid_draws: Annotated[StrictInt, Field(gt=0)]
    statistic_version: OpaqueId
    rng_version: OpaqueId

    @model_validator(mode="after")
    def pinned_group_policy(self) -> Self:
        if self.draws != 2000 or self.level != 0.95:
            raise ValueError("v1 paired group profile uses2000 draws and95% level")
        if len(set(self.group_order)) != len(self.group_order):
            raise ValueError("duplicate group")
        if self.stratum_map is not None and self.stratum_map.keys() != set(self.group_order):
            raise ValueError("one declared stratum per whole group")
        if self.min_valid_draws > self.draws:
            raise ValueError("required valid draws exceed total")
        return self


class MetricSpec(Wire):
    metric: OpaqueId
    statistic_version: OpaqueId
    population: Literal["as_frozen", "comparable", "answered_only"]
    denominator_policy: OpaqueId
    zero_denominator_reason: OpaqueId
    averaging: Literal["none", "micro", "macro", "weighted"]


class EvaluationRun(Wire):
    run_id: OpaqueId
    manifest_sha256: Sha256
    candidate_commit: OpaqueId
    split: Split
    policy_sha256: Sha256
    method_config_refs: dict[OpaqueId, Sha256]
    requested_item_ids: tuple[OpaqueId, ...]
    status: Literal["measured", "not_measured", "incomplete"]
    private_outcomes_ref: OpaqueId | None
    metric_rows: tuple[MetricRow, ...]
    rerun_reason: str | None
    parent_run_ref: OpaqueId | None

    @model_validator(mode="after")
    def named_methods(self) -> Self:
        if len(set(self.requested_item_ids)) != len(self.requested_item_ids):
            raise ValueError("duplicate requested case")
        if set(self.method_config_refs) != {row.method for row in self.metric_rows}:
            raise ValueError("every expected method must have explicit rows")
        return self


WIRE_MODELS = (
    FieldLabel,
    GoldRecord,
    PublicMethodInput,
    Prediction,
    Manifest,
    Outcome,
    MetricRow,
    ResamplingSpec,
    MetricSpec,
    PublicProjectionPolicy,
    EvaluationRun,
    S1MinimalManifest,
    ManifestEnrichmentResult,
)
