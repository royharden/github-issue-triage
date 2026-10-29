"""Closed structural wire models. Validation is not source or semantic verification."""

import hashlib
import json
import re
from functools import reduce
from operator import or_
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Discriminator,
    Field,
    Tag,
    TypeAdapter,
    model_validator,
)


def _version(value: object) -> object:
    if type(value) is not int:
        raise ValueError("schema_version must be integer 1")
    return value


def _logical_id(value: object) -> object:
    if isinstance(value, str) and (
        value.startswith(("/", "\\"))
        or "\\" in value
        or "://" in value
        or re.match(r"^[A-Za-z]:", value)
        or any(part in (".", "..") for part in value.split("/"))
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError("logical identifier cannot be a path or fetch URL")
    return value


def _array(value: object) -> object:
    # JSON arrays and Python lists get one explicit lossless immutable representation.
    return tuple(value) if type(value) is list else value


Version = Annotated[Literal[1], BeforeValidator(_version)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)]
LogicalID = Annotated[str, Field(min_length=1, max_length=256), BeforeValidator(_logical_id)]
Revision = Annotated[str, Field(min_length=1, max_length=512), BeforeValidator(_logical_id)]
Text = Annotated[str, Field(min_length=1, max_length=32768)]
PositiveInt = Annotated[int, Field(ge=1, le=2**53 - 1)]
NonnegativeInt = Annotated[int, Field(ge=0, le=2**53 - 1)]
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Coordinate = Annotated[float, Field(ge=0, allow_inf_nan=False)]
IDs = Annotated[tuple[LogicalID, ...], BeforeValidator(_array), Field(max_length=10000)]
Scope = Literal["text", "spatial", "text_and_spatial", "asserted_spatial"]
Geometry = Literal["measured_ocr", "native", "model_claimed", "none"]


class WireModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        revalidate_instances="always",
    )


class ArtifactRef(WireModel):
    """Logical reference only; no file opener or URL authority."""

    artifact_id: LogicalID
    artifact_sha256: Digest
    profile_id: LogicalID


class QuoteLocator(WireModel):
    quote: Text | None = None
    excerpt_sha256: Digest | None = None

    @model_validator(mode="after")
    def quote_binding(self) -> Self:
        if (self.quote is None) != (self.excerpt_sha256 is None):
            raise ValueError("quote and excerpt digest must both exist or both be null")
        if self.quote is not None:
            if hashlib.sha256(self.quote.encode("utf-8")).hexdigest() != self.excerpt_sha256:
                raise ValueError("literal UTF-8 quote digest mismatch")
        return self


class LineLocator(QuoteLocator):
    line_start: PositiveInt
    line_end: PositiveInt

    @model_validator(mode="after")
    def line_bounds(self) -> Self:
        if self.line_end < self.line_start:
            raise ValueError("line_end precedes line_start")
        return self


class LogLocator(LineLocator):
    view_kind: Literal["redacted_result"]
    source_byte_start: NonnegativeInt | None = None
    source_byte_end: NonnegativeInt | None = None
    byte_coordinate_space: Literal["source_physical"] = "source_physical"
    artifact_byte_start: NonnegativeInt | None = None
    artifact_byte_end: NonnegativeInt | None = None
    artifact_coordinate_space: Literal["redacted_artifact"] = "redacted_artifact"

    @model_validator(mode="after")
    def offset_pairs(self) -> Self:
        for start, end in (
            (self.source_byte_start, self.source_byte_end),
            (self.artifact_byte_start, self.artifact_byte_end),
        ):
            if (start is None) != (end is None) or (
                start is not None and end is not None and end < start
            ):
                raise ValueError("byte interval must be a complete ordered pair")
        return self


class SectionLocator(QuoteLocator):
    section_id: LogicalID


class FragmentLocator(QuoteLocator):
    fragment_id: LogicalID


class AdvisoryLocator(QuoteLocator):
    advisory_id: LogicalID


class BoxPx(WireModel):
    units: Literal["px"] = "px"
    x0: Coordinate
    y0: Coordinate
    x1: Coordinate
    y1: Coordinate

    @model_validator(mode="after")
    def nonempty_box(self) -> Self:
        if self.x0 >= self.x1 or self.y0 >= self.y1:
            raise ValueError("box must have positive area")
        return self


class RegionLocator(WireModel):
    document_id: LogicalID
    page_id: LogicalID
    page_index: NonnegativeInt
    page_sha256: Digest
    page_digest_algorithm: Literal["rgba8-source-grid-v1"]
    source_grid_profile: LogicalID
    width_px: PositiveInt
    height_px: PositiveInt
    units: Literal["px"] = "px"
    origin: Literal["top-left"] = "top-left"
    bbox_px: BoxPx | None = None
    word_ids: IDs | None = None
    line_ids: IDs | None = None
    excerpt_sha256: Digest | None = None
    transform_ref: ArtifactRef | None = None

    @model_validator(mode="after")
    def region_shape(self) -> Self:
        for ids in (self.word_ids, self.line_ids):
            if ids is not None and (not ids or len(set(ids)) != len(ids)):
                raise ValueError("word/line IDs must be nonempty and unique when present")
        if self.bbox_px is None and self.word_ids is None and self.line_ids is None:
            raise ValueError("region needs an actual box or declared word/line IDs")
        if self.bbox_px is not None and (
            self.bbox_px.x1 > self.width_px or self.bbox_px.y1 > self.height_px
        ):
            raise ValueError("box outside source dimensions")
        return self


class ProductLocator(QuoteLocator):
    dataset_id: LogicalID
    record_id: LogicalID
    field_id: Literal["id", "name", "brand", "size", "unit", "price", "category", "description"]
    quote: Text
    excerpt_sha256: Digest


class SnapshotLocator(WireModel):
    repository_id: LogicalID
    source_kind: Literal["git_commit", "fixture_inventory"]
    snapshot_id: Annotated[str, Field(min_length=40, max_length=64)]
    inventory_sha256: Digest

    @model_validator(mode="after")
    def snapshot_shape(self) -> Self:
        if self.source_kind == "git_commit":
            if re.fullmatch(r"[0-9a-f]{40}", self.snapshot_id) is None:
                raise ValueError("initial Git capture profile supports SHA1 only")
        elif self.snapshot_id != self.inventory_sha256:
            raise ValueError("fixture snapshot ID must equal raw inventory digest")
        return self


class RepositoryLocator(SnapshotLocator):
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    line_start: PositiveInt
    line_end: PositiveInt
    definition_kind: Literal[
        "path", "module", "function", "class", "cli_flag", "http_route", "config_key"
    ]

    @model_validator(mode="after")
    def repository_bounds(self) -> Self:
        if (
            self.path.startswith("/")
            or "\\" in self.path
            or ":" in self.path
            or any(part in ("", ".", "..") for part in self.path.split("/"))
            or any(ord(char) < 32 for char in self.path)
            or len(self.path.encode("utf-8")) > 4096
            or self.line_end < self.line_start
        ):
            raise ValueError("invalid relative source path or line interval")
        return self


class CodeReportLocator(SnapshotLocator):
    item_id: Digest
    reference_id: Digest
    query_sha256: Digest
    coverage_sha256: Digest

    @model_validator(mode="after")
    def report_item_shape(self) -> Self:
        if self.item_id != self.reference_id:
            raise ValueError("initial report item ID equals reference ID")
        return self


class PointerBase(WireModel):
    schema_version: Version = 1
    source_id: LogicalID
    source_sha256: Digest
    source_revision: Revision
    evidence_artifact_sha256: Digest
    provenance_ref: ArtifactRef | None = None


class SuppliedLinePointer(PointerBase):
    kind: Literal["file:line"]
    source_type: Literal["supplied_text"]
    locator_subtype: Literal["line"]
    locator: LineLocator


class LogPointer(PointerBase):
    kind: Literal["file:line"]
    source_type: Literal["configured_log"]
    locator_subtype: Literal["line"]
    locator: LogLocator
    source_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$", max_length=64)]

    @model_validator(mode="after")
    def raw_revision_binding(self) -> Self:
        if self.source_revision != f"sha256:{self.source_sha256}":
            raise ValueError("neutral log revision must bind original raw digest")
        return self


class RepositoryPointer(PointerBase):
    kind: Literal["file:line"]
    source_type: Literal["repository_file"]
    locator_subtype: Literal["line"]
    locator: RepositoryLocator

    @model_validator(mode="after")
    def snapshot_binding(self) -> Self:
        _check_snapshot(self, self.locator)
        if self.source_sha256 != self.evidence_artifact_sha256:
            raise ValueError("direct repository artifact equals original file-byte digest")
        return self


class CodeReportPointer(PointerBase):
    kind: Literal["doc:section"]
    source_type: Literal["code_existence_report"]
    locator_subtype: Literal["report_item"]
    locator: CodeReportLocator

    @model_validator(mode="after")
    def snapshot_binding(self) -> Self:
        _check_snapshot(self, self.locator)
        if self.source_sha256 != self.locator.inventory_sha256:
            raise ValueError("report raw source digest equals current raw inventory digest")
        return self


def _check_snapshot(pointer: PointerBase, locator: SnapshotLocator) -> None:
    expected = f"snapshot:{locator.source_kind}:{locator.snapshot_id}"
    if pointer.source_id != locator.repository_id or pointer.source_revision != expected:
        raise ValueError("repository/raw snapshot identity join mismatch")


class SectionPointer(PointerBase):
    kind: Literal["doc:section"]
    source_type: Literal["supplied_text"]
    locator_subtype: Literal["section"]
    locator: SectionLocator


class DocumentPointer(PointerBase):
    kind: Literal["doc:page:bbox"]
    source_type: Literal["document_page"]
    locator_subtype: Literal["region"]
    locator: RegionLocator

    @model_validator(mode="after")
    def document_binding(self) -> Self:
        if self.source_id != self.locator.document_id:
            raise ValueError("document source identity mismatch")
        return self


class ScreenshotPointer(PointerBase):
    kind: Literal["doc:page:bbox"]
    source_type: Literal["screenshot_collection"]
    locator_subtype: Literal["source_region"]
    locator: RegionLocator

    @model_validator(mode="after")
    def document_binding(self) -> Self:
        if self.source_id != self.locator.document_id:
            raise ValueError("document source identity mismatch")
        return self


class ProductPointer(PointerBase):
    kind: Literal["row:id"]
    source_type: Literal["product_catalog"]
    locator_subtype: Literal["record_field"]
    locator: ProductLocator

    @model_validator(mode="after")
    def dataset_binding(self) -> Self:
        if self.source_id != self.locator.dataset_id:
            raise ValueError("dataset source identity mismatch")
        if self.source_revision != f"rg1:{self.source_sha256}":
            raise ValueError("product raw revision must bind original raw-record digest")
        declared_field = {
            "algorithm": "product-record-field-evidence-v1",
            "dataset_id": self.locator.dataset_id,
            "record_id": self.locator.record_id,
            "source_sha256": self.source_sha256,
            "source_revision": self.source_revision,
            "field_id": self.locator.field_id,
            "raw_value": self.locator.quote,
        }
        preimage = json.dumps(
            declared_field,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if hashlib.sha256(preimage).hexdigest() != self.evidence_artifact_sha256:
            raise ValueError("declared product field artifact preimage mismatch")
        return self


class EventPointer(PointerBase):
    """Declared route only; owner row locator schema is not adopted in this slice."""

    kind: Literal["row:id"]
    source_type: Literal["event_table"]
    locator_subtype: Literal["row"]
    locator: None


class MetricPointer(PointerBase):
    """Declared route only; owner metric locator schema awaits an exact attachment."""

    kind: Literal["row:id"]
    source_type: Literal["metric_table"]
    locator_subtype: Literal["metric"]
    locator: None


class FragmentPointer(PointerBase):
    kind: Literal["url#fragment"]
    source_type: Literal["saved_web"]
    locator_subtype: Literal["fragment"]
    locator: FragmentLocator


class AdvisoryPointer(PointerBase):
    kind: Literal["advisory:id"]
    source_type: Literal["advisory_record"]
    locator_subtype: Literal["id"]
    locator: AdvisoryLocator


def pointer_key(value: object) -> tuple[str, str, str] | None:
    if isinstance(value, dict):
        parts = tuple(value.get(key) for key in ("kind", "source_type", "locator_subtype"))
    elif isinstance(value, PointerBase):
        parts = tuple(
            getattr(value, key, None) for key in ("kind", "source_type", "locator_subtype")
        )
    else:
        return None
    return parts if all(type(part) is str for part in parts) else None


def _tag(value: object) -> str | None:
    key = pointer_key(value)
    return "|".join(key) if key else None


POINTER_MODELS = (
    SuppliedLinePointer,
    LogPointer,
    RepositoryPointer,
    CodeReportPointer,
    SectionPointer,
    DocumentPointer,
    ScreenshotPointer,
    ProductPointer,
    EventPointer,
    MetricPointer,
    FragmentPointer,
    AdvisoryPointer,
)
DOMAIN_KEYS = frozenset(
    tuple(
        model.model_fields[name].annotation.__args__[0]
        for name in ("kind", "source_type", "locator_subtype")
    )
    for model in POINTER_MODELS
)
_TAGGED_MODELS = tuple(
    Annotated[model, Tag("|".join(key))]
    for model in POINTER_MODELS
    for key in [
        tuple(
            model.model_fields[name].annotation.__args__[0]
            for name in ("kind", "source_type", "locator_subtype")
        )
    ]
)
# A runtime-built union uses type composition, not a tuple mistaken for one type.
Pointer = Annotated[reduce(or_, _TAGGED_MODELS), Discriminator(_tag)]
POINTER_ADAPTER = TypeAdapter(Pointer)


class LineMapping(WireModel):
    source_line: PositiveInt
    canonical_line: PositiveInt


class SourceArtifact(WireModel):
    """Declared source metadata, not an acquisition or normalization implementation."""

    schema_version: Version = 1
    source_id: LogicalID
    source_type: LogicalID
    source_sha256: Digest
    source_revision: Revision
    evidence_artifact_sha256: Digest
    raw_byte_length: NonnegativeInt
    canonical_text_sha256: Digest | None = None
    newline_policy: Literal["identity", "crlf-to-lf"] | None = None
    line_map: Annotated[
        tuple[LineMapping, ...], BeforeValidator(_array), Field(max_length=10000)
    ] = ()

    @model_validator(mode="after")
    def text_metadata(self) -> Self:
        if (self.canonical_text_sha256 is None) != (self.newline_policy is None):
            raise ValueError("canonical digest and explicit newline policy belong together")
        if self.line_map and self.canonical_text_sha256 is None:
            raise ValueError("line map requires explicit canonical text identity")
        pairs = [(entry.source_line, entry.canonical_line) for entry in self.line_map]
        original = [pair[0] for pair in pairs]
        canonical = [pair[1] for pair in pairs]
        if original != sorted(set(original)) or canonical != sorted(set(canonical)):
            raise ValueError("line map must be ordered, unique and unambiguous")
        return self


class MethodRef(WireModel):
    method_id: LogicalID
    origin: Literal["deterministic", "typed", "generative", "synthetic_replay", "actual_replay"]
    policy_sha256: Digest
    model_requested: LogicalID | None = None
    model_reported: LogicalID | None = None


class Finding(WireModel):
    """Generic semantic claim; even a matching quote cannot certify its truth."""

    schema_version: Version = 1
    id: LogicalID
    text: Text
    verdict: Literal["partial", "unsupported"]
    probability: Probability | None = None
    confidence: Probability | None = None
    evidence: Annotated[tuple[Pointer, ...], BeforeValidator(_array), Field(max_length=128)]
    method: MethodRef | None = None


class Coverage(WireModel):
    status: Literal["complete", "partial", "unknown"]
    requested: NonnegativeInt | None = None
    returned: NonnegativeInt | None = None
    output_truncated: bool | None = None
    profile_ref: ArtifactRef | None = None


class ResolutionProvenance(WireModel):
    geometry_provenance: Geometry | None = None
    ocr_confidence: Probability | None = None
    owner_resolution_scope: Literal["redacted_text"] | None = None
    view_kind: Literal["raw_source", "redacted_result"] | None = None
    coverage: Coverage | None = None
    profile_ref: ArtifactRef | None = None


class Resolution(WireModel):
    status: Literal["resolved", "unsupported", "stale", "missing", "invalid"]
    checked_source_revision: Revision | None = None
    checked_source_sha256: Digest | None = None
    checked_artifact_sha256: Digest | None = None
    scope: Scope | None = None
    excerpt: Text | None = None
    excerpt_sha256: Digest | None = None
    reason: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$", max_length=64)]
    provenance: ResolutionProvenance | None = None

    @model_validator(mode="after")
    def honest_scope(self) -> Self:
        if self.status != "resolved":
            if (
                self.scope is not None
                or self.excerpt is not None
                or self.excerpt_sha256 is not None
            ):
                raise ValueError("failed resolution cannot claim a successful excerpt or scope")
            return self
        if None in (
            self.checked_source_revision,
            self.checked_source_sha256,
            self.checked_artifact_sha256,
            self.scope,
        ):
            raise ValueError("resolved result needs all checked source/artifact bindings and scope")
        if (self.excerpt is None) != (self.excerpt_sha256 is None):
            raise ValueError("excerpt and literal digest must both exist or both be null")
        if self.excerpt is not None and (
            hashlib.sha256(self.excerpt.encode("utf-8")).hexdigest() != self.excerpt_sha256
        ):
            raise ValueError("resolved literal excerpt digest mismatch")
        geometry = self.provenance.geometry_provenance if self.provenance else None
        if self.scope in ("spatial", "text_and_spatial") and geometry not in (
            "native",
            "measured_ocr",
        ):
            raise ValueError("spatial scope requires native/measured provenance")
        if self.scope == "asserted_spatial" and geometry != "model_claimed":
            raise ValueError("asserted scope must retain model-claimed provenance")
        if self.scope in ("spatial", "asserted_spatial") and self.excerpt is not None:
            raise ValueError("spatial-only scope cannot claim a checked text excerpt")
        return self


class ResolutionContext(WireModel):
    """Caller-supplied policy references; structural shape does not grant access."""

    namespace_id: LogicalID
    access_policy_ref: ArtifactRef
    generation_policy_ref: ArtifactRef
    required_scope: Literal["text", "spatial", "text_and_spatial"] | None = None
