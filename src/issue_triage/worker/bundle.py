"""Explicit original local UTF-8 source bundles; never Git capture or executable input."""

from dataclasses import dataclass
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from ..contracts.domain import IssueInput, utc_epoch_us
from ..ingest.labels import LabelInventory, LabelWire
from ..judges.context import JudgmentContext
from ..shared.cited import ArtifactRef, Registry, ResolutionContext
from ..shared.codeindex.canonical import digest
from ..shared.codeindex.cited_adapter import CodeIndexCitedResolver, install_codeindex
from ..shared.codeindex.index import build_index
from ..shared.codeindex.inventory import InventoryReader, inventory_from_files
from ..shared.codeindex.models import SnapshotRef
from ..shared.codeindex.report import build_existence_report
from ..shared.screen import ScreenPolicy, UntrustedText, screen_rules
from ..suggest.labels import LabelMap

MAX_BUNDLE_BYTES = 8 * 1024 * 1024


class SourceFile(LabelWire):
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    content: Annotated[str, Field(max_length=1048576, repr=False)]


class MappingWire(LabelWire):
    type_labels: dict[str, tuple[str, ...]]
    priority_labels: dict[str, tuple[str, ...]]
    common_labels: tuple[str, ...] = ()

    @field_validator("type_labels", "priority_labels", mode="before")
    @classmethod
    def tuples_in_maps(cls, value):
        if type(value) is dict:
            return {
                key: tuple(names) if type(names) is list else names for key, names in value.items()
            }
        return value

    @field_validator("common_labels", mode="before")
    @classmethod
    def tuple_names(cls, value):
        return tuple(value) if type(value) is list else value

    def checked(self):
        if any(key not in {"0", "1", "2", "3"} for key in self.priority_labels):
            raise ValueError("invalid_priority_mapping_key")
        return LabelMap(
            self.type_labels,
            {int(key): names for key, names in self.priority_labels.items()},
            self.common_labels,
        )


class LocalBundle(LabelWire):
    source_kind: Literal["fixture_inventory"]
    label_origin: Literal["agent_provisional_original_local"]
    issue: IssueInput = Field(repr=False)
    files: Annotated[tuple[SourceFile, ...], Field(max_length=5000, repr=False)]
    labels: LabelInventory
    label_mapping: MappingWire
    captured_at: str

    @field_validator("files", mode="before")
    @classmethod
    def tuple_files(cls, value):
        return tuple(value) if type(value) is list else value

    @model_validator(mode="after")
    def bounded_and_bound(self) -> Self:
        utc_epoch_us(self.captured_at)
        if self.labels.repository_id != self.issue.key.repository_id:
            raise ValueError("bundle_repository_mismatch")
        if len({file.path for file in self.files}) != len(self.files):
            raise ValueError("duplicate_bundle_path")
        if len(self.canonical_bytes()) > MAX_BUNDLE_BYTES:
            raise ValueError("bundle_byte_limit")
        self.label_mapping.checked()
        # Validates every raw path/collision/byte limit without probing the filesystem.
        inventory_from_files(
            {file.path: file.content.encode("utf-8", errors="strict") for file in self.files}
        )
        return self


def parse_bundle(data):
    if type(data) is not bytes or len(data) > MAX_BUNDLE_BYTES:
        raise ValueError("invalid_local_bundle")
    # ClosedModel's parser has an intentional 1MiB general limit; this explicit port
    # allows 8MiB while preserving duplicate-key/nonfinite/strict model checks.
    import json

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("nonfinite_json")

    try:
        return LocalBundle.model_validate(
            json.loads(data, object_pairs_hook=unique, parse_constant=invalid)
        )
    except Exception:
        raise ValueError("invalid_local_bundle") from None


@dataclass(frozen=True)
class Analysis:
    context: JudgmentContext
    registry: Registry
    resolution_context: ResolutionContext


def analyze(bundle):
    bundle = parse_bundle(bundle.canonical_bytes())
    issue = bundle.issue
    files = {file.path: file.content.encode("utf-8") for file in bundle.files}
    inventory = inventory_from_files(files)
    snapshot = SnapshotRef(
        f"github-repository-{issue.key.repository_id}",
        "fixture_inventory",
        inventory.sha256,
        inventory.sha256,
        bundle.captured_at,
        True,
    )
    index = build_index(snapshot, InventoryReader(inventory, files))
    source = UntrustedText(issue.key.stable_id, issue.sha256, issue.model_bound_text)
    policy = ScreenPolicy("s6-local-fixture-screen/1", "rules")
    screen = screen_rules(source, policy)
    report = build_existence_report(index, issue.model_bound_text)
    context = JudgmentContext(issue, source, screen, policy, index, report)
    namespace = "s6-local-fixture/1"

    class Access:
        reference = ArtifactRef(
            artifact_id="explicit-fixture-access",
            artifact_sha256=digest("explicit local fixture only"),
            profile_id="s6-local-fixture-access/1",
        )

        def decision(self, ns, repository):
            return "allow" if (ns, repository) == (namespace, snapshot.repository_id) else "deny"

    class Generation:
        reference = ArtifactRef(
            artifact_id="explicit-fixture-generation",
            artifact_sha256=digest("retained explicit fixture only"),
            profile_id="s6-local-fixture-generation/1",
        )

        def current(self, ns, repository):
            return snapshot if (ns, repository) == (namespace, snapshot.repository_id) else None

    access, generation = Access(), Generation()
    resolution_context = ResolutionContext(
        namespace_id=namespace,
        access_policy_ref=access.reference,
        generation_policy_ref=generation.reference,
        required_scope="text",
    )
    registry = Registry()
    install_codeindex(
        registry,
        CodeIndexCitedResolver(
            index, namespace_id=namespace, access=access, generation=generation, reports=(report,)
        ),
    )
    return Analysis(context, registry, resolution_context)
