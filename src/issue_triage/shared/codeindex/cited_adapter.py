"""Optional exact citation bridge; no acquisition, default access or mutable HEAD."""

import hashlib
from dataclasses import asdict, dataclass
from types import MappingProxyType

from pydantic import TypeAdapter

from ..cited import POINTER_ADAPTER, ArtifactRef, Registry, Resolution, ResolutionContext
from ..cited.models import Coverage, LogicalID, ResolutionProvenance, pointer_key
from ..cited.registry import DuplicateResolverError
from .canonical import CodeIndexError, canonical_bytes, digest
from .index import CodeIndex, resolve_pointer
from .models import CodePointer, SnapshotRef
from .report import ExistenceReport, ReportItemRef, resolve_report_item

FILE_KEY = ("file:line", "repository_file", "line")
REPORT_KEY = ("doc:section", "code_existence_report", "report_item")
PROFILE_REF = ArtifactRef(
    artifact_id="codeindex-cited-profile",
    profile_id="codeindex-to-cited/1",
    artifact_sha256=digest(
        {
            "profile": "codeindex-to-cited/1",
            "contract_sha256": "973708f0a2d8c19799372884aaec12cfc2865f286671f70e97130b976cfab479",
        }
    ),
)


def to_cited_file(pointer):
    if type(pointer) is not CodePointer:
        raise CodeIndexError("invalid_code_pointer")
    pointer.__post_init__()
    locator = pointer.wire()
    locator.pop("source_sha256")
    return POINTER_ADAPTER.validate_python(
        {
            "schema_version": 1,
            "kind": FILE_KEY[0],
            "source_type": FILE_KEY[1],
            "locator_subtype": FILE_KEY[2],
            "source_id": pointer.repository_id,
            "source_sha256": pointer.source_sha256,
            "source_revision": f"snapshot:{pointer.source_kind}:{pointer.snapshot_id}",
            "evidence_artifact_sha256": pointer.source_sha256,
            "locator": locator,
        }
    )


def to_cited_report(ref):
    if type(ref) is not ReportItemRef:
        raise CodeIndexError("invalid_report_item_ref")
    ref.__post_init__()
    locator = ref.wire()
    locator.pop("report_sha256")
    return POINTER_ADAPTER.validate_python(
        {
            "schema_version": 1,
            "kind": REPORT_KEY[0],
            "source_type": REPORT_KEY[1],
            "locator_subtype": REPORT_KEY[2],
            "source_id": ref.repository_id,
            "source_sha256": ref.inventory_sha256,
            "source_revision": f"snapshot:{ref.source_kind}:{ref.snapshot_id}",
            "evidence_artifact_sha256": ref.report_sha256,
            "locator": locator,
        }
    )


@dataclass(frozen=True, slots=True)
class BridgeBounds:
    max_reports: int = 128
    max_retained_report_bytes: int = 8 * 1024 * 1024
    max_excerpt_characters: int = 32768
    max_source_view_bytes: int = 1024 * 1024

    def __post_init__(self):
        for value, maximum in (
            (self.max_reports, 128),
            (self.max_retained_report_bytes, 8 * 1024 * 1024),
            (self.max_excerpt_characters, 32768),
            (self.max_source_view_bytes, 1024 * 1024),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise CodeIndexError("invalid_bridge_bounds")


DEFAULT_BRIDGE_BOUNDS = BridgeBounds()


class CodeIndexCitedResolver:
    """Host supplies trusted namespace/access/generation and retained immutable artifacts.

    Generation.current(namespace_id, repository_id) returns the actually admitted SnapshotRef.
    Policy references are joins; this adapter does not manufacture their authority.
    """

    def __init__(
        self,
        index,
        *,
        namespace_id,
        access,
        generation,
        reports=(),
        prior=None,
        trusted_mappings=(),
        bounds=DEFAULT_BRIDGE_BOUNDS,
    ):
        if type(index) is not CodeIndex or (prior is not None and type(prior) is not CodeIndex):
            raise CodeIndexError("invalid_bridge_index")
        if type(bounds) is not BridgeBounds or type(reports) is not tuple:
            raise CodeIndexError("invalid_bridge_inputs")
        bounds.__post_init__()
        TypeAdapter(LogicalID).validate_python(namespace_id, strict=True)
        TypeAdapter(LogicalID).validate_python(index.snapshot.repository_id, strict=True)
        if len(reports) > bounds.max_reports:
            raise CodeIndexError("bridge_report_count_limit")
        if type(trusted_mappings) not in {tuple, list} or len(trusted_mappings) > 128:
            raise CodeIndexError("mapping_count_limit")
        retained, total = {}, 0
        for report in reports:
            if type(report) is not ExistenceReport:
                raise CodeIndexError("invalid_bridge_report")
            checked = ExistenceReport(report.preimage)
            if checked.wire()["current_snapshot"] != index.snapshot.wire():
                raise CodeIndexError("bridge_report_current_mismatch")
            if checked.sha256 in retained:
                raise CodeIndexError("duplicate_bridge_report")
            total += len(checked.preimage)
            if total > bounds.max_retained_report_bytes:
                raise CodeIndexError("bridge_retained_report_limit")
            retained[checked.sha256] = checked.preimage
        self._index, self._prior = index, prior
        self._namespace, self._access, self._generation = namespace_id, access, generation
        self._reports, self._mappings = MappingProxyType(retained), tuple(trusted_mappings)
        self._bounds = bounds
        self._profile_ref = ArtifactRef(
            artifact_id=PROFILE_REF.artifact_id,
            profile_id=PROFILE_REF.profile_id,
            artifact_sha256=digest(
                {"profile_contract_sha256": PROFILE_REF.artifact_sha256, "bounds": asdict(bounds)}
            ),
        )

    def _admit(self, pointer, context):
        if context.namespace_id != self._namespace:
            return Resolution(status="unsupported", reason="namespace_not_allowed")
        try:
            access_ref = ArtifactRef.model_validate(self._access.reference)
            generation_ref = ArtifactRef.model_validate(self._generation.reference)
            if (
                access_ref != context.access_policy_ref
                or generation_ref != context.generation_policy_ref
            ):
                return Resolution(status="unsupported", reason="policy_reference_mismatch")
            decision = self._access.decision(context.namespace_id, pointer.source_id)
            if type(decision) is not str or decision != "allow":
                return Resolution(status="unsupported", reason="access_not_allowed")
            current = self._generation.current(context.namespace_id, pointer.source_id)
            if current is None:
                return Resolution(status="unsupported", reason="current_generation_unknown")
            if type(current) is not SnapshotRef:
                return Resolution(status="unsupported", reason="current_generation_unsupported")
            current = SnapshotRef(**current.wire())
        except Exception:
            return Resolution(status="unsupported", reason="policy_unavailable")
        if current.repository_id != pointer.source_id:
            return Resolution(status="invalid", reason="current_repository_mismatch")
        if current.wire() != self._index.snapshot.wire():
            return Resolution(status="stale", reason="current_generation_mismatch")
        locator = pointer.locator
        if (
            locator.repository_id,
            locator.source_kind,
            locator.snapshot_id,
            locator.inventory_sha256,
        ) != (
            current.repository_id,
            current.source_kind,
            current.snapshot_id,
            current.inventory_sha256,
        ):
            return Resolution(status="stale", reason="pointer_snapshot_mismatch")
        return current

    def resolve(self, pointer, context):
        if pointer_key(pointer) not in {FILE_KEY, REPORT_KEY}:
            return Resolution(status="unsupported", reason="codeindex_domain_unsupported")
        try:
            pointer = POINTER_ADAPTER.validate_python(pointer)
            context = ResolutionContext.model_validate(context)
        except Exception:
            return Resolution(status="invalid", reason="wire_contract_error")
        if context.required_scope in {"spatial", "text_and_spatial"}:
            return Resolution(status="unsupported", reason="required_scope_unavailable")
        admission = self._admit(pointer, context)
        if isinstance(admission, Resolution):
            return admission
        try:
            if pointer_key(pointer) == FILE_KEY:
                native = CodePointer(
                    **(pointer.locator.model_dump() | {"source_sha256": pointer.source_sha256})
                )
                raw = self._index.reader.read(native.path)
                if len(raw) > self._bounds.max_source_view_bytes:
                    return Resolution(status="unsupported", reason="source_view_limit_exceeded")
                status = resolve_pointer(native, self._index.snapshot, self._index.reader)
                if status != "verified":
                    return Resolution(status=status, reason="retained_file_pointer_unverified")
                if hashlib.sha256(raw).hexdigest() != pointer.source_sha256:
                    return Resolution(status="stale", reason="retained_file_digest_mismatch")
                # Constant-memory LF traversal; never allocate an offset per line.
                left = 0
                for _ in range(native.line_start - 1):
                    left = raw.find(b"\n", left) + 1
                right = left
                for _ in range(native.line_end - native.line_start + 1):
                    ending = raw.find(b"\n", right)
                    right = len(raw) if ending < 0 else ending + 1
                    if right - left > 4 * self._bounds.max_excerpt_characters:
                        return Resolution(status="unsupported", reason="excerpt_limit_exceeded")
                excerpt_bytes, coverage, reason = raw[left:right], None, "retained_file_text"
            else:
                native_ref = ReportItemRef(
                    report_sha256=pointer.evidence_artifact_sha256, **pointer.locator.model_dump()
                )
                raw = self._reports.get(native_ref.report_sha256)
                checked = resolve_report_item(
                    native_ref, raw, self._index, prior=self._prior, trusted_mappings=self._mappings
                )
                if checked.status != "verified":
                    return Resolution(status=checked.status, reason=checked.reason_code)
                payload = ExistenceReport(raw).wire()
                item = next(
                    item for item in payload["items"] if item["item_id"] == native_ref.item_id
                )
                excerpt_bytes = canonical_bytes(item)
                if excerpt_bytes not in raw:
                    return Resolution(status="invalid", reason="report_item_text_mismatch")
                scope = payload["coverage"][native_ref.coverage_sha256]
                coverage = Coverage(
                    status="complete" if checked.coverage_complete else "partial",
                    requested=scope["counts"]["relevant_files"],
                    returned=len(scope["files"]),
                    output_truncated=False,
                    profile_ref=self._profile_ref,
                )
                reason = "recorded_search_scope"
            excerpt = excerpt_bytes.decode("utf-8", errors="strict")
            if len(excerpt) > self._bounds.max_excerpt_characters:
                return Resolution(status="unsupported", reason="excerpt_limit_exceeded")
            final = self._admit(pointer, context)
            if isinstance(final, Resolution):
                return final
            if final != admission:
                return Resolution(status="stale", reason="generation_changed_during_resolution")
            if (
                pointer_key(pointer) == FILE_KEY
                and resolve_pointer(native, self._index.snapshot, self._index.reader) != "verified"
            ):
                return Resolution(status="stale", reason="retained_file_changed_during_resolution")
            return Resolution(
                status="resolved",
                checked_source_revision=pointer.source_revision,
                checked_source_sha256=pointer.source_sha256,
                checked_artifact_sha256=pointer.evidence_artifact_sha256,
                scope="text",
                excerpt=excerpt,
                excerpt_sha256=hashlib.sha256(excerpt_bytes).hexdigest(),
                reason=reason,
                provenance=ResolutionProvenance(coverage=coverage, profile_ref=self._profile_ref),
            )
        except (CodeIndexError, ValueError, TypeError, KeyError, StopIteration):
            return Resolution(status="invalid", reason="retained_codeindex_contract_error")


def install_codeindex(registry, resolver):
    """Explicit single-threaded configuration; duplicates reject before either tuple changes."""
    if type(registry) is not Registry or type(resolver) is not CodeIndexCitedResolver:
        raise TypeError("canonical Registry and explicit codeindex resolver required")
    if {FILE_KEY, REPORT_KEY} & registry.installed_domains:
        raise DuplicateResolverError("codeindex domain already installed")
    registry.register(FILE_KEY, resolver)
    registry.register(REPORT_KEY, resolver)
