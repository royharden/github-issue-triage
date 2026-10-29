"""Bounded immutable supplied text. No acquisition, default access or global store."""

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Literal, Protocol

from pydantic import TypeAdapter

from .models import (
    POINTER_ADAPTER,
    ArtifactRef,
    LineMapping,
    LogicalID,
    Pointer,
    Resolution,
    ResolutionContext,
    Revision,
    SourceArtifact,
)
from .registry import DuplicateResolverError, Registry

LINE_KEY = ("file:line", "supplied_text", "line")
SECTION_KEY = ("doc:section", "supplied_text", "section")
_ID = TypeAdapter(LogicalID)
_REVISION = TypeAdapter(Revision)


@dataclass(frozen=True, slots=True)
class MemoryBounds:
    max_source_bytes: int = 262144
    max_lines: int = 5000
    max_sections: int = 500
    max_sources: int = 128
    max_retained_bytes: int = 8388608

    def __post_init__(self) -> None:
        ceilings = (262144, 5000, 500, 128, 8388608)
        for value, ceiling in zip(asdict(self).values(), ceilings, strict=True):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError("memory bounds must be positive integers within profile ceilings")


DEFAULT_BOUNDS = MemoryBounds()


@dataclass(frozen=True, slots=True)
class SectionSpan:
    section_id: str
    line_start: int
    line_end: int

    def __post_init__(self) -> None:
        _ID.validate_python(self.section_id, strict=True)
        if type(self.line_start) is not int or type(self.line_end) is not int:
            raise ValueError("section line bounds must be integers")
        if not 1 <= self.line_start <= self.line_end:
            raise ValueError("section line bounds must be positive and ordered")


@dataclass(frozen=True, slots=True)
class MemoryLine:
    source_line: int
    canonical_line: int
    source_byte_start: int
    source_byte_end: int
    canonical_byte_start: int
    canonical_byte_end: int


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _intervals(value: bytes) -> tuple[tuple[int, int], ...]:
    """LF only, ending bytes retained, no phantom last line."""
    ends = [index + 1 for index, byte in enumerate(value) if byte == 10]
    if value and (not ends or ends[-1] != len(value)):
        ends.append(len(value))
    starts = [0, *ends[:-1]] if ends else []
    return tuple(zip(starts, ends, strict=True))


def _derive(
    namespace_id: str,
    source_id: str,
    source_revision: str,
    raw: bytes,
    newline_policy: Literal["identity", "crlf-to-lf"],
    sections: tuple[SectionSpan, ...],
    bounds: MemoryBounds,
) -> tuple[SourceArtifact, bytes, tuple[MemoryLine, ...], tuple[SectionSpan, ...]]:
    _ID.validate_python(namespace_id, strict=True)
    _ID.validate_python(source_id, strict=True)
    _REVISION.validate_python(source_revision, strict=True)
    if type(raw) is not bytes:
        raise TypeError("source buffer must be immutable bytes")
    if type(bounds) is not MemoryBounds or type(sections) is not tuple:
        raise TypeError("explicit bounds and immutable section tuple required")
    bounds.__post_init__()
    if len(raw) > bounds.max_source_bytes:
        raise ValueError("source byte limit exceeded")
    if newline_policy not in ("identity", "crlf-to-lf"):
        raise ValueError("explicit supported newline policy required")
    text = raw.decode("utf-8", errors="strict")
    canonical = (text.replace("\r\n", "\n") if newline_policy == "crlf-to-lf" else text).encode(
        "utf-8"
    )
    original_intervals, canonical_intervals = _intervals(raw), _intervals(canonical)
    if len(original_intervals) > bounds.max_lines:
        raise ValueError("source line limit exceeded")
    if len(original_intervals) != len(canonical_intervals):
        raise ValueError("newline conversion changed physical line identity")
    lines = tuple(
        MemoryLine(index, index, original[0], original[1], converted[0], converted[1])
        for index, (original, converted) in enumerate(
            zip(original_intervals, canonical_intervals, strict=True), start=1
        )
    )
    if len(sections) > bounds.max_sections or any(
        type(span) is not SectionSpan for span in sections
    ):
        raise ValueError("section limit/type mismatch")
    for span in sections:
        span.__post_init__()
    if len({span.section_id for span in sections}) != len(sections):
        raise ValueError("duplicate section identity")
    if any(span.line_end > len(lines) for span in sections):
        raise ValueError("section outside actual physical lines")
    ordered_sections = tuple(sorted(sections, key=lambda span: span.section_id.encode("utf-8")))
    raw_hash, canonical_hash = _sha(raw), _sha(canonical)
    artifact = {
        "algorithm": "supplied-text-memory/1",
        "namespace_id": namespace_id,
        "source_id": source_id,
        "source_revision": source_revision,
        "source_sha256": raw_hash,
        "canonical_text_sha256": canonical_hash,
        "newline_policy": newline_policy,
        "lines": [asdict(line) for line in lines],
        "sections": [asdict(section) for section in ordered_sections],
    }
    encoded = json.dumps(
        artifact, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    metadata = SourceArtifact(
        source_id=source_id,
        source_type="supplied_text",
        source_sha256=raw_hash,
        source_revision=source_revision,
        evidence_artifact_sha256=_sha(encoded),
        raw_byte_length=len(raw),
        canonical_text_sha256=canonical_hash,
        newline_policy=newline_policy,
        line_map=tuple(
            LineMapping(source_line=line.source_line, canonical_line=line.canonical_line)
            for line in lines
        ),
    )
    return metadata, canonical, lines, ordered_sections


@dataclass(frozen=True, slots=True)
class MemorySource:
    namespace_id: str
    metadata: SourceArtifact
    raw: bytes
    canonical: bytes
    lines: tuple[MemoryLine, ...]
    sections: tuple[SectionSpan, ...]
    bounds: MemoryBounds

    @classmethod
    def from_bytes(
        cls,
        *,
        namespace_id: str,
        source_id: str,
        source_revision: str,
        raw: bytes,
        newline_policy: Literal["identity", "crlf-to-lf"],
        sections: tuple[SectionSpan, ...] = (),
        bounds: MemoryBounds = DEFAULT_BOUNDS,
    ) -> "MemorySource":
        metadata, canonical, lines, ordered = _derive(
            namespace_id, source_id, source_revision, raw, newline_policy, sections, bounds
        )
        return cls(namespace_id, metadata, raw, canonical, lines, ordered, bounds)

    def validate_retained(self) -> None:
        if type(self.canonical) is not bytes or type(self.lines) is not tuple:
            raise ValueError("retained canonical bytes and line metadata must be immutable")
        if any(
            type(line) is not MemoryLine
            or any(type(value) is not int for value in asdict(line).values())
            for line in self.lines
        ):
            raise ValueError("retained line intervals must contain exact integers")
        metadata = SourceArtifact.model_validate(self.metadata)
        expected = _derive(
            self.namespace_id,
            metadata.source_id,
            metadata.source_revision,
            self.raw,
            metadata.newline_policy,
            self.sections,
            self.bounds,
        )
        if (metadata, self.canonical, self.lines, self.sections) != expected:
            raise ValueError("retained source or metadata changed")


class AccessPolicy(Protocol):
    reference: ArtifactRef

    def decision(
        self, namespace_id: str, source_id: str
    ) -> Literal["allow", "deny", "unknown"]: ...


class GenerationPolicy(Protocol):
    reference: ArtifactRef

    def current(self, namespace_id: str, source_id: str) -> SourceArtifact | None: ...


class MemoryTextResolver:
    """Explicit trusted-policy injection; the actual source is already retained in memory."""

    def __init__(
        self,
        sources: tuple[MemorySource, ...],
        *,
        access: AccessPolicy,
        generation: GenerationPolicy,
        bounds: MemoryBounds = DEFAULT_BOUNDS,
    ) -> None:
        if type(sources) is not tuple or type(bounds) is not MemoryBounds:
            raise TypeError("immutable source collection and explicit bounds required")
        bounds.__post_init__()
        if len(sources) > bounds.max_sources:
            raise ValueError("retained source count exceeded")
        index: dict[tuple[str, str, str], MemorySource] = {}
        total = 0
        for source in sources:
            if type(source) is not MemorySource:
                raise TypeError("memory source type required")
            source.validate_retained()
            if (
                len(source.raw) > bounds.max_source_bytes
                or len(source.lines) > bounds.max_lines
                or len(source.sections) > bounds.max_sections
            ):
                raise ValueError("source exceeds tighter resolver bounds")
            total += len(source.raw)
            key = (source.namespace_id, source.metadata.source_id, source.metadata.source_revision)
            if key in index:
                raise ValueError("duplicate source namespace/identity/revision")
            index[key] = source
        if total > bounds.max_retained_bytes:
            raise ValueError("retained raw byte limit exceeded")
        self._sources = index
        self._access, self._generation = access, generation

    def _admit(self, pointer: Pointer, context: ResolutionContext) -> Resolution | SourceArtifact:
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
            current = SourceArtifact.model_validate(current)
        except Exception:
            return Resolution(status="unsupported", reason="policy_unavailable")
        if current.source_id != pointer.source_id or current.source_type != "supplied_text":
            return Resolution(status="invalid", reason="current_source_identity_mismatch")
        if (
            current.source_revision != pointer.source_revision
            or current.source_sha256 != pointer.source_sha256
            or current.evidence_artifact_sha256 != pointer.evidence_artifact_sha256
        ):
            return Resolution(status="stale", reason="current_generation_mismatch")
        return current

    def resolve(self, pointer: Pointer, context: ResolutionContext) -> Resolution:
        try:
            pointer = POINTER_ADAPTER.validate_python(pointer)
            context = ResolutionContext.model_validate(context)
        except Exception:
            return Resolution(status="invalid", reason="wire_contract_error")
        key = (pointer.kind, pointer.source_type, pointer.locator_subtype)
        if key not in (LINE_KEY, SECTION_KEY):
            return Resolution(status="unsupported", reason="memory_domain_unsupported")
        if context.required_scope in ("spatial", "text_and_spatial"):
            return Resolution(status="unsupported", reason="required_scope_unavailable")
        current = self._admit(pointer, context)
        if isinstance(current, Resolution):
            return current
        source = self._sources.get(
            (context.namespace_id, pointer.source_id, pointer.source_revision)
        )
        if source is None:
            return Resolution(status="missing", reason="retained_source_missing")
        try:
            source.validate_retained()
        except Exception:
            return Resolution(status="invalid", reason="retained_source_mismatch")
        if source.namespace_id != context.namespace_id or source.metadata != current:
            return Resolution(status="stale", reason="retained_generation_mismatch")
        if key == LINE_KEY:
            start, end = pointer.locator.line_start, pointer.locator.line_end
        else:
            spans = [
                span for span in source.sections if span.section_id == pointer.locator.section_id
            ]
            if not spans:
                return Resolution(status="missing", reason="section_missing")
            start, end = spans[0].line_start, spans[0].line_end
        if not 1 <= start <= end <= len(source.lines):
            return Resolution(status="invalid", reason="line_outside_source")
        window = source.canonical[
            source.lines[start - 1].canonical_byte_start : source.lines[end - 1].canonical_byte_end
        ]
        quote = pointer.locator.quote
        if quote is not None:
            encoded = quote.encode("utf-8")
            position = window.find(encoded)
            if position < 0 or _sha(encoded) != pointer.locator.excerpt_sha256:
                return Resolution(status="invalid", reason="quote_outside_window")
            excerpt_bytes = window[position : position + len(encoded)]
        else:
            excerpt_bytes = window
        excerpt = excerpt_bytes.decode("utf-8") if excerpt_bytes else None
        if excerpt is not None and len(excerpt) > 32768:
            return Resolution(status="unsupported", reason="excerpt_limit_exceeded")
        # Recheck revocation/current generation before disclosure; never cache an earlier allow.
        final = self._admit(pointer, context)
        if isinstance(final, Resolution):
            return final
        if final != current:
            return Resolution(status="stale", reason="generation_changed_during_resolution")
        try:
            source.validate_retained()
        except Exception:
            return Resolution(status="invalid", reason="retained_source_mismatch")
        if source.metadata != final:
            return Resolution(status="stale", reason="retained_generation_mismatch")
        return Resolution(
            status="resolved",
            checked_source_revision=current.source_revision,
            checked_source_sha256=_sha(source.raw),
            checked_artifact_sha256=source.metadata.evidence_artifact_sha256,
            scope="text",
            excerpt=excerpt,
            excerpt_sha256=_sha(excerpt_bytes) if excerpt is not None else None,
            reason="literal_occurrence_checked",
        )


def install_supplied_text(registry: Registry, resolver: MemoryTextResolver) -> None:
    """Call during single-writer setup; preserve both existing owners on conflict."""
    if any(key in registry.installed_domains for key in (LINE_KEY, SECTION_KEY)):
        raise DuplicateResolverError("supplied source tuple already registered")
    registry.register(LINE_KEY, resolver)
    registry.register(SECTION_KEY, resolver)
