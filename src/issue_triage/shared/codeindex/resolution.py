"""Deterministic, coverage-aware source facts. Similarity never establishes lineage."""

import hashlib
from dataclasses import asdict, dataclass

from .canonical import CodeIndexError, canonical_bytes, decode_canonical, digest
from .models import CodePointer, valid_digest, valid_name
from .references import DEFAULT_EXTRACTION_POLICY, Query, Reference

RESOLVER_VERSION = "coverage-four-status/1"


@dataclass(frozen=True, slots=True)
class CandidatePolicy:
    version: str = "lexical-trigrams/1"
    minimum_score_millis: int = 650
    max_candidates: int = 5

    def __post_init__(self):
        if (
            self.version != "lexical-trigrams/1"
            or type(self.minimum_score_millis) is not int
            or not 1 <= self.minimum_score_millis <= 1000
            or type(self.max_candidates) is not int
            or not 1 <= self.max_candidates <= 5
        ):
            raise CodeIndexError("invalid_candidate_policy")

    def wire(self):
        return asdict(self)

    @property
    def sha256(self):
        return digest(self.wire())


DEFAULT_CANDIDATE_POLICY = CandidatePolicy()


@dataclass(frozen=True, slots=True)
class RelevantCoverage:
    preimage: bytes

    def __post_init__(self):
        decode_canonical(self.preimage, max_bytes=4 * 1024 * 1024)

    @property
    def sha256(self):
        return hashlib.sha256(self.preimage).hexdigest()

    def wire(self):
        return decode_canonical(self.preimage, max_bytes=4 * 1024 * 1024)

    @property
    def complete(self):
        return self.wire()["complete"]


def _in_scope(definition, query):
    return (
        definition.pointer.definition_kind == query.kind
        and (query.path_hint is None or definition.pointer.path == query.path_hint)
        and (query.language_hint is None or definition.language == query.language_hint)
    )


def _matches(definition, query):
    if not _in_scope(definition, query):
        return False
    name = query.normalized_query
    if query.kind in {"function", "class", "module"}:
        match = name in (
            definition.name,
            definition.qualified_name,
        ) or definition.qualified_name.endswith("." + name)
        if query.qualifier_hint is not None:
            prefix = definition.qualified_name.rpartition(".")[0]
            match = match and (
                prefix == query.qualifier_hint or prefix.endswith("." + query.qualifier_hint)
            )
        return match
    return name == definition.name


def relevant_coverage(index, query, candidate_policy=DEFAULT_CANDIDATE_POLICY):
    from .index import CodeIndex
    from .parser import EXTRACTOR_VERSION, PARSER_VERSION

    if (
        type(index) is not CodeIndex
        or type(query) is not Query
        or type(candidate_policy) is not CandidatePolicy
    ):
        raise CodeIndexError("invalid_resolution_input")
    expected = {entry.path: entry.source_sha256 for entry in index.reader.inventory.files}
    actual = {row.path: row.source_sha256 for row in index.coverage}
    if expected != actual or len(actual) != len(index.coverage):
        raise CodeIndexError("coverage_inventory_mismatch")
    rows = [
        row
        for row in index.coverage
        if (query.path_hint is None or row.path == query.path_hint)
        and (query.language_hint is None or row.language in {query.language_hint, "unsupported"})
    ]
    rows.sort(key=lambda row: row.path.encode("utf-8"))
    complete = all(query.kind in row.complete_kinds for row in rows)
    reasons = {
        reason for row in rows if query.kind not in row.complete_kinds for reason in row.reasons
    }
    if query.kind == "path":
        present = any(
            entry.path == query.normalized_query for entry in index.reader.inventory.files
        )
        readable = any(_matches(definition, query) for definition in index.definitions)
        if present and not readable:
            complete = False
            reasons.add("present_path_without_readable_pointer")
        if query.path_hint is not None and query.path_hint != query.normalized_query:
            complete = False
            reasons.add("conflicting_path_hint")
    payload = {
        "coverage_schema_version": 1,
        "inventory_sha256": index.snapshot.inventory_sha256,
        "query_kind": query.kind,
        "query_sha256": query.sha256,
        "files": [row.wire() for row in rows],
        "parser_version": PARSER_VERSION,
        "parser_config_sha256": digest({"version": PARSER_VERSION}),
        "extractor_version": EXTRACTOR_VERSION,
        "extractor_config_sha256": digest({"version": EXTRACTOR_VERSION}),
        "query_version": DEFAULT_EXTRACTION_POLICY.version,
        "query_policy_sha256": DEFAULT_EXTRACTION_POLICY.sha256,
        "resolver_version": RESOLVER_VERSION,
        "index_policy_sha256": index.policy.sha256,
        "candidate_policy_sha256": candidate_policy.sha256,
        "limits": asdict(index.policy)
        | {"excluded_prefixes": list(index.policy.excluded_prefixes)},
        "counts": {
            "inventory_files": len(index.reader.inventory.files),
            "relevant_files": len(rows),
            "relevant_definitions": sum(_in_scope(item, query) for item in index.definitions),
            "exact_matches": sum(_matches(item, query) for item in index.definitions),
            "parsed_bytes": sum(row.parsed_bytes for row in rows),
            "nodes_seen": sum(row.nodes_seen for row in rows),
        },
        "truncated": False,
        "complete": complete,
        "reasons": sorted(reasons),
    }
    preimage = canonical_bytes(payload)
    if len(preimage) > 4 * 1024 * 1024:
        raise CodeIndexError("coverage_byte_limit")
    return RelevantCoverage(preimage)


@dataclass(frozen=True, slots=True)
class MappingAuthority:
    """Trusted host configuration, never constructed from an issue or model answer.

    The host supplies an actual admitted source, expected artifact hash and approval receipt.
    This local library checks their joins; it does not claim a human approved those bytes.
    """

    source_id: str
    artifact_sha256: str
    approval_receipt_sha256: str

    def __post_init__(self):
        valid_name(self.source_id)
        valid_digest(self.artifact_sha256)
        valid_digest(self.approval_receipt_sha256)


@dataclass(frozen=True, slots=True)
class TrustedMapping:
    authority: MappingAuthority
    preimage: bytes

    def __post_init__(self):
        if type(self.authority) is not MappingAuthority:
            raise CodeIndexError("mapping_authority_required")
        if (
            type(self.preimage) is not bytes
            or hashlib.sha256(self.preimage).hexdigest() != self.authority.artifact_sha256
        ):
            raise CodeIndexError("mapping_artifact_mismatch")
        value = decode_canonical(self.preimage, max_bytes=32768)
        if (
            type(value) is not dict
            or set(value)
            != {
                "mapping_schema_version",
                "prior_pointer",
                "current_pointer",
                "prior_qualified_name",
                "current_qualified_name",
            }
            or type(value["mapping_schema_version"]) is not int
            or value["mapping_schema_version"] != 1
        ):
            raise CodeIndexError("invalid_mapping_schema")
        for branch in ("prior", "current"):
            valid_name(value[branch + "_qualified_name"])
            try:
                if type(value[branch + "_pointer"]) is not dict:
                    raise TypeError
                CodePointer(**value[branch + "_pointer"])
            except (TypeError, CodeIndexError):
                raise CodeIndexError("invalid_mapping_pointer") from None

    def wire(self):
        return {
            "source_id": self.authority.source_id,
            "artifact_sha256": self.authority.artifact_sha256,
            "approval_receipt_sha256": self.authority.approval_receipt_sha256,
            "mapping": decode_canonical(self.preimage, max_bytes=32768),
        }


@dataclass(frozen=True, slots=True)
class RankedCandidate:
    pointer: CodePointer
    qualified_name: str
    similarity: str

    def wire(self):
        return {
            "pointer": self.pointer.wire(),
            "qualified_name": self.qualified_name,
            "similarity": self.similarity,
            "evidence_kind": "near_match_candidate",
        }


@dataclass(frozen=True, slots=True)
class Resolution:
    reference_id: str
    status: str
    evidence_kind: str
    reason_code: str
    current_pointers: tuple[CodePointer, ...]
    historical_pointers: tuple[CodePointer, ...]
    ranked_candidates: tuple[RankedCandidate, ...]
    coverage_sha256: str
    mapping_provenance: tuple[TrustedMapping, ...] = ()

    def wire(self):
        return {
            "item_id": self.reference_id,
            "reference_id": self.reference_id,
            "status": self.status,
            "evidence_kind": self.evidence_kind,
            "reason_code": self.reason_code,
            "current_pointers": [pointer.wire() for pointer in self.current_pointers],
            "historical_pointers": [pointer.wire() for pointer in self.historical_pointers],
            "ranked_candidates": [candidate.wire() for candidate in self.ranked_candidates],
            "coverage_sha256": self.coverage_sha256,
            "mapping_provenance": [mapping.wire() for mapping in self.mapping_provenance],
        }


def _ordered(definitions):
    return sorted(
        definitions,
        key=lambda item: (
            item.pointer.path.encode("utf-8"),
            item.pointer.line_start,
            item.pointer.line_end,
            item.qualified_name.encode("utf-8"),
        ),
    )


def _validate_mapping(mapping, current, prior):
    from .index import resolve_pointer

    if type(mapping) is not TrustedMapping or prior is None:
        raise CodeIndexError("trusted_mapping_context_required")
    value = mapping.wire()["mapping"]
    found = []
    for branch, index in (("prior", prior), ("current", current)):
        pointer = CodePointer(**value[branch + "_pointer"])
        name = value[branch + "_qualified_name"]
        matches = [
            item
            for item in index.definitions
            if item.qualified_name == name
            and item.pointer.definition_kind == pointer.definition_kind
        ]
        if (
            resolve_pointer(pointer, index.snapshot, index.reader) != "verified"
            or len(matches) != 1
            or matches[0].pointer != pointer
            or not relevant_coverage(index, Query(pointer.definition_kind, name)).complete
        ):
            raise CodeIndexError("trusted_mapping_definition_mismatch")
        found.append(matches[0])
    if (
        found[0].pointer.repository_id != found[1].pointer.repository_id
        or found[0].pointer.definition_kind != found[1].pointer.definition_kind
    ):
        raise CodeIndexError("trusted_mapping_scope_mismatch")
    return found


def _score(left, right):
    def grams(value):
        value = "^^" + value + "$$"
        return {value[index : index + 3] for index in range(len(value) - 2)}

    a, b = grams(left), grams(right)
    return 1000 * len(a & b) // len(a | b)


def resolve_reference(
    index, reference, prior=None, trusted_mappings=(), candidate_policy=DEFAULT_CANDIDATE_POLICY
):
    from .index import CodeIndex

    if (
        type(index) is not CodeIndex
        or type(reference) is not Reference
        or (prior is not None and type(prior) is not CodeIndex)
    ):
        raise CodeIndexError("invalid_resolution_input")
    if prior is not None and prior.snapshot.repository_id != index.snapshot.repository_id:
        raise CodeIndexError("prior_repository_mismatch")
    if type(trusted_mappings) not in {tuple, list} or len(trusted_mappings) > 128:
        raise CodeIndexError("mapping_count_limit")
    mappings = [_validate_mapping(mapping, index, prior) for mapping in trusted_mappings]
    if len({mapping.authority.artifact_sha256 for mapping in trusted_mappings}) != len(
        trusted_mappings
    ):
        raise CodeIndexError("duplicate_trusted_mapping")
    query = reference.query
    coverage = relevant_coverage(index, query, candidate_policy)
    matches = _ordered([item for item in index.definitions if _matches(item, query)])
    historical = (
        _ordered([item for item in prior.definitions if _matches(item, query)]) if prior else []
    )

    def result(status, evidence, reason, current=(), old=(), candidates=(), provenance=()):
        return Resolution(
            reference.id,
            status,
            evidence,
            reason,
            tuple(current),
            tuple(old),
            tuple(candidates),
            coverage.sha256,
            tuple(provenance),
        )

    if len(matches) > 1:
        return result(
            "ambiguous",
            "multiple_definitions",
            "pointer_limit" if len(matches) > 10 else "multiple_definitions",
            [item.pointer for item in matches[:10]],
        )
    if not coverage.complete:
        return result(
            "ambiguous",
            "coverage_incomplete",
            "coverage_incomplete",
            [item.pointer for item in matches],
        )
    if matches:
        return result("found", "exact", "exact_definition", [matches[0].pointer])
    moves = [
        (pair, mapping)
        for pair, mapping in zip(mappings, trusted_mappings, strict=True)
        if _matches(pair[0], query)
    ]
    if len(moves) > 1:
        return result("ambiguous", "multiple_definitions", "multiple_trusted_moves")
    if moves:
        (old, current), mapping = moves[0]
        return result(
            "renamed_or_moved",
            "verified_move",
            "trusted_explicit_mapping",
            [current.pointer],
            [old.pointer],
            provenance=[mapping],
        )
    if len(historical) > 10:
        return result(
            "ambiguous",
            "multiple_definitions",
            "historical_pointer_limit",
            old=[item.pointer for item in historical[:10]],
        )
    ranked = []
    for item in index.definitions:
        if _in_scope(item, query):
            score = max(
                _score(query.normalized_query, item.name),
                _score(query.normalized_query, item.qualified_name),
            )
            if score >= candidate_policy.minimum_score_millis:
                ranked.append((score, item))
    ranked.sort(
        key=lambda row: (
            -row[0],
            row[1].pointer.path.encode("utf-8"),
            row[1].pointer.line_start,
            row[1].qualified_name.encode("utf-8"),
        )
    )
    if ranked:
        candidates = [
            RankedCandidate(
                item.pointer, item.qualified_name, f"{score // 1000}.{score % 1000:03d}"
            )
            for score, item in ranked[: candidate_policy.max_candidates]
        ]
        return result(
            "renamed_or_moved",
            "near_match_candidate",
            "tentative_lexical_similarity",
            old=[item.pointer for item in historical],
            candidates=candidates,
        )
    return result(
        "not_found",
        "removed_since_prior" if historical else "none",
        "removed_since_prior" if historical else "complete_scope_no_match",
        old=[item.pointer for item in historical[:10]],
    )
