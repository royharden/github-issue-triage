"""Nonrecursive canonical reports and local, current-index-backed item verification."""

import hashlib
import re
from dataclasses import asdict, dataclass

from .canonical import CodeIndexError, canonical_bytes, decode_canonical, digest
from .models import CodePointer, IndexPolicy, SnapshotRef, SourceCoverage, valid_digest, valid_name
from .references import (
    DEFAULT_EXTRACTION_POLICY,
    ExtractionPolicy,
    Query,
    Reference,
    extract_references,
    reference_id,
)
from .resolution import (
    DEFAULT_CANDIDATE_POLICY,
    RESOLVER_VERSION,
    CandidatePolicy,
    MappingAuthority,
    TrustedMapping,
    relevant_coverage,
)

MAX_REPORT_BYTES = 4 * 1024 * 1024
LIMITS = {
    "max_report_bytes": MAX_REPORT_BYTES,
    "max_items": 128,
    "max_query_rows": 128,
    "max_coverage_rows": 128,
    "max_inventory_files": 5000,
    "max_current_pointers": 10,
    "max_historical_pointers": 10,
    "max_candidates": 5,
}
STATUSES = {"found", "ambiguous", "renamed_or_moved", "not_found"}


def _closed(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise CodeIndexError("invalid_report_fields")


def _count(value, ceiling):
    if type(value) is not int or not 0 <= value <= ceiling:
        raise CodeIndexError("invalid_report_count")


def _identity(snapshot):
    return (
        snapshot.repository_id,
        snapshot.source_kind,
        snapshot.snapshot_id,
        snapshot.inventory_sha256,
    )


def _policy_wire(policy):
    return asdict(policy) | {"excluded_prefixes": list(policy.excluded_prefixes)}


def _index_policy(value):
    if type(value) is not dict or type(value.get("excluded_prefixes")) is not list:
        raise CodeIndexError("invalid_report_policy")
    policy = IndexPolicy(**(value | {"excluded_prefixes": tuple(value["excluded_prefixes"])}))
    if value != _policy_wire(policy):
        raise CodeIndexError("invalid_report_policy")
    return policy


def _configuration(index, candidate_policy, prior=None):
    from .parser import EXTRACTOR_VERSION, PARSER_VERSION

    return {
        "parser_version": PARSER_VERSION,
        "parser_config_sha256": digest({"version": PARSER_VERSION}),
        "extractor_version": EXTRACTOR_VERSION,
        "extractor_config_sha256": digest({"version": EXTRACTOR_VERSION}),
        "resolver_version": RESOLVER_VERSION,
        "index_policy": _policy_wire(index.policy),
        "index_policy_sha256": index.policy.sha256,
        "candidate_policy": candidate_policy.wire(),
        "candidate_policy_sha256": candidate_policy.sha256,
        "prior_index_policy": _policy_wire(prior.policy) if prior is not None else None,
        "prior_index_policy_sha256": prior.policy.sha256 if prior is not None else None,
    }


def _validate_payload(payload):
    """Structural joins only. Runtime verification below also recomputes actual source facts."""
    from .parser import EXTRACTOR_VERSION, PARSER_VERSION

    _closed(
        payload,
        {
            "report_schema_version",
            "current_snapshot",
            "prior_snapshot",
            "input",
            "extraction",
            "configuration",
            "limits",
            "counts",
            "references",
            "queries",
            "coverage",
            "items",
        },
    )
    if type(payload["report_schema_version"]) is not int or payload["report_schema_version"] != 1:
        raise CodeIndexError("unsupported_report_version")
    current = SnapshotRef(**payload["current_snapshot"])
    prior = (
        SnapshotRef(**payload["prior_snapshot"]) if payload["prior_snapshot"] is not None else None
    )
    if payload["current_snapshot"] != current.wire() or (
        prior is not None and payload["prior_snapshot"] != prior.wire()
    ):
        raise CodeIndexError("invalid_report_snapshot_fields")
    if prior and prior.repository_id != current.repository_id:
        raise CodeIndexError("report_prior_repository_mismatch")
    _closed(payload["input"], {"input_sha256", "byte_length"})
    valid_digest(payload["input"]["input_sha256"])
    _count(payload["input"]["byte_length"], 2 * 1024 * 1024)
    _closed(payload["extraction"], {"policy", "policy_sha256", "reference_count", "truncated"})
    extraction = ExtractionPolicy(**payload["extraction"]["policy"])
    _count(payload["extraction"]["reference_count"], extraction.max_references)
    if (
        payload["extraction"]["policy_sha256"] != extraction.sha256
        or payload["extraction"]["truncated"] is not False
        or payload["input"]["byte_length"] > extraction.max_input_bytes
        or payload["extraction"]["policy"] != asdict(extraction)
    ):
        raise CodeIndexError("report_extraction_mismatch")
    config = payload["configuration"]
    _closed(
        config,
        {
            "parser_version",
            "parser_config_sha256",
            "extractor_version",
            "extractor_config_sha256",
            "resolver_version",
            "index_policy",
            "index_policy_sha256",
            "candidate_policy",
            "candidate_policy_sha256",
            "prior_index_policy",
            "prior_index_policy_sha256",
        },
    )
    index_policy = _index_policy(config["index_policy"])
    candidate_policy = CandidatePolicy(**config["candidate_policy"])
    if prior is None:
        if (
            config["prior_index_policy"] is not None
            or config["prior_index_policy_sha256"] is not None
        ):
            raise CodeIndexError("report_prior_policy_mismatch")
    elif _index_policy(config["prior_index_policy"]).sha256 != config["prior_index_policy_sha256"]:
        raise CodeIndexError("report_prior_policy_mismatch")
    if config["candidate_policy"] != candidate_policy.wire():
        raise CodeIndexError("invalid_report_policy")
    if (
        config["parser_version"] != PARSER_VERSION
        or config["extractor_version"] != EXTRACTOR_VERSION
        or config["resolver_version"] != RESOLVER_VERSION
    ):
        raise CodeIndexError("unsupported_report_configuration")
    if (
        config["parser_config_sha256"] != digest({"version": PARSER_VERSION})
        or config["extractor_config_sha256"] != digest({"version": EXTRACTOR_VERSION})
        or config["index_policy_sha256"] != index_policy.sha256
        or config["candidate_policy_sha256"] != candidate_policy.sha256
    ):
        raise CodeIndexError("report_configuration_mismatch")
    if canonical_bytes(payload["limits"]) != canonical_bytes(LIMITS):
        raise CodeIndexError("invalid_report_limits")
    _closed(
        payload["counts"], {"items", "queries", "coverage_rows", "inventory_files", "by_status"}
    )
    for field, limit in (
        ("items", 128),
        ("queries", 128),
        ("coverage_rows", 128),
        ("inventory_files", 5000),
    ):
        _count(payload["counts"][field], limit)
    _closed(payload["counts"]["by_status"], STATUSES)
    for count in payload["counts"]["by_status"].values():
        _count(count, 128)
    for field in ("references", "items"):
        if type(payload[field]) is not list or len(payload[field]) > 128:
            raise CodeIndexError("report_item_limit")
    for field in ("queries", "coverage"):
        if type(payload[field]) is not dict or len(payload[field]) > 128:
            raise CodeIndexError("report_table_limit")
    references = {}
    for value in payload["references"]:
        ref = Reference(**value)
        if value != ref.wire():
            raise CodeIndexError("invalid_report_reference_fields")
        if (
            ref.id
            != reference_id(
                payload["input"]["input_sha256"],
                ref.original_start_byte,
                ref.original_end_byte,
                ref.query.sha256,
            )
            or ref.original_end_byte > payload["input"]["byte_length"]
            or ref.id in references
        ):
            raise CodeIndexError("report_reference_mismatch")
        references[ref.id] = ref
    if list(references) != sorted(references):
        raise CodeIndexError("unsorted_report_references")
    intervals = sorted(
        (ref.original_start_byte, ref.original_end_byte) for ref in references.values()
    )
    if any(left[1] > right[0] for left, right in zip(intervals, intervals[1:], strict=False)):
        raise CodeIndexError("overlapping_report_references")
    for key, value in payload["queries"].items():
        if Query(**value).sha256 != key or digest(value) != key:
            raise CodeIndexError("report_query_digest_mismatch")
    needed_queries = {ref.query.sha256 for ref in references.values()}
    if needed_queries != set(payload["queries"]):
        raise CodeIndexError("orphan_report_query")
    for ref in references.values():
        if ref.query.wire() != payload["queries"][ref.query.sha256]:
            raise CodeIndexError("report_query_reference_mismatch")
    coverage_keys = {
        "coverage_schema_version",
        "inventory_sha256",
        "query_kind",
        "query_sha256",
        "files",
        "parser_version",
        "parser_config_sha256",
        "extractor_version",
        "extractor_config_sha256",
        "query_version",
        "query_policy_sha256",
        "resolver_version",
        "index_policy_sha256",
        "candidate_policy_sha256",
        "limits",
        "counts",
        "truncated",
        "complete",
        "reasons",
    }
    for key, value in payload["coverage"].items():
        _closed(value, coverage_keys)
        if digest(value) != key or value["inventory_sha256"] != current.inventory_sha256:
            raise CodeIndexError("report_coverage_digest_mismatch")
        if (
            type(value["coverage_schema_version"]) is not int
            or value["coverage_schema_version"] != 1
            or type(value["complete"]) is not bool
            or value["truncated"] is not False
            or value["query_sha256"] not in payload["queries"]
            or value["query_kind"] != payload["queries"][value["query_sha256"]]["kind"]
        ):
            raise CodeIndexError("report_coverage_query_mismatch")
        for field in (
            "parser_version",
            "parser_config_sha256",
            "extractor_version",
            "extractor_config_sha256",
            "resolver_version",
            "index_policy_sha256",
            "candidate_policy_sha256",
        ):
            if value[field] != config[field]:
                raise CodeIndexError("report_coverage_configuration_mismatch")
        if (
            value["query_version"] != DEFAULT_EXTRACTION_POLICY.version
            or value["query_policy_sha256"] != DEFAULT_EXTRACTION_POLICY.sha256
            or value["limits"] != _policy_wire(index_policy)
        ):
            raise CodeIndexError("report_coverage_configuration_mismatch")
        if type(value["files"]) is not list or len(value["files"]) > 5000:
            raise CodeIndexError("report_coverage_file_limit")
        paths = []
        for row in value["files"]:
            if (
                type(row) is not dict
                or type(row.get("complete_kinds")) is not list
                or type(row.get("reasons")) is not list
            ):
                raise CodeIndexError("invalid_report_source_coverage")
            source = SourceCoverage(
                **(
                    row
                    | {
                        "complete_kinds": tuple(row["complete_kinds"]),
                        "reasons": tuple(row["reasons"]),
                    }
                )
            )
            paths.append(source.path)
            if row != source.wire():
                raise CodeIndexError("invalid_report_source_coverage")
        if paths != sorted(set(paths), key=lambda path: path.encode("utf-8")):
            raise CodeIndexError("duplicate_or_unsorted_report_paths")
        _closed(
            value["counts"],
            {
                "inventory_files",
                "relevant_files",
                "relevant_definitions",
                "exact_matches",
                "parsed_bytes",
                "nodes_seen",
            },
        )
        for count in value["counts"].values():
            _count(count, 10**9)
        if (
            value["counts"]["relevant_files"] != len(paths)
            or value["counts"]["inventory_files"] != payload["counts"]["inventory_files"]
        ):
            raise CodeIndexError("report_coverage_count_mismatch")
        if (
            type(value["reasons"]) is not list
            or any(type(reason) is not str for reason in value["reasons"])
            or value["reasons"] != sorted(set(value["reasons"]))
        ):
            raise CodeIndexError("invalid_report_coverage_reasons")
    item_ids, used_coverage, by_status = [], set(), dict.fromkeys(STATUSES, 0)
    for item in payload["items"]:
        _closed(
            item,
            {
                "item_id",
                "reference_id",
                "query_sha256",
                "status",
                "evidence_kind",
                "reason_code",
                "current_pointers",
                "historical_pointers",
                "ranked_candidates",
                "coverage_sha256",
                "mapping_provenance",
            },
        )
        if item["item_id"] != item["reference_id"] or item["reference_id"] not in references:
            raise CodeIndexError("report_item_reference_mismatch")
        ref = references[item["reference_id"]]
        if (
            item["query_sha256"] != ref.query.sha256
            or item["coverage_sha256"] not in payload["coverage"]
        ):
            raise CodeIndexError("report_item_join_mismatch")
        coverage = payload["coverage"][item["coverage_sha256"]]
        if coverage["query_sha256"] != ref.query.sha256:
            raise CodeIndexError("report_item_coverage_query_mismatch")
        if type(item["status"]) is not str or item["status"] not in STATUSES:
            raise CodeIndexError("invalid_report_status")
        valid_name(item["reason_code"])
        for field, snapshot in (("current_pointers", current), ("historical_pointers", prior)):
            if type(item[field]) is not list or len(item[field]) > 10:
                raise CodeIndexError("report_pointer_limit")
            for wire in item[field]:
                pointer = CodePointer(**wire)
                if snapshot is None or _identity(pointer) != _identity(snapshot):
                    raise CodeIndexError("report_pointer_identity_mismatch")
        if (
            type(item["ranked_candidates"]) is not list
            or len(item["ranked_candidates"]) > candidate_policy.max_candidates
        ):
            raise CodeIndexError("report_candidate_limit")
        for candidate in item["ranked_candidates"]:
            _closed(candidate, {"pointer", "qualified_name", "similarity", "evidence_kind"})
            pointer = CodePointer(**candidate["pointer"])
            valid_name(candidate["qualified_name"])
            if (
                _identity(pointer) != _identity(current)
                or type(candidate["similarity"]) is not str
                or re.fullmatch(r"(?:0\.\d{3}|1\.000)", candidate["similarity"]) is None
                or candidate["evidence_kind"] != "near_match_candidate"
            ):
                raise CodeIndexError("invalid_report_candidate")
        if type(item["mapping_provenance"]) is not list or len(item["mapping_provenance"]) > 1:
            raise CodeIndexError("report_mapping_limit")
        for provenance in item["mapping_provenance"]:
            _closed(
                provenance, {"source_id", "artifact_sha256", "approval_receipt_sha256", "mapping"}
            )
            # This validates wire integrity only; it does not admit this authority for lookup.
            TrustedMapping(
                MappingAuthority(
                    provenance["source_id"],
                    provenance["artifact_sha256"],
                    provenance["approval_receipt_sha256"],
                ),
                canonical_bytes(provenance["mapping"]),
            )
        c, h, n, m = (
            len(item[field])
            for field in (
                "current_pointers",
                "historical_pointers",
                "ranked_candidates",
                "mapping_provenance",
            )
        )
        evidence = item["evidence_kind"]
        valid = (
            item["status"] == "found"
            and evidence == "exact"
            and coverage["complete"]
            and (c, h, n, m) == (1, 0, 0, 0)
            or item["status"] == "ambiguous"
            and evidence in {"multiple_definitions", "coverage_incomplete"}
            and n == m == 0
            or item["status"] == "renamed_or_moved"
            and coverage["complete"]
            and (
                evidence == "verified_move"
                and (c, h, n, m) == (1, 1, 0, 1)
                or evidence == "near_match_candidate"
                and c == m == 0
                and n > 0
            )
            or item["status"] == "not_found"
            and coverage["complete"]
            and c == n == m == 0
            and (evidence == "none" and h == 0 or evidence == "removed_since_prior" and h > 0)
        )
        if not valid:
            raise CodeIndexError("report_evidence_status_mismatch")
        item_ids.append(item["item_id"])
        used_coverage.add(item["coverage_sha256"])
        by_status[item["status"]] += 1
    if item_ids != sorted(set(item_ids)) or set(item_ids) != set(references):
        raise CodeIndexError("duplicate_or_missing_report_item")
    if used_coverage != set(payload["coverage"]):
        raise CodeIndexError("orphan_report_coverage")
    if (
        len(item_ids) != payload["counts"]["items"]
        or len(references) != payload["extraction"]["reference_count"]
        or len(references) > extraction.max_references
        or len(payload["queries"]) != payload["counts"]["queries"]
        or len(payload["coverage"]) != payload["counts"]["coverage_rows"]
        or by_status != payload["counts"]["by_status"]
    ):
        raise CodeIndexError("report_count_mismatch")


@dataclass(frozen=True, slots=True)
class ReportItemRef:
    report_sha256: str
    item_id: str
    reference_id: str
    query_sha256: str
    repository_id: str
    source_kind: str
    snapshot_id: str
    inventory_sha256: str
    coverage_sha256: str

    def __post_init__(self):
        valid_name(self.repository_id)
        for value in (
            self.report_sha256,
            self.item_id,
            self.reference_id,
            self.query_sha256,
            self.inventory_sha256,
            self.coverage_sha256,
        ):
            valid_digest(value)
        if (
            self.item_id != self.reference_id
            or self.source_kind not in ("fixture_inventory", "retained_capture")
            or (
                self.source_kind == "fixture_inventory"
                and self.snapshot_id != self.inventory_sha256
            )
        ):
            raise CodeIndexError("invalid_report_item_ref")
        if self.source_kind == "retained_capture":
            valid_digest(self.snapshot_id)

    def wire(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ExistenceReport:
    preimage: bytes

    def __post_init__(self):
        try:
            _validate_payload(decode_canonical(self.preimage, max_bytes=MAX_REPORT_BYTES))
        except CodeIndexError:
            raise
        except (TypeError, KeyError, ValueError, AttributeError):
            raise CodeIndexError("invalid_report_schema") from None

    @property
    def sha256(self):
        return hashlib.sha256(self.preimage).hexdigest()

    def wire(self):
        return decode_canonical(self.preimage, max_bytes=MAX_REPORT_BYTES)

    def item_ref(self, item_id):
        payload = self.wire()
        item = next((item for item in payload["items"] if item["item_id"] == item_id), None)
        if item is None:
            raise CodeIndexError("report_item_missing")
        snapshot = payload["current_snapshot"]
        return ReportItemRef(
            self.sha256,
            item_id,
            item["reference_id"],
            item["query_sha256"],
            snapshot["repository_id"],
            snapshot["source_kind"],
            snapshot["snapshot_id"],
            snapshot["inventory_sha256"],
            item["coverage_sha256"],
        )


def build_existence_report(
    index,
    original_text,
    *,
    prior=None,
    trusted_mappings=(),
    extraction_policy=DEFAULT_EXTRACTION_POLICY,
    candidate_policy=DEFAULT_CANDIDATE_POLICY,
):
    from .index import CodeIndex

    if (
        type(index) is not CodeIndex
        or (prior is not None and type(prior) is not CodeIndex)
        or type(candidate_policy) is not CandidatePolicy
    ):
        raise CodeIndexError("invalid_report_index")
    if type(trusted_mappings) not in {tuple, list} or len(trusted_mappings) > 128:
        raise CodeIndexError("mapping_count_limit")
    refs = extract_references(original_text, extraction_policy)
    if not refs and trusted_mappings:
        raise CodeIndexError("mapping_context_without_references")
    items, queries, coverage = [], {}, {}
    encoded_value_bytes = 0
    for ref in refs:
        result = index.resolve(ref, prior, trusted_mappings, candidate_policy=candidate_policy)
        row = relevant_coverage(index, ref.query, candidate_policy)
        item = result.wire() | {"query_sha256": ref.query.sha256}
        # A running lower bound stops large tables before serializing a full oversized report.
        # The final exact cap includes container keys, separators and metadata as well.
        encoded_value_bytes += len(canonical_bytes(item)) + len(canonical_bytes(ref.wire()))
        if ref.query.sha256 not in queries:
            encoded_value_bytes += len(canonical_bytes(ref.query.wire()))
        if row.sha256 not in coverage:
            encoded_value_bytes += len(row.preimage)
        if encoded_value_bytes > MAX_REPORT_BYTES:
            raise CodeIndexError("report_byte_limit")
        queries[ref.query.sha256] = ref.query.wire()
        coverage[row.sha256] = row.wire()
        items.append(item)
    payload = {
        "report_schema_version": 1,
        "current_snapshot": index.snapshot.wire(),
        "prior_snapshot": prior.snapshot.wire() if prior is not None else None,
        "input": {
            "input_sha256": hashlib.sha256(original_text.encode()).hexdigest(),
            "byte_length": len(original_text.encode()),
        },
        "extraction": {
            "policy": asdict(extraction_policy),
            "policy_sha256": extraction_policy.sha256,
            "reference_count": len(refs),
            "truncated": False,
        },
        "configuration": _configuration(index, candidate_policy, prior),
        "limits": dict(LIMITS),
        "counts": {
            "items": len(items),
            "queries": len(queries),
            "coverage_rows": len(coverage),
            "inventory_files": len(index.reader.inventory.files),
            "by_status": {
                status: sum(item["status"] == status for item in items)
                for status in sorted(STATUSES)
            },
        },
        "references": [ref.wire() for ref in sorted(refs, key=lambda ref: ref.id)],
        "queries": queries,
        "coverage": coverage,
        "items": sorted(items, key=lambda item: item["item_id"]),
    }
    raw = canonical_bytes(payload)
    if len(raw) > MAX_REPORT_BYTES:
        raise CodeIndexError("report_byte_limit")
    return ExistenceReport(raw)


@dataclass(frozen=True, slots=True)
class ReportLookup:
    status: str
    reason_code: str
    recorded_status: str | None = None
    evidence_kind: str | None = None
    coverage_complete: bool | None = None
    scope: str = "recorded_search_scope"


def resolve_report_item(ref, artifact_bytes, index, *, prior=None, trusted_mappings=()):
    from .index import CodeIndex

    if type(ref) is not ReportItemRef or type(index) is not CodeIndex:
        return ReportLookup("unsupported", "report_domain_input_unsupported")
    if artifact_bytes is None:
        return ReportLookup("missing", "report_artifact_unavailable")
    if type(artifact_bytes) is not bytes or len(artifact_bytes) > MAX_REPORT_BYTES:
        return ReportLookup("invalid", "report_byte_limit")
    if hashlib.sha256(artifact_bytes).hexdigest() != ref.report_sha256:
        return ReportLookup("stale", "report_artifact_digest_mismatch")
    if _identity(ref) != _identity(index.snapshot):
        return ReportLookup("stale", "report_current_identity_mismatch")
    try:
        report = ExistenceReport(artifact_bytes)
        payload = report.wire()
        if payload["current_snapshot"] != index.snapshot.wire():
            return ReportLookup("stale", "report_current_capture_mismatch")
        if payload["prior_snapshot"] is not None:
            if prior is None:
                return ReportLookup("missing", "report_prior_source_unavailable")
            if type(prior) is not CodeIndex or prior.snapshot.wire() != payload["prior_snapshot"]:
                return ReportLookup("stale", "report_prior_identity_mismatch")
        elif prior is not None:
            return ReportLookup("stale", "report_unexpected_prior")
        item = next((item for item in payload["items"] if item["item_id"] == ref.item_id), None)
        if item is None:
            return ReportLookup("missing", "report_item_unavailable")
        if report.item_ref(ref.item_id) != ref:
            return ReportLookup("stale", "report_item_ref_join_mismatch")
        candidate_policy = CandidatePolicy(**payload["configuration"]["candidate_policy"])
        if payload["configuration"] != _configuration(index, candidate_policy, prior):
            return ReportLookup("stale", "report_current_configuration_mismatch")
        reference = Reference(
            **next(value for value in payload["references"] if value["id"] == ref.reference_id)
        )
        coverage = relevant_coverage(index, reference.query, candidate_policy)
        if coverage.wire() != payload["coverage"][ref.coverage_sha256]:
            return ReportLookup("stale", "report_current_coverage_mismatch")
        if item["mapping_provenance"] and not trusted_mappings:
            return ReportLookup("unsupported", "report_mapping_authority_unavailable")
        expected = index.resolve(
            reference, prior, trusted_mappings, candidate_policy=candidate_policy
        )
        if expected.wire() | {"query_sha256": reference.query.sha256} != item:
            return ReportLookup("invalid", "report_recorded_semantics_mismatch")
        return ReportLookup(
            "verified",
            "retained_scope_and_semantics_verified",
            item["status"],
            item["evidence_kind"],
            coverage.complete,
        )
    except CodeIndexError as error:
        code = str(error)
        return ReportLookup("unsupported" if code.startswith("unsupported_") else "invalid", code)
