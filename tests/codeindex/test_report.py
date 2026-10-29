"""what_bug_this_catches: self hashing, orphan joins or hashed false search claims accepted."""

import hashlib
import socket
import subprocess
from dataclasses import replace

import pytest

from issue_triage.shared.codeindex.canonical import CodeIndexError, canonical_bytes, digest
from issue_triage.shared.codeindex.index import build_index
from issue_triage.shared.codeindex.inventory import InventoryReader, inventory_from_files
from issue_triage.shared.codeindex.models import IndexPolicy, SnapshotRef
from issue_triage.shared.codeindex.references import ExtractionPolicy, Query
from issue_triage.shared.codeindex.report import (
    MAX_REPORT_BYTES,
    ExistenceReport,
    build_existence_report,
    resolve_report_item,
)
from issue_triage.shared.codeindex.resolution import MappingAuthority, TrustedMapping


def index_for(files=None, **limits):
    files = {"a.py": b"def target():\n return 7\n"} if files is None else files
    inventory = inventory_from_files(files)
    return build_index(
        SnapshotRef(
            "original-report-controls",
            "fixture_inventory",
            inventory.sha256,
            inventory.sha256,
            "2026-10-15T00:00:00Z",
            True,
        ),
        InventoryReader(inventory, files),
        IndexPolicy(**limits),
    )


def case(text="target()", files=None, **kwargs):
    index = index_for(files)
    report = build_existence_report(index, text, **kwargs)
    return index, report, report.item_ref(report.wire()["items"][0]["item_id"])


def changed_lookup(payload, ref, index, **kwargs):
    raw = canonical_bytes(payload)
    return resolve_report_item(
        replace(ref, report_sha256=hashlib.sha256(raw).hexdigest()), raw, index, **kwargs
    )


def rehash_coverage(payload, ref):
    old = ref.coverage_sha256
    value = payload["coverage"].pop(old)
    new = digest(value)
    payload["coverage"][new] = value
    for item in payload["items"]:
        if item["coverage_sha256"] == old:
            item["coverage_sha256"] = new
    return replace(ref, coverage_sha256=new)


def test_nonrecursive_canonical_report_and_external_ref_are_stable():
    index, report, ref = case("é target() then target() and missing()")
    assert report.sha256 == hashlib.sha256(report.preimage).hexdigest()
    assert report.preimage == canonical_bytes(report.wire())
    assert b'"report_sha256":' not in report.preimage
    assert report.wire()["counts"]["items"] == 3
    assert report.wire()["counts"]["queries"] == report.wire()["counts"]["coverage_rows"] == 2
    assert len({item["reference_id"] for item in report.wire()["items"]}) == 3
    result = resolve_report_item(ref, report.preimage, index)
    assert result.status == "verified" and result.scope == "recorded_search_scope"
    wire = report.wire()
    wire["counts"]["items"] = 999
    assert report.wire()["counts"]["items"] == 3
    assert (
        build_existence_report(index, "é target() then target() and missing()").preimage
        == report.preimage
    )


@pytest.mark.parametrize("text,expected", [("target()", "found"), ("missing()", "not_found")])
def test_complete_positive_and_negative_scope_is_verified_locally(text, expected):
    index, report, ref = case(text)
    result = resolve_report_item(ref, report.preimage, index)
    assert result.status == "verified" and result.recorded_status == expected
    assert result.coverage_complete is True
    assert ref.report_sha256 == report.sha256
    assert ref.query_sha256 in report.wire()["queries"]


def test_valid_incomplete_report_never_becomes_absence_evidence():
    index, report, ref = case("missing()", {"opaque.custom": b"unknown source"})
    result = resolve_report_item(ref, report.preimage, index)
    assert result.status == "verified" and result.recorded_status == "ambiguous"
    assert result.coverage_complete is False
    payload = report.wire()
    item = payload["items"][0]
    item.update(status="not_found", evidence_kind="none", reason_code="complete_scope_no_match")
    assert changed_lookup(payload, ref, index).status == "invalid"


@pytest.mark.parametrize(
    "mutation",
    [
        "self_hash",
        "counts",
        "limits",
        "duplicate_item",
        "orphan_query",
        "orphan_coverage",
        "query_digest",
        "query_nulls",
        "coverage_digest",
        "unknown_item",
        "bool_count",
        "missing_policy_field",
        "missing_snapshot_field",
    ],
)
def test_closed_schema_preimages_and_unique_table_joins_are_required(mutation):
    index, report, ref = case()
    payload = report.wire()
    if mutation == "self_hash":
        payload["report_sha256"] = report.sha256
    elif mutation == "counts":
        payload["counts"]["items"] += 1
    elif mutation == "limits":
        payload["limits"]["max_items"] = 999
    elif mutation == "duplicate_item":
        payload["items"].append(dict(payload["items"][0]))
    elif mutation == "orphan_query":
        query = Query("function", "orphan")
        payload["queries"][query.sha256] = query.wire()
    elif mutation == "orphan_coverage":
        row = dict(payload["coverage"][ref.coverage_sha256])
        row["reasons"] = ["orphan-control"]
        payload["coverage"][digest(row)] = row
    elif mutation == "query_digest":
        payload["queries"][ref.query_sha256]["normalized_query"] = "other"
    elif mutation == "query_nulls":
        del payload["queries"][ref.query_sha256]["language_hint"]
    elif mutation == "coverage_digest":
        payload["coverage"][ref.coverage_sha256]["counts"]["exact_matches"] = 999
    elif mutation == "unknown_item":
        payload["items"][0]["unexpected"] = True
    elif mutation == "bool_count":
        payload["extraction"]["reference_count"] = True
    elif mutation == "missing_policy_field":
        del payload["configuration"]["index_policy"]["version"]
    else:
        del payload["current_snapshot"]["coverage"]
    assert changed_lookup(payload, ref, index).status == "invalid"


def test_self_consistent_coverage_hash_does_not_prove_actual_search_scope():
    index, report, ref = case()
    payload = report.wire()
    payload["coverage"][ref.coverage_sha256]["counts"]["exact_matches"] = 999
    ref = rehash_coverage(payload, ref)
    raw = canonical_bytes(payload)
    assert ExistenceReport(raw)  # Well-formed record, still false about actual retained scope.
    result = changed_lookup(payload, ref, index)
    assert (result.status, result.reason_code) == ("stale", "report_current_coverage_mismatch")


def test_self_consistent_report_cannot_change_actual_definition_lines():
    index, report, ref = case()
    payload = report.wire()
    pointer = payload["items"][0]["current_pointers"][0]
    pointer["line_start"] = pointer["line_end"] = 2
    assert ExistenceReport(canonical_bytes(payload))
    result = changed_lookup(payload, ref, index)
    assert (result.status, result.reason_code) == ("invalid", "report_recorded_semantics_mismatch")


@pytest.mark.parametrize("field", ["query_sha256", "coverage_sha256", "item_id"])
def test_external_ref_joins_are_checked_without_fallback(field):
    index, report, ref = case()
    updates = {field: digest("wrong join")}
    if field == "item_id":
        updates["reference_id"] = updates["item_id"]
    result = resolve_report_item(replace(ref, **updates), report.preimage, index)
    assert result.status in {"stale", "missing"}


def test_changed_source_policy_capture_or_artifact_is_stale():
    index, report, ref = case()
    changed = index_for({"a.py": b"def target():\n return 8\n"})
    assert (
        resolve_report_item(ref, report.preimage, changed).reason_code
        == "report_current_identity_mismatch"
    )
    policy = index_for(max_nodes_per_file=2)
    assert (
        resolve_report_item(ref, report.preimage, policy).reason_code
        == "report_current_configuration_mismatch"
    )
    time = replace(index, snapshot=replace(index.snapshot, captured_at="2026-10-15T00:00:01Z"))
    assert (
        resolve_report_item(ref, report.preimage, time).reason_code
        == "report_current_capture_mismatch"
    )
    assert resolve_report_item(ref, report.preimage + b" ", index).status == "stale"
    assert resolve_report_item(ref, None, index).status == "missing"


@pytest.mark.parametrize("suffix", [b"\n", b',"report_schema_version":1}'])
def test_noncanonical_or_duplicate_json_keys_are_rejected(suffix):
    index, report, ref = case()
    raw = report.preimage + suffix if suffix == b"\n" else report.preimage[:-1] + suffix
    result = resolve_report_item(
        replace(ref, report_sha256=hashlib.sha256(raw).hexdigest()), raw, index
    )
    assert result.status == "invalid"


def test_history_requires_retained_prior_and_binds_prior_policy():
    prior = index_for()
    current = index_for({"now.py": b"# removed\n"})
    report = build_existence_report(current, "target()", prior=prior)
    ref = report.item_ref(report.wire()["items"][0]["item_id"])
    assert resolve_report_item(ref, report.preimage, current).status == "missing"
    result = resolve_report_item(ref, report.preimage, current, prior=prior)
    assert result.status == "verified" and result.evidence_kind == "removed_since_prior"
    other_policy = index_for(max_nodes_per_file=1)
    assert resolve_report_item(ref, report.preimage, current, prior=other_policy).status == "stale"


def test_mapping_provenance_in_report_does_not_admit_its_own_authority():
    prior = index_for({"a.py": b"def target(): pass\n"})
    current = index_for({"b.py": b"def renamed(): pass\n"})
    old = next(item for item in prior.definitions if item.name == "target")
    new = next(item for item in current.definitions if item.name == "renamed")
    payload = {
        "mapping_schema_version": 1,
        "prior_pointer": old.pointer.wire(),
        "current_pointer": new.pointer.wire(),
        "prior_qualified_name": old.qualified_name,
        "current_qualified_name": new.qualified_name,
    }
    mapping = TrustedMapping(
        MappingAuthority(
            "synthetic-host-configuration", digest(payload), digest("synthetic approval fixture")
        ),
        canonical_bytes(payload),
    )
    report = build_existence_report(current, "target()", prior=prior, trusted_mappings=[mapping])
    ref = report.item_ref(report.wire()["items"][0]["item_id"])
    result = resolve_report_item(ref, report.preimage, current, prior=prior)
    assert (
        result.status == "unsupported"
        and result.reason_code == "report_mapping_authority_unavailable"
    )
    admitted = resolve_report_item(
        ref, report.preimage, current, prior=prior, trusted_mappings=[mapping]
    )
    assert admitted.status == "verified" and admitted.evidence_kind == "verified_move"


def test_empty_reports_and_whole_input_limits_never_return_partial_reports():
    index = index_for()
    report = build_existence_report(index, "ordinary prose")
    assert report.wire()["counts"]["items"] == 0 and not report.wire()["queries"]
    with pytest.raises(CodeIndexError, match="report_item_missing"):
        report.item_ref(digest("absent"))
    with pytest.raises(CodeIndexError, match="reference_count_limit"):
        build_existence_report(index, "target() " * 129)
    with pytest.raises(CodeIndexError, match="reference_input_limit"):
        build_existence_report(
            index, "X" * 21, extraction_policy=ExtractionPolicy(max_input_bytes=20)
        )
    with pytest.raises(CodeIndexError, match="canonical_byte_limit"):
        ExistenceReport(b" " * (MAX_REPORT_BYTES + 1))
    assert resolve_report_item(None, None, index).status == "unsupported"


def test_report_build_and_verification_cannot_start_processes_or_network(monkeypatch):
    index = index_for()

    def denied(*args, **kwargs):
        raise AssertionError("local report must not perform external effects")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    report = build_existence_report(index, "target() missing()")
    for item in report.wire()["items"]:
        assert (
            resolve_report_item(report.item_ref(item["item_id"]), report.preimage, index).status
            == "verified"
        )


def test_large_query_scope_tables_fail_whole_report_before_returning_prefix():
    # Memory-only POSIX paths; no long path is materialized on Windows.
    index = index_for(
        {"a" * 3000 + str(number) + ".py": b"# original empty module\n" for number in range(20)}
    )
    text = " ".join(f"missing{number}()" for number in range(90))
    with pytest.raises(CodeIndexError, match="report_byte_limit"):
        build_existence_report(index, text)
