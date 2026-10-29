"""what_bug_this_catches: missing scope, old pointers or similarity claimed as current truth."""

from dataclasses import replace

import pytest

from issue_triage.shared.codeindex.canonical import CodeIndexError, canonical_bytes, digest
from issue_triage.shared.codeindex.index import build_index, resolve_pointer
from issue_triage.shared.codeindex.inventory import InventoryReader, inventory_from_files
from issue_triage.shared.codeindex.models import IndexPolicy, SnapshotRef
from issue_triage.shared.codeindex.references import extract_references
from issue_triage.shared.codeindex.resolution import (
    CandidatePolicy,
    MappingAuthority,
    TrustedMapping,
    relevant_coverage,
)


def index_for(files, *, repository="original-resolution-controls", **limits):
    inventory = inventory_from_files(files)
    return build_index(
        SnapshotRef(
            repository,
            "fixture_inventory",
            inventory.sha256,
            inventory.sha256,
            "2026-10-15T00:00:00Z",
            True,
        ),
        InventoryReader(inventory, files),
        IndexPolicy(**limits),
    )


def reference(text="target()", **changes):
    return replace(extract_references(text)[0], **changes)


def approved_mapping(prior, current, old="target", new="renamed", **changes):
    before = next(item for item in prior.definitions if item.name == old)
    after = next(item for item in current.definitions if item.name == new)
    payload = {
        "mapping_schema_version": 1,
        "prior_pointer": before.pointer.wire(),
        "current_pointer": after.pointer.wire(),
        "prior_qualified_name": before.qualified_name,
        "current_qualified_name": after.qualified_name,
    } | changes
    raw = canonical_bytes(payload)
    authority = MappingAuthority(
        "synthetic-host-approved-map", digest(payload), digest("synthetic approval fixture")
    )
    return TrustedMapping(authority, raw)


def test_exact_current_pointer_and_qualified_suffix_not_usage():
    index = index_for({"pkg/api.py": b"class Box:\n def target(self): return 1\n"})
    result = index.resolve(reference("Box.target()"))
    assert (result.status, result.evidence_kind) == ("found", "exact")
    assert result.current_pointers[0] == index.exists("pkg.api.Box.target", "function")
    assert result.current_pointers[0].line_start == 2
    assert not result.historical_pointers and not result.ranked_candidates
    assert index.resolve(reference("missing()")).status == "not_found"


def test_duplicate_definitions_cannot_be_arbitrarily_selected():
    index = index_for({"a.py": b"def target(): pass\n", "b.py": b"def target(): pass\n"})
    result = index.resolve(reference())
    assert (result.status, result.evidence_kind) == ("ambiguous", "multiple_definitions")
    assert [pointer.path for pointer in result.current_pointers] == ["a.py", "b.py"]
    assert index.exists("target", "function") is None
    scoped = index.resolve(reference(path_hint="b.py"))
    assert scoped.status == "found" and scoped.current_pointers[0].path == "b.py"


@pytest.mark.parametrize(
    "other",
    [
        {"unknown.custom": b"opaque"},
        {"broken.py": b"def broken(:"},
        {"generated.py": b"# @generated\ndef mystery(): pass\n"},
        {"vendor/extra.py": b"def mystery(): pass\n"},
    ],
)
def test_partial_scope_prevents_confident_absence_and_uniqueness(other):
    index = index_for({"a.py": b"def target(): pass\n"} | other)
    for ref in (reference(), reference("missing()")):
        result = index.resolve(ref)
        assert result.status == "ambiguous" and result.evidence_kind == "coverage_incomplete"
        assert not relevant_coverage(index, ref.query).complete


def test_explicit_language_scope_and_path_absence_are_bound_in_coverage():
    index = index_for({"a.py": b"def target(): pass\n", "bad.ts": b"function {"})
    assert index.resolve(reference()).status == "ambiguous"
    ref = reference(language_hint="python")
    assert index.resolve(ref).status == "found"
    coverage = relevant_coverage(index, ref.query)
    assert [row["path"] for row in coverage.wire()["files"]] == ["a.py"]
    assert index.resolve(reference(path_hint="missing.py")).status == "not_found"
    unknown = index_for({"a.py": b"def target(): pass\n", "opaque.custom": b"opaque"})
    assert unknown.resolve(ref).status == "ambiguous"


def test_coverage_preimage_accounts_for_every_retained_path_and_policy_separately():
    files = {"a.py": b"def target(): pass\n", "README.md": b"docs"}
    normal = index_for(files)
    limited = index_for(files, max_nodes_per_file=1)
    query = reference().query
    first, second = relevant_coverage(normal, query), relevant_coverage(limited, query)
    assert normal.snapshot.inventory_sha256 == limited.snapshot.inventory_sha256
    assert first.sha256 != second.sha256
    assert first.wire()["inventory_sha256"] == normal.snapshot.inventory_sha256
    assert first.wire()["counts"]["relevant_files"] == 2
    assert [row["path"] for row in first.wire()["files"]] == ["README.md", "a.py"]
    wire = first.wire()
    wire["complete"] = False
    assert first.complete and digest(first.wire()) == first.sha256
    with pytest.raises(CodeIndexError, match="coverage_inventory_mismatch"):
        relevant_coverage(replace(normal, coverage=normal.coverage[:1]), query)


def test_removed_symbol_returns_only_historical_pointer_and_never_current_exists():
    prior = index_for({"before.py": b"def target(): return 7\n"})
    current = index_for({"after.py": b"# original empty module\n"})
    result = current.resolve(reference(), prior=prior)
    assert (result.status, result.evidence_kind) == ("not_found", "removed_since_prior")
    assert not result.current_pointers and len(result.historical_pointers) == 1
    assert current.exists("target", "function") is None
    pointer = result.historical_pointers[0]
    assert resolve_pointer(pointer, prior.snapshot, prior.reader) == "verified"
    assert resolve_pointer(pointer, current.snapshot, current.reader) == "stale"


def test_equal_bodies_unrelated_names_do_not_establish_move_or_lineage():
    prior = index_for({"a.py": b"def target(): return 7\n"})
    current = index_for({"b.py": b"def zebra(): return 7\n"})
    result = current.resolve(reference(), prior=prior)
    assert result.status == "not_found" and not result.mapping_provenance
    assert not result.ranked_candidates


def test_multiple_lexical_candidates_are_explicitly_tentative_and_bounded():
    current = index_for({"a.py": b"def dispatch_tasks(): pass\ndef dispatch_task_now(): pass\n"})
    result = current.resolve(
        reference("dispatch_task()"), candidate_policy=CandidatePolicy(minimum_score_millis=300)
    )
    assert (result.status, result.evidence_kind) == ("renamed_or_moved", "near_match_candidate")
    assert not result.current_pointers and not result.mapping_provenance
    assert len(result.ranked_candidates) == 2
    assert all(
        candidate.wire()["evidence_kind"] == "near_match_candidate"
        for candidate in result.ranked_candidates
    )
    assert all(type(candidate.similarity) is str for candidate in result.ranked_candidates)
    assert canonical_bytes(result.wire())
    limited = current.resolve(
        reference("dispatch_task()"),
        candidate_policy=CandidatePolicy(minimum_score_millis=300, max_candidates=1),
    )
    assert len(limited.ranked_candidates) == 1
    assert limited.coverage_sha256 != result.coverage_sha256


def test_explicit_host_mapping_validates_both_actual_unique_definitions():
    prior = index_for({"old.py": b"def target(): return 1\n"})
    current = index_for({"new.py": b"def renamed(): return 2\n"})
    mapping = approved_mapping(prior, current)
    result = current.resolve(reference(), prior, [mapping])
    assert (result.status, result.evidence_kind) == ("renamed_or_moved", "verified_move")
    assert result.current_pointers[0].path == "new.py"
    assert result.historical_pointers[0].path == "old.py"
    assert result.mapping_provenance == (mapping,)
    assert (
        result.wire()["mapping_provenance"][0]["artifact_sha256"]
        == mapping.authority.artifact_sha256
    )
    # Same-name current facts take precedence; mappings never erase an actual exact result.
    still = index_for(
        {"new.py": b"def renamed(): return 2\n", "old.py": b"def target(): return 1\n"}
    )
    fresh = approved_mapping(prior, still)
    assert still.resolve(reference(), prior, [fresh]).status == "found"


@pytest.mark.parametrize(
    "mutation", ["prior_hash", "current_hash", "prior_name", "current_name", "line", "snapshot"]
)
def test_mapping_mismatches_never_fall_back_to_verified_move(mutation):
    prior = index_for({"old.py": b"def target(): return 1\n"})
    current = index_for({"new.py": b"def renamed(): return 2\n"})
    payload = approved_mapping(prior, current).wire()["mapping"]
    if mutation.endswith("hash"):
        payload[mutation.split("_")[0] + "_pointer"]["source_sha256"] = digest("wrong source")
    elif mutation.endswith("name"):
        payload[mutation.split("_")[0] + "_qualified_name"] = "forged.name"
    elif mutation == "line":
        payload["current_pointer"]["line_start"] = payload["current_pointer"]["line_end"] = 999
    else:
        payload["current_pointer"]["snapshot_id"] = payload["current_pointer"][
            "inventory_sha256"
        ] = digest("other snapshot")
    mapping = TrustedMapping(
        MappingAuthority("synthetic-approved", digest(payload), digest("approval fixture")),
        canonical_bytes(payload),
    )
    with pytest.raises(CodeIndexError, match="trusted_mapping_definition_mismatch"):
        current.resolve(reference(), prior, [mapping])


def test_mapping_requires_actual_configured_hash_and_unique_closure():
    prior = index_for({"old.py": b"def target(): pass\n"})
    current = index_for({"new.py": b"def renamed(): pass\n"})
    mapping = approved_mapping(prior, current)
    with pytest.raises(CodeIndexError, match="mapping_artifact_mismatch"):
        TrustedMapping(
            replace(mapping.authority, artifact_sha256=digest("unapproved")), mapping.preimage
        )
    with pytest.raises(CodeIndexError, match="context_required"):
        current.resolve(reference(), trusted_mappings=[mapping])
    with pytest.raises(CodeIndexError, match="duplicate_trusted_mapping"):
        current.resolve(reference(), prior, [mapping, mapping])
    duplicate = index_for({"new.py": b"def renamed(): pass\ndef renamed(): pass\n"})
    with pytest.raises(CodeIndexError, match="definition_mismatch"):
        duplicate.resolve(reference(), prior, [approved_mapping(prior, duplicate)])
    incomplete = index_for({"new.py": b"def renamed(): pass\n", "opaque.unknown": b"?"})
    with pytest.raises(CodeIndexError, match="definition_mismatch"):
        incomplete.resolve(reference(), prior, [approved_mapping(prior, incomplete)])


def test_cross_repository_prior_and_mapping_are_rejected():
    prior = index_for({"old.py": b"def target(): pass\n"}, repository="other")
    current = index_for({"new.py": b"def renamed(): pass\n"})
    with pytest.raises(CodeIndexError, match="prior_repository_mismatch"):
        current.resolve(reference(), prior)


def test_binary_empty_and_case_mismatched_paths_never_get_fake_lines():
    index = index_for({"empty.py": b"", "binary.py": b"\0bytes", "Case.py": b"# text\n"})
    for path in ("empty.py", "binary.py"):
        result = index.resolve(reference(path))
        assert result.status == "ambiguous" and not result.current_pointers
        assert (
            "present_path_without_readable_pointer"
            in relevant_coverage(index, reference(path).query).wire()["reasons"]
        )
    assert index.resolve(reference("case.py")).status == "not_found"
    assert index.resolve(reference("Case.py")).status == "found"


def test_pointer_overflow_and_invalid_policy_are_explicit():
    index = index_for({f"p{number}.py": b"def target(): pass\n" for number in range(11)})
    result = index.resolve(reference())
    assert result.status == "ambiguous" and result.reason_code == "pointer_limit"
    assert len(result.current_pointers) == 10
    assert relevant_coverage(index, reference().query).wire()["counts"]["exact_matches"] == 11
    with pytest.raises(CodeIndexError, match="invalid_candidate_policy"):
        CandidatePolicy(minimum_score_millis=True)


def test_occurrence_ids_remain_distinct_and_query_coverage_reusable():
    index = index_for({"a.py": b"def target(): pass\n"})
    refs = extract_references("target() then target()")
    left, right = (index.resolve(ref) for ref in refs)
    assert left.reference_id != right.reference_id
    assert left.coverage_sha256 == right.coverage_sha256
    assert left.wire()["item_id"] == left.reference_id


def test_identical_definition_bytes_in_another_module_are_not_verified_lineage():
    raw = b"def target(): return 7\n"
    prior = index_for({"a.py": raw})
    current = index_for({"b.py": raw})
    result = current.resolve(
        reference("a.target()"), prior, candidate_policy=CandidatePolicy(minimum_score_millis=300)
    )
    assert result.evidence_kind == "near_match_candidate" and not result.mapping_provenance
    assert not result.current_pointers
    assert result.historical_pointers[0].path == "a.py"
    assert (
        prior.reader.inventory.files[0].source_sha256
        == current.reader.inventory.files[0].source_sha256
    )


def test_history_overflow_and_conflicting_path_hint_are_explicit():
    prior = index_for({f"p{number}.py": b"def target(): pass\n" for number in range(11)})
    current = index_for({"now.py": b"# no definitions\n"})
    result = current.resolve(reference(), prior)
    assert result.status == "ambiguous" and result.reason_code == "historical_pointer_limit"
    assert len(result.historical_pointers) == 10
    ref = reference("now.py", path_hint="elsewhere.py")
    assert current.resolve(ref).status == "ambiguous"
    assert "conflicting_path_hint" in relevant_coverage(current, ref.query).wire()["reasons"]


def test_issue_text_or_model_dictionary_is_never_a_trusted_mapping():
    current = index_for({"now.py": b"# original control\n"})
    with pytest.raises(CodeIndexError, match="trusted_mapping_context_required"):
        current.resolve(reference(), current, [{"approved": True, "move": "target"}])
    with pytest.raises(CodeIndexError, match="mapping_count_limit"):
        current.resolve(reference(), current, [None] * 129)
