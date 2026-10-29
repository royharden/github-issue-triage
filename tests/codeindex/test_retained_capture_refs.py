"""Retained record identity never becomes fixture identity or authenticated Git origin."""

import hashlib
from dataclasses import replace

import pytest
from issue_triage.shared.codeindex.canonical import CodeIndexError, canonical_bytes
from issue_triage.shared.codeindex.cited_adapter import to_cited_file, to_cited_report
from issue_triage.shared.codeindex.index import build_index
from issue_triage.shared.codeindex.inventory import InventoryReader, inventory_from_files
from issue_triage.shared.codeindex.models import CodePointer, SnapshotRef
from issue_triage.shared.codeindex.report import (
    ExistenceReport,
    build_existence_report,
    resolve_report_item,
)

STAMP = "2026-10-21T00:00:00Z"
RECORD = "a" * 64


def retained_case(record=RECORD):
    files = {"a.py": b"def target():\n    return 1\n"}
    inventory = inventory_from_files(files)
    snapshot = SnapshotRef(
        "test-repository", "retained_capture", record, inventory.sha256, STAMP, True
    )
    index = build_index(snapshot, InventoryReader(inventory, files))
    report = build_existence_report(index, "target()")
    item = report.wire()["items"][0]
    return index, report, report.item_ref(item["item_id"])


def test_retained_snapshot_pointer_and_report_round_trip_preserve_record_identity():
    index, report, ref = retained_case()
    pointer = index.exists("target", "function")
    assert pointer is not None
    assert pointer.source_kind == ref.source_kind == "retained_capture"
    assert pointer.snapshot_id == ref.snapshot_id == index.snapshot.snapshot_id == RECORD
    assert pointer.inventory_sha256 == ref.inventory_sha256 != RECORD
    assert pointer.source_sha256 == hashlib.sha256(index.reader.read(pointer.path)).hexdigest()
    assert 1 <= pointer.line_start <= pointer.line_end <= 2
    assert CodePointer(**pointer.wire()) == pointer
    assert SnapshotRef(**index.snapshot.wire()) == index.snapshot
    restored = ExistenceReport(report.preimage)
    assert restored.preimage == canonical_bytes(restored.wire())
    assert restored.sha256 == report.sha256
    verified = resolve_report_item(ref, restored.preimage, index)
    assert (verified.status, verified.recorded_status) == ("verified", "found")


@pytest.mark.parametrize("record", ["a" * 40, "A" * 64, "g" * 64, 1])
def test_retained_identity_requires_exact_capture_record_digest(record):
    index, report, ref = retained_case()
    with pytest.raises(CodeIndexError):
        replace(index.snapshot, snapshot_id=record)
    with pytest.raises(CodeIndexError):
        replace(index.exists("target", "function"), snapshot_id=record)
    with pytest.raises(CodeIndexError):
        replace(ref, snapshot_id=record)


@pytest.mark.parametrize(
    "kind", ["git_commit", "configured_transport", "synthetic_transport", "other"]
)
def test_kind_label_does_not_admit_other_sources(kind):
    index, _, ref = retained_case()
    with pytest.raises(CodeIndexError):
        replace(index.snapshot, source_kind=kind)
    with pytest.raises(CodeIndexError):
        replace(index.exists("target", "function"), source_kind=kind)
    with pytest.raises(CodeIndexError):
        replace(ref, source_kind=kind)


def test_fixture_wire_identity_and_canonical_citation_behavior_stay_unchanged():
    index, _, _ = retained_case()
    fixture = replace(
        index.snapshot, source_kind="fixture_inventory", snapshot_id=index.reader.inventory.sha256
    )
    fixture_index = build_index(fixture, index.reader)
    pointer = fixture_index.exists("target", "function")
    assert pointer.snapshot_id == pointer.inventory_sha256
    assert to_cited_file(pointer).locator.source_kind == "fixture_inventory"
    with pytest.raises(CodeIndexError, match="fixture_identity_mismatch"):
        replace(fixture, snapshot_id=RECORD)


def test_report_rejects_mismatched_pointer_record_and_lookup_rejects_stale_record():
    index, report, ref = retained_case()
    altered = report.wire()
    altered["items"][0]["current_pointers"][0]["snapshot_id"] = "b" * 64
    with pytest.raises(CodeIndexError, match="report_pointer_identity_mismatch"):
        ExistenceReport(canonical_bytes(altered))
    other_index, _, _ = retained_case("b" * 64)
    assert resolve_report_item(ref, report.preimage, other_index).status == "stale"


def test_s5_bridge_refuses_retained_capture_without_relabeling():
    index, _, ref = retained_case()
    with pytest.raises(ValueError):
        to_cited_file(index.exists("target", "function"))
    with pytest.raises(ValueError):
        to_cited_report(ref)
