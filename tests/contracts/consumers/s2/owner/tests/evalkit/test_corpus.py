"""Authored tiny corpus controls, not independent heldout Gold or actual human data."""

import hashlib
import json
from pathlib import Path

import pytest

from issue_triage.shared.evalkit.corpus import (
    FrozenCorpusError,
    contained_corpus_path,
    load_corpus,
    s1_minimal_to_evalkit,
)
from issue_triage.shared.evalkit.identity import ordered_ids_digest
from issue_triage.shared.evalkit.models import GoldRecord, Manifest, S1MinimalManifest


class Adapter:
    def validate_gold(self, record):
        assert record.label_source == "synthetic"


def fixture(root: Path):
    h = "a" * 64
    rows = tuple(
        GoldRecord.model_validate(
            {
                "item_id": "case:" + str(i),
                "dataset": "tiny",
                "group_id": "g" + str(i),
                "split": "dev",
                "label_version": "fixture/1",
                "source_ref": {"handle": "private:" + str(i), "sha256": h},
                "input_sha256": h,
                "label_source": "synthetic",
                "label_provenance_ref": None,
                "domain_kind": "conformance",
                "label_payload": {"kind": "domain_labels", "payload": {"target": bool(i)}},
            }
        )
        for i in range(2)
    )
    data = ("\n".join(record.model_dump_json() for record in rows) + "\n").encode()
    file = root / "dev.jsonl"
    file.write_bytes(data)
    pinned = {"status": "available", "ref": "fixture/1", "sha256": h}
    wire = {
        "manifest_id": "tiny",
        "parent_manifest_sha256": None,
        "split_seed": None,
        "partition_provenance": "published_canonical",
        "frozen_at": "2026-01-01T00:00:00Z",
        "scorer_version": "fixture/1",
        "comparator_config": pinned,
        "domain_adapter_ref": pinned,
        "experiment_refs": {"gold": pinned},
        "splits": (
            {
                "split": "dev",
                "items_file": "dev.jsonl",
                "item_count": 2,
                "ordered_item_ids": tuple(r.item_id for r in rows),
                "items_sha256": hashlib.sha256(data).hexdigest(),
                "ordered_ids_sha256": ordered_ids_digest(tuple(r.item_id for r in rows)),
                "group_ids": ("g0", "g1"),
            },
        ),
        "group_split_map": {"g0": "dev", "g1": "dev"},
        "group_members": {"g0": ("case:0",), "g1": ("case:1",)},
        "source_artifacts": (
            {
                "namespace": "synthetic-corpus",
                "status": "available",
                "sha256": hashlib.sha256(data).hexdigest(),
                "count": 2,
                "member_ids": tuple(r.item_id for r in rows),
            },
        ),
        "publication_policy": {
            "mode": "aggregate_only",
            "allowed_dimensions": (),
            "allowed_value_sets": {},
            "allowed_numeric_metrics": (),
            "synthetic_example_refs": (),
        },
        "run_history_ref": "fixture-history",
    }
    return rows, Manifest.model_validate(wire), file


def test_actual_order_hash_count_and_group_frozen_corpus(tmp_path):
    rows, manifest, file = fixture(tmp_path)
    assert load_corpus(tmp_path, manifest, "dev", Adapter()) == rows
    before = file.read_bytes()
    file.write_bytes(before + b" ")
    with pytest.raises(FrozenCorpusError, match="frozen_corpus_bytes_changed"):
        load_corpus(tmp_path, manifest, "dev", Adapter())
    assert file.read_bytes() == before + b" "  # validation never repairs or silently reseals


def test_wrong_label_domain_count_limits_and_missing_split(tmp_path):
    _, manifest, _ = fixture(tmp_path)
    with pytest.raises(FrozenCorpusError):
        load_corpus(tmp_path, manifest, "heldout", Adapter())
    with pytest.raises(FrozenCorpusError):
        load_corpus(tmp_path, manifest, "dev", Adapter(), max_bytes=1)
    with pytest.raises(FrozenCorpusError):
        load_corpus(tmp_path, manifest, "dev", Adapter(), max_rows=1)

    class Rejecting:
        def validate_gold(self, record):
            raise ValueError("private label CANARY")

    with pytest.raises(FrozenCorpusError, match="invalid_domain_gold") as failure:
        load_corpus(tmp_path, manifest, "dev", Rejecting())
    assert "CANARY" not in str(failure.value)


def test_s1_partial_missing_metadata_cannot_make_canonical_and_freeze_preserved(tmp_path):
    rows, manifest, _ = fixture(tmp_path)
    minimal = S1MinimalManifest.model_validate(
        {
            "schema": 1,
            "split": "dev",
            "seed": None,
            "frozen_at": manifest.frozen_at,
            "items_file": "dev.jsonl",
            "item_count": 2,
        }
    )
    missing = s1_minimal_to_evalkit(minimal, rows, {})
    assert missing.status == "needs_owner_metadata" and missing.canonical_manifest is None
    enrichment = manifest.model_dump()
    for key in ("schema_version", "split_seed", "frozen_at"):
        enrichment.pop(key)
    result = s1_minimal_to_evalkit(minimal, rows, enrichment)
    assert (
        result.canonical_manifest.split_seed is None
        and result.canonical_manifest.frozen_at == minimal.frozen_at
    )
    bad = json.loads(manifest.model_dump_json())
    bad["splits"][0]["items_file"] = "other.jsonl"
    for key in ("schema_version", "split_seed", "frozen_at"):
        bad.pop(key)
    with pytest.raises(FrozenCorpusError):
        s1_minimal_to_evalkit(minimal, rows, bad)


def test_relative_paths_cannot_escape_or_resolve_links(tmp_path):
    outside = tmp_path.parent / "outside-synthetic"
    outside.mkdir(exist_ok=True)
    for relative in ("../outside-synthetic/a.jsonl", "/a.jsonl", r"C:\a.jsonl", "a/../b.jsonl"):
        with pytest.raises(ValueError):
            contained_corpus_path(tmp_path, relative)
    # Missing targets cannot be repaired or inferred from filenames.
    with pytest.raises(FrozenCorpusError):
        contained_corpus_path(tmp_path, "missing.jsonl")


def test_actual_native_link_reparse_corpus_refuses_without_reading_target(tmp_path):
    import os
    import subprocess

    outside = tmp_path / "owned-target"
    outside.mkdir()
    (outside / "data.jsonl").write_text("synthetic private canary")
    root = tmp_path / "corpus"
    root.mkdir()
    alias = root / "alias"
    if os.name == "nt":
        run = subprocess.run(
            ["cmd", "/d", "/c", "mklink", "/J", str(alias), str(outside)],
            capture_output=True,
            timeout=10,
        )
        assert run.returncode == 0
    else:
        os.symlink(outside, alias, target_is_directory=True)
    try:
        with pytest.raises(FrozenCorpusError):
            contained_corpus_path(root, "alias/data.jsonl")
        assert (outside / "data.jsonl").read_text() == "synthetic private canary"
    finally:
        if os.name == "nt":
            os.rmdir(alias)
        else:
            alias.unlink()


def test_enrichment_freeze_seed_changes_refuse_and_empty_source_stays_partial(tmp_path):
    rows, manifest, _ = fixture(tmp_path)
    minimal = S1MinimalManifest.model_validate(
        {
            "schema": 1,
            "split": "dev",
            "seed": None,
            "frozen_at": manifest.frozen_at,
            "items_file": "dev.jsonl",
            "item_count": 2,
        }
    )
    enrichment = manifest.model_dump()
    for key in ("schema_version", "split_seed", "frozen_at"):
        enrichment.pop(key)
    for field, value in (
        ("frozen_at", "2026-02-01T00:00:00Z"),
        ("split_seed", False),
        ("split_seed", 0),
    ):
        with pytest.raises(FrozenCorpusError):
            s1_minimal_to_evalkit(minimal, rows, enrichment | {field: value})
    partial = s1_minimal_to_evalkit(minimal, rows, enrichment | {"source_artifacts": ()})
    assert partial.status == "needs_owner_metadata" and partial.canonical_manifest is None
