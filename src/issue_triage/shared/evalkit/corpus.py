"""Bounded frozen corpus validation; no source acquisition, tuning or implicit resealing."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import TYPE_CHECKING

from .identity import ordered_ids_digest
from .models import GoldRecord, Manifest, ManifestEnrichmentResult, S1MinimalManifest

if TYPE_CHECKING:
    from .interfaces import DomainAdapter


class FrozenCorpusError(ValueError):
    """Closed reason codes without private paths/source/label payloads."""


def _is_link(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def contained_corpus_path(root: Path, relative: str) -> Path:
    from .models import SplitEntry

    SplitEntry.relative_path(relative)
    root = Path(root).absolute()
    if not root.is_dir() or any(_is_link(part) for part in (*root.parents, root)):
        raise FrozenCorpusError("invalid_corpus_root")
    canonical_root = root.resolve(strict=True)
    current = root
    for component in relative.split("/"):
        current = current / component
        if not os.path.lexists(current) or _is_link(current):
            raise FrozenCorpusError("missing_or_linked_corpus")
    resolved = current.resolve(strict=True)
    if not resolved.is_relative_to(canonical_root) or not resolved.is_file():
        raise FrozenCorpusError("corpus_containment_failure")
    return resolved


def validate_records(
    records: tuple[GoldRecord, ...], manifest: Manifest, split: str, adapter: DomainAdapter
) -> None:
    entries = [entry for entry in manifest.splits if entry.split == split]
    if len(entries) != 1:
        raise FrozenCorpusError("missing_or_ambiguous_split")
    entry = entries[0]
    ids = tuple(record.item_id for record in records)
    if len(records) != entry.item_count or ids != entry.ordered_item_ids:
        raise FrozenCorpusError("frozen_count_or_order_changed")
    if ordered_ids_digest(ids) != entry.ordered_ids_sha256:
        raise FrozenCorpusError("frozen_order_digest_changed")
    for record in records:
        if record.split != split or manifest.group_split_map.get(record.group_id) != split:
            raise FrozenCorpusError("group_split_leakage")
        if record.item_id not in manifest.group_members.get(record.group_id, ()):
            raise FrozenCorpusError("case_group_membership_changed")
        try:
            adapter.validate_gold(record)
        except Exception:
            raise FrozenCorpusError("invalid_domain_gold") from None


def load_corpus(
    root: Path,
    manifest: Manifest,
    split: str,
    adapter: DomainAdapter,
    *,
    max_bytes: int = 10 * 1024 * 1024,
    max_rows: int = 100000,
    max_row_bytes: int = 64 * 1024,
) -> tuple[GoldRecord, ...]:
    if any(type(n) is not int or n <= 0 for n in (max_bytes, max_rows, max_row_bytes)):
        raise ValueError("positive bounded corpus limits required")
    entries = [entry for entry in manifest.splits if entry.split == split]
    if len(entries) != 1:
        raise FrozenCorpusError("missing_or_ambiguous_split")
    entry = entries[0]
    path = contained_corpus_path(root, entry.items_file)
    if path.stat().st_size > max_bytes or entry.item_count > max_rows:
        raise FrozenCorpusError("corpus_limit")
    data = path.read_bytes()
    if len(data) > max_bytes or hashlib.sha256(data).hexdigest() != entry.items_sha256:
        raise FrozenCorpusError("frozen_corpus_bytes_changed")
    lines = data.splitlines()
    if len(lines) > max_rows or any(not line or len(line) > max_row_bytes for line in lines):
        raise FrozenCorpusError("corpus_row_limit_or_blank")
    try:
        records = tuple(GoldRecord.model_validate_json(line) for line in lines)
    except ValueError:
        raise FrozenCorpusError("invalid_gold_wire") from None
    validate_records(records, manifest, split, adapter)
    return records


def s1_minimal_to_evalkit(
    minimal: S1MinimalManifest, records: tuple[GoldRecord, ...], enrichment: dict[str, object]
) -> ManifestEnrichmentResult:
    """An explicitly enriched full candidate or needs_owner_metadata; never reseal partial input."""
    required = {
        "manifest_id",
        "parent_manifest_sha256",
        "partition_provenance",
        "scorer_version",
        "comparator_config",
        "domain_adapter_ref",
        "experiment_refs",
        "splits",
        "group_split_map",
        "group_members",
        "source_artifacts",
        "publication_policy",
        "run_history_ref",
    }
    missing = tuple(sorted(required - enrichment.keys()))
    if records and not enrichment.get("source_artifacts"):
        missing = tuple(sorted(set(missing) | {"source_artifacts"}))
    if missing:
        return ManifestEnrichmentResult(
            status="needs_owner_metadata", canonical_manifest=None, missing_metadata=missing
        )
    for field, expected in (("split_seed", minimal.seed), ("frozen_at", minimal.frozen_at)):
        if field in enrichment:
            from .statistics import typed_equal

            if not typed_equal(enrichment[field], expected):
                raise FrozenCorpusError("minimal_freeze_or_seed_changed")
    if "schema_version" in enrichment and type(enrichment["schema_version"]) is not int:
        raise FrozenCorpusError("minimal_schema_changed")
    if "schema_version" in enrichment and enrichment["schema_version"] != 1:
        raise FrozenCorpusError("minimal_schema_changed")
    actual_ids = tuple(record.item_id for record in records)
    if len(records) != minimal.item_count:
        raise FrozenCorpusError("minimal_count_changed")
    value = enrichment | {
        "schema_version": 1,
        "split_seed": minimal.seed,
        "frozen_at": minimal.frozen_at,
    }
    try:
        # JSON boundary preserves strict tuple/list wire conversion without coercing bool counters.
        from .identity import canonical_bytes

        manifest = Manifest.model_validate_json(canonical_bytes(value))
    except ValueError:
        raise FrozenCorpusError("invalid_enrichment") from None
    entries = [entry for entry in manifest.splits if entry.split == minimal.split]
    if len(entries) != 1:
        raise FrozenCorpusError("minimal_split_changed")
    entry = entries[0]
    if (entry.items_file, entry.item_count, entry.ordered_item_ids) != (
        minimal.items_file,
        minimal.item_count,
        actual_ids,
    ):
        raise FrozenCorpusError("minimal_identity_or_order_changed")
    if any(record.split != minimal.split for record in records):
        raise FrozenCorpusError("minimal_row_split_changed")
    return ManifestEnrichmentResult(
        status="ready", canonical_manifest=manifest, missing_metadata=()
    )
