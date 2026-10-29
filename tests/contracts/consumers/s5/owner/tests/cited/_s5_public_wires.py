"""what_bug_this_catches: structural metadata silently becomes evidence or authority."""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from issue_triage.shared.cited import DOMAIN_KEYS, POINTER_ADAPTER, Finding, SourceArtifact
from issue_triage.shared.cited.models import (
    ArtifactRef,
    Resolution,
    ResolutionProvenance,
)
from issue_triage.shared.cited.schema import encoded_schemas

RAW = "a" * 64
ARTIFACT = "b" * 64
PAGE = "c" * 64
QUERY = "d" * 64


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def wire(source_type="supplied_text", subtype="line", kind="file:line", locator=None):
    """Construct synthetic wire inputs; hashes are placeholders, not captured source proof."""
    return {
        "schema_version": 1,
        "kind": kind,
        "source_type": source_type,
        "locator_subtype": subtype,
        "source_id": "source-1",
        "source_sha256": RAW,
        "source_revision": "generation-1",
        "evidence_artifact_sha256": ARTIFACT,
        "provenance_ref": None,
        "locator": {"line_start": 1, "line_end": 2} if locator is None else locator,
    }


def region(**changes):
    result = {
        "document_id": "source-1",
        "page_id": "page-1",
        "page_index": 0,
        "page_sha256": PAGE,
        "page_digest_algorithm": "rgba8-source-grid-v1",
        "source_grid_profile": "retained-rgba8/1",
        "width_px": 100,
        "height_px": 80,
        "units": "px",
        "origin": "top-left",
        "bbox_px": None,
        "word_ids": None,
        "line_ids": ["line-1"],
        "excerpt_sha256": None,
        "transform_ref": None,
    }
    result.update(changes)
    return result


def snapshot():
    return {
        "repository_id": "source-1",
        "source_kind": "fixture_inventory",
        "snapshot_id": RAW,
        "inventory_sha256": RAW,
    }


def domain_wires():
    base = [
        wire(),
        wire(
            "configured_log",
            locator={"line_start": 1, "line_end": 2, "view_kind": "redacted_result"},
        ),
        wire(
            "repository_file",
            locator={
                **snapshot(),
                "path": "src/a.py",
                "line_start": 1,
                "line_end": 1,
                "definition_kind": "function",
            },
        ),
        wire(
            "code_existence_report",
            "report_item",
            "doc:section",
            {
                **snapshot(),
                "item_id": QUERY,
                "reference_id": QUERY,
                "query_sha256": PAGE,
                "coverage_sha256": ARTIFACT,
            },
        ),
        wire("supplied_text", "section", "doc:section", {"section_id": "release-1"}),
        wire("document_page", "region", "doc:page:bbox", region()),
        wire("screenshot_collection", "source_region", "doc:page:bbox", region()),
        wire(
            "product_catalog",
            "record_field",
            "row:id",
            {
                "dataset_id": "source-1",
                "record_id": "record-1",
                "field_id": "name",
                "quote": "  é Fixture NAME  ",
                "excerpt_sha256": digest("  é Fixture NAME  "),
            },
        ),
        {**wire("event_table", "row", "row:id"), "locator": None},
        {**wire("metric_table", "metric", "row:id"), "locator": None},
        wire("saved_web", "fragment", "url#fragment", {"fragment_id": "anchor-1"}),
        wire("advisory_record", "id", "advisory:id", {"advisory_id": "GHSA-fixture"}),
    ]
    for value in base:
        if value["source_type"] == "configured_log":
            value["source_revision"] = f"sha256:{RAW}"
        if value["source_type"] == "product_catalog":
            value["source_revision"] = f"rg1:{RAW}"
            field = {
                "algorithm": "product-record-field-evidence-v1",
                "dataset_id": "source-1",
                "record_id": "record-1",
                "source_sha256": RAW,
                "source_revision": f"rg1:{RAW}",
                "field_id": "name",
                "raw_value": value["locator"]["quote"],
            }
            value["evidence_artifact_sha256"] = digest(
                json.dumps(
                    field,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
            )
        if value["source_type"] in ("repository_file", "code_existence_report"):
            value["source_revision"] = f"snapshot:fixture_inventory:{RAW}"
        if value["source_type"] == "repository_file":
            value["evidence_artifact_sha256"] = RAW
    return base
