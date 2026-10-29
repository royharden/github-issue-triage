"""what_bug_this_catches: canonical S3 drift, dropped license/assets or unrecorded test edits."""

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
MANIFEST = json.loads((ROOT / "docs/vendor/s3/SOURCE.002.json").read_bytes())


@pytest.mark.parametrize("entry", MANIFEST["entries"], ids=lambda entry: entry["destination_path"])
def test_published_source_and_adapted_tests_are_exact(entry):
    relative = Path(entry["destination_path"])
    assert not relative.is_absolute() and ".." not in relative.parts
    actual = (ROOT / relative).read_bytes()
    assert hashlib.sha256(actual).hexdigest() == entry["adapted_sha256"]
    if entry["adaptation"].startswith("none"):
        assert entry["adapted_sha256"] == entry["source_sha256"]


def test_complete_canonical_closure_and_license_are_retained():
    entries = MANIFEST["entries"]
    destinations = [entry["destination_path"] for entry in entries]
    assert len(destinations) == len(set(destinations))
    canonical = [entry for entry in entries if entry["source_path"].startswith("src/")]
    assert len(canonical) == MANIFEST["canonical_source_files"] == 14
    assert all(entry["adapted_sha256"] == entry["source_sha256"] for entry in canonical)
    assert "src/issue_triage/shared/LICENSE.S3" in destinations
    assert "tests/contracts/consumers/s3/owner/prices/synthetic-unit-v1.json" in destinations
    assert "tests/contracts/consumers/s3/owner/scripts/generate_schemas.py" in destinations
