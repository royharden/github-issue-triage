"""what_bug_this_catches: canonical eval math/schema drift or unrecorded source/test fork."""

import hashlib
import json
from pathlib import Path

import pytest

from issue_triage.shared.evalkit import models, runner, statistics

ROOT = Path(__file__).resolve().parents[4]
MANIFEST = json.loads((ROOT / "docs/vendor/s2/SOURCE.001.json").read_bytes())


@pytest.mark.parametrize("entry", MANIFEST["entries"], ids=lambda entry: entry["destination_path"])
def test_exact_published_runtime_and_explicit_test_mapping(entry):
    path = Path(entry["destination_path"])
    assert not path.is_absolute() and ".." not in path.parts
    data = (ROOT / path).read_bytes()
    assert hashlib.sha256(data).hexdigest() == entry["adapted_sha256"]
    if entry["adaptation"].startswith("none"):
        assert entry["source_sha256"] == entry["adapted_sha256"]


def test_complete_module_license_and_conformance_closure():
    entries = MANIFEST["entries"]
    assert len(entries) == 21
    assert len({entry["destination_path"] for entry in entries}) == 21
    assert sum(entry["source_path"].startswith("src/") for entry in entries) == 11
    assert sum(entry["source_path"].startswith("tests/") for entry in entries) == 9
    assert "src/issue_triage/shared/LICENSE.S2" in {entry["destination_path"] for entry in entries}


def test_schema_bundle_matches_actual_canonical_models_after_namespace_move():
    actual = json.loads(Path(models.__file__).with_name("schema.json").read_bytes())
    assert actual == {
        "module": "evalkit",
        "schema_bundle_version": 1,
        "stage": "models-only",
        "schemas": {model.__name__: model.model_json_schema() for model in models.WIRE_MODELS},
    }


def test_actual_runtime_uses_same_canonical_prediction_outcome_types():
    assert runner.Prediction is models.Prediction
    assert runner.PublicMethodInput is models.PublicMethodInput
    assert statistics.Outcome is models.Outcome
    for module in (models, runner, statistics):
        Path(module.__file__).resolve().relative_to(ROOT / "src/issue_triage/shared/evalkit")
