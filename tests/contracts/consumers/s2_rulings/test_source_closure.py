"""what_bug_this_catches: a hash-only copy passes while journal/replay/import behavior breaks."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from issue_triage.shared.rulings.models import WIRE_MODELS

ROOT = Path(__file__).resolve().parents[4]
MANIFEST = ROOT / "docs/vendor/s2-rulings/SOURCE.001.json"
SOURCE = json.loads(MANIFEST.read_bytes())
GUARD = """import importlib.abc, socket, sys
class DenyForeign(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name.split('.')[0] in {
            'rfr','issue_triage','openai','typesafe','typesafeai','fastapi',
            'httpx','requests','aiohttp','PIL','pytesseract'
        }:
            raise RuntimeError('foreign application/provider import denied')
sys.meta_path.insert(0, DenyForeign())
def no_network(*args, **kwargs): raise RuntimeError('network denied')
socket.create_connection = no_network
socket.socket.connect = no_network
"""


@pytest.mark.parametrize("entry", SOURCE["entries"], ids=lambda e: e["consumer_path"])
def test_all_actual_consumer_objects_match_declared_exact_source_mapping(entry):
    value = (ROOT / entry["consumer_path"]).read_bytes()
    assert hashlib.sha256(value).hexdigest() == entry["consumer_sha256"]
    assert len(value) == entry["bytes"]
    if entry.get("mapping") == "byte-identical":
        assert entry["consumer_sha256"] == entry["source_sha256"]
    else:
        assert entry["original_assertions_removed"] == 0


def test_pinned_publication_schema_and_license_do_not_expand_authority():
    assert SOURCE["source_commit"] == "455d73c6efe283fdf3919267532de7ad5d39924b"
    assert SOURCE["source_tree"] == "100dc262ed0bd53d52e4a508cfc22aabecbb5aaa"
    assert len(SOURCE["entries"]) == 16 and SOURCE["license"] == "MIT"
    assert "MIT License" in (ROOT / "src/issue_triage/shared/LICENSE.S2-RULINGS").read_text()
    schema = json.loads((ROOT / "src/issue_triage/shared/rulings/schema.json").read_bytes())
    assert schema["schemas"] == {model.__name__: model.model_json_schema() for model in WIRE_MODELS}
    assert not any("docio" in entry["source_path"] for entry in SOURCE["entries"])


def test_full_actual_moved_journal_suite_with_owner_consumer_and_providers_denied(tmp_path):
    runtime = ROOT / "src/issue_triage/shared/rulings"
    shutil.copytree(
        runtime, tmp_path / "src/standalone_rulings", ignore=shutil.ignore_patterns("__pycache__")
    )
    owner = Path(__file__).parent / "owner"
    moved = tmp_path / "tests/contracts/consumers/s2_rulings/owner"
    moved.mkdir(parents=True)
    for original in owner.glob("*.py"):
        text = original.read_text(encoding="utf-8")
        text = text.replace("issue_triage.shared.rulings", "standalone_rulings")
        text = text.replace("src/issue_triage/shared/rulings", "src/standalone_rulings")
        (moved / original.name).write_text(text, encoding="utf-8", newline="\n")
    # Non-isolated real process workers inherit only the moved source path and this denial hook.
    (tmp_path / "src/sitecustomize.py").write_text(GUARD, encoding="utf-8")
    script = f"""import sys, importlib
sys.path.insert(0, {str(tmp_path / "src")!r})
exec({GUARD!r})
for name in ('rfr', 'issue_triage', 'openai', 'typesafe'):
    try: importlib.import_module(name)
    except RuntimeError: pass
    else: raise AssertionError('import denial canary failed')
try: socket.create_connection(('synthetic.invalid', 443))
except RuntimeError: pass
else: raise AssertionError('network denial canary failed')
import pytest
raise SystemExit(pytest.main([
    {str(moved)!r}, '-q', '--basetemp', {str(tmp_path / "owned-temp")!r},
    '--junitxml', {str(tmp_path / "moved.xml")!r}
]))
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    run = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    import xml.etree.ElementTree as ET

    cases = ET.parse(tmp_path / "moved.xml").getroot().findall(".//testcase")
    assert len(cases) == 49 and all(not list(case) for case in cases)
