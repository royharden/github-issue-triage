"""what_bug_this_catches: canonical citation drift or omitted source/license/helper closure."""

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
MANIFEST = json.loads((ROOT / "docs/vendor/s5/SOURCE.001.json").read_bytes())


@pytest.mark.parametrize("entry", MANIFEST["entries"], ids=lambda entry: entry["destination_path"])
def test_exact_source_or_explicit_mapped_asset(entry):
    path = Path(entry["destination_path"])
    assert not path.is_absolute() and ".." not in path.parts
    assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == entry["adapted_sha256"]
    if entry["adaptation"].startswith("none"):
        assert entry["source_sha256"] == entry["adapted_sha256"]


def test_complete_runtime_notice_and_bounded_helper():
    entries = MANIFEST["entries"]
    assert len({entry["destination_path"] for entry in entries}) == len(entries) == 10
    assert len([entry for entry in entries if entry["source_path"].startswith("src/")]) == 6
    assert any(
        entry["destination_path"] == "src/issue_triage/shared/LICENSE.S5" for entry in entries
    )
    helper = ROOT / "tests/contracts/consumers/s5/owner/tests/cited/_s5_public_wires.py"
    assert "def domain_wires" in helper.read_text()
    assert "def test_" not in helper.read_text()


def test_actual_whole_memory_runtime_controls_under_detached_namespace(tmp_path):
    """what_bug_this_catches: smoke succeeds but moved positive/negative closure imports the app."""
    import shutil
    import subprocess
    import sys
    import xml.etree.ElementTree as ET

    portable = tmp_path / "portable/cited"
    portable.mkdir(parents=True)
    (portable.parent / "__init__.py").write_bytes(b"")
    for source in (ROOT / "src/issue_triage/shared/cited").glob("*.py"):
        shutil.copyfile(source, portable / source.name)
    shutil.copyfile(ROOT / "src/issue_triage/shared/LICENSE.S5", portable / "LICENSE")
    tests = tmp_path / "tests"
    tests.mkdir()
    for name in ("test_memory.py", "_s5_public_wires.py"):
        raw = (ROOT / "tests/contracts/consumers/s5/owner/tests/cited" / name).read_bytes()
        (tests / name).write_bytes(raw.replace(b"issue_triage.shared.cited", b"portable.cited"))
    (tests / "conftest.py").write_text(
        "import sys,builtins,socket\nfrom pathlib import Path\n"
        "sys.path.insert(0,str(Path(__file__).resolve().parents[1]))\n"
        "original=builtins.__import__\n"
        "def guarded(name,*args,**kwargs):\n"
        " if name.split('.')[0] in "
        "{'issue_triage','changelog_advisor','openai','typesafe','requests','httpx'}:"
        " raise AssertionError('owner/app/provider import forbidden')\n"
        " return original(name,*args,**kwargs)\n"
        "def denied(*args,**kwargs):raise AssertionError('network forbidden')\n"
        "builtins.__import__=guarded\nsocket.socket=denied\nsocket.create_connection=denied\n"
        "for canary in (lambda:__import__('issue_triage'),"
        "lambda:__import__('changelog_advisor'),lambda:socket.socket()):\n"
        " try:canary()\n except AssertionError:pass\n else:raise AssertionError('missing guard')\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-m",
            "pytest",
            str(tests),
            "-q",
            "-p",
            "no:cacheprovider",
            "--junitxml=" + str(tmp_path / "moved.xml"),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    nodes = list(ET.parse(tmp_path / "moved.xml").getroot().iter("testcase"))
    assert nodes and not any(
        list(node.iter(tag)) for node in nodes for tag in ("failure", "error", "skipped")
    )
