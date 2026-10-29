"""what_bug_this_catches: -I ignores PYTHONDONTWRITEBYTECODE and writes runtime caches."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from issue_triage.worker import runner
from issue_triage.worker.bundle import analyze, parse_bundle

EXAMPLE = Path(__file__).parents[2] / "examples/local-bundle.json"


def test_actual_production_rules_child_reports_bytecode_disabled(tmp_path, monkeypatch):
    original = parse_bundle(EXAMPLE.read_bytes())
    observed = []
    actual_run = subprocess.run

    def trace_real_run(*args, **kwargs):
        # Observe the actual production launch/output, never substitute a process or result.
        completed = actual_run(*args, **kwargs)
        observed.append(json.loads(completed.stdout))
        return completed

    monkeypatch.setattr(runner.subprocess, "run", trace_real_run)
    judgment, observation = runner.run_rules(original, analyze(original), cwd=tmp_path)
    assert judgment.status == "proposal" and judgment.method == "rules"
    assert observation["isolated"] is True
    assert len(observed) == 1
    assert observed[0]["bundle_sha256"] == original.sha256
    assert observed[0]["isolated"] is True
    assert observed[0]["dont_write_bytecode"] is True
    assert observed[0]["provider_dispatch"] == "disabled"


@pytest.mark.parametrize("explicit_flag", [False, True], ids=["environment-ignored", "explicit-B"])
def test_real_isolated_interpreter_cache_control_requires_flag(tmp_path, explicit_flag):
    # The negative control imports only a new trusted probe in owned scratch. It must not
    # import application/dependency source without -B and write into a read-only runtime.
    module = tmp_path / "original_bytecode_probe.py"
    module.write_text(
        "import sys\nisolated = bool(sys.flags.isolated)\n"
        "dont_write_bytecode = sys.dont_write_bytecode\n",
        encoding="utf-8",
    )
    script = (
        "import sys,json;sys.path.insert(0," + repr(str(tmp_path)) + ");"
        "import original_bytecode_probe as p;"
        "print(json.dumps({'isolated':p.isolated,'dont_write_bytecode':p.dont_write_bytecode,"
        "'pycache_prefix':sys.pycache_prefix}))"
    )
    env = runner.child_environment("judge", os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Even startup/stdlib caches in the intentional no-B control must stay in scratch.
    # -S avoids site/.pth hooks; explicit -X works when -I ignores PYTHON* variables.
    cache = tmp_path / "owned-cache"
    args = [sys.executable, "-I", "-S", "-X", "pycache_prefix=" + str(cache)]
    if explicit_flag:
        args.append("-B")
    completed = subprocess.run(
        args + ["-c", script], cwd=tmp_path, env=env, capture_output=True, timeout=10, check=True
    )
    observed = json.loads(completed.stdout)
    assert not completed.stderr and observed["isolated"] is True
    assert observed["dont_write_bytecode"] is explicit_flag
    assert observed["pycache_prefix"] == str(cache)
    assert bool(list(cache.rglob("original_bytecode_probe*.pyc"))) is not explicit_flag
    if explicit_flag:
        assert not list(cache.rglob("*.pyc"))
