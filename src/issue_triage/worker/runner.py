"""Actual isolated interpreter plus an explicit environment projection; no OS sandbox claim."""

import json
import os
import subprocess
import sys
from pathlib import Path

from ..judges.contracts import JudgeHold, JudgmentRecord
from ..runtime.env import COMMON, child_environment
from ..suggest.comments import validate_current_judgment


def run_rules(bundle, analysis, *, cwd, supplied_environment=None):
    if analysis.context.screen.decision != "pass":
        raise JudgeHold("screen_needs_human")
    env = child_environment(
        "judge", os.environ if supplied_environment is None else supplied_environment
    )
    bootstrap = (
        "import sys;sys.path.insert(0,"
        + repr(str(Path(__file__).resolve().parents[2]))
        + ");from issue_triage.worker.rules import main;raise SystemExit(main())"
    )
    try:
        run = subprocess.run(
            [sys.executable, "-I", "-B", "-c", bootstrap],
            input=bundle.canonical_bytes(),
            cwd=cwd,
            env=env,
            capture_output=True,
            timeout=10,
        )
        if run.returncode or len(run.stdout) > 65536 or run.stderr:
            raise ValueError
        value = json.loads(run.stdout)
        if set(value) != {
            "bundle_sha256",
            "judgment",
            "isolated",
            "dont_write_bytecode",
            "environment_names",
            "provider_dispatch",
        }:
            raise ValueError
        allowed = COMMON | {"PYTHONUTF8", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE", "LC_CTYPE"}
        if (
            value["bundle_sha256"] != bundle.sha256
            or value["isolated"] is not True
            or value["dont_write_bytecode"] is not True
            or value["provider_dispatch"] != "disabled"
            or not set(value["environment_names"]) <= allowed
        ):
            raise ValueError
        judgment = JudgmentRecord.model_validate(value["judgment"])
        _, judgment = validate_current_judgment(analysis.context, judgment)
        return judgment, {
            key: value[key] for key in ("isolated", "environment_names", "provider_dispatch")
        }
    except subprocess.TimeoutExpired:
        raise JudgeHold("rules_subprocess_timeout") from None
    except Exception:
        raise JudgeHold("rules_subprocess_unavailable") from None
