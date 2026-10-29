"""what_bug_this_catches: payload/origin economics drift or hidden owner app imports."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from issue_triage.shared.callledger import models as ledger
from issue_triage.shared.providers import models as providers


def result_data(typed_request):
    return dict(
        schema_version=1,
        kind="typed",
        status="invalid_output",
        text=None,
        parsed=None,
        typed=None,
        error={"code": "invalid_output"},
        model_requested=typed_request.model,
        model_reported="jev-1.13.0",
        usage_raw={"input_tokens": 1000},
        normalized_usage={"input_tokens": 1000, "output_tokens": None},
        accounting_ref="event1",
        attempt_ids=["attempt1"],
        origin="live",
        source_capture=None,
        latency_ms=12.0,
        first_output_ms=None,
        first_output_kind="unavailable",
        current_external_cost_usd="0.000042",
    )


def test_invalid_paid_output_preserves_usage_without_usable_answer(typed_request):
    value = providers.validate_result_wire(json.dumps(result_data(typed_request)), typed_request)
    assert value.status == "invalid_output"
    assert value.normalized_usage.input_tokens == 1000
    assert value.normalized_usage.output_tokens is None
    assert value.current_external_cost_usd == "0.000042"
    assert value.typed is None


def test_native_typed_success_cannot_be_generated_prose(typed_request):
    data = result_data(typed_request)
    data.update(kind="generated", status="ok", text="Everything looks fine", error=None)
    with pytest.raises(ValueError, match="native typed request"):
        providers.validate_result_wire(json.dumps(data), typed_request)


@pytest.mark.parametrize("origin", ["mock", "replay"])
def test_source_cost_unknown_stays_unknown_and_current_replay_is_zero(typed_request, origin):
    data = result_data(typed_request)
    source = dict(
        capture_id="capture1",
        capture_sha256=ledger.canonical_digest("capture"),
        origin="synthetic" if origin == "mock" else "live",
        source_run_id="source-run",
        request_identity_sha256=ledger.canonical_digest("request"),
        model_requested=typed_request.model,
        model_reported=typed_request.model,
        cost_usd=None,
        latency_ms=123.0,
        first_output_kind="unavailable",
    )
    data.update(
        origin=origin, source_capture=source, current_external_cost_usd="0.00", latency_ms=1.0
    )
    value = providers.Result.model_validate(data)
    assert value.source_capture.cost_usd is None
    assert value.source_capture.latency_ms == 123.0 and value.latency_ms == 1.0
    data["current_external_cost_usd"] = "0.10"
    with pytest.raises(ValidationError):
        providers.Result.model_validate(data)


def test_unavailable_first_output_cannot_be_total_duration(typed_request):
    data = result_data(typed_request)
    data["first_output_ms"] = data["latency_ms"]
    with pytest.raises(ValidationError):
        providers.Result.model_validate(data)


def test_generation_text_and_parsed_must_agree():
    typed_request = providers.GenerateRequest.model_validate(
        dict(
            schema_version=1,
            kind="generate",
            model="synthetic",
            messages=[{"role": "user", "content": [{"type": "text", "text": "Test"}]}],
            schema={"type": "object"},
            max_output_tokens=512,
            stream=False,
        )
    )
    data = result_data(typed_request)
    data.update(
        kind="generated",
        status="ok",
        error=None,
        model_reported="synthetic",
        text='{"value":1}',
        parsed={"value": 2},
    )
    with pytest.raises(ValueError, match="inconsistency"):
        providers.validate_result_wire(json.dumps(data), typed_request)
    data["parsed"] = {"value": 1}
    assert providers.validate_result_wire(json.dumps(data), typed_request).parsed == {"value": 1}


def test_declared_shared_models_move_without_owner_namespace_or_network(tmp_path):
    source = Path(providers.__file__).resolve().parents[1]
    package = tmp_path / "detached"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    shutil.copytree(source, package / "shared", ignore=shutil.ignore_patterns("__pycache__"))
    script = """
import builtins, socket
def blocked(*a, **k): raise RuntimeError("blocked network positive control")
socket.socket=blocked
socket.create_connection=blocked
try: socket.socket()
except RuntimeError: pass
else: raise AssertionError("network control did not fail")
original=builtins.__import__
def importing(name, *args, **kwargs):
    if name.startswith("llm_router_eval"):
        raise AssertionError("owner app import forbidden")
    return original(name, *args, **kwargs)
builtins.__import__=importing
from detached.shared.providers.models import NoulAnswer, TypedJudgmentRequest
from detached.shared.callledger.models import NormalizedUsage
assert NoulAnswer(type="noul", noul=0.7).noul == 0.7
assert NormalizedUsage(input_tokens=100).output_tokens is None
assert TypedJudgmentRequest.__module__.startswith("detached.")
print("detached model closure imported without owner app/network")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "detached model closure" in completed.stdout


def test_generated_schema_bytes_match_normative_models():
    repo = Path(__file__).resolve().parents[2]
    completed = subprocess.run(
        [sys.executable, str(repo / "scripts/generate_schemas.py"), "--check"],
        cwd=repo,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "18 generated schemas" in completed.stdout
