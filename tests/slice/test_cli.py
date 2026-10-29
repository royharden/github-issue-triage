"""what_bug_this_catches: API success masks unpinned CLI inputs or broken restart/replay."""

import hashlib
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from issue_triage.cli import main

EXAMPLE = Path(__file__).parents[2] / "examples/local-bundle.json"


@pytest.mark.parametrize("invalid", ["bad-sha", "malformed", "duplicate-key", "oversize"])
def test_invalid_input_is_refused_before_creating_state(tmp_path, capsys, monkeypatch, invalid):
    data = {
        "bad-sha": EXAMPLE.read_bytes(),
        "malformed": b"not JSON",
        "duplicate-key": b'{"source_kind":1,"source_kind":2}',
        "oversize": b" " * (8 * 1024 * 1024 + 1),
    }[invalid]
    source = tmp_path / "input.json"
    source.write_bytes(data)
    expected = "0" * 64 if invalid == "bad-sha" else hashlib.sha256(data).hexdigest()

    def forbidden(*args, **kwargs):
        raise AssertionError("invalid bundle must not reach transport")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    state = tmp_path / "must-not-exist"
    assert (
        main(
            [
                "triage",
                "--input",
                str(source),
                "--input-sha256",
                expected,
                "--state-dir",
                str(state),
                "--delivery-id",
                "invalid",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["status"] == "refused"
    assert not state.exists()


def test_cli_requires_explicit_input_pin_before_any_work(tmp_path):
    with pytest.raises(SystemExit) as error:
        main(
            [
                "triage",
                "--input",
                str(EXAMPLE),
                "--state-dir",
                str(tmp_path),
                "--delivery-id",
                "missing-pin",
            ]
        )
    assert error.value.code == 2


def test_separate_cli_processes_review_replay_and_dry_run(tmp_path):
    """Fresh CLI processes exercise persisted state rather than retaining Python objects."""
    state = tmp_path / "state"

    def invoke(*args):
        run = subprocess.run(
            [sys.executable, "-I", "-B", "-m", "issue_triage", *args],
            capture_output=True,
            timeout=20,
        )
        assert run.returncode == 0, run.stdout
        assert not run.stderr
        return json.loads(run.stdout)

    triage = [
        "triage",
        "--input",
        str(EXAMPLE),
        "--input-sha256",
        hashlib.sha256(EXAMPLE.read_bytes()).hexdigest(),
        "--state-dir",
        str(state),
        "--delivery-id",
        "cli-one",
    ]
    first = invoke(*triage)
    result = first["result"]
    assert first["intake"]["status"] == "queued" and first["processed"]
    assert result["source_kind"] == "fixture_inventory"
    assert result["process"]["isolated"]
    request = {
        "event_id": "cli-review",
        "issue_key": result["issue_key"],
        "field": "labels",
        "expected_revision": result["suggestions"]["revision_sha256"],
        "expected_prior_event_id": None,
        "disposition": "edit",
        "value": ["needs-info"],
        "actor_label": "synthetic-cli",
        "at_utc": "2026-10-15T04:05:00Z",
        "reason": "Provisional local review rehearsal",
    }
    decision = tmp_path / "decision.json"
    decision.write_text(json.dumps(request), encoding="utf-8")
    review = ["review", "--state-dir", str(state), "--decision", str(decision), "--provisional"]
    accepted = invoke(*review)
    assert accepted["authority"] == "agent_provisional"
    assert not accepted["remote_apply_allowed"]
    args = ["dry-run", "--state-dir", str(state), "--issue", result["issue_key"], "--provisional"]
    preview = invoke(*args)
    assert len(preview["receipts"]) == 1
    assert preview["receipts"][0]["payload"] == {"labels": ["needs-info"]}
    assert preview["http_writes"] == 0
    assert invoke(*args) == preview
    assert invoke(*review)["receipt"]["outcome"] == "exact_retry"
    repeated = invoke(*triage)
    assert repeated["intake"]["status"] == "duplicate" and not repeated["processed"]
    assert repeated["result"] == result
