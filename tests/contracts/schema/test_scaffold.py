"""what_bug_this_catches: offline status reads secrets or implies live/human authority."""

import json
from pathlib import Path

import pytest

from issue_triage.__main__ import main


def test_scaffold_needs_neither_network_nor_credentials(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("Scaffold attempted network or file access")

    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("socket.socket", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setenv("OPENAI_API_KEY_FILE", "unreadable-test-placeholder")
    monkeypatch.setenv("TYPESAFE_API_KEY_FILE", "unreadable-test-placeholder")
    assert main(["--offline"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["mode"] == "offline"
    assert status["dry_run"] is True
    assert status["triage_implemented"] is True
    assert status["triage_scope"] == "explicit_fixture_inventory_only"
    assert status["evaluations"] == "not_yet_measured"
    assert status["stage"] == "local_fixture_workflow"
    assert status["human_authority"] == "not_authenticated"
    assert status["live_apply"] == "unavailable"
    assert status["fixtures"] == "independent_corpus_sealed_agent_provisional"


def test_live_flag_is_rejected_without_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Unsupported live mode attempted network")

    monkeypatch.setattr("socket.create_connection", forbidden)
    with pytest.raises(SystemExit) as caught:
        main(["--live"])
    assert caught.value.code == 2
