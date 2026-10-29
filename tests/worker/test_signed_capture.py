"""Original synthetic composition controls, with no sockets, subprocesses or real keys."""

import gzip
import hashlib
import hmac
import io
import json
import tarfile
from datetime import UTC, datetime

import pytest

from issue_triage.cli import main
from issue_triage.shared.codeindex.canonical import canonical_bytes
from issue_triage.shared.ghapp.capture import RepositoryIdentity
from issue_triage.shared.ghapp.reader import ReadResponse
from issue_triage.store import JobStore
from issue_triage.worker.capture_checks import check_capture
from issue_triage.worker.signed_capture import receive_signed_capture

IDENTITY = RepositoryIdentity(11, 22, "synthetic", "composition")
STAMP = "2026-10-21T00:00:10Z"
NOW = int(datetime(2026, 10, 21, tzinfo=UTC).timestamp())
SECRET = b"public-composition-webhook-control"
TOKEN = "public-composition-token-canary"
SHA = "a" * 40
PERMISSIONS = {"contents": "read", "issues": "read", "metadata": "read"}


@pytest.fixture(autouse=True)
def deny_external_effects(monkeypatch):
    import os
    import socket
    import subprocess

    def denied(*args, **kwargs):
        pytest.fail("composition controls must not invoke real network/process effects")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(os, "system", denied)


class Signer:
    def __init__(self):
        self.calls = 0

    def sign(self, data, *, algorithm):
        self.calls += 1
        assert algorithm == "RS256" and type(data) is bytes
        return b"invented-non-rsa-signature"


def archive():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as handle:
        body = b"def alpha():\n    return 1\n"
        info = tarfile.TarInfo("synthetic-root/src/main.py")
        info.size = len(body)
        handle.addfile(info, io.BytesIO(body))
    return gzip.compress(stream.getvalue(), mtime=0)


class Transport:
    def __init__(self, *, failure=None):
        self.calls = []
        self.failure = failure

    def post_token(self, request, **bounds):
        self.calls.append("token")
        assert request.payload() == {"repository_ids": [22], "permissions": PERMISSIONS}
        assert 0 < bounds["timeout_seconds"] <= 30
        if self.failure == "token":
            return ReadResponse(403, {}, b"denied")
        return ReadResponse(
            201,
            {},
            canonical_bytes(
                {
                    "token": TOKEN,
                    "permissions": PERMISSIONS,
                    "repositories": [{"id": 22}],
                    "repository_selection": "selected",
                    "expires_at": "2026-10-21T01:00:00Z",
                }
            ),
        )

    def get(self, request, **bounds):
        self.calls.append(request.url)
        assert request.headers["authorization"] == "Bearer " + TOKEN
        assert 0 < bounds["timeout_seconds"] <= 30
        root = "https://api.github.com/repos/synthetic/composition"
        if request.url == root:
            value = {"id": 22, "full_name": "synthetic/composition", "default_branch": "main"}
        elif request.url == root + "/commits/main":
            value = {"sha": SHA}
        else:
            assert request.url == root + "/tarball/" + SHA
            body = b"invalid archive" if self.failure == "archive" else archive()
            return ReadResponse(200, {}, body)
        return ReadResponse(200, {}, canonical_bytes(value))


def raw_issue(*, updated="2026-10-21T00:00:01Z", title="Check alpha()", owner="synthetic"):
    return canonical_bytes(
        {
            "action": "opened",
            "installation": {"id": 11},
            "repository": {"id": 22, "owner": {"login": owner}, "name": "composition"},
            "issue": {
                "number": 3,
                "title": title,
                "body": "Please inspect alpha().",
                "updated_at": updated,
                "user": {"id": 12, "login": "synthetic-author"},
            },
        }
    )


def submit(jobs, transport, signer, *, raw=None, **changes):
    raw = raw_issue() if raw is None else raw
    options = dict(
        signature_header="sha256=" + hmac.new(SECRET, raw, hashlib.sha256).hexdigest(),
        webhook_secret=SECRET,
        delivery_id="composition-1",
        event="issues",
        received_at=STAMP,
        captured_at=STAMP,
        issuer="synthetic-app",
        signer=signer,
        registered_permissions=PERMISSIONS,
        transport=transport,
        now_seconds=NOW,
        clock=lambda: 0,
        provenance="synthetic_transport",
    )
    options.update(changes)
    return receive_signed_capture(jobs, IDENTITY, raw, **options)


def test_signed_intake_token_capture_restart_reference_and_cli(tmp_path, capsys):
    database = tmp_path / "capture.sqlite3"
    port, signer = Transport(), Signer()
    with JobStore(database) as jobs:
        first = submit(jobs, port, signer)
        assert first.outcome.status == "queued"
        assert len(port.calls) == 4 and port.calls[0] == "token" and signer.calls == 1
        assert jobs.status_counts() == {"queued": 1}
        stored = "\n".join(jobs.connection.iterdump())
        assert TOKEN not in stored and SECRET.decode() not in stored
    with JobStore(database) as jobs:
        before = tuple(jobs.connection.iterdump())
        report = check_capture(jobs, IDENTITY, first.outcome.work_key).wire()
        assert tuple(jobs.connection.iterdump()) == before
        assert report["capture"]["snapshot_id"] == first.snapshot_id
        assert report["capture"]["commit_sha"] == SHA
        assert report["capture"]["source_kind"] == "retained_capture"
        assert report["capture"]["authenticated_github_origin"] is False
        assert report["current_processing_authority"] is False
        assert report["s5_cited_proposals_supported"] is False
        assert any(item["status"] == "found" for item in report["report"]["items"])
    assert main(cli_args(database, first.outcome.work_key)) == 0
    output = capsys.readouterr().out
    assert json.loads(output) == report
    assert TOKEN not in output and SECRET.decode() not in output


def cli_args(database, work_key):
    return [
        "--offline",
        "capture-check",
        "--database",
        str(database),
        "--work-key",
        work_key,
        "--installation-id",
        "11",
        "--repository-id",
        "22",
        "--owner",
        "synthetic",
        "--repository",
        "composition",
    ]


@pytest.mark.parametrize("delivery_id", ["composition-1", "composition-new-guid"])
def test_replay_and_new_guid_coalescing_never_reacquire_token(tmp_path, delivery_id):
    port, signer = Transport(), Signer()
    with JobStore(tmp_path / "replay.sqlite3") as jobs:
        first = submit(jobs, port, signer)
        repeated = submit(jobs, port, signer, delivery_id=delivery_id)
        assert repeated.outcome.status == "duplicate"
        assert repeated.outcome.work_key == first.outcome.work_key
        assert repeated.snapshot_id == first.snapshot_id
        assert len(port.calls) == 4 and signer.calls == 1
        assert jobs.status_counts() == {"queued": 1}


@pytest.mark.parametrize("fault", ["signature", "payload", "repository"])
def test_authentication_and_repository_refusal_precede_signing_or_effects(tmp_path, fault):
    port, signer = Transport(), Signer()
    with JobStore(tmp_path / "refuse.sqlite3") as jobs:
        before = tuple(jobs.connection.iterdump())
        changes = {"signature_header": "sha256=" + "0" * 64} if fault == "signature" else {}
        raw = (
            b"malformed"
            if fault == "payload"
            else raw_issue(owner="wrong" if fault == "repository" else "synthetic")
        )
        with pytest.raises(ValueError if fault != "repository" else RuntimeError):
            submit(jobs, port, signer, raw=raw, **changes)
        assert tuple(jobs.connection.iterdump()) == before
        assert not port.calls and signer.calls == 0


@pytest.mark.parametrize("event", ["ping", "issue_comment"])
def test_ignored_events_record_receipt_without_tokens_or_jobs(tmp_path, event):
    port, signer = Transport(), Signer()
    with JobStore(tmp_path / "ignored.sqlite3") as jobs:
        result = submit(jobs, port, signer, event=event)
        assert result.outcome.status == "ignored" and result.capture is None
        assert jobs.status_counts() == {} and not port.calls and signer.calls == 0


@pytest.mark.parametrize("failure", ["token", "archive"])
def test_acquisition_failure_rolls_back_receipt_head_job_and_capture(tmp_path, failure):
    port, signer = Transport(failure=failure), Signer()
    with JobStore(tmp_path / "rollback.sqlite3") as jobs:
        before = tuple(jobs.connection.iterdump())
        with pytest.raises(ValueError):
            submit(jobs, port, signer)
        assert tuple(jobs.connection.iterdump()) == before
        assert port.calls.count("token") == 1


@pytest.mark.parametrize("kind", ["stale", "equal-time", "delivery-conflict"])
def test_noncurrent_or_conflicting_input_never_starts_another_token(tmp_path, kind):
    port, signer = Transport(), Signer()
    with JobStore(tmp_path / "causal.sqlite3") as jobs:
        submit(jobs, port, signer)
        raw = raw_issue(
            updated="2026-10-21T00:00:00Z" if kind == "stale" else "2026-10-21T00:00:01Z",
            title="Different alpha() revision",
        )
        result = submit(
            jobs,
            port,
            signer,
            raw=raw,
            delivery_id="composition-1" if kind == "delivery-conflict" else "next",
        )
        expected = {"stale": "stale", "equal-time": "needs_human", "delivery-conflict": "conflict"}
        assert result.outcome.status == expected[kind]
        assert result.capture is None and len(port.calls) == 4 and signer.calls == 1


def test_cli_missing_database_refuses_without_creating_it(tmp_path, capsys):
    database = tmp_path / "missing.sqlite3"
    assert main(cli_args(database, "f" * 64)) == 2
    assert not database.exists()
    assert json.loads(capsys.readouterr().out)["status"] == "refused"


def test_cli_wrong_identity_refuses_without_job_transition(tmp_path, capsys):
    database = tmp_path / "wrong.sqlite3"
    with JobStore(database) as jobs:
        first = submit(jobs, Transport(), Signer())
        before = tuple(jobs.connection.iterdump())
    args = cli_args(database, first.outcome.work_key)
    args[args.index("--repository-id") + 1] = "23"
    assert main(args) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "refused"
    with JobStore(database) as jobs:
        assert tuple(jobs.connection.iterdump()) == before
