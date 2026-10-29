"""A real stored-work-to-reference-report journey using original synthetic inputs."""

import hashlib
import hmac
from dataclasses import FrozenInstanceError

import pytest
from issue_triage.ingest import capture as capture_module
from issue_triage.ingest.capture import CaptureIntake
from issue_triage.shared.codeindex.canonical import canonical_bytes
from issue_triage.shared.ghapp import parse_delivery
from issue_triage.shared.ghapp.capture import CapturedRepository, RepositoryIdentity
from issue_triage.store import JobStore, StoreError
from issue_triage.worker.capture_checks import check_capture

IDENTITY = RepositoryIdentity(1, 2, "synthetic", "consumer")
STAMP = "2026-10-21T00:00:10Z"
FILES = {
    "a.py": b"def alpha():\n    return 1\n",
    "b.js": b"function bravo() { return 2; }\n",
    "c.ts": b"export function charlie(): number { return 3; }\n",
}


@pytest.fixture(autouse=True)
def deny_external_effects(monkeypatch):
    import os
    import socket
    import subprocess

    def denied(*args, **kwargs):
        pytest.fail("capture checks must not dispatch a process or network operation")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(os, "system", denied)


def seed(jobs, monkeypatch, *, provenance="synthetic_transport", revision=1, files=None):
    """Stub only the acquisition port; actual signed intake/persistence/reload run."""
    raw = canonical_bytes(
        {
            "action": "opened" if revision == 1 else "edited",
            "installation": {"id": 1},
            "repository": {"id": 2, "owner": {"login": "synthetic"}, "name": "consumer"},
            "issue": {
                "number": 3,
                "title": "Check named functions",
                "body": "Please check alpha(), bravo() and charlie()." + " " * revision,
                "updated_at": f"2026-10-21T00:00:0{revision}Z",
                "user": {"id": 12, "login": "original-author"},
            },
            "sender": {"id": 12},
        }
    )
    secret = b"public-original-consumer-control"
    delivery = parse_delivery(
        raw,
        signature_header="sha256=" + hmac.new(secret, raw, hashlib.sha256).hexdigest(),
        secret=secret,
        delivery_id=f"original-{revision}",
        event="issues",
        received_at=STAMP,
        installation_id=1,
        repository_id=2,
    )

    def acquisition(identity, **options):
        return CapturedRepository(
            identity,
            ("a" if revision == 1 else "b") * 40,
            options["provenance"],
            "c" * 64,
            "d" * 64,
            FILES if files is None else files,
        )

    monkeypatch.setattr(capture_module, "capture_repository", acquisition)
    return CaptureIntake(jobs, IDENTITY).receive(
        delivery,
        token="public-synthetic-token",
        transport=None,
        clock=lambda: 0,
        captured_at=STAMP,
        provenance=provenance,
    )


def inspect_without_writes(jobs, work_key, monkeypatch, identity=IDENTITY):
    def denied(*args, **kwargs):
        pytest.fail("consumer must use persisted bytes, never acquire again")

    monkeypatch.setattr(capture_module, "capture_repository", denied)
    before = tuple(jobs.connection.iterdump())
    changes = jobs.connection.total_changes
    try:
        return check_capture(jobs, identity, work_key)
    finally:
        assert tuple(jobs.connection.iterdump()) == before
        assert jobs.connection.total_changes == changes


def test_restart_consumes_stored_work_and_resolves_python_js_ts(tmp_path, monkeypatch):
    path = tmp_path / "consumer.sqlite3"
    with JobStore(path) as jobs:
        first = seed(jobs, monkeypatch)
    with JobStore(path) as jobs:
        result = inspect_without_writes(jobs, first.outcome.work_key, monkeypatch)
        wire = result.wire()
        assert wire["work_key"] == first.outcome.work_key
        assert wire["issue_sha256"] == first.outcome.issue_sha256
        assert wire["capture"] == {
            "source_kind": "retained_capture",
            "snapshot_id": first.snapshot_id,
            "captured_at": STAMP,
            "commit_sha": "a" * 40,
            "inventory_sha256": first.inventory_sha256,
            "provenance": "synthetic_transport",
            "authenticated_github_origin": False,
        }
        assert wire["current_processing_authority"] is False
        assert wire["s5_cited_proposals_supported"] is False
        assert wire["report"]["current_snapshot"]["snapshot_id"] == first.snapshot_id
        pointers = [p for item in wire["report"]["items"] for p in item["current_pointers"]]
        assert {p["path"] for p in pointers} == set(FILES)
        assert all(p["source_kind"] == "retained_capture" for p in pointers)
        assert all(p["snapshot_id"] == first.snapshot_id for p in pointers)
        assert all(
            p["source_sha256"] == hashlib.sha256(FILES[p["path"]]).hexdigest() for p in pointers
        )
        assert all(
            1 <= p["line_start"] <= p["line_end"] <= len(FILES[p["path"]].splitlines())
            for p in pointers
        )
        assert all(item["status"] == "found" for item in wire["report"]["items"])
        assert result.canonical_bytes() == canonical_bytes(wire)
        assert result.sha256 == hashlib.sha256(result.canonical_bytes()).hexdigest()
        with pytest.raises(FrozenInstanceError):
            result.report = None


@pytest.mark.parametrize("provenance", ["synthetic_transport", "configured_transport"])
def test_provenance_label_never_claims_authenticated_origin(tmp_path, monkeypatch, provenance):
    with JobStore(tmp_path / "provenance.sqlite3") as jobs:
        first = seed(jobs, monkeypatch, provenance=provenance)
        wire = inspect_without_writes(jobs, first.outcome.work_key, monkeypatch).wire()
        assert wire["capture"]["provenance"] == provenance
        assert wire["capture"]["source_kind"] == "retained_capture"
        assert wire["capture"]["authenticated_github_origin"] is False


@pytest.mark.parametrize("fault", ["missing", "legacy", "manifest", "fixture", "repository"])
def test_invalid_or_unavailable_retained_input_refuses_without_effects(
    tmp_path, monkeypatch, fault
):
    with JobStore(tmp_path / "refusal.sqlite3") as jobs:
        first = seed(jobs, monkeypatch)
        key, identity = first.outcome.work_key, IDENTITY
        if fault == "missing":
            key = "f" * 64
        elif fault == "legacy":
            jobs.connection.execute("UPDATE work_captures SET binding_sha256=NULL")
        elif fault == "manifest":
            jobs.connection.execute("UPDATE repository_captures SET manifest_json=?", (b"{}",))
        elif fault == "fixture":
            jobs.connection.execute(
                "INSERT INTO local_inputs VALUES(?,?,?)", (key, "f" * 64, b"{}")
            )
        else:
            identity = RepositoryIdentity(1, 9, "synthetic", "consumer")
        with pytest.raises(StoreError):
            inspect_without_writes(jobs, key, monkeypatch, identity)


def test_substituted_capture_mapping_refuses_and_valid_historical_capture_remains_inspectable(
    tmp_path, monkeypatch
):
    with JobStore(tmp_path / "mapping.sqlite3") as jobs:
        first = seed(jobs, monkeypatch)
        second = seed(jobs, monkeypatch, revision=2)
        original = inspect_without_writes(jobs, first.outcome.work_key, monkeypatch)
        assert original.retained.snapshot_id == first.snapshot_id
        jobs.connection.execute(
            "UPDATE work_captures SET snapshot_id=? WHERE work_key=?",
            (second.snapshot_id, first.outcome.work_key),
        )
        with pytest.raises(StoreError):
            inspect_without_writes(jobs, first.outcome.work_key, monkeypatch)
        assert (
            inspect_without_writes(jobs, second.outcome.work_key, monkeypatch).retained.snapshot_id
            == second.snapshot_id
        )


def test_consumer_keeps_active_job_lease_unchanged(tmp_path, monkeypatch):
    with JobStore(tmp_path / "lease.sqlite3") as jobs:
        first = seed(jobs, monkeypatch)
        lease = jobs.lease("capture-check-control", now_us=9_000_000_000_000_000, duration_us=1000)
        assert lease is not None
        inspect_without_writes(jobs, first.outcome.work_key, monkeypatch)
        row = jobs.connection.execute("SELECT * FROM jobs").fetchone()
        assert (row["status"], row["lease_token"], row["lease_until_us"]) == (
            "leased",
            lease.token,
            lease.lease_until_us,
        )


def test_consumer_preserves_incomplete_coverage_instead_of_claiming_absence(tmp_path, monkeypatch):
    with JobStore(tmp_path / "coverage.sqlite3") as jobs:
        first = seed(jobs, monkeypatch, files={"unknown.custom": b"opaque source"})
        wire = inspect_without_writes(jobs, first.outcome.work_key, monkeypatch).wire()
        assert wire["report"]["items"]
        assert all(item["status"] == "ambiguous" for item in wire["report"]["items"])
