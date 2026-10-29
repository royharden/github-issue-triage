"""Original synthetic capture persistence controls; reuse the existing public intake helper."""

import gzip
import io
import json
import tarfile
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_intake import delivery

from issue_triage.ingest.capture import CaptureIntake
from issue_triage.shared.ghapp.capture import CaptureError, RepositoryIdentity
from issue_triage.shared.ghapp.reader import ReadResponse
from issue_triage.store import JobStore, StoreError, database

IDENTITY = RepositoryIdentity(1, 2, "synthetic", "demo")
STAMP = "2026-10-17T21:00:00Z"
SHA = "a" * 40


class Transport:
    def __init__(self, *, sha=SHA, content=b"original", cached=False, fail=False):
        self.calls = []
        self.responses = [
            ReadResponse(
                200,
                {},
                json.dumps(
                    {"id": 2, "full_name": "synthetic/demo", "default_branch": "main"}
                ).encode(),
            ),
            ReadResponse(200, {}, json.dumps({"sha": sha}).encode()),
        ]
        if not cached:
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as handle:
                member = tarfile.TarInfo("synthetic-root/a.py")
                member.size = len(content)
                handle.addfile(member, io.BytesIO(content))
            self.responses.append(ReadResponse(200, {}, gzip.compress(stream.getvalue(), mtime=0)))
        self.fail = fail

    def get(self, request, **bounds):
        self.calls.append(request.url)
        if self.fail:
            raise RuntimeError("synthetic failure")
        return self.responses.pop(0)


def receive(store, item=None, *, port=None, stamp=STAMP):
    return store.receive(
        delivery() if item is None else item,
        token="SYNTHETIC_CAPTURE_TOKEN",
        transport=port if port is not None else Transport(),
        clock=lambda: 0,
        captured_at=stamp,
        provenance="synthetic_transport",
    )


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    import socket

    def denied(*args, **kwargs):
        pytest.fail("unexpected real socket")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def test_first_capture_survives_same_id_new_guid_and_reopen_without_fetch(tmp_path):
    path = tmp_path / "capture.sqlite3"
    with JobStore(path) as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        first = receive(store)
        assert first.outcome.status == "queued"
        for item in (delivery(), delivery("second")):
            port = Transport(fail=True)
            again = receive(store, item, port=port, stamp="2026-10-18T00:00:00Z")
            assert again.outcome.status == "duplicate"
            assert again.snapshot_id == first.snapshot_id and again.captured_at == STAMP
            assert not port.calls
    with JobStore(path) as jobs:
        port = Transport(fail=True)
        replay = receive(CaptureIntake(jobs, IDENTITY), delivery("third"), port=port)
        assert replay.capture.files == {"a.py": b"original"}
        assert replay.snapshot_id == first.snapshot_id and not port.calls


def test_new_revision_same_sha_uses_repo_cache_without_second_archive(tmp_path):
    with JobStore(tmp_path / "capture.sqlite3") as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        first = receive(store)
        port = Transport(cached=True)
        second = receive(
            store,
            delivery("edit", text="edited", updated="2026-10-14T10:00:02Z"),
            port=port,
            stamp="2026-10-18T00:00:00Z",
        )
        assert second.outcome.status == "queued" and second.snapshot_id == first.snapshot_id
        assert second.captured_at == STAMP and len(port.calls) == 2
        assert (
            jobs.connection.execute("SELECT COUNT(*) FROM repository_captures").fetchone()[0] == 1
        )
        assert jobs.connection.execute("SELECT COUNT(*) FROM work_captures").fetchone()[0] == 2


def test_new_revision_different_sha_preserves_both_captures(tmp_path):
    with JobStore(tmp_path / "capture.sqlite3") as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        first = receive(store)
        second = receive(
            store,
            delivery("edit", text="edited", updated="2026-10-14T10:00:02Z"),
            port=Transport(sha="b" * 40, content=b"new"),
        )
        assert first.snapshot_id != second.snapshot_id
        assert second.capture.files == {"a.py": b"new"}
        assert (
            jobs.connection.execute("SELECT COUNT(*) FROM repository_captures").fetchone()[0] == 2
        )


@pytest.mark.parametrize("fault", ["transport", "manifest"])
def test_capture_failure_rolls_back_receipt_head_job_and_capture(tmp_path, monkeypatch, fault):
    with JobStore(tmp_path / "capture.sqlite3") as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        if fault == "manifest":

            def fail(*args):
                raise StoreError("synthetic persistence failure")

            monkeypatch.setattr(store, "_manifest", fail)
        with pytest.raises((CaptureError, StoreError)):
            receive(store, port=Transport(fail=fault == "transport"))
        for table in ("deliveries", "issue_heads", "jobs", "repository_captures", "work_captures"):
            assert jobs.connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] == 0


@pytest.mark.parametrize(
    "column,value",
    [
        ("files_json", b'{"a.py":"dGFtcGVyZWQ="}'),
        ("manifest_json", b"{}"),
        ("inventory_sha256", "f" * 64),
    ],
)
def test_reloaded_tampered_capture_refuses_without_new_receipt(tmp_path, column, value):
    with JobStore(tmp_path / "capture.sqlite3") as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        first = receive(store)
        jobs.connection.execute(
            "UPDATE repository_captures SET " + column + "=? WHERE snapshot_id=?",
            (value, first.snapshot_id),
        )
        with pytest.raises(StoreError, match="stored_capture_invalid"):
            receive(store, delivery("retry"), port=Transport(fail=True))
        assert jobs.connection.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 1


def test_wrong_approved_repository_rolls_back_intake(tmp_path):
    with JobStore(tmp_path / "capture.sqlite3") as jobs:
        port = Transport()
        with pytest.raises(StoreError, match="capture_delivery_repository_mismatch"):
            receive(CaptureIntake(jobs, RepositoryIdentity(1, 99, "synthetic", "demo")), port=port)
        assert not port.calls and jobs.status_counts() == {}


def test_ignored_and_stale_delivery_never_fetch(tmp_path):
    with JobStore(tmp_path / "capture.sqlite3") as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        receive(store, delivery(updated="2026-10-14T10:00:02Z"))
        for item, expected in (
            (delivery("old"), "stale"),
            (delivery("ping", event="ping"), "ignored"),
        ):
            port = Transport(fail=True)
            result = receive(store, item, port=port)
            assert result.outcome.status == expected and result.capture is None and not port.calls


def test_migration_three_to_five_retains_old_checksums_and_job(tmp_path, monkeypatch):
    path = tmp_path / "upgrade.sqlite3"
    migrations = database.MIGRATIONS
    monkeypatch.setattr(database, "MIGRATIONS", migrations[:3])
    with JobStore(path) as old:
        old.enqueue("d" * 64, b"{}", now_us=1)
        checksums = list(old.connection.execute("SELECT version,checksum FROM schema_migrations"))
    monkeypatch.setattr(database, "MIGRATIONS", migrations)
    with JobStore(path) as current:
        assert current.connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert [
            tuple(row)
            for row in current.connection.execute(
                "SELECT version,checksum FROM schema_migrations WHERE version<=3"
            )
        ] == [tuple(row) for row in checksums]
        assert current.status_counts() == {"queued": 1}


def test_concurrent_duplicate_receives_capture_once(tmp_path):
    path = tmp_path / "concurrent.sqlite3"
    with JobStore(path):
        pass
    ports = [Transport(), Transport()]

    def run(index):
        with JobStore(path) as jobs:
            return receive(
                CaptureIntake(jobs, IDENTITY), delivery("thread-" + str(index)), port=ports[index]
            ).outcome.status

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(run, (0, 1))) == ["duplicate", "queued"]
    assert sorted(len(port.calls) for port in ports) == [0, 3]


def test_failed_new_edit_preserves_previous_head_job_and_capture(tmp_path):
    with JobStore(tmp_path / "capture.sqlite3") as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        original = delivery()
        first = receive(store, original)
        with pytest.raises(CaptureError):
            receive(
                store,
                delivery("edit", text="edited", updated="2026-10-14T10:00:02Z"),
                port=Transport(fail=True),
            )
        assert store.intake.is_current(original.envelope.issue)
        assert jobs.status_counts() == {"queued": 1}
        assert jobs.connection.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 1
        assert (
            jobs.connection.execute("SELECT snapshot_id FROM work_captures").fetchone()[0]
            == first.snapshot_id
        )


def test_fixture_job_cannot_silently_gain_git_capture(tmp_path):
    with JobStore(tmp_path / "capture.sqlite3") as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        existing = store.intake.receive(delivery())
        jobs.connection.execute(
            "INSERT INTO local_inputs VALUES(?,?,?)", (existing.work_key, "f" * 64, b"{}")
        )
        port = Transport()
        with pytest.raises(StoreError, match="fixture_work_cannot_be_recaptured"):
            receive(store, port=port)
        assert not port.calls
        assert (
            jobs.connection.execute("SELECT COUNT(*) FROM repository_captures").fetchone()[0] == 0
        )
