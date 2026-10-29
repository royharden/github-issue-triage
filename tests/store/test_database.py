"""Durability and concurrent claims of local synthetic jobs, not provider accounting."""

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from issue_triage.store import JobStore, StoreError, database

KEY = hashlib.sha256(b"original-local-contract-job").hexdigest()


def test_enqueue_duplicate_conflict_and_restart(tmp_path):
    path = tmp_path / "jobs.sqlite3"
    with JobStore(path) as store:
        assert store.enqueue(KEY, b'{"control":1}', now_us=1)
        assert not store.enqueue(KEY, b'{"control":1}', now_us=2)
        with pytest.raises(StoreError, match="work_key_conflict"):
            store.enqueue(KEY, b'{"control":2}', now_us=3)
    with JobStore(path) as reopened:
        lease = reopened.lease("worker", now_us=3, duration_us=10)
        assert lease.payload == b'{"control":1}' and lease.attempt == 1
        assert reopened.finish(lease, now_us=4)
        assert not reopened.finish(lease, now_us=5)
        assert reopened.status_counts() == {"done": 1}
        assert not reopened.enqueue(KEY, b'{"control":1}', now_us=6)
        assert reopened.lease("worker", now_us=7, duration_us=10) is None


def test_two_connections_claim_exactly_once(tmp_path):
    path = tmp_path / "jobs.sqlite3"
    with JobStore(path) as store:
        store.enqueue(KEY, b"{}", now_us=0)

    def claim(owner):
        with JobStore(path) as store:
            return store.lease(owner, now_us=1, duration_us=100)

    with ThreadPoolExecutor(max_workers=2) as pool:
        leases = list(pool.map(claim, ("worker-a", "worker-b")))
    assert sum(lease is not None for lease in leases) == 1


def test_crashed_lease_reclaimed_and_late_writer_rejected(tmp_path):
    path = tmp_path / "jobs.sqlite3"
    with JobStore(path) as store:
        store.enqueue(KEY, b"{}", now_us=0)
        first = store.lease("worker-a", now_us=1, duration_us=10)
    with JobStore(path) as store:
        assert store.lease("worker-b", now_us=10, duration_us=10) is None
        second = store.lease("worker-b", now_us=11, duration_us=10)
        assert second.attempt == 2 and second.token != first.token
        assert not store.finish(first, now_us=12)
        assert not store.retry(first, now_us=12, delay_us=1, reason="late")
        assert store.finish(second, now_us=12)


def test_max_attempts_and_retry_deadline_are_durable(tmp_path):
    path = tmp_path / "jobs.sqlite3"
    with JobStore(path) as store:
        store.enqueue(KEY, b"{}", now_us=0, max_attempts=2)
        first = store.lease("worker", now_us=1, duration_us=10)
        assert store.retry(first, now_us=2, delay_us=10, reason="transient")
        assert store.lease("worker", now_us=11, duration_us=10) is None
        final = store.lease("worker", now_us=12, duration_us=10)
        assert final.attempt == 2
    with JobStore(path) as store:
        assert not store.finish(final, now_us=22)
        assert store.lease("worker", now_us=22, duration_us=10) is None
        assert store.status_counts() == {"failed": 1}


def test_transaction_failure_rolls_back_domain_write(tmp_path):
    with JobStore(tmp_path / "jobs.sqlite3") as store:
        with pytest.raises(RuntimeError, match="synthetic_failure"):
            with store.transaction() as connection:
                connection.execute("UPDATE schema_migrations SET checksum='bad'")
                raise RuntimeError("synthetic_failure")
        assert (
            store.connection.execute("SELECT checksum FROM schema_migrations").fetchone()[0]
            != "bad"
        )


def test_migration_failure_rolls_back_all_schema_changes(tmp_path, monkeypatch):
    path = tmp_path / "jobs.sqlite3"
    monkeypatch.setattr(
        database, "MIGRATIONS", (("CREATE TABLE first_table(id INTEGER)", "NOT VALID SQL"),)
    )
    with pytest.raises(sqlite3.OperationalError):
        JobStore(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert (
            connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == []
        )


def test_unrelated_future_or_tampered_database_fails_closed(tmp_path):
    unrelated = tmp_path / "unrelated.sqlite3"
    with sqlite3.connect(unrelated) as connection:
        connection.execute("CREATE TABLE unrelated(id INTEGER)")
    with pytest.raises(StoreError, match="unrelated_database"):
        JobStore(unrelated)
    path = tmp_path / "jobs.sqlite3"
    with JobStore(path) as store:
        store.connection.execute("PRAGMA user_version=99")
    with pytest.raises(StoreError, match="unsupported_database_version"):
        JobStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=1")
        connection.execute("UPDATE schema_migrations SET checksum='bad'")
    with pytest.raises(StoreError, match="migration_checksum_mismatch"):
        JobStore(path)


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(now_us=True),
        dict(now_us=-1),
        dict(now_us=0, max_attempts=True),
        dict(now_us=0, max_attempts=0),
    ],
)
def test_invalid_queue_bounds_are_rejected(tmp_path, kwargs):
    with JobStore(tmp_path / "jobs.sqlite3") as store:
        with pytest.raises(StoreError):
            store.enqueue(KEY, b"{}", **kwargs)


@pytest.mark.parametrize("payload", [b'{"x":1,"x":2}', b'{"x":NaN}', b"not json"])
def test_invalid_json_never_creates_a_job(tmp_path, payload):
    with JobStore(tmp_path / "jobs.sqlite3") as store:
        with pytest.raises(StoreError, match="invalid_payload"):
            store.enqueue(KEY, payload, now_us=0)
        assert store.status_counts() == {}
