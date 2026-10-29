"""Original synthetic state-machine controls; no sealed author fixture imports."""

import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from issue_triage.ingest import IntakeStore
from issue_triage.shared.ghapp import parse_delivery
from issue_triage.store import JobStore, StoreError, database

SECRET = b"original-intake-contract-secret"


def delivery(
    identifier="d1", *, text="Original local issue", updated="2026-10-14T10:00:00Z", event="issues"
):
    raw = json.dumps(
        {
            "action": "opened",
            "installation": {"id": 1},
            "repository": {"id": 2, "owner": {"login": "synthetic"}, "name": "demo"},
            "issue": {
                "number": 3,
                "title": "Original control",
                "body": text,
                "updated_at": updated,
                "user": {"id": 12, "login": "author"},
            },
            "sender": {"id": 12},
        },
        sort_keys=True,
    ).encode()
    signature = "sha256=" + hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
    return parse_delivery(
        raw,
        signature_header=signature,
        secret=SECRET,
        delivery_id=identifier,
        event=event,
        received_at="2026-10-14T10:00:01Z",
        installation_id=1,
        repository_id=2,
    )


def test_duplicate_id_and_new_guid_coalesce_durable_job(tmp_path):
    path = tmp_path / "intake.sqlite3"
    first = delivery()
    with JobStore(path) as jobs:
        intake = IntakeStore(jobs)
        result = intake.receive(first)
        assert result.status == "queued"
        assert intake.receive(first).status == "duplicate"
        same_issue = intake.receive(delivery("d2"))
        assert (
            same_issue.reason == "coalesced_issue_revision"
            and same_issue.work_key == result.work_key
        )
        assert jobs.status_counts() == {"queued": 1}
    with JobStore(path) as reopened:
        assert IntakeStore(reopened).receive(first).status == "duplicate"
        assert reopened.status_counts() == {"queued": 1}


def test_same_delivery_id_different_bytes_is_audited_never_overwritten(tmp_path):
    with JobStore(tmp_path / "intake.sqlite3") as jobs:
        intake = IntakeStore(jobs)
        first = delivery()
        intake.receive(first)
        assert intake.receive(delivery(text="Changed bytes")).status == "conflict"
        assert intake.receive(delivery(text="Changed bytes")).status == "conflict"
        assert jobs.connection.execute("SELECT COUNT(*) FROM delivery_conflicts").fetchone()[0] == 1
        assert (
            jobs.connection.execute("SELECT raw_body_sha256 FROM deliveries").fetchone()[0]
            == first.raw_body_sha256
        )
        assert jobs.status_counts() == {"queued": 1}


@pytest.mark.parametrize("phase", ["before_enqueue", "after_enqueue"])
def test_claim_and_enqueue_rollback_together(tmp_path, monkeypatch, phase):
    with JobStore(tmp_path / "intake.sqlite3") as jobs:
        intake = IntakeStore(jobs)
        original = jobs.enqueue_in

        def fail(*args, **kwargs):
            if phase == "after_enqueue":
                original(*args, **kwargs)
            raise StoreError("synthetic_crash_between_claim_and_job")

        monkeypatch.setattr(jobs, "enqueue_in", fail)
        with pytest.raises(StoreError, match="synthetic_crash"):
            intake.receive(delivery())
        assert jobs.connection.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 0
        assert jobs.connection.execute("SELECT COUNT(*) FROM issue_heads").fetchone()[0] == 0
        assert jobs.status_counts() == {}
        monkeypatch.setattr(jobs, "enqueue_in", original)
        assert intake.receive(delivery()).status == "queued"


def test_concurrent_new_guid_claims_make_one_job(tmp_path):
    path = tmp_path / "intake.sqlite3"
    with JobStore(path):
        pass
    one, two = delivery("d1"), delivery("d2")

    def receive(item):
        with JobStore(path) as jobs:
            return IntakeStore(jobs).receive(item).status

    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(receive, (one, two)))
    assert sorted(result) == ["duplicate", "queued"]
    with JobStore(path) as jobs:
        assert jobs.status_counts() == {"queued": 1}
        assert sum(IntakeStore(jobs).counts().values()) == 2


def test_older_edit_cannot_overwrite_or_make_another_job(tmp_path):
    with JobStore(tmp_path / "intake.sqlite3") as jobs:
        intake = IntakeStore(jobs)
        current = delivery(updated="2026-10-14T10:00:02Z")
        intake.receive(current)
        assert (
            intake.receive(delivery("older", text="older", updated="2026-10-14T10:00:00Z")).status
            == "stale"
        )
        assert intake.is_current(current.envelope.issue)
        assert jobs.status_counts() == {"queued": 1}


def test_equal_time_conflict_blocks_both_revisions_and_late_worker(tmp_path):
    with JobStore(tmp_path / "intake.sqlite3") as jobs:
        intake = IntakeStore(jobs)
        first = delivery()
        intake.receive(first)
        lease = jobs.lease("worker", now_us=1791972001000000, duration_us=10000000)
        conflict = delivery("d2", text="different content at same timestamp")
        assert intake.receive(conflict).status == "needs_human"
        assert not intake.is_current(first.envelope.issue) and not intake.is_current(
            conflict.envelope.issue
        )
        assert jobs.status_counts() == {"failed": 1}
        assert not jobs.finish(lease, now_us=1791972002000000)
        assert intake.receive(delivery("d3")).status == "needs_human"
        newer = delivery("d4", text="new causal revision", updated="2026-10-14T10:00:03Z")
        assert intake.receive(newer).status == "queued"
        assert intake.is_current(newer.envelope.issue)


def test_ignored_receipt_is_visible_and_no_job(tmp_path):
    with JobStore(tmp_path / "intake.sqlite3") as jobs:
        intake = IntakeStore(jobs)
        assert intake.receive(delivery(event="issue_comment")).status == "ignored"
        assert intake.counts() == {"ignored": 1} and jobs.status_counts() == {}


def test_migration_upgrade_preserves_exact_v1_checksum_and_job(tmp_path, monkeypatch):
    path = tmp_path / "upgrade.sqlite3"
    all_migrations = database.MIGRATIONS
    monkeypatch.setattr(database, "MIGRATIONS", all_migrations[:1])
    key = "a" * 64
    with JobStore(path) as old:
        assert (
            old.connection.execute(
                "SELECT checksum FROM schema_migrations WHERE version=1"
            ).fetchone()[0]
            == "b3734278ad0e1f00a3ad1535be72a208f05333a9764d778276bb9a43cd228809"
        )
        old.enqueue(key, b"{}", now_us=0)
    monkeypatch.setattr(database, "MIGRATIONS", all_migrations)
    with JobStore(path) as current:
        assert current.connection.execute("PRAGMA user_version").fetchone()[0] == len(
            all_migrations
        )
        assert current.status_counts() == {"queued": 1}
        assert IntakeStore(current).receive(delivery()).status == "queued"
