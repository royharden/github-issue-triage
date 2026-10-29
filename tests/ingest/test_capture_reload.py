"""Retained-capture reload controls; original synthetic data, no sealed corpus."""

import hashlib
from dataclasses import FrozenInstanceError

import pytest
from test_capture_intake import IDENTITY, STAMP, Transport, delivery, receive

from issue_triage.contracts import IssueInput
from issue_triage.ingest import capture as capture_module
from issue_triage.ingest.capture import CaptureIntake
from issue_triage.shared.ghapp.capture import RepositoryIdentity
from issue_triage.store import JobStore, StoreError, database


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    import socket

    def denied(*args, **kwargs):
        pytest.fail("reload must not perform network activity")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


@pytest.fixture
def captured(tmp_path, monkeypatch):
    with JobStore(tmp_path / "capture.sqlite3") as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        first = receive(store)

        def denied(*args, **kwargs):
            pytest.fail("reload must not invoke capture_repository")

        monkeypatch.setattr(capture_module, "capture_repository", denied)
        yield store, first


def load_without_writes(store, key):
    """Include every table and lease column, not just capture row counts."""
    before = tuple(store.jobs.connection.iterdump())
    changes = store.jobs.connection.total_changes
    try:
        return store.load(key)
    finally:
        assert store.jobs.connection.total_changes == changes
        assert tuple(store.jobs.connection.iterdump()) == before


def test_reload_after_reopen_retains_original_bytes_and_is_immutable(tmp_path, monkeypatch):
    path = tmp_path / "restart.sqlite3"
    with JobStore(path) as jobs:
        first = receive(CaptureIntake(jobs, IDENTITY))

    def denied(*args, **kwargs):
        pytest.fail("restart reload must not recapture")

    monkeypatch.setattr(capture_module, "capture_repository", denied)
    with JobStore(path) as reopened:
        value = load_without_writes(CaptureIntake(reopened, IDENTITY), first.outcome.work_key)
        assert value.work_key == first.outcome.work_key
        assert value.issue.sha256 == first.outcome.issue_sha256
        assert value.snapshot_id == first.snapshot_id
        assert value.captured_at == first.captured_at == STAMP
        assert value.inventory_sha256 == first.inventory_sha256
        assert value.commit_sha == first.capture.commit_sha
        assert value.provenance == "synthetic_transport"
        assert value.capture.manifest_bytes() == first.capture.manifest_bytes()
        assert value.capture.files == first.capture.files == {"a.py": b"original"}
        # Capture record, Git commit and inventory are distinct identities.
        assert value.snapshot_id != value.inventory_sha256
        assert value.snapshot_id != value.commit_sha
        with pytest.raises(FrozenInstanceError):
            value.snapshot_id = "f" * 64
        with pytest.raises(TypeError):
            value.capture.files["a.py"] = b"changed"
        with pytest.raises(ValueError):
            value.issue.title = "changed"


def test_valid_same_repository_capture_substitution_refuses_without_writes(tmp_path, monkeypatch):
    with JobStore(tmp_path / "substitution.sqlite3") as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        first = receive(store)
        second = receive(
            store,
            delivery("edit", text="edited", updated="2026-10-14T10:00:02Z"),
            port=Transport(sha="b" * 40, content=b"new"),
        )
        assert first.snapshot_id != second.snapshot_id

        def denied(*args, **kwargs):
            pytest.fail("reload must not recapture")

        monkeypatch.setattr(capture_module, "capture_repository", denied)
        # Both records independently validate before only the original mapping is changed.
        assert load_without_writes(store, first.outcome.work_key).snapshot_id == first.snapshot_id
        assert load_without_writes(store, second.outcome.work_key).snapshot_id == second.snapshot_id
        jobs.connection.execute(
            "UPDATE work_captures SET snapshot_id=? WHERE work_key=?",
            (second.snapshot_id, first.outcome.work_key),
        )
        with pytest.raises(StoreError, match="^stored_capture_invalid$"):
            load_without_writes(store, first.outcome.work_key)
        # The unaffected valid revision is still readable.
        assert load_without_writes(store, second.outcome.work_key).snapshot_id == second.snapshot_id


def test_shared_capture_keeps_distinct_revision_bindings_after_restart(tmp_path, monkeypatch):
    path = tmp_path / "shared.sqlite3"
    with JobStore(path) as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        first = receive(store)
        second = receive(
            store,
            delivery("edit", text="edited", updated="2026-10-14T10:00:02Z"),
            port=Transport(cached=True),
            stamp="2026-10-18T00:00:00Z",
        )
        assert first.outcome.work_key != second.outcome.work_key
        assert first.snapshot_id == second.snapshot_id and second.captured_at == STAMP
        bindings = jobs.connection.execute("SELECT binding_sha256 FROM work_captures").fetchall()
        assert len(bindings) == 2 and bindings[0][0] != bindings[1][0]

    def denied(*args, **kwargs):
        pytest.fail("shared restart reload must not recapture")

    monkeypatch.setattr(capture_module, "capture_repository", denied)
    with JobStore(path) as jobs:
        store = CaptureIntake(jobs, IDENTITY)
        for original in (first, second):
            value = load_without_writes(store, original.outcome.work_key)
            assert value.issue.sha256 == original.outcome.issue_sha256
            assert value.snapshot_id == original.snapshot_id
            assert value.captured_at == STAMP
            assert value.capture.files == {"a.py": b"original"}


def test_migration_preserves_legacy_mapping_without_blessing_it(tmp_path, monkeypatch):
    # Seed valid retained bytes, then reproduce the pre-anchor storage shape exactly.
    with JobStore(tmp_path / "seed.sqlite3") as jobs:
        first = receive(CaptureIntake(jobs, IDENTITY))
        capture_row = tuple(jobs.connection.execute("SELECT * FROM repository_captures").fetchone())
    migrations = database.MIGRATIONS
    monkeypatch.setattr(database, "MIGRATIONS", migrations[:4])
    path = tmp_path / "legacy.sqlite3"
    with JobStore(path) as jobs:
        outcome = CaptureIntake(jobs, IDENTITY).intake.receive(delivery())
        assert outcome.work_key == first.outcome.work_key
        jobs.connection.execute(
            "INSERT INTO repository_captures VALUES(?,?,?,?,?,?,?,?,?)", capture_row
        )
        jobs.connection.execute(
            "INSERT INTO work_captures VALUES(?,?)", (outcome.work_key, first.snapshot_id)
        )
        checksums = [
            tuple(row)
            for row in jobs.connection.execute("SELECT version,checksum FROM schema_migrations")
        ]
    monkeypatch.setattr(database, "MIGRATIONS", migrations)
    with JobStore(path) as jobs:
        assert jobs.connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert [
            tuple(row)
            for row in jobs.connection.execute(
                "SELECT version,checksum FROM schema_migrations WHERE version<=4"
            )
        ] == checksums
        mapping = jobs.connection.execute("SELECT * FROM work_captures").fetchone()
        assert mapping["snapshot_id"] == first.snapshot_id and mapping["binding_sha256"] is None
        store = CaptureIntake(jobs, IDENTITY)
        with pytest.raises(StoreError, match="^stored_capture_invalid$"):
            load_without_writes(store, outcome.work_key)
        before = tuple(jobs.connection.iterdump())
        port = Transport(fail=True)
        with pytest.raises(StoreError, match="^stored_capture_invalid$"):
            receive(store, delivery("retry"), port=port)
        assert not port.calls
        assert tuple(jobs.connection.iterdump()) == before


@pytest.mark.parametrize("binding", [None, "", "f" * 64])
def test_missing_or_inconsistent_capture_anchor_refuses_without_writes(captured, binding):
    store, first = captured
    store.jobs.connection.execute(
        "UPDATE work_captures SET binding_sha256=? WHERE work_key=?",
        (binding, first.outcome.work_key),
    )
    with pytest.raises(StoreError, match="^stored_capture_invalid$"):
        load_without_writes(store, first.outcome.work_key)


@pytest.mark.parametrize("key", [None, True, b"a" * 64, "", "A" * 64, "a" * 63, "a" * 65])
def test_malformed_work_key_refuses_without_writes(captured, key):
    store, _ = captured
    with pytest.raises(StoreError, match="^invalid_work_key$"):
        load_without_writes(store, key)


def test_missing_work_or_capture_binding_refuses_without_writes(captured):
    store, first = captured
    with pytest.raises(StoreError, match="^stored_capture_unavailable$"):
        load_without_writes(store, "f" * 64)
    store.jobs.connection.execute(
        "DELETE FROM work_captures WHERE work_key=?", (first.outcome.work_key,)
    )
    with pytest.raises(StoreError, match="^stored_capture_unavailable$"):
        load_without_writes(store, first.outcome.work_key)


@pytest.mark.parametrize(
    "column,value",
    [
        ("payload", b"{}"),
        ("payload", "not a stored BLOB"),
        ("payload_sha256", "f" * 64),
        ("issue_key", "1:2:999"),
        ("issue_sha256", "f" * 64),
    ],
)
def test_job_payload_and_issue_binding_tampering_refuses(captured, column, value):
    store, first = captured
    store.jobs.connection.execute(
        f"UPDATE jobs SET {column}=? WHERE work_key=?", (value, first.outcome.work_key)
    )
    with pytest.raises(StoreError, match="^stored_capture_invalid$"):
        load_without_writes(store, first.outcome.work_key)


def test_coherent_issue_replacement_cannot_keep_original_work_key(captured):
    store, first = captured
    original = store.jobs.connection.execute("SELECT payload FROM jobs").fetchone()[0]
    wire = IssueInput.parse_json(original).model_dump(mode="json")
    wire["body"] = "different issue revision"
    changed = IssueInput.model_validate(wire)
    raw = changed.canonical_bytes()
    store.jobs.connection.execute(
        "UPDATE jobs SET payload=?,payload_sha256=?,issue_sha256=? WHERE work_key=?",
        (raw, hashlib.sha256(raw).hexdigest(), changed.sha256, first.outcome.work_key),
    )
    with pytest.raises(StoreError, match="^stored_capture_invalid$"):
        load_without_writes(store, first.outcome.work_key)


@pytest.mark.parametrize(
    "identity",
    [
        RepositoryIdentity(9, 2, "synthetic", "demo"),
        RepositoryIdentity(1, 9, "synthetic", "demo"),
        RepositoryIdentity(1, 2, "different", "demo"),
        RepositoryIdentity(1, 2, "synthetic", "different"),
    ],
)
def test_configured_installation_repository_and_names_must_match(captured, identity):
    store, first = captured
    with pytest.raises(StoreError, match="^stored_capture_invalid$"):
        load_without_writes(CaptureIntake(store.jobs, identity), first.outcome.work_key)


@pytest.mark.parametrize(
    "column,value",
    [
        ("files_json", b'{"a.py":"dGFtcGVyZWQ="}'),
        ("manifest_json", b"{}"),
        ("inventory_sha256", "f" * 64),
        ("captured_at", "2026-10-18T00:00:00Z"),
        ("commit_sha", "b" * 40),
        ("provenance", "configured_transport"),
        ("installation_id", 9),
        ("repository_id", 9),
    ],
)
def test_inconsistent_retained_capture_refuses(captured, column, value):
    store, first = captured
    store.jobs.connection.execute(
        f"UPDATE repository_captures SET {column}=? WHERE snapshot_id=?",
        (value, first.snapshot_id),
    )
    with pytest.raises(StoreError, match="^stored_capture_invalid$"):
        load_without_writes(store, first.outcome.work_key)


def test_fixture_input_cannot_be_upgraded_even_with_capture_mapping(captured):
    store, first = captured
    store.jobs.connection.execute(
        "INSERT INTO local_inputs VALUES(?,?,?)", (first.outcome.work_key, "f" * 64, b"{}")
    )
    with pytest.raises(StoreError, match="^fixture_work_cannot_be_recaptured$"):
        load_without_writes(store, first.outcome.work_key)


def test_reload_keeps_existing_lease_and_all_persistent_state(captured):
    store, first = captured
    lease = store.jobs.lease("reload-control", now_us=9_000_000_000_000_000, duration_us=1000)
    assert lease is not None and lease.work_key == first.outcome.work_key
    value = load_without_writes(store, lease.work_key)
    assert value.work_key == lease.work_key
    row = store.jobs.connection.execute("SELECT * FROM jobs").fetchone()
    assert row["status"] == "leased"
    assert (row["lease_token"], row["lease_owner"], row["lease_until_us"]) == (
        lease.token,
        lease.owner,
        lease.lease_until_us,
    )
