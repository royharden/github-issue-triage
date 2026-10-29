"""Small SQLite application queue with migration checksums and expiring lease tokens."""

import hashlib
import json
import re
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

APPLICATION_ID = 0x53365452
MIGRATIONS = (
    (
        "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, checksum TEXT NOT NULL)",
        """CREATE TABLE jobs(
            work_key TEXT PRIMARY KEY, payload BLOB NOT NULL, payload_sha256 TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('queued','leased','done','failed')),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
            max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 10),
            available_us INTEGER NOT NULL, created_us INTEGER NOT NULL,
            lease_token TEXT, lease_owner TEXT, lease_until_us INTEGER, result_code TEXT)""",
        "CREATE INDEX jobs_available ON jobs(status, available_us, created_us)",
    ),
    (
        "ALTER TABLE jobs ADD COLUMN issue_key TEXT",
        "ALTER TABLE jobs ADD COLUMN issue_sha256 TEXT",
        """CREATE TABLE deliveries(
            delivery_id TEXT PRIMARY KEY, raw_body_sha256 TEXT NOT NULL,
            event TEXT NOT NULL, action TEXT, received_at TEXT NOT NULL,
            outcome TEXT NOT NULL, reason TEXT NOT NULL, work_key TEXT, issue_sha256 TEXT)""",
        """CREATE TABLE delivery_conflicts(
            delivery_id TEXT NOT NULL, raw_body_sha256 TEXT NOT NULL,
            received_at TEXT NOT NULL, PRIMARY KEY(delivery_id,raw_body_sha256))""",
        """CREATE TABLE issue_heads(
            issue_key TEXT PRIMARY KEY, updated_us INTEGER NOT NULL,
            issue_sha256 TEXT NOT NULL, issue_json BLOB NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('active','conflict')))""",
        "CREATE INDEX jobs_issue_revision ON jobs(issue_key,issue_sha256,status)",
    ),
    (
        "CREATE TABLE local_inputs(work_key TEXT PRIMARY KEY REFERENCES jobs(work_key), "
        "input_sha256 TEXT NOT NULL,input_json BLOB NOT NULL)",
        "CREATE TABLE local_results(work_key TEXT PRIMARY KEY REFERENCES jobs(work_key), "
        "issue_key TEXT NOT NULL,issue_sha256 TEXT NOT NULL,result_json BLOB NOT NULL)",
        "CREATE TABLE local_dry_runs(action_id TEXT PRIMARY KEY,issue_key TEXT NOT NULL, "
        "revision_sha256 TEXT NOT NULL,ruling_event_id TEXT NOT NULL,operation TEXT NOT NULL, "
        "payload_sha256 TEXT NOT NULL,payload_json BLOB NOT NULL,mode TEXT NOT NULL "
        "CHECK(mode='dry_run'),created_at TEXT NOT NULL)",
    ),
    (
        "CREATE TABLE repository_captures(snapshot_id TEXT PRIMARY KEY, "
        "installation_id INTEGER NOT NULL,repository_id INTEGER NOT NULL,commit_sha TEXT NOT NULL,"
        "provenance TEXT NOT NULL,captured_at TEXT NOT NULL,manifest_json BLOB NOT NULL,"
        "files_json BLOB NOT NULL,inventory_sha256 TEXT NOT NULL,"
        "UNIQUE(installation_id,repository_id,commit_sha,provenance))",
        "CREATE TABLE work_captures(work_key TEXT PRIMARY KEY REFERENCES jobs(work_key),"
        "snapshot_id TEXT NOT NULL REFERENCES repository_captures(snapshot_id))",
    ),
    (
        # NULL deliberately leaves pre-binding captures untrusted; never infer an anchor.
        "ALTER TABLE work_captures ADD COLUMN binding_sha256 TEXT",
    ),
)


class StoreError(RuntimeError):
    pass


def _integer(value, code="invalid_time"):
    if type(value) is not int or value < 0 or value > 9223372036854775807:
        raise StoreError(code)


def _key(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise StoreError("invalid_work_key")


def _identifier(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        raise StoreError("invalid_identifier")


@dataclass(frozen=True, slots=True)
class JobLease:
    work_key: str
    token: str = field(repr=False)
    owner: str
    attempt: int
    lease_until_us: int
    payload: bytes = field(repr=False)


class JobStore:
    """One connection per worker. All claims/transitions use BEGIN IMMEDIATE."""

    def __init__(self, path: Path | str):
        self.connection = sqlite3.connect(path, timeout=5, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        try:
            app_id = self.connection.execute("PRAGMA application_id").fetchone()[0]
            tables = self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            if app_id not in (0, APPLICATION_ID) or (app_id == 0 and tables):
                raise StoreError("unrelated_database")
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA busy_timeout=5000")
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=FULL")
            self._migrate()
        except Exception:
            self.connection.close()
            raise

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @contextmanager
    def transaction(self):
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self.connection
            self.connection.execute("COMMIT")
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    def _migrate(self):
        with self.transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version < 0 or version > len(MIGRATIONS):
                raise StoreError("unsupported_database_version")
            if version:
                rows = connection.execute(
                    "SELECT version, checksum FROM schema_migrations ORDER BY version"
                ).fetchall()
                expected = [
                    (index, hashlib.sha256("\n".join(statements).encode()).hexdigest())
                    for index, statements in enumerate(MIGRATIONS[:version], 1)
                ]
                if [(row[0], row[1]) for row in rows] != expected:
                    raise StoreError("migration_checksum_mismatch")
            for index, statements in enumerate(MIGRATIONS[version:], version + 1):
                for statement in statements:
                    connection.execute(statement)
                checksum = hashlib.sha256("\n".join(statements).encode()).hexdigest()
                connection.execute("INSERT INTO schema_migrations VALUES(?,?)", (index, checksum))
                connection.execute(f"PRAGMA user_version={index}")
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")

    def enqueue(self, work_key: str, payload: bytes, *, now_us: int, max_attempts: int = 3) -> bool:
        with self.transaction() as connection:
            return self.enqueue_in(
                connection, work_key, payload, now_us=now_us, max_attempts=max_attempts
            )

    def enqueue_in(
        self, connection, work_key: str, payload: bytes, *, now_us: int, max_attempts: int = 3
    ) -> bool:
        """Same-connection extension for atomic application delivery+job claims only."""
        if connection is not self.connection or not connection.in_transaction:
            raise StoreError("enqueue_requires_owned_transaction")
        _key(work_key)
        _integer(now_us)
        if type(payload) is not bytes or len(payload) > 1048576:
            raise StoreError("invalid_payload")
        if type(max_attempts) is not int or not 1 <= max_attempts <= 10:
            raise StoreError("invalid_attempt_limit")

        # Only valid JSON is stored; callers own domain schema validation.
        def unique_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate_key")
                result[key] = value
            return result

        def invalid_constant(_):
            raise ValueError("nonfinite_json")

        try:
            json.loads(payload, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)
        except (ValueError, UnicodeError):
            raise StoreError("invalid_payload") from None
        digest = hashlib.sha256(payload).hexdigest()
        existing = connection.execute(
            "SELECT payload_sha256,max_attempts FROM jobs WHERE work_key=?", (work_key,)
        ).fetchone()
        if existing:
            if existing[0] != digest or existing[1] != max_attempts:
                raise StoreError("work_key_conflict")
            return False
        connection.execute(
            "INSERT INTO jobs(work_key,payload,payload_sha256,status,max_attempts,"
            "available_us,created_us) VALUES(?,?,?,'queued',?,?,?)",
            (work_key, payload, digest, max_attempts, now_us, now_us),
        )
        return True

    def lease(self, owner: str, *, now_us: int, duration_us: int) -> JobLease | None:
        _identifier(owner)
        _integer(now_us)
        _integer(duration_us)
        if duration_us == 0 or now_us + duration_us > 9223372036854775807:
            raise StoreError("invalid_lease_duration")
        with self.transaction() as connection:
            connection.execute(
                "UPDATE jobs SET status='failed',lease_token=NULL,lease_owner=NULL,"
                "lease_until_us=NULL,result_code='attempts_exhausted' "
                "WHERE status='leased' AND lease_until_us<=? AND attempts>=max_attempts",
                (now_us,),
            )
            row = connection.execute(
                "SELECT * FROM jobs WHERE attempts<max_attempts AND available_us<=? "
                "AND (status='queued' OR (status='leased' AND lease_until_us<=?)) "
                "ORDER BY created_us,work_key LIMIT 1",
                (now_us, now_us),
            ).fetchone()
            if row is None:
                return None
            token = secrets.token_hex(16)
            until = now_us + duration_us
            connection.execute(
                "UPDATE jobs SET status='leased',attempts=attempts+1,lease_token=?,"
                "lease_owner=?,lease_until_us=? WHERE work_key=?",
                (token, owner, until, row["work_key"]),
            )
            return JobLease(
                row["work_key"], token, owner, row["attempts"] + 1, until, bytes(row["payload"])
            )

    def finish(self, lease: JobLease, *, now_us: int, result_code: str = "complete") -> bool:
        _integer(now_us)
        _identifier(result_code)
        with self.transaction() as connection:
            result = connection.execute(
                "UPDATE jobs SET status='done',result_code=?,lease_token=NULL,lease_owner=NULL,"
                "lease_until_us=NULL WHERE work_key=? AND status='leased' AND lease_token=? "
                "AND lease_owner=? AND lease_until_us>?",
                (result_code, lease.work_key, lease.token, lease.owner, now_us),
            )
            return result.rowcount == 1

    def retry(self, lease: JobLease, *, now_us: int, delay_us: int, reason: str) -> bool:
        _integer(now_us)
        _integer(delay_us)
        _identifier(reason)
        _integer(now_us + delay_us)
        with self.transaction() as connection:
            result = connection.execute(
                "UPDATE jobs SET status=CASE WHEN attempts<max_attempts THEN 'queued' "
                "ELSE 'failed' END,available_us=?,result_code=?,lease_token=NULL,"
                "lease_owner=NULL,lease_until_us=NULL WHERE work_key=? AND status='leased' "
                "AND lease_token=? AND lease_owner=? AND lease_until_us>?",
                (now_us + delay_us, reason, lease.work_key, lease.token, lease.owner, now_us),
            )
            return result.rowcount == 1

    def status_counts(self) -> dict[str, int]:
        return {
            row[0]: row[1]
            for row in self.connection.execute("SELECT status,COUNT(*) FROM jobs GROUP BY status")
        }
