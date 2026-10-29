"""Atomic capture/intake extension of JobStore; no separate queue or Git admission bypass."""

import base64
import hashlib
import re
from dataclasses import dataclass, field

from ..contracts import IssueInput, utc_epoch_us
from ..shared.codeindex.canonical import canonical_bytes, decode_canonical
from ..shared.codeindex.inventory import inventory_from_files
from ..shared.ghapp.capture import CapturedRepository, RepositoryIdentity, capture_repository
from ..store import JobStore, StoreError
from .intake import IntakeOutcome, IntakeStore


@dataclass(frozen=True, slots=True)
class CapturedIntake:
    outcome: IntakeOutcome
    capture: CapturedRepository | None = field(repr=False)
    snapshot_id: str | None = None
    captured_at: str | None = None
    inventory_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class RetainedCapture:
    """Validated persisted input, not current-job or authenticated Git authority."""

    work_key: str
    issue: IssueInput = field(repr=False)
    capture: CapturedRepository = field(repr=False)
    snapshot_id: str
    captured_at: str
    inventory_sha256: str

    @property
    def commit_sha(self):
        return self.capture.commit_sha

    @property
    def provenance(self):
        return self.capture.provenance


class CaptureIntake:
    """One SQLite transaction binds receipt/head/job to its first immutable capture.

    The bounded injected read occurs while the write transaction is held. Competing writers
    may hit the existing SQLite busy timeout; they must retry the delivery, never bypass it.
    Synthetic/configured provenance is retained and cannot create a Git SnapshotRef.
    """

    def __init__(self, jobs: JobStore, identity: RepositoryIdentity):
        if type(identity) is not RepositoryIdentity:
            raise StoreError("invalid_capture_identity")
        self.jobs = jobs
        self.identity = identity
        self.intake = IntakeStore(jobs)

    def _decode(self, row):
        try:
            wire = decode_canonical(row["files_json"], max_bytes=145 * 1024 * 1024)
            if type(wire) is not dict or not 1 <= len(wire) <= 5000:
                raise ValueError
            files = {}
            for path, encoded in wire.items():
                if type(encoded) is not str or len(encoded) > 140 * 1024 * 1024:
                    raise ValueError
                files[path] = base64.b64decode(encoded, validate=True)
                if base64.b64encode(files[path]).decode("ascii") != encoded:
                    raise ValueError
            inventory = inventory_from_files(files)
            manifest = decode_canonical(row["manifest_json"], max_bytes=24 * 1024 * 1024)
            capture = CapturedRepository(
                self.identity,
                row["commit_sha"],
                row["provenance"],
                manifest["capture"]["compressed_sha256"],
                manifest["capture"]["expanded_tar_sha256"],
                files,
            )
            expected = self._manifest(capture, row["captured_at"], inventory.sha256)
            if (
                row["installation_id"] != self.identity.installation_id
                or row["repository_id"] != self.identity.repository_id
                or row["inventory_sha256"] != inventory.sha256
                or row["manifest_json"] != expected
                or row["snapshot_id"] != hashlib.sha256(expected).hexdigest()
            ):
                raise ValueError
            utc_epoch_us(row["captured_at"])
            return capture
        except Exception:
            raise StoreError("stored_capture_invalid") from None

    @staticmethod
    def _manifest(capture, captured_at, inventory_sha256):
        # Reuse the canonical inventory identity rather than creating another index manifest.
        import json

        return canonical_bytes(
            {
                "capture": json.loads(capture.manifest_bytes()),
                "captured_at": captured_at,
                "inventory_sha256": inventory_sha256,
            }
        )

    @staticmethod
    def _binding(work_key, issue_key, issue_sha256, snapshot_id):
        return hashlib.sha256(
            canonical_bytes(
                {
                    "kind": "work-capture/1",
                    "work_key": work_key,
                    "issue_key": issue_key,
                    "issue_sha256": issue_sha256,
                    "snapshot_id": snapshot_id,
                }
            )
        ).hexdigest()

    def _validate_binding(self, row, work_key, issue):
        # A missing legacy anchor cannot safely be reconstructed from today's mapping.
        expected = self._binding(work_key, issue.key.stable_id, issue.sha256, row["snapshot_id"])
        if row["binding_sha256"] != expected:
            raise StoreError("stored_capture_invalid")

    def load(self, work_key: str) -> RetainedCapture:
        """Reload original capture bytes without intake, fetching or job transitions.

        A historical/superseded job may still be inspected; callers must separately
        validate a current lease/revision before processing it. No Git SnapshotRef
        admission or account-authentication claim follows from this value.
        """
        with self.jobs.transaction() as connection:
            return self.load_in(connection, work_key)

    def load_in(self, connection, work_key: str) -> RetainedCapture:
        """Same loader inside an owned transaction, for atomic current-work completion."""
        if connection is not self.jobs.connection or not connection.in_transaction:
            raise StoreError("capture_load_requires_owned_transaction")
        if type(work_key) is not str or re.fullmatch(r"[0-9a-f]{64}", work_key) is None:
            raise StoreError("invalid_work_key")
        if connection.execute(
            "SELECT 1 FROM local_inputs WHERE work_key=?", (work_key,)
        ).fetchone():
            raise StoreError("fixture_work_cannot_be_recaptured")
        row = connection.execute(
            "SELECT c.*,w.binding_sha256,j.payload AS job_payload,"
            "j.payload_sha256 AS job_payload_sha256,"
            "j.issue_key AS job_issue_key,j.issue_sha256 AS job_issue_sha256 "
            "FROM jobs j JOIN work_captures w ON w.work_key=j.work_key "
            "JOIN repository_captures c ON c.snapshot_id=w.snapshot_id WHERE j.work_key=?",
            (work_key,),
        ).fetchone()
        if row is None:
            raise StoreError("stored_capture_unavailable")
        try:
            raw = row["job_payload"]
            if type(raw) is not bytes or len(raw) > 1048576:
                raise ValueError
            issue = IssueInput.parse_json(raw)
            key = issue.key
            expected_work_key = hashlib.sha256(
                ("snapshot-intake/1\0" + key.stable_id + "\0" + issue.sha256).encode()
            ).hexdigest()
            if (
                hashlib.sha256(raw).hexdigest() != row["job_payload_sha256"]
                or raw != issue.canonical_bytes()
                or row["job_issue_key"] != key.stable_id
                or row["job_issue_sha256"] != issue.sha256
                or expected_work_key != work_key
                or key.installation_id != self.identity.installation_id
                or key.repository_id != self.identity.repository_id
                or key.owner.casefold() != self.identity.owner.casefold()
                or key.repository.casefold() != self.identity.repository.casefold()
            ):
                raise ValueError
            self._validate_binding(row, work_key, issue)
            capture = self._decode(row)
            return RetainedCapture(
                work_key,
                issue,
                capture,
                row["snapshot_id"],
                row["captured_at"],
                row["inventory_sha256"],
            )
        except Exception:
            raise StoreError("stored_capture_invalid") from None

    def receive(
        self, delivery, *, token=None, transport, clock, captured_at, provenance, token_factory=None
    ):
        """Acquire an explicit deferred token only for work needing its first capture.

        The factory runs inside the same rollback boundary after replay/identity checks.
        Its caller owns signing, transport and credential configuration; nothing is discovered.
        """
        if token_factory is not None and (token is not None or not callable(token_factory)):
            raise StoreError("invalid_capture_token_source")
        utc_epoch_us(captured_at)
        with self.jobs.transaction() as connection:
            outcome = self.intake.receive_in(connection, delivery)
            if outcome.work_key is None or outcome.status not in ("queued", "duplicate"):
                return CapturedIntake(outcome, None)
            if delivery.envelope is None:
                raise StoreError("capture_delivery_binding_missing")
            key = delivery.envelope.issue.key
            if (
                key.installation_id != self.identity.installation_id
                or key.repository_id != self.identity.repository_id
                or key.owner.casefold() != self.identity.owner.casefold()
                or key.repository.casefold() != self.identity.repository.casefold()
            ):
                raise StoreError("capture_delivery_repository_mismatch")
            row = connection.execute(
                "SELECT c.*,w.binding_sha256 FROM work_captures w JOIN repository_captures c "
                "ON c.snapshot_id=w.snapshot_id WHERE w.work_key=?",
                (outcome.work_key,),
            ).fetchone()
            if row:
                self._validate_binding(row, outcome.work_key, delivery.envelope.issue)
                capture = self._decode(row)
                return CapturedIntake(
                    outcome,
                    capture,
                    row["snapshot_id"],
                    row["captured_at"],
                    row["inventory_sha256"],
                )
            if connection.execute(
                "SELECT 1 FROM local_inputs WHERE work_key=?", (outcome.work_key,)
            ).fetchone():
                raise StoreError("fixture_work_cannot_be_recaptured")

            def cached(identity, sha, origin):
                existing = connection.execute(
                    "SELECT * FROM repository_captures WHERE installation_id=? AND repository_id=? "
                    "AND commit_sha=? AND provenance=?",
                    (identity.installation_id, identity.repository_id, sha, origin),
                ).fetchone()
                return self._decode(existing) if existing else None

            capture_token = token if token_factory is None else token_factory()
            capture = capture_repository(
                self.identity,
                token=capture_token,
                transport=transport,
                clock=clock,
                provenance=provenance,
                cached=cached,
            )
            inventory = inventory_from_files(capture.files)
            row = connection.execute(
                "SELECT * FROM repository_captures WHERE installation_id=? AND repository_id=? "
                "AND commit_sha=? AND provenance=?",
                (
                    self.identity.installation_id,
                    self.identity.repository_id,
                    capture.commit_sha,
                    provenance,
                ),
            ).fetchone()
            if row is None:
                manifest = self._manifest(capture, captured_at, inventory.sha256)
                snapshot_id = hashlib.sha256(manifest).hexdigest()
                files_json = canonical_bytes(
                    {
                        path: base64.b64encode(body).decode("ascii")
                        for path, body in capture.files.items()
                    }
                )
                connection.execute(
                    "INSERT INTO repository_captures VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        snapshot_id,
                        self.identity.installation_id,
                        self.identity.repository_id,
                        capture.commit_sha,
                        provenance,
                        captured_at,
                        manifest,
                        files_json,
                        inventory.sha256,
                    ),
                )
            else:
                snapshot_id, captured_at = row["snapshot_id"], row["captured_at"]
            connection.execute(
                "INSERT INTO work_captures(work_key,snapshot_id,binding_sha256) VALUES(?,?,?)",
                (
                    outcome.work_key,
                    snapshot_id,
                    self._binding(
                        outcome.work_key, key.stable_id, delivery.envelope.issue.sha256, snapshot_id
                    ),
                ),
            )
            return CapturedIntake(outcome, capture, snapshot_id, captured_at, inventory.sha256)
