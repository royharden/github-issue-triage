"""Delivery identity, bounded job coalescing and causal issue-head state in one transaction."""

import hashlib
from dataclasses import dataclass

from issue_triage.contracts import IssueInput, utc_epoch_us
from issue_triage.shared.ghapp import Delivery
from issue_triage.store import JobStore, StoreError


@dataclass(frozen=True, slots=True)
class IntakeOutcome:
    delivery_id: str
    status: str
    reason: str
    work_key: str | None = None
    issue_sha256: str | None = None


class IntakeStore:
    def __init__(self, jobs: JobStore):
        self.jobs = jobs

    def receive(self, delivery: Delivery) -> IntakeOutcome:
        """Accept only a local verifier's typed result, never arbitrary webhook JSON."""
        with self.jobs.transaction() as connection:
            return self.receive_in(connection, delivery)

    def receive_in(self, connection, delivery: Delivery) -> IntakeOutcome:
        """Extend only an owned active transaction (e.g. atomic captured local input)."""
        if connection is not self.jobs.connection or not connection.in_transaction:
            raise StoreError("receive_requires_owned_transaction")
        if type(delivery) is not Delivery or delivery.disposition not in ("supported", "ignored"):
            raise StoreError("unverified_delivery")
        now = utc_epoch_us(delivery.received_at)
        existing = connection.execute(
            "SELECT * FROM deliveries WHERE delivery_id=?", (delivery.delivery_id,)
        ).fetchone()
        if existing:
            if existing["raw_body_sha256"] != delivery.raw_body_sha256:
                connection.execute(
                    "INSERT OR IGNORE INTO delivery_conflicts VALUES(?,?,?)",
                    (delivery.delivery_id, delivery.raw_body_sha256, delivery.received_at),
                )
                return IntakeOutcome(delivery.delivery_id, "conflict", "delivery_bytes_conflict")
            return IntakeOutcome(
                delivery.delivery_id,
                "duplicate",
                "delivery_already_recorded",
                existing["work_key"],
                existing["issue_sha256"],
            )
        if delivery.disposition == "ignored":
            outcome = IntakeOutcome(delivery.delivery_id, "ignored", delivery.reason)
        else:
            envelope = delivery.envelope
            if (
                envelope is None
                or envelope.delivery_id != delivery.delivery_id
                or envelope.raw_body_sha256 != delivery.raw_body_sha256
            ):
                raise StoreError("delivery_binding_mismatch")
            issue = envelope.issue
            updated = utc_epoch_us(issue.updated_at)
            key = issue.key.stable_id
            head = connection.execute(
                "SELECT * FROM issue_heads WHERE issue_key=?", (key,)
            ).fetchone()
            if head and updated < head["updated_us"]:
                outcome = IntakeOutcome(
                    delivery.delivery_id,
                    "stale",
                    "older_issue_revision",
                    issue_sha256=issue.sha256,
                )
            elif (
                head
                and updated == head["updated_us"]
                and (head["state"] == "conflict" or head["issue_sha256"] != issue.sha256)
            ):
                # Preserve first bytes as historical input; neither arrival wins causality.
                connection.execute(
                    "UPDATE issue_heads SET state='conflict' WHERE issue_key=?", (key,)
                )
                self._invalidate_pending(connection, key, "issue_time_conflict")
                outcome = IntakeOutcome(
                    delivery.delivery_id,
                    "needs_human",
                    "equal_time_revision_conflict",
                    issue_sha256=issue.sha256,
                )
            else:
                if head is None or updated > head["updated_us"]:
                    self._invalidate_pending(connection, key, "superseded_revision")
                    connection.execute(
                        "INSERT INTO issue_heads VALUES(?,?,?,?,'active') "
                        "ON CONFLICT(issue_key) DO UPDATE SET "
                        "updated_us=excluded.updated_us,issue_sha256=excluded.issue_sha256,"
                        "issue_json=excluded.issue_json,state='active'",
                        (key, updated, issue.sha256, issue.canonical_bytes()),
                    )
                # Intake only: paid evaluation identity additionally needs captured SHA,
                # labels/policy/threshold/schema digests and its own S3 admission later.
                work_key = hashlib.sha256(
                    ("snapshot-intake/1\0" + key + "\0" + issue.sha256).encode()
                ).hexdigest()
                created = self.jobs.enqueue_in(
                    connection, work_key, issue.canonical_bytes(), now_us=now
                )
                connection.execute(
                    "UPDATE jobs SET issue_key=?,issue_sha256=? WHERE work_key=?",
                    (key, issue.sha256, work_key),
                )
                outcome = IntakeOutcome(
                    delivery.delivery_id,
                    "queued" if created else "duplicate",
                    "new_issue_revision" if created else "coalesced_issue_revision",
                    work_key,
                    issue.sha256,
                )
        connection.execute(
            "INSERT INTO deliveries VALUES(?,?,?,?,?,?,?,?,?)",
            (
                delivery.delivery_id,
                delivery.raw_body_sha256,
                delivery.event,
                delivery.action,
                delivery.received_at,
                outcome.status,
                outcome.reason,
                outcome.work_key,
                outcome.issue_sha256,
            ),
        )
        return outcome

    @staticmethod
    def _invalidate_pending(connection, issue_key, reason):
        connection.execute(
            "UPDATE jobs SET status='failed',result_code=?,lease_token=NULL,"
            "lease_owner=NULL,lease_until_us=NULL WHERE issue_key=? "
            "AND status IN ('queued','leased')",
            (reason, issue_key),
        )

    def is_current(self, issue: IssueInput) -> bool:
        row = self.jobs.connection.execute(
            "SELECT state,issue_sha256 FROM issue_heads WHERE issue_key=?", (issue.key.stable_id,)
        ).fetchone()
        return bool(row and row["state"] == "active" and row["issue_sha256"] == issue.sha256)

    def counts(self) -> dict[str, int]:
        return {
            row[0]: row[1]
            for row in self.jobs.connection.execute(
                "SELECT outcome,COUNT(*) FROM deliveries GROUP BY outcome"
            )
        }
