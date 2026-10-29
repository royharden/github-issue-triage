"""Durable, fixture-only local workflow. No GitHub, provider or human-authentication client."""

import hashlib
import hmac
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import field_validator

from ..contracts.domain import Digest, utc_epoch_us
from ..ingest import IntakeStore
from ..ingest.labels import LabelWire
from ..judges.contracts import JudgeHold, JudgmentRecord
from ..shared.codeindex.canonical import canonical_bytes
from ..shared.ghapp import parse_delivery
from ..shared.rulings.store import JournalStore
from ..store import JobStore
from ..suggest.comments import build_comment
from ..suggest.envelope import SuggestionSet, build_suggestions
from ..suggest.labels import propose_labels
from .bundle import analyze, parse_bundle
from .runner import run_rules


class WorkflowError(RuntimeError):
    """Closed public reason, never raw payloads or private exception messages."""


def now_utc():
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class ProcessObservation(LabelWire):
    isolated: Literal[True]
    environment_names: tuple[str, ...]
    provider_dispatch: Literal["disabled"]

    @field_validator("environment_names", mode="before")
    @classmethod
    def immutable_names(cls, value):
        return tuple(value) if type(value) is list else value


class LocalResult(LabelWire):
    issue_key: str
    issue_sha256: Digest
    bundle_sha256: Digest
    source_kind: Literal["fixture_inventory"] = "fixture_inventory"
    status: Literal["proposal", "needs_human"]
    reason_codes: tuple[str, ...]
    judgment: JudgmentRecord | None
    suggestions: SuggestionSet | None
    process: ProcessObservation | None

    @field_validator("reason_codes", mode="before")
    @classmethod
    def immutable_reasons(cls, value):
        return tuple(value) if type(value) is list else value


def synthetic_delivery(bundle, delivery_id, *, signature_header=None):
    """Exercise HMAC/intake with an explicitly public demo key, never GitHub authentication."""
    issue, key = bundle.issue, bundle.issue.key
    raw = canonical_bytes(
        {
            "action": "opened",
            "installation": {"id": key.installation_id},
            "repository": {
                "id": key.repository_id,
                "owner": {"login": key.owner},
                "name": key.repository,
            },
            "issue": {
                "number": key.issue_number,
                "title": issue.title,
                "body": issue.body,
                "updated_at": issue.updated_at,
                "user": {"id": issue.author_id, "login": issue.author_login},
            },
            "sender": {"id": issue.author_id},
        }
    )
    public_demo_key = b"public-local-demo-not-a-credential"
    signature = (
        "sha256=" + hmac.new(public_demo_key, raw, hashlib.sha256).hexdigest()
        if signature_header is None
        else signature_header
    )
    return parse_delivery(
        raw,
        signature_header=signature,
        secret=public_demo_key,
        delivery_id=delivery_id,
        event="issues",
        received_at=bundle.captured_at,
        installation_id=key.installation_id,
        repository_id=key.repository_id,
    )


def make_suggestions(bundle, analysis, judgment):
    ctx = analysis.context
    labels = propose_labels(ctx.issue, judgment, bundle.labels, bundle.label_mapping.checked())
    comment = build_comment(
        ctx, judgment, registry=analysis.registry, resolution_context=analysis.resolution_context
    )
    return build_suggestions(ctx, judgment, bundle.labels, labels, comment)


class LocalWorkflow:
    def __init__(self, root):
        self.root = Path(root).absolute()
        self.root.mkdir(mode=0o700, exist_ok=True)
        # Validate local root/ancestors before opening SQLite. Hostile replacement is not supported.
        self.journal = JournalStore(self.root, "review.jsonl")
        self.judge_dir = self.root / "judge"
        self.judge_dir.mkdir(mode=0o700, exist_ok=True)
        JournalStore(self.judge_dir, "boundary-check.jsonl")
        self.jobs = JobStore(self.root / "jobs.sqlite3")
        self.intake = IntakeStore(self.jobs)

    def close(self):
        self.jobs.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def submit(self, bundle, delivery_id, *, signature_header=None):
        bundle = parse_bundle(bundle.canonical_bytes())
        delivery = synthetic_delivery(bundle, delivery_id, signature_header=signature_header)
        # Receipt, head, job and immutable captured bundle must survive or roll back together.
        with self.jobs.transaction() as connection:
            outcome = self.intake.receive_in(connection, delivery)
            if outcome.work_key is not None:
                row = connection.execute(
                    "SELECT input_sha256 FROM local_inputs WHERE work_key=?", (outcome.work_key,)
                ).fetchone()
                if row and row[0] != bundle.sha256:
                    raise WorkflowError("captured_input_conflict")
                connection.execute(
                    "INSERT OR IGNORE INTO local_inputs VALUES(?,?,?)",
                    (outcome.work_key, bundle.sha256, bundle.canonical_bytes()),
                )
        return outcome

    def _bundle(self, work_key):
        row = self.jobs.connection.execute(
            "SELECT input_sha256,input_json FROM local_inputs WHERE work_key=?", (work_key,)
        ).fetchone()
        if row is None:
            raise WorkflowError("local_input_unavailable")
        bundle = parse_bundle(bytes(row[1]))
        if bundle.sha256 != row[0]:
            raise WorkflowError("local_input_hash_mismatch")
        return bundle

    def run_once(self, *, at_utc=None, supplied_environment=None):
        stamp = now_utc() if at_utc is None else at_utc
        now = utc_epoch_us(stamp)
        began = time.monotonic()
        lease = self.jobs.lease("local-fixture-worker", now_us=now, duration_us=30000000)
        if lease is None:
            return None
        try:
            bundle = self._bundle(lease.work_key)
            issue = bundle.issue
            if not self.intake.is_current(issue) or lease.payload != issue.canonical_bytes():
                raise WorkflowError("stale_issue_revision")
            analysis = analyze(bundle)
            judgment = suggestions = process = None
            reasons = ("screen_needs_human",)
            if analysis.context.screen.decision == "pass":
                try:
                    judgment, observation = run_rules(
                        bundle,
                        analysis,
                        cwd=self.judge_dir,
                        supplied_environment=supplied_environment,
                    )
                    process = ProcessObservation.model_validate(observation)
                    suggestions = make_suggestions(bundle, analysis, judgment)
                    reasons = judgment.reason_codes
                except JudgeHold as error:
                    reasons = (str(error),)
            result = LocalResult(
                issue_key=issue.key.stable_id,
                issue_sha256=issue.sha256,
                bundle_sha256=bundle.sha256,
                status="proposal" if judgment and judgment.status == "proposal" else "needs_human",
                reason_codes=reasons,
                judgment=judgment,
                suggestions=suggestions,
                process=process,
            )
            with self.jobs.transaction() as connection:
                if not self.intake.is_current(issue):
                    raise WorkflowError("stale_issue_revision")
                finished_us = now + int((time.monotonic() - began) * 1000000)
                completed = connection.execute(
                    "UPDATE jobs SET status='done',result_code=?,lease_token=NULL,"
                    "lease_owner=NULL,lease_until_us=NULL WHERE work_key=? AND status='leased' "
                    "AND lease_token=? AND lease_owner=? AND lease_until_us>?",
                    (result.status, lease.work_key, lease.token, lease.owner, finished_us),
                ).rowcount
                if completed != 1:
                    raise WorkflowError("lease_no_longer_current")
                connection.execute(
                    "INSERT INTO local_results VALUES(?,?,?,?)",
                    (lease.work_key, issue.key.stable_id, issue.sha256, result.canonical_bytes()),
                )
            return result
        except Exception:
            finished_us = now + int((time.monotonic() - began) * 1000000)
            self.jobs.retry(
                lease, now_us=finished_us, delay_us=1000000, reason="local_worker_unavailable"
            )
            raise WorkflowError("local_worker_unavailable") from None

    def queue(self):
        return [
            dict(row)
            for row in self.jobs.connection.execute(
                "SELECT j.work_key,j.issue_key,j.issue_sha256,j.status,j.result_code,"
                "h.state AS issue_state FROM jobs j LEFT JOIN issue_heads h "
                "ON j.issue_key=h.issue_key ORDER BY j.created_us,j.work_key"
            )
        ]

    def result(self, issue_key):
        row = self.jobs.connection.execute(
            "SELECT r.result_json FROM local_results r JOIN issue_heads h "
            "ON r.issue_key=h.issue_key AND r.issue_sha256=h.issue_sha256 "
            "WHERE r.issue_key=? AND h.state='active'",
            (issue_key,),
        ).fetchone()
        if row is None:
            raise WorkflowError("current_result_unavailable")
        result = LocalResult.parse_json(bytes(row[0]))
        if result.issue_key != issue_key:
            raise WorkflowError("current_result_mismatch")
        return result

    def current(self, issue_key):
        result = self.result(issue_key)
        row = self.jobs.connection.execute(
            "SELECT work_key FROM local_results WHERE issue_key=? AND issue_sha256=?",
            (issue_key, result.issue_sha256),
        ).fetchone()
        bundle = self._bundle(row[0])
        if result.bundle_sha256 != bundle.sha256 or not self.intake.is_current(bundle.issue):
            raise WorkflowError("stale_issue_revision")
        if result.suggestions is None or result.judgment is None:
            raise WorkflowError("no_reviewable_proposal")
        analysis = analyze(bundle)
        current = make_suggestions(bundle, analysis, result.judgment)
        if current != result.suggestions:
            raise WorkflowError("proposal_generation_changed")
        return bundle, analysis, result
