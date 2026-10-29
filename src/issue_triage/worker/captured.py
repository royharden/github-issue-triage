"""Explicit retained-work consumer; local deterministic port, no transport or apply path."""

import time
from typing import Annotated, Literal

from pydantic import Field, model_validator

from ..contracts.domain import Digest, utc_epoch_us
from ..ingest.capture import CaptureIntake
from ..ingest.labels import LabelInventory, LabelWire
from ..judges.context import JudgmentContext
from ..judges.contracts import DEFAULT_JUDGMENT_POLICY, JudgmentPolicy, JudgmentRecord
from ..judges.rules import judge_rules
from ..shared.codeindex.canonical import digest
from ..shared.ghapp.capture import RepositoryIdentity
from ..shared.screen import ScreenPolicy, UntrustedText, screen_rules
from ..store import JobStore
from ..store.database import JobLease
from ..suggest.comments import TEMPLATE_SHA256, CommentDraft, validate_current_judgment
from ..suggest.envelope import SuggestionSet, build_suggestions
from ..suggest.labels import LabelMap, propose_labels
from .capture_checks import check_capture

DEFAULT_CAPTURE_SCREEN = ScreenPolicy("s6-retained-capture-screen/1", "rules")
CITATION_HOLD = "source_citation_contract_unavailable"


class CapturedWorkflowError(RuntimeError):
    """Only fixed codes cross this boundary; no issue or injected-port exception text."""


class CapturedResult(LabelWire):
    result_kind: Literal["retained_capture_worker/1"] = "retained_capture_worker/1"
    source_kind: Literal["retained_capture"] = "retained_capture"
    work_key: Digest
    issue_key: str
    issue_sha256: Digest
    snapshot_id: Digest
    commit_sha: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    inventory_sha256: Digest
    captured_at: str
    transport_provenance: Literal["synthetic_transport", "configured_transport"]
    authenticated_github_origin: Literal[False] = False
    dependencies_sha256: Digest
    lease_sha256: Digest
    report_sha256: Digest
    status: Literal["needs_human"] = "needs_human"
    reason: Literal[
        "screen_needs_human",
        "deterministic_judge_unavailable",
        "source_citation_contract_unavailable",
    ]
    comment_status: Literal["held"] = "held"
    judgment: JudgmentRecord | None = None
    suggestions: SuggestionSet | None = None
    judge_dispatched: bool = False
    judge_port: Literal["local_injected_deterministic_not_process_isolated"] = (
        "local_injected_deterministic_not_process_isolated"
    )

    @model_validator(mode="after")
    def held_boundary(self):
        utc_epoch_us(self.captured_at)
        if self.reason == "screen_needs_human" and self.judge_dispatched:
            raise ValueError("screen_hold_cannot_dispatch")
        if self.reason != CITATION_HOLD:
            if self.judgment is not None or self.suggestions is not None:
                raise ValueError("held_captured_result_has_no_proposals")
        else:
            if self.judgment is None or self.suggestions is None or not self.judge_dispatched:
                raise ValueError("captured_result_components_missing")
            suggestion = self.suggestions
            comment = suggestion.fields[-1]
            if (
                self.judgment.issue_sha256 != self.issue_sha256
                or self.judgment.report_sha256 != self.report_sha256
                or suggestion.key.stable_id != self.issue_key
                or suggestion.issue_sha256 != self.issue_sha256
                or suggestion.report_sha256 != self.report_sha256
                or suggestion.judgment_sha256 != self.judgment.sha256
                or comment.field != "comment"
                or comment.status != "needs_human"
                or comment.value is not None
            ):
                raise ValueError("invalid_captured_result_components")
        return self


def _capture_identity(retained):
    return {
        "work_key": retained.work_key,
        "issue_key": retained.issue.key.stable_id,
        "issue_sha256": retained.issue.sha256,
        "snapshot_id": retained.snapshot_id,
        "commit_sha": retained.commit_sha,
        "inventory_sha256": retained.inventory_sha256,
        "captured_at": retained.captured_at,
        "transport_provenance": retained.provenance,
    }


def _lease_digest(lease):
    # An exact retry proves the original capability without persisting its raw token.
    return digest(
        {
            "work_key": lease.work_key,
            "token": lease.token,
            "owner": lease.owner,
            "attempt": lease.attempt,
            "lease_until_us": lease.lease_until_us,
        }
    )


def _dependencies(retained, labels, mapping, screen_policy, judgment_policy):
    return digest(
        {
            "consumer": "retained_capture_worker/1",
            "capture": _capture_identity(retained),
            "labels": labels.sha256,
            "mapping": mapping.sha256,
            "screen": screen_policy.sha256,
            "judgment": judgment_policy.sha256,
            "judge": "existing_local_deterministic_rules/1",
            "comment": CITATION_HOLD,
            "template": TEMPLATE_SHA256,
        }
    )


class CapturedWorkflow:
    """Host owns store, repository, label observations and trusted local judge callable.

    This port never claims queue work. A caller supplies an already-acquired lease.
    It does not supply a default judge, provider environment, token or subprocess.
    Exceptions leave the lease untouched for the existing expiry/retry mechanism.
    """

    def __init__(self, jobs: JobStore, identity: RepositoryIdentity):
        if type(jobs) is not JobStore or type(identity) is not RepositoryIdentity:
            raise CapturedWorkflowError("invalid_captured_worker_input")
        self.jobs = jobs
        self.identity = identity
        self.loader = CaptureIntake(jobs, identity)

    def _current(self, connection, lease, retained, *, now_us, completed=False):
        if not self.loader.intake.is_current(retained.issue):
            raise CapturedWorkflowError("stale_issue_revision")
        row = connection.execute(
            "SELECT * FROM jobs WHERE work_key=?", (lease.work_key,)
        ).fetchone()
        if (
            row is None
            or bytes(row["payload"]) != lease.payload
            or lease.payload != retained.issue.canonical_bytes()
            or row["attempts"] != lease.attempt
            or row["issue_key"] != retained.issue.key.stable_id
            or row["issue_sha256"] != retained.issue.sha256
        ):
            raise CapturedWorkflowError("lease_no_longer_current")
        if completed:
            if row["status"] != "done" or row["result_code"] != "needs_human":
                raise CapturedWorkflowError("stored_captured_result_invalid")
        elif (
            row["status"] != "leased"
            or row["lease_token"] != lease.token
            or row["lease_owner"] != lease.owner
            or row["lease_until_us"] != lease.lease_until_us
            or row["lease_until_us"] <= now_us
        ):
            raise CapturedWorkflowError("lease_no_longer_current")

    def consume(
        self,
        lease,
        *,
        labels,
        mapping,
        judge,
        at_utc,
        screen_policy=DEFAULT_CAPTURE_SCREEN,
        judgment_policy=DEFAULT_JUDGMENT_POLICY,
    ):
        try:
            return self._consume(
                lease,
                labels=labels,
                mapping=mapping,
                judge=judge,
                at_utc=at_utc,
                screen_policy=screen_policy,
                judgment_policy=judgment_policy,
            )
        except CapturedWorkflowError:
            raise
        except Exception:
            raise CapturedWorkflowError("captured_worker_unavailable") from None

    def _consume(self, lease, *, labels, mapping, judge, at_utc, screen_policy, judgment_policy):
        if (
            type(lease) is not JobLease
            or type(labels) is not LabelInventory
            or type(mapping) is not LabelMap
            or not callable(judge)
            or type(screen_policy) is not ScreenPolicy
            or screen_policy.required_method != "rules"
            or type(judgment_policy) is not JudgmentPolicy
        ):
            raise CapturedWorkflowError("invalid_captured_worker_input")
        supplied_labels = labels
        labels = LabelInventory.model_validate(labels.model_dump(mode="python"))
        screen_policy.__post_init__()
        judgment_policy.__post_init__()
        now = utc_epoch_us(at_utc)
        if now < 0:
            raise CapturedWorkflowError("invalid_captured_worker_input")
        began = time.monotonic()
        with self.jobs.transaction() as connection:
            retained = self.loader.load_in(connection, lease.work_key)
            if labels.repository_id != retained.issue.key.repository_id:
                raise CapturedWorkflowError("label_repository_mismatch")
            dependencies = _dependencies(retained, labels, mapping, screen_policy, judgment_policy)
            prior = connection.execute(
                "SELECT * FROM local_results WHERE work_key=?", (lease.work_key,)
            ).fetchone()
            self._current(connection, lease, retained, now_us=now, completed=prior is not None)
            if prior is not None:
                result = CapturedResult.parse_json(bytes(prior["result_json"]))
                if (
                    prior["issue_key"] != retained.issue.key.stable_id
                    or prior["issue_sha256"] != retained.issue.sha256
                    or result.dependencies_sha256 != dependencies
                    or result.lease_sha256 != _lease_digest(lease)
                    or any(
                        getattr(result, key) != value
                        for key, value in _capture_identity(retained).items()
                    )
                ):
                    raise CapturedWorkflowError("captured_result_dependencies_changed")
                return result

        # Reference checks use the same canonical retained loader and index builder.
        checks = check_capture(self.jobs, self.identity, lease.work_key)
        if _capture_identity(checks.retained) != _capture_identity(retained):
            raise CapturedWorkflowError("captured_input_changed")
        source = UntrustedText(
            retained.issue.key.stable_id, retained.issue.sha256, retained.issue.model_bound_text
        )
        screen = screen_rules(source, screen_policy)
        context = JudgmentContext(
            retained.issue, source, screen, screen_policy, checks.index, checks.report
        )
        judgment = suggestions = None
        judge_dispatched = False
        reason = "screen_needs_human"
        if screen.permits_model_input(source, screen_policy):
            with self.jobs.transaction() as connection:
                current = self.loader.load_in(connection, lease.work_key)
                if (
                    supplied_labels.sha256 != labels.sha256
                    or _dependencies(current, labels, mapping, screen_policy, judgment_policy)
                    != dependencies
                ):
                    raise CapturedWorkflowError("captured_input_changed")
                dispatch_us = now + int((time.monotonic() - began) * 1000000)
                self._current(connection, lease, current, now_us=dispatch_us)
            try:
                # Admit before dispatch, then validate the exact deterministic baseline after it.
                expected = judge_rules(context, judgment_policy)
                judge_dispatched = True
                candidate = judge(context, judgment_policy)
                _, candidate = validate_current_judgment(context, candidate, judgment_policy)
                if candidate != expected:
                    raise ValueError
                label_proposal = propose_labels(retained.issue, candidate, labels, mapping)
                comment = CommentDraft(
                    status="needs_human",
                    scope="none",
                    text=None,
                    evidence=(),
                    issue_sha256=retained.issue.sha256,
                    judgment_sha256=candidate.sha256,
                    report_sha256=checks.report.sha256,
                    template_sha256=TEMPLATE_SHA256,
                    resolution_context_sha256=None,
                    reason_codes=(CITATION_HOLD,),
                )
                suggestions = build_suggestions(
                    context, candidate, labels, label_proposal, comment, policy=judgment_policy
                )
                judgment = candidate
                reason = CITATION_HOLD
            except Exception:
                # Injected-port errors are never surfaced or used as persisted diagnostics.
                reason = "deterministic_judge_unavailable"
        result = CapturedResult(
            **_capture_identity(retained),
            dependencies_sha256=dependencies,
            lease_sha256=_lease_digest(lease),
            report_sha256=checks.report.sha256,
            reason=reason,
            judgment=judgment,
            suggestions=suggestions,
            judge_dispatched=judge_dispatched,
        )
        with self.jobs.transaction() as connection:
            current = self.loader.load_in(connection, lease.work_key)
            if (
                supplied_labels.sha256 != labels.sha256
                or _dependencies(current, labels, mapping, screen_policy, judgment_policy)
                != dependencies
            ):
                raise CapturedWorkflowError("captured_input_changed")
            finished = now + int((time.monotonic() - began) * 1000000)
            self._current(connection, lease, current, now_us=finished)
            changed = connection.execute(
                "UPDATE jobs SET status='done',result_code='needs_human',lease_token=NULL,"
                "lease_owner=NULL,lease_until_us=NULL WHERE work_key=? AND status='leased' "
                "AND lease_token=? AND lease_owner=? AND attempts=? AND lease_until_us=? "
                "AND lease_until_us>?",
                (
                    lease.work_key,
                    lease.token,
                    lease.owner,
                    lease.attempt,
                    lease.lease_until_us,
                    finished,
                ),
            ).rowcount
            if changed != 1:
                raise CapturedWorkflowError("lease_no_longer_current")
            connection.execute(
                "INSERT INTO local_results VALUES(?,?,?,?)",
                (
                    lease.work_key,
                    retained.issue.key.stable_id,
                    retained.issue.sha256,
                    result.canonical_bytes(),
                ),
            )
        return result
