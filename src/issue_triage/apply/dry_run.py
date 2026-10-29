"""Persist idempotent previews separately from actual sent/confirmed remote effects."""

import hashlib
import json

from ..review.local import NAMESPACE, current_views, field_context, validate_value
from ..shared.codeindex.canonical import canonical_bytes, digest
from ..shared.rulings.store import subject_key
from ..worker.local import WorkflowError, now_utc


def dry_run(
    workflow, issue_key, *, provisional=False, expected_revision=None, expected_journal_sha256=None
):
    if provisional is not True:
        raise WorkflowError("authenticated_human_authority_unavailable")
    with workflow.jobs.transaction() as connection:
        bundle, _, result = workflow.current(issue_key)
        suggestions = result.suggestions
        snapshot, views = current_views(workflow, suggestions)
        if expected_revision is not None and suggestions.revision_sha256 != expected_revision:
            raise WorkflowError("stale_preview_revision")
        if expected_journal_sha256 is not None:
            actual = hashlib.sha256(
                workflow.journal.path.read_bytes() if workflow.journal.path.exists() else b""
            ).hexdigest()
            if actual != expected_journal_sha256:
                raise WorkflowError("stale_preview_journal")
        events = {event.event_id: event for event in snapshot.events}
        receipts = []
        for field_name, operation in (("labels", "add_labels"), ("comment", "create_comment")):
            proposed, subject, _ = field_context(suggestions, field_name)
            view = views.get(subject_key(NAMESPACE, subject))
            if view is None or view.state != "effective" or view.effective_event_id is None:
                continue
            event = events[view.effective_event_id]
            if event.actor_provenance != "agent_provisional":
                raise WorkflowError("unverified_human_is_not_authority")
            value = validate_value(bundle, proposed, view.value)
            action_id = digest(
                {
                    "action_schema_version": 1,
                    "issue_key": issue_key,
                    "ruling_event_id": event.event_id,
                    "operation": operation,
                    "visible_payload_sha256": digest(value),
                }
            )
            if field_name == "comment":
                body = value + "\n\n<!-- issue-triage-action:" + action_id + " -->"
                if len(body.encode("utf-8")) > 4096:
                    raise WorkflowError("comment_with_marker_exceeds_limit")
                payload = {"body": body}
            else:
                payload = {"labels": value}
            raw = canonical_bytes(payload)
            payload_sha = hashlib.sha256(raw).hexdigest()
            row = connection.execute(
                "SELECT * FROM local_dry_runs WHERE action_id=?", (action_id,)
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO local_dry_runs VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        action_id,
                        issue_key,
                        suggestions.revision_sha256,
                        event.event_id,
                        operation,
                        payload_sha,
                        raw,
                        "dry_run",
                        now_utc(),
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM local_dry_runs WHERE action_id=?", (action_id,)
                ).fetchone()
            if (
                row["issue_key"],
                row["revision_sha256"],
                row["ruling_event_id"],
                row["operation"],
                row["payload_sha256"],
                bytes(row["payload_json"]),
                row["mode"],
            ) != (
                issue_key,
                suggestions.revision_sha256,
                event.event_id,
                operation,
                payload_sha,
                raw,
                "dry_run",
            ):
                raise WorkflowError("dry_run_receipt_conflict")
            receipts.append(
                {
                    "action_id": action_id,
                    "operation": operation,
                    "payload_sha256": payload_sha,
                    "payload": json.loads(raw),
                    "ruling_event_id": event.event_id,
                    "mode": "dry_run",
                    "created_at": row["created_at"],
                    "authority": "agent_provisional_rehearsal",
                    "remote_apply_allowed": False,
                    "http_writes": 0,
                }
            )
        return receipts


def live_apply(*args, **kwargs):
    raise WorkflowError("live_apply_not_implemented_and_not_authorized")
