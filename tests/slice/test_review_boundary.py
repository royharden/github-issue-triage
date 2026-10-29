"""what_bug_this_catches: transport authorization bypasses current provisional review guards.

BrowserMutation is an explicit typed HTTP-adapter double, not a real browser/request parser.
The store, current proposals, canonical journal and dry-run join are real app components.
"""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from issue_triage.apply.dry_run import dry_run
from issue_triage.review.local import DecisionRequest
from issue_triage.review.security import BoundaryError, BrowserMutation, OperatorBoundary
from issue_triage.review.service import provisional_form, submit_provisional
from issue_triage.shared.rulings.store import PriorConflict
from issue_triage.worker.bundle import parse_bundle
from issue_triage.worker.local import LocalWorkflow, WorkflowError

ORIGIN = "http://127.0.0.1:24001"  # Synthetic policy value; no listener or port is claimed.
CREDENTIAL = b"original-public-operator-control-01"
SESSION_KEY = b"different-public-session-control-01"
REVISION = "a" * 64
ISSUE = "601:602:1"
EXAMPLE = Path(__file__).parents[2] / "examples/local-bundle.json"


def boundary(**changes):
    return OperatorBoundary(
        **{
            "origin": ORIGIN,
            "operator_credential": CREDENTIAL,
            "session_key": SESSION_KEY,
            "lifetime": 60,
            **changes,
        }
    )


def login(policy, *, now=100):
    return policy.login(method="POST", origin=policy.origin, credential=CREDENTIAL, now=now).value


def request(*, revision=REVISION, prior=None, event="control-1", **changes):
    return DecisionRequest(
        **{
            "event_id": event,
            "issue_key": ISSUE,
            "field": "labels",
            "expected_revision": revision,
            "expected_prior_event_id": prior,
            "disposition": "accept",
            "value": None,
            "actor_label": "synthetic-operator",
            "at_utc": "2026-10-15T04:08:00Z",
            "reason": "Provisional transport-boundary control",
            **changes,
        }
    )


def transport(policy, session, decision, *, now=101):
    return BrowserMutation(
        "POST",
        policy.origin,
        session,
        policy.challenge(
            session,
            issue_key=decision.issue_key,
            revision=decision.expected_revision,
            field_name=decision.field,
            prior=decision.expected_prior_event_id,
            now=now,
        ),
    )


@pytest.mark.parametrize(
    "origin",
    [
        None,
        12,
        "https://external.invalid:443",
        "http://localhost",
        "http://localhost:24001/",
        "http://user@localhost:24001",
        "http://localhost:24001#fragment",
    ],
)
def test_configured_origin_requires_explicit_local_origin(origin):
    with pytest.raises(BoundaryError, match="invalid_trusted_origin"):
        boundary(origin=origin)


@pytest.mark.parametrize("origin", ["http://@localhost:24001", "http://:@localhost:24001"])
def test_empty_url_userinfo_is_not_a_trusted_origin(origin):
    """what_bug_this_catches: empty parsed username/password bypass truthiness checks."""
    with pytest.raises(BoundaryError, match="invalid_trusted_origin"):
        boundary(origin=origin)


@pytest.mark.parametrize(
    "changes",
    [
        {"operator_credential": b"short"},
        {"session_key": CREDENTIAL},
        {"session_key": "not-bytes"},
        {"lifetime": True},
        {"lifetime": 0},
    ],
)
def test_configuration_fails_closed_without_distinct_bounded_keys(changes):
    with pytest.raises(BoundaryError, match="boundary_configuration_unavailable"):
        boundary(**changes)


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"method": "GET"}, "post_required"),
        ({"origin": None}, "exact_origin_required"),
        ({"origin": "http://localhost:24001"}, "exact_origin_required"),
        ({"credential": b"incorrect"}, "operator_auth_required"),
        ({"credential": "incorrect"}, "operator_auth_required"),
        ({"now": True}, "clock_unavailable"),
    ],
)
def test_login_does_not_trust_missing_origin_or_unknown_credential(change, reason):
    policy = boundary()
    with pytest.raises(BoundaryError, match=reason):
        policy.login(
            **{"method": "POST", "origin": ORIGIN, "credential": CREDENTIAL, "now": 100, **change}
        )


def test_sessions_expire_reject_tampering_and_are_bound_to_origin_and_key():
    policy = boundary()
    session = login(policy)
    policy.require_session(session, now=100)
    policy.require_session(session, now=159)
    for now in (99, 160):
        with pytest.raises(BoundaryError, match="operator_session_required"):
            policy.require_session(session, now=now)
    tampered = session[:-1] + ("0" if session[-1] != "0" else "1")
    for invalid in (tampered, None, "x" * 257, session.replace(".160.", ".999.")):
        with pytest.raises(BoundaryError, match="operator_session_required"):
            policy.require_session(invalid, now=101)
    for other in (
        boundary(origin="http://localhost:24001"),
        boundary(session_key=b"another-public-session-control-02"),
    ):
        with pytest.raises(BoundaryError, match="operator_session_required"):
            other.require_session(session, now=101)
    assert CREDENTIAL.decode() not in session


@pytest.mark.parametrize(
    "changed",
    [
        {"method": "GET"},
        {"origin": None},
        {"origin": "null"},
        {"origin": "http://127.0.0.1:24002"},
        {"origin": ORIGIN + "/"},
        {"session": None},
        {"csrf": None},
        {"csrf": "0" * 64},
    ],
)
def test_mutation_requires_origin_session_method_and_csrf(changed):
    policy = boundary()
    session = login(policy)
    decision = request()
    approved = transport(policy, session, decision)
    policy.authorize(approved, decision, now=101)
    with pytest.raises(BoundaryError):
        policy.authorize(replace(approved, **changed), decision, now=101)


def test_csrf_is_bound_to_session_issue_field_revision_and_prior():
    policy = boundary()
    session = login(policy)
    decision = request()
    approved = transport(policy, session, decision)
    variants = [
        request(issue_key="601:602:2"),
        request(field="comment"),
        request(revision="b" * 64),
        request(prior="new-head"),
    ]
    for changed in variants:
        with pytest.raises(BoundaryError, match="csrf_required"):
            policy.authorize(approved, changed, now=101)
    with pytest.raises(BoundaryError, match="csrf_required"):
        policy.authorize(replace(approved, session=login(policy)), decision, now=101)


def test_guarded_review_persists_only_provisional_authority_and_exact_retry(tmp_path):
    policy = boundary()
    session = login(policy)
    original = parse_bundle(EXAMPLE.read_bytes())
    with LocalWorkflow(tmp_path) as workflow:
        workflow.submit(original, "guarded-provisional")
        result = workflow.run_once()
        form = provisional_form(
            workflow, policy, session, issue_key=ISSUE, field_name="labels", now=101
        )
        assert form.authority == "agent_provisional" and not form.remote_apply_allowed
        assert form.proposed_value == ["needs-info"]
        decision = request(revision=form.revision, prior=form.prior)
        auth = BrowserMutation("POST", ORIGIN, session, form.csrf)
        for denied in (
            replace(auth, origin="null"),
            replace(auth, csrf=None),
            replace(auth, session=None),
        ):
            with pytest.raises(BoundaryError):
                submit_provisional(workflow, policy, denied, decision.canonical_bytes(), now=101)
            assert not workflow.journal.path.exists()
        receipt = submit_provisional(workflow, policy, auth, decision.canonical_bytes(), now=101)
        assert receipt.sequence == 1
        before = workflow.journal.path.read_bytes()
        assert workflow.journal.replay().events[0].actor_provenance == "agent_provisional"
        assert (
            submit_provisional(workflow, policy, auth, decision.canonical_bytes(), now=102).outcome
            == "exact_retry"
        )
        assert workflow.journal.path.read_bytes() == before
        preview = dry_run(workflow, result.issue_key, provisional=True)
        assert len(preview) == 1 and preview[0]["http_writes"] == 0
        assert not preview[0]["remote_apply_allowed"]
        refreshed = provisional_form(
            workflow, policy, session, issue_key=ISSUE, field_name="labels", now=102
        )
        assert refreshed.prior == decision.event_id
        edited = request(
            revision=refreshed.revision,
            prior=refreshed.prior,
            event="later-edit",
            disposition="edit",
            value=["bug"],
        )
        refreshed_auth = BrowserMutation("POST", ORIGIN, session, refreshed.csrf)
        assert (
            submit_provisional(
                workflow, policy, refreshed_auth, edited.canonical_bytes(), now=102
            ).sequence
            == 2
        )
        after_edit = workflow.journal.path.read_bytes()
        assert (
            submit_provisional(workflow, policy, auth, decision.canonical_bytes(), now=103).outcome
            == "exact_retry"
        )
        assert workflow.journal.path.read_bytes() == after_edit
        preview = dry_run(workflow, result.issue_key, provisional=True)
        assert preview[0]["payload"] == {"labels": ["bug"]}
    with LocalWorkflow(tmp_path) as workflow:
        assert dry_run(workflow, ISSUE, provisional=True) == preview


def test_old_form_cas_and_changed_issue_cannot_write_a_new_decision(tmp_path):
    policy = boundary()
    session = login(policy)
    original = parse_bundle(EXAMPLE.read_bytes())
    with LocalWorkflow(tmp_path) as workflow:
        workflow.submit(original, "old-form")
        workflow.run_once()
        form = provisional_form(
            workflow, policy, session, issue_key=ISSUE, field_name="labels", now=101
        )
        decision = request(revision=form.revision, prior=form.prior)
        auth = BrowserMutation("POST", ORIGIN, session, form.csrf)
        submit_provisional(workflow, policy, auth, decision.canonical_bytes(), now=101)
        before = workflow.journal.path.read_bytes()
        with pytest.raises(PriorConflict):
            submit_provisional(
                workflow,
                policy,
                auth,
                decision.model_copy(update={"event_id": "stale-form"}).canonical_bytes(),
                now=101,
            )
        assert workflow.journal.path.read_bytes() == before
        value = json.loads(original.canonical_bytes())
        value["issue"]["updated_at"] = "2026-10-15T04:09:00Z"
        workflow.submit(parse_bundle(json.dumps(value).encode()), "changed-issue")
        with pytest.raises(WorkflowError, match="current_result_unavailable"):
            submit_provisional(
                workflow,
                policy,
                auth,
                decision.model_copy(update={"event_id": "changed-form"}).canonical_bytes(),
                now=101,
            )
        assert workflow.journal.path.read_bytes() == before


def test_unknown_or_oversize_decision_data_never_opens_authority(tmp_path):
    policy = boundary()
    with LocalWorkflow(tmp_path) as workflow:
        for raw in (
            b"not JSON",
            b" " * 65537,
            json.dumps({**request().model_dump(mode="json"), "actor_provenance": "human"}).encode(),
        ):
            with pytest.raises(BoundaryError):
                submit_provisional(workflow, policy, BrowserMutation("POST", ORIGIN), raw, now=101)
            assert not workflow.journal.path.exists()
