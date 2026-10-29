"""Current provisional review through an explicit local authorization port, without HTTP."""

from dataclasses import dataclass, field

from ..worker.local import WorkflowError
from .local import NAMESPACE, DecisionRequest, current_views, field_context, record_provisional
from .security import BoundaryError


@dataclass(frozen=True, slots=True)
class ReviewForm:
    issue_key: str
    field_name: str
    revision: str
    prior: str | None
    csrf: str = field(repr=False)
    proposed_value: object = field(repr=False)
    authority: str = "agent_provisional"
    remote_apply_allowed: bool = False


def provisional_form(workflow, boundary, session, *, issue_key, field_name, now):
    boundary.require_session(session, now=now)
    with workflow.jobs.transaction():
        _, _, result = workflow.current(issue_key)
        try:
            proposed, subject, _ = field_context(result.suggestions, field_name)
        except StopIteration:
            raise WorkflowError("unknown_proposal_field") from None
        snapshot, _ = current_views(workflow, result.suggestions)
        history = [
            event
            for event in snapshot.events
            if event.namespace == NAMESPACE and event.subject == subject
        ]
        prior = history[-1].event_id if history else None
        token = boundary.challenge(
            session,
            issue_key=issue_key,
            revision=result.suggestions.revision_sha256,
            field_name=field_name,
            prior=prior,
            now=now,
        )
        return ReviewForm(
            issue_key,
            field_name,
            result.suggestions.revision_sha256,
            prior,
            token,
            proposed.model_dump(mode="json")["value"],
        )


def submit_provisional(workflow, boundary, transport, raw_decision, *, now):
    if type(raw_decision) is not bytes or len(raw_decision) > 65536:
        raise BoundaryError("decision_byte_limit")
    try:
        decision = DecisionRequest.parse_json(raw_decision)
    except Exception:
        raise BoundaryError("decision_invalid") from None
    boundary.authorize(transport, decision, now=now)
    # Current proposal/CAS/value checks remain in the existing canonical-rulings adapter.
    # An operator session never upgrades its agent-provisional provenance to human evidence.
    return record_provisional(workflow, decision)
