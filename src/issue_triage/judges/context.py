"""Actual current source facts and passed full-input screening precede every judgment."""

import hashlib
from dataclasses import dataclass, field

from ..contracts.domain import IssueInput
from ..shared.codeindex.index import CodeIndex
from ..shared.codeindex.references import ExtractionPolicy, extract_references
from ..shared.codeindex.report import ExistenceReport, resolve_report_item
from ..shared.screen.models import HeldInput, ScreenPolicy, ScreenResult, UntrustedText
from ..shared.screen.prepare import prepare_text
from ..shared.screen.rules import safety_flags, screen_rules
from .contracts import JudgeHold, JudgmentPolicy


@dataclass(frozen=True, slots=True)
class JudgmentContext:
    issue: IssueInput = field(repr=False)
    source: UntrustedText = field(repr=False)
    screen: ScreenResult = field(repr=False)
    screen_policy: ScreenPolicy = field(repr=False)
    index: CodeIndex = field(repr=False)
    report: ExistenceReport = field(repr=False)
    prior: CodeIndex | None = field(default=None, repr=False)
    trusted_mappings: tuple = field(default=(), repr=False)


@dataclass(frozen=True, slots=True)
class SourceFacts:
    reference_count: int
    found: int
    not_found: int
    verified_moves: int


def admit_context(context, policy):
    if type(context) is not JudgmentContext or type(policy) is not JudgmentPolicy:
        raise JudgeHold("invalid_judgment_context")
    policy.__post_init__()
    try:
        issue = IssueInput.model_validate(context.issue.model_dump(mode="python"))
    except Exception:
        raise JudgeHold("invalid_current_issue") from None
    if (
        type(context.source) is not UntrustedText
        or type(context.screen) is not ScreenResult
        or type(context.screen_policy) is not ScreenPolicy
        or type(context.index) is not CodeIndex
        or type(context.report) is not ExistenceReport
        or type(context.trusted_mappings) is not tuple
    ):
        raise JudgeHold("invalid_judgment_context")
    if (
        context.source.source_id != issue.key.stable_id
        or context.source.source_generation != issue.sha256
        or context.source.text != issue.model_bound_text
    ):
        raise JudgeHold("current_issue_screen_binding_mismatch")
    if not context.screen.permits_model_input(context.source, context.screen_policy):
        raise JudgeHold("current_input_not_permitted")
    prepared = prepare_text(context.source, context.screen_policy)
    if isinstance(prepared, HeldInput) or safety_flags(prepared):
        raise JudgeHold("deterministic_screen_hold")
    if context.screen_policy.required_method == "rules" and not screen_rules(
        context.source, context.screen_policy
    ).permits_model_input(context.source, context.screen_policy):
        raise JudgeHold("deterministic_screen_hold")
    if context.index.snapshot.repository_id != f"github-repository-{issue.key.repository_id}":
        raise JudgeHold("current_repository_mismatch")
    try:
        report = ExistenceReport(context.report.preimage)
        payload = report.wire()
        if (
            payload["input"]["input_sha256"]
            != hashlib.sha256(issue.model_bound_text.encode()).hexdigest()
        ):
            raise JudgeHold("current_issue_report_mismatch")
        extraction = ExtractionPolicy(**payload["extraction"]["policy"])
        expected = extract_references(issue.model_bound_text, extraction)
        if payload["references"] != [
            ref.wire() for ref in sorted(expected, key=lambda ref: ref.id)
        ]:
            raise JudgeHold("current_issue_reference_mismatch")
        counts = {"found": 0, "not_found": 0, "verified_move": 0}
        for item in payload["items"]:
            checked = resolve_report_item(
                report.item_ref(item["item_id"]),
                report.preimage,
                context.index,
                prior=context.prior,
                trusted_mappings=context.trusted_mappings,
            )
            if checked.status != "verified":
                raise JudgeHold("current_source_report_unverified")
            if (
                not checked.coverage_complete
                or checked.recorded_status == "ambiguous"
                or checked.evidence_kind == "near_match_candidate"
            ):
                raise JudgeHold("source_evidence_uncertain")
            key = (
                "verified_move"
                if checked.evidence_kind == "verified_move"
                else checked.recorded_status
            )
            counts[key] += 1
        # Empty reports still have to bind the actual current retained source.
        if payload["current_snapshot"] != context.index.snapshot.wire():
            raise JudgeHold("current_source_report_mismatch")
    except JudgeHold:
        raise
    except Exception:
        raise JudgeHold("invalid_current_source_report") from None
    return SourceFacts(
        len(payload["items"]), counts["found"], counts["not_found"], counts["verified_move"]
    )


def common_record(context, policy):
    return {
        "issue_sha256": context.issue.sha256,
        "input_sha256": context.screen.input_sha256,
        "report_sha256": context.report.sha256,
        "screen_policy_sha256": context.screen_policy.sha256,
        "judgment_policy_sha256": policy.sha256,
    }
