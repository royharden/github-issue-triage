"""Fixed neutral drafts and pre-approval canonicalization; no posting or human authority."""

import re
import unicodedata
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from ..contracts.domain import Digest
from ..ingest.labels import LabelWire
from ..judges.context import admit_context, common_record
from ..judges.contracts import DEFAULT_JUDGMENT_POLICY, JudgeHold, JudgmentRecord
from ..shared.cited import Finding, Pointer, Registry, ResolutionContext
from ..shared.cited.assessment import assess_required_evidence
from ..shared.codeindex.canonical import digest
from ..shared.codeindex.cited_adapter import to_cited_file, to_cited_report
from ..shared.codeindex.models import CodePointer

TEMPLATES = {
    "found": (
        "At least one explicit reference has exact evidence in the retained source. "
        "Please review the captured evidence and the reproduction details."
    ),
    "verified_move": (
        "A separately supplied explicit mapping links a prior and current definition. "
        "Please review its provenance and confirm the relevant version."
    ),
    "not_found": (
        "At least one explicit reference did not match the complete retained search scope. "
        "This can reflect a different version or missing context. Please confirm the "
        "version and share a minimal example."
    ),
    "neutral": (
        "Thanks for the report. Please add the relevant version and a minimal example, "
        "including expected and actual behavior where applicable, so a maintainer "
        "can review it."
    ),
}
TEMPLATE_SHA256 = digest({"template_profile": "neutral-triage/1", "templates": TEMPLATES})


class CommentError(ValueError):
    pass


def canonical_comment(text):
    """The caller previews this exact value before approval; never mutate an approved value."""
    try:
        if type(text) is not str or len(text.encode("utf-8", errors="strict")) > 4096:
            raise ValueError
    except (UnicodeError, ValueError):
        raise CommentError("comment_byte_limit") from None
    if any(unicodedata.category(char) == "Cc" and char not in "\r\n\t" for char in text):
        raise CommentError("comment_control_character")
    text = "".join(char for char in text if unicodedata.category(char) != "Cf")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1 [link omitted]", text)
    text = re.sub(
        r"(?i)\b(?:https?|ftp|file|javascript|data):[^\s<>]+|\bwww\.[^\s<>]+", "[URL omitted]", text
    )
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("@", "@\u200b")
    text = re.sub(r"#(?=\d)", "issue ", text)
    text = re.sub(r"(?m)^([ \t]*)/[A-Za-z][A-Za-z0-9_-]*\b", r"\1[command omitted]", text)
    if not text.strip() or len(text.encode()) > 4096:
        raise CommentError("comment_byte_limit")
    return text


class CommentDraft(LabelWire):
    status: Literal["proposal", "needs_human"]
    scope: Literal["retained_source", "neutral_request", "none"]
    text: str | None = Field(default=None, repr=False)
    issue_sha256: Digest
    judgment_sha256: Digest
    report_sha256: Digest
    template_sha256: Digest
    resolution_context_sha256: Digest | None
    evidence: tuple[Pointer, ...]
    reason_codes: tuple[str, ...]

    @field_validator("evidence", "reason_codes", mode="before")
    @classmethod
    def immutable_arrays(cls, value):
        return tuple(value) if type(value) is list else value

    @model_validator(mode="after")
    def no_usable_held_comment(self) -> Self:
        if self.status == "needs_human":
            if self.text is not None or self.evidence or self.scope != "none":
                raise ValueError("held_comment_has_no_payload")
        elif self.text is None or canonical_comment(self.text) != self.text or self.scope == "none":
            raise ValueError("comment_must_be_canonical")
        if self.scope == "retained_source" and (
            not self.evidence or self.resolution_context_sha256 is None
        ):
            raise ValueError("source_comment_requires_evidence")
        if self.scope == "neutral_request" and self.evidence:
            raise ValueError("neutral_request_cannot_claim_source_proof")
        return self


def validate_current_judgment(context, judgment, policy=DEFAULT_JUDGMENT_POLICY):
    facts = admit_context(context, policy)
    try:
        if type(judgment) is not JudgmentRecord:
            raise ValueError
        judgment = JudgmentRecord.model_validate(judgment.model_dump(mode="python"))
    except Exception:
        raise JudgeHold("invalid_current_judgment") from None
    if any(
        getattr(judgment, key) != value for key, value in common_record(context, policy).items()
    ):
        raise JudgeHold("stale_current_judgment")
    return facts, judgment


def build_comment(
    context, judgment, *, registry, resolution_context, policy=DEFAULT_JUDGMENT_POLICY
):
    facts, judgment = validate_current_judgment(context, judgment, policy)
    if type(registry) is not Registry:
        raise JudgeHold("canonical_evidence_registry_required")
    try:
        resolution_context = ResolutionContext.model_validate(resolution_context)
    except Exception:
        raise JudgeHold("invalid_evidence_context") from None
    common = {
        "issue_sha256": context.issue.sha256,
        "judgment_sha256": judgment.sha256,
        "report_sha256": context.report.sha256,
        "template_sha256": TEMPLATE_SHA256,
        "resolution_context_sha256": digest(resolution_context.model_dump(mode="json")),
    }

    def hold(reason):
        return CommentDraft(
            status="needs_human",
            scope="none",
            text=None,
            evidence=(),
            reason_codes=(reason,),
            **common,
        )

    if judgment.status != "proposal":
        return hold("judgment_needs_human")
    if not facts.reference_count:
        return CommentDraft(
            status="proposal",
            scope="neutral_request",
            text=canonical_comment(TEMPLATES["neutral"]),
            evidence=(),
            reason_codes=("no_source_claim", "human_disposition_required"),
            **common,
        )
    representatives = {}
    for item in context.report.wire()["items"]:
        key = "verified_move" if item["evidence_kind"] == "verified_move" else item["status"]
        representatives.setdefault(key, item)
    evidence, paragraphs = [], []
    for category in ("found", "verified_move", "not_found"):
        item = representatives.get(category)
        if item is None:
            continue
        pointers = [to_cited_report(context.report.item_ref(item["item_id"]))]
        if category in {"found", "verified_move"}:
            pointers.append(to_cited_file(CodePointer(**item["current_pointers"][0])))
        finding = Finding(
            id="triage-comment-" + category.replace("_", "-"),
            text=TEMPLATES[category],
            verdict="partial",
            evidence=pointers,
        )
        assessment = assess_required_evidence(finding, registry, resolution_context)
        if assessment.finding.verdict == "unsupported" or assessment.unresolved_count:
            return hold("source_evidence_unresolved")
        indices = range(len(evidence) + 1, len(evidence) + len(pointers) + 1)
        evidence.extend(pointers)
        paragraphs.append(
            TEMPLATES[category]
            + " Evidence: "
            + ", ".join(f"E{number}" for number in indices)
            + "."
        )
    if not paragraphs:
        return hold("source_evidence_unavailable")
    try:
        text = canonical_comment("\n\n".join(paragraphs))
    except CommentError:
        return hold("comment_byte_limit")
    return CommentDraft(
        status="proposal",
        scope="retained_source",
        text=text,
        evidence=tuple(evidence),
        reason_codes=("human_disposition_required",),
        **common,
    )
