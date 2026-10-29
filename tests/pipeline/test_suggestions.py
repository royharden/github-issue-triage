"""what_bug_this_catches: stale or unresolved drafts become approved-looking field payloads."""

import importlib.util
import socket
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from issue_triage.ingest.labels import LabelInventory, RepositoryLabel
from issue_triage.judges.contracts import JudgeHold
from issue_triage.judges.rules import judge_rules
from issue_triage.shared.cited import ArtifactRef, Registry, ResolutionContext
from issue_triage.shared.codeindex.canonical import digest
from issue_triage.shared.codeindex.cited_adapter import CodeIndexCitedResolver, install_codeindex
from issue_triage.suggest.comments import (
    CommentDraft,
    CommentError,
    build_comment,
    canonical_comment,
)
from issue_triage.suggest.envelope import FIELDS, ProposedField, SuggestionSet, build_suggestions
from issue_triage.suggest.labels import LabelMap, propose_labels

SPEC = importlib.util.spec_from_file_location(
    "suggestion_original_controls", Path(__file__).parents[1] / "judges/test_contracts.py"
)
HELPERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPERS)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("suggestion controls cannot dispatch network effects")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


class Access:
    reference = ArtifactRef(
        artifact_id="suggestion-access-control",
        artifact_sha256=digest("original synthetic access"),
        profile_id="suggestion-access/1",
    )

    def __init__(self):
        self.answer = "allow"

    def decision(self, namespace, repository):
        return self.answer


class Generation:
    reference = ArtifactRef(
        artifact_id="suggestion-generation-control",
        artifact_sha256=digest("original synthetic generation"),
        profile_id="suggestion-generation/1",
    )

    def __init__(self, snapshot):
        self.snapshot = snapshot

    def current(self, namespace, repository):
        return self.snapshot


def rig(*, title="Bug in target()", body=None, installed=True, missing_label=False):
    ctx = HELPERS.context(title, **({"body": body} if body is not None else {}))
    judgment = judge_rules(ctx)
    access, generation = Access(), Generation(ctx.index.snapshot)
    evidence_context = ResolutionContext(
        namespace_id="suggestion-original-controls",
        access_policy_ref=access.reference,
        generation_policy_ref=generation.reference,
        required_scope="text",
    )
    registry = Registry()
    resolver = CodeIndexCitedResolver(
        ctx.index,
        namespace_id=evidence_context.namespace_id,
        access=access,
        generation=generation,
        reports=(ctx.report,),
    )
    if installed:
        install_codeindex(registry, resolver)
    inventory = LabelInventory(
        repository_id=7,
        labels=(RepositoryLabel(id=1, name="bug", archival_state="active"),),
        captured_at="2026-10-15T00:00:00Z",
        page_sha256=(digest("synthetic label page"),),
    )
    mapping = LabelMap(
        {"bug": ("missing" if missing_label else "bug",), "likely_invalid": ("bug",)},
        {2: ()},
    )
    labels = propose_labels(ctx.issue, judgment, inventory, mapping)
    return SimpleNamespace(**locals())


def comment(r):
    return build_comment(
        r.ctx, r.judgment, registry=r.registry, resolution_context=r.evidence_context
    )


def suggestions(r, *, draft=None, labels=None):
    return build_suggestions(
        r.ctx, r.judgment, r.inventory, labels or r.labels, draft or comment(r)
    )


def test_actual_current_source_and_report_are_required_before_source_draft():
    r = rig()
    draft = comment(r)
    assert draft.status == "proposal" and draft.scope == "retained_source"
    assert len(draft.evidence) == 2
    assert {p.source_type for p in draft.evidence} == {
        "repository_file",
        "code_existence_report",
    }
    assert "retained source" in draft.text and "Evidence: E1, E2" in draft.text
    for pointer in draft.evidence:
        assert r.registry.resolve(pointer, r.evidence_context).status == "resolved"
    assert CommentDraft.parse_json(draft.canonical_bytes()) == draft
    assert "target" not in draft.text and "synthetic-owner" not in draft.text


def test_complete_absence_cites_report_and_keeps_version_uncertainty():
    r = rig(title="Bug in missing_symbol()")
    draft = comment(r)
    assert draft.status == "proposal" and len(draft.evidence) == 1
    assert draft.evidence[0].source_type == "code_existence_report"
    assert "did not match" in draft.text and "different version" in draft.text
    assert "missing_symbol" not in draft.text


def test_mixed_found_and_absent_references_keep_both_categories():
    r = rig(title="Bug in target() and missing_symbol()")
    draft = comment(r)
    assert len(draft.evidence) == 3
    assert "exact evidence" in draft.text and "did not match" in draft.text


@pytest.mark.parametrize("failure", ["uninstalled", "revoked", "unknown_generation", "context"])
def test_source_denial_suppresses_the_entire_draft(failure):
    r = rig(installed=failure != "uninstalled")
    if failure == "revoked":
        r.access.answer = "deny"
    elif failure == "unknown_generation":
        r.generation.snapshot = None
    elif failure == "context":
        r.evidence_context = r.evidence_context.model_copy(update={"namespace_id": "different"})
    draft = comment(r)
    assert draft.status == "needs_human" and draft.text is None and not draft.evidence
    assert draft.reason_codes == ("source_evidence_unresolved",)


def test_source_free_request_is_explicit_and_never_interpolates_untrusted_text():
    r = rig(
        title="Bug: wrong color",
        body="Steps: open. Expected: blue. Actual: red. @everyone https://evil.invalid/ Fixes #42",
        installed=False,
    )
    draft = comment(r)
    assert draft.status == "proposal" and draft.scope == "neutral_request"
    assert not draft.evidence and draft.reason_codes[0] == "no_source_claim"
    assert all(value not in draft.text for value in ("@", "http", "Fixes", "#42", "evil"))


def test_canonicalization_is_preapproval_idempotent_and_removes_active_markdown():
    raw = (
        "@everyone @\u200bperson Fixes #42 <script>x</script>\r\n"
        "/close now\n[x](https://evil.invalid) ![p](file:///private) www.evil.invalid"
    )
    text = canonical_comment(raw)
    assert canonical_comment(text) == text
    assert "@everyone" not in text and "@\u200bperson" in text
    assert "#42" not in text and "/close" not in text and "<script>" not in text
    assert "evil.invalid" not in text and "file:" not in text and "\r" not in text
    assert "issue 42" in text and "[command omitted]" in text


@pytest.mark.parametrize("raw", ["", " ", "x" * 4097, "@" * 2000, "\x00", "\ud800"])
def test_invalid_or_expanded_overflow_comment_has_no_prefix(raw):
    with pytest.raises(CommentError):
        canonical_comment(raw)


def test_four_fields_are_independent_current_and_deeply_immutable():
    r = rig()
    result = suggestions(r)
    assert tuple(f.field for f in result.fields) == FIELDS
    assert all(f.status == "proposal" for f in result.fields)
    assert result.fields[0].value == ("bug",)
    assert result.fields[1].value == "bug" and result.fields[2].value == 2
    assert SuggestionSet.parse_json(result.canonical_bytes()) == result
    with pytest.raises(ValidationError):
        result.fields[0].value = ("unapproved",)
    wire = result.model_dump(mode="json")
    wire["fields"][0]["value"].append("unapproved")
    assert result.fields[0].value == ("bug",)
    with pytest.raises(ValidationError, match="invalid_suggestion_revision"):
        SuggestionSet.model_validate(wire)


def test_missing_label_or_comment_does_not_hide_other_valid_fields():
    r = rig(missing_label=True, installed=False)
    result = suggestions(r)
    assert [f.status for f in result.fields] == [
        "needs_human",
        "proposal",
        "proposal",
        "needs_human",
    ]
    assert result.fields[0].value is result.fields[3].value is None


def test_held_judgment_suppresses_every_field():
    r = rig(title="A vague observation", body="More context would help")
    result = suggestions(r)
    assert all(f.status == "needs_human" and f.value is None for f in result.fields)


@pytest.mark.parametrize("component", ["issue", "judgment", "labels", "comment", "repo"])
def test_unchecked_stale_component_cannot_become_current_proposal(component):
    r = rig()
    draft = comment(r)
    if component == "issue":
        r.ctx = replace(r.ctx, issue=r.ctx.issue.model_copy(update={"body": "edited"}))
    elif component == "judgment":
        r.judgment = r.judgment.model_copy(update={"issue_sha256": digest("different")})
    elif component == "labels":
        r.labels = r.labels.model_copy(update={"label_set_sha256": digest("different")})
    elif component == "comment":
        draft = draft.model_copy(update={"report_sha256": digest("different")})
    else:
        r.inventory = r.inventory.model_copy(update={"repository_id": 8})
    with pytest.raises(JudgeHold):
        suggestions(r, draft=draft)


def test_field_ids_survive_revision_but_evidence_and_mapping_changes_do_not():
    r = rig()
    original = suggestions(r)
    other = rig(missing_label=True)
    changed = suggestions(other)
    assert [f.id for f in original.fields] == [f.id for f in changed.fields]
    assert original.revision_sha256 != changed.revision_sha256
    assert original.label_map_sha256 != changed.label_map_sha256
    assert original.fields[0].evidence_sha256 != changed.fields[0].evidence_sha256
    assert [f.id for f in original.fields] == list(dict.fromkeys(f.id for f in original.fields))


@pytest.mark.parametrize(
    "field,value", [("priority", True), ("type", "invented"), ("comment", "@x")]
)
def test_invalid_per_field_payload_is_rejected(field, value):
    with pytest.raises(ValidationError):
        ProposedField(
            field=field,
            id=digest("id"),
            status="proposal",
            value=value,
            evidence_sha256=digest("evidence"),
        )
