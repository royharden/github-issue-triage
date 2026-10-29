"""what_bug_this_catches: stale or model-proposed names bypass the current active allowlist."""

import pytest

from issue_triage.contracts.domain import IssueInput, IssueKey
from issue_triage.ingest.labels import LabelError, LabelInventory, RepositoryLabel
from issue_triage.judges.contracts import JudgmentRecord
from issue_triage.shared.codeindex.canonical import digest
from issue_triage.suggest.labels import LabelMap, LabelProposal, propose_labels


def inputs():
    # Authored scalar unit input, not a source execution or human approval receipt.
    issue = IssueInput(
        key=IssueKey(
            installation_id=12,
            repository_id=7,
            issue_number=9,
            owner="synthetic-owner",
            repository="original-label-controls",
        ),
        title="Original defect",
        body="Original data",
        updated_at="2026-10-15T00:00:00Z",
        author_id=19,
        author_login="synthetic-author",
    )
    judgment = JudgmentRecord(
        status="proposal",
        method="rules",
        issue_sha256=issue.sha256,
        input_sha256=digest("original issue control"),
        report_sha256=digest("report control"),
        screen_policy_sha256=digest("screen control"),
        judgment_policy_sha256=digest("policy control"),
        type_decision="bug",
        priority=2,
        reason_codes=("synthetic_unit_input",),
        current_external_cost_usd="0",
    )
    inventory = LabelInventory(
        repository_id=7,
        labels=tuple(
            RepositoryLabel(id=number, name=name, archival_state="active")
            for number, name in enumerate(("kind: bug", "priority: normal", "review"), start=1)
        ),
        captured_at="2026-10-15T00:00:00Z",
        page_sha256=(digest("synthetic page"),),
    )
    mapping = LabelMap({"bug": "kind: bug"}, {2: "priority: normal"}, ("review",))
    return issue, judgment, inventory, mapping


def test_only_current_exact_active_labels_are_bound_in_proposal():
    issue, judgment, inventory, mapping = inputs()
    result = propose_labels(issue, judgment, inventory, mapping)
    assert result.status == "proposal" and [label.id for label in result.labels] == [1, 2, 3]
    assert result.label_set_sha256 == inventory.label_set_sha256
    assert result.label_map_sha256 == mapping.sha256 and result.judgment_sha256 == judgment.sha256
    assert LabelProposal.parse_json(result.canonical_bytes()) == result
    assert propose_labels(issue, judgment, inventory, mapping) == result


@pytest.mark.parametrize(
    "mapping",
    [
        LabelMap({}, {2: "priority: normal"}),
        LabelMap({"bug": "KIND: BUG"}, {2: "priority: normal"}),
        LabelMap({"bug": "invented"}, {2: "priority: normal"}),
    ],
)
def test_missing_mapping_or_unknown_exact_name_returns_no_partial_labels(mapping):
    issue, judgment, inventory, _ = inputs()
    result = propose_labels(issue, judgment, inventory, mapping)
    assert result.status == "needs_human" and result.labels == ()


@pytest.mark.parametrize("state", ["archived", "unknown"])
def test_selected_inactive_or_unknown_status_label_blocks_the_whole_proposal(state):
    issue, judgment, inventory, mapping = inputs()
    labels = (
        inventory.labels[0].model_copy(
            update={
                "archival_state": state,
                "archived_at": "2026-10-14T00:00:00Z" if state == "archived" else None,
            }
        ),
        *inventory.labels[1:],
    )
    inventory = inventory.model_copy(update={"labels": labels})
    result = propose_labels(issue, judgment, inventory, mapping)
    assert result.status == "needs_human" and result.labels == ()


def test_stale_issue_or_repository_and_unchecked_model_copy_fail():
    issue, judgment, inventory, mapping = inputs()
    for change in (
        judgment.model_copy(update={"issue_sha256": digest("stale")}),
        judgment.model_copy(update={"priority": True}),
    ):
        with pytest.raises(LabelError):
            propose_labels(issue, change, inventory, mapping)
    with pytest.raises(LabelError):
        propose_labels(issue, judgment, inventory.model_copy(update={"repository_id": 8}), mapping)


def test_maximum_five_deduplication_and_immutable_operator_map():
    issue, judgment, inventory, _ = inputs()
    names = [f"label-{number}" for number in range(6)]
    inventory = inventory.model_copy(
        update={
            "labels": tuple(
                RepositoryLabel(id=number + 1, name=name, archival_state="active")
                for number, name in enumerate(names)
            )
        }
    )
    mapping = LabelMap({"bug": names[:3]}, {2: names[3:]})
    assert propose_labels(issue, judgment, inventory, mapping).status == "needs_human"
    values = {"bug": ["label-0"]}
    mapping = LabelMap(values, {2: "label-0"})
    values["bug"].append("invented")
    result = propose_labels(issue, judgment, inventory, mapping)
    assert len(result.labels) == 1 and result.labels[0].name == "label-0"
    with pytest.raises(TypeError):
        mapping.type_labels["bug"] = ("invented",)


def test_held_judgment_is_not_a_label_proposal_and_bad_mapping_keys_reject():
    issue, judgment, inventory, mapping = inputs()
    held = judgment.model_copy(
        update={"status": "needs_human", "type_decision": None, "priority": None}
    )
    assert propose_labels(issue, held, inventory, mapping).labels == ()
    with pytest.raises(LabelError):
        LabelMap({"unknown_type": "review"}, {2: "review"})
    with pytest.raises(LabelError):
        LabelMap({"bug": "review"}, {True: "review"})
