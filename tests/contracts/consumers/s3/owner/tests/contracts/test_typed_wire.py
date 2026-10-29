"""what_bug_this_catches: malformed native answers accepted as usable typed judgments."""

import copy
import json

import pytest
from pydantic import ValidationError

from issue_triage.shared.callledger.models import decode_wire_json
from issue_triage.shared.providers import models as wire


def test_valid_exact_question_map(typed_request, typed_result_data):
    result = wire.validate_typed_wire(json.dumps(typed_result_data), typed_request)
    assert set(result.answers) == {"category", "condition"}
    assert result.answers["condition"].model_dump() == {"type": "noul", "noul": 0.7}


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "wrong_type",
        "unknown_option",
        "bad_sum",
        "model_absent",
        "question_digest",
    ],
)
def test_bad_bound_answers_rejected(typed_request, typed_result_data, mutation):
    data = copy.deepcopy(typed_result_data)
    if mutation == "missing":
        del data["answers"]["condition"]
    elif mutation == "extra":
        data["answers"]["extra"] = {"type": "noul", "noul": 0.7}
    elif mutation == "wrong_type":
        data["answers"]["condition"] = data["answers"]["category"]
    elif mutation == "unknown_option":
        data["answers"]["category"]["probabilities"] = {"a": 0.8, "unknown": 0.2}
    elif mutation == "bad_sum":
        data["answers"]["category"]["probabilities"] = {"a": 0.8, "b": 0.8}
    elif mutation == "model_absent":
        del data["model_reported"]
    else:
        data["question_spec_sha256"] = "a" * 64
    with pytest.raises(ValueError):
        wire.validate_typed_wire(json.dumps(data), typed_request)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -0.1, 1.1, True, "0.8"])
def test_probability_is_finite_strict_and_in_range(bad):
    with pytest.raises(ValidationError):
        wire.NoulAnswer.model_validate({"type": "noul", "noul": bad})


@pytest.mark.parametrize("levels", [2, 3, 4, 5, 6, 10])
def test_generic_fractional_score_uses_full_legend(levels):
    criteria = [f"Level {i}" for i in range(levels)]
    typed_request = wire.TypedJudgmentRequest.model_validate(
        dict(
            schema_version=1,
            kind="typed_judgment",
            model="jev-1.13.0",
            state="Synthetic",
            questions={"score": dict(type="score", instructions="Rate", criteria=criteria)},
        )
    )
    probabilities = {str(i): 0.0 for i in range(levels)}
    probabilities["0"] = 0.25
    probabilities[str(levels - 1)] = 0.75
    result = wire.TypedJudgmentResult.model_validate(
        dict(
            schema_version=1,
            model_reported="jev-1.13.0",
            question_spec_sha256=typed_request.question_spec_sha256,
            answers={
                "score": dict(
                    type="score",
                    score=0.75 * (levels - 1),
                    legend={str(i): value for i, value in enumerate(criteria)},
                    probabilities=probabilities,
                    confidence=0.7,
                )
            },
        )
    ).validate_for(typed_request)
    assert result.answers["score"].score == 0.75 * (levels - 1)
    assert len(result.answers["score"].legend) == levels


@pytest.mark.parametrize("change", ["sum", "position", "keys", "legend_type", "extra"])
def test_score_rejects_invalid_distribution_and_legend(change):
    data = dict(
        type="score",
        score=0.7,
        legend={"0": "Low", "1": "High"},
        probabilities={"0": 0.3, "1": 0.7},
        confidence=0.6,
    )
    if change == "sum":
        data["probabilities"] = {"0": 0.7, "1": 0.7}
    elif change == "position":
        data["score"] = 0.1
    elif change == "keys":
        data["legend"] = {"1": "Low", "2": "High"}
    elif change == "legend_type":
        data["legend"]["0"] = {"description": "Low"}
    else:
        data["hidden_gold"] = "must not fit closed wire"
    with pytest.raises(ValidationError):
        wire.ScoreAnswer.model_validate(data)


def test_structured_score_criterion_is_not_stringified_or_compared_to_object():
    typed_request = wire.TypedJudgmentRequest.model_validate(
        dict(
            schema_version=1,
            kind="typed_judgment",
            model="jev-1.13.0",
            state="Synthetic",
            questions={
                "s": dict(
                    type="score",
                    instructions={"task": "Compare"},
                    criteria=["unrelated", {"description": "related"}, ["same", "size"]],
                )
            },
        )
    )
    data = dict(
        schema_version=1,
        model_reported="jev-1.13.0",
        question_spec_sha256=typed_request.question_spec_sha256,
        answers={
            "s": dict(
                type="score",
                score=1.6,
                legend={"0": "unrelated", "1": "related", "2": "same size"},
                probabilities={"0": 0.1, "1": 0.2, "2": 0.7},
                confidence=0.8,
            )
        },
    )
    result = wire.validate_typed_wire(json.dumps(data), typed_request)
    assert typed_request.questions["s"].criteria[1] == {"description": "related"}
    assert result.answers["s"].legend["1"] == "related"


@pytest.mark.parametrize("criteria", ["yes", ["yes", "no"], {"other": "yes"}, None, {"true": None}])
def test_noul_criteria_requires_optional_true_false_description_map(criteria):
    with pytest.raises(ValidationError):
        wire.NoulSpec.model_validate(dict(type="noul", instructions="Test", criteria=criteria))


def test_noul_structured_true_false_and_no_invented_confidence():
    spec = wire.NoulSpec.model_validate(
        dict(
            type="noul",
            instructions="Test",
            criteria={"true": {"means": "present"}, "false": ["absent"]},
        )
    )
    assert spec.criteria.true == {"means": "present"}
    with pytest.raises(ValidationError):
        wire.NoulAnswer.model_validate(dict(type="noul", noul=0.8, confidence=0.6))


@pytest.mark.parametrize("invalid", [False, True])
def test_choice_six_option_sum_addendum(invalid):
    probabilities = {
        str(i): value
        for i, value in enumerate([0.3] * 6 if invalid else [0.4, 0.2, 0.1, 0.1, 0.1, 0.1])
    }
    data = dict(type="choice", choice="0", probabilities=probabilities, confidence=0.28)
    if invalid:
        with pytest.raises(ValidationError):
            wire.ChoiceAnswer.model_validate(data)
        assert probabilities == {str(i): 0.3 for i in range(6)}
    else:
        assert wire.ChoiceAnswer.model_validate(data).probabilities == probabilities


@pytest.mark.parametrize("payload", ['{"q":1,"q":2}', '{"q":NaN}', '{"q":Infinity}'])
def test_duplicate_keys_and_nonfinite_json_rejected(payload):
    with pytest.raises(ValueError):
        decode_wire_json(payload)


def test_duplicate_actual_answer_id_rejected(typed_request, typed_result_data):
    payload = json.dumps(typed_result_data)
    payload = payload.replace('"answers": {', '"answers": {"condition":{"type":"noul","noul":0.4},')
    with pytest.raises(ValueError, match="duplicate JSON key"):
        wire.validate_typed_wire(payload, typed_request)


def test_closed_request_and_bool_version_rejected(typed_request):
    for extra in [{"schema_version": True}, {"gold": "secret"}, {"kind": "image"}]:
        data = {**typed_request.model_dump(mode="json"), **extra}
        with pytest.raises(ValidationError):
            wire.TypedJudgmentRequest.model_validate(data)


def test_noul_absent_criteria_and_description_roundtrip(typed_request):
    """what_bug_this_catches: serialization inventing explicitly forbidden null criteria."""
    data = typed_request.model_dump(mode="json")
    assert "criteria" not in data["questions"]["condition"]
    assert wire.TypedJudgmentRequest.model_validate(data).question_spec_sha256 == (
        typed_request.question_spec_sha256
    )
    spec = wire.NoulSpec(type="noul", instructions="Test", criteria={"true": "present"})
    assert spec.model_dump()["criteria"] == {"true": "present"}
    assert wire.NoulSpec.model_validate(spec.model_dump()).criteria.true == "present"


def test_validation_boundary_rechecks_mutated_nested_answer(typed_request, typed_result_data):
    """what_bug_this_catches: shallow frozen models bypassing probability validation."""
    result = wire.TypedJudgmentResult.model_validate(typed_result_data)
    result.answers["category"].probabilities["a"] = 0.3
    with pytest.raises(ValidationError):
        result.validate_for(typed_request)
