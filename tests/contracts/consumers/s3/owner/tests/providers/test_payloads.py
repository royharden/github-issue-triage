"""what_bug_this_catches: flavor mixing, coerced native criteria and invalid paid answers."""

import json
from decimal import Decimal

import pytest

from issue_triage.shared.providers.adapters import AdapterError, decode_outcome
from issue_triage.shared.providers.schema import SchemaError, check_schema, validate_output


@pytest.mark.parametrize(
    "flavor,typed",
    [("openai_responses", False), ("openai_chat", False), ("typesafe", True), ("anthropic", False)],
)
def test_payload_contract_has_only_explicit_flavor_fields(factory, tmp_path, flavor, typed):
    rig = factory(tmp_path / "unused.sqlite3", flavor, typed)
    body = json.loads(rig.prepared().payload_json)
    assert "purpose" not in body and "allocation" not in body and "budget" not in body
    assert "api_key" not in body and "Authorization" not in body
    if flavor == "typesafe":
        assert list(body) == ["state", "model", "questions"]
        assert body["questions"]["condition"]["criteria"] == {
            "true": {"means": "present"},
            "false": ["absent"],
        }
        assert body["questions"]["score"]["criteria"] == [
            "unrelated",
            {"description": "related"},
            ["same size"],
        ]
        assert list(body["questions"]["category"]["criteria"]) == ["a", "b"]
    elif flavor == "openai_responses":
        assert body["text"]["format"] == {
            "type": "json_schema",
            "name": "response",
            "strict": True,
            "schema": rig.request.output_schema,
        }
        assert "response_format" not in body and body["max_output_tokens"] == 32
        assert body["input"][0]["content"][0]["type"] == "input_text"
    elif flavor == "openai_chat":
        assert body["response_format"]["json_schema"]["strict"] is True
        assert "text" not in body and body["max_completion_tokens"] == 32
    else:
        assert body["system"] == [] and body["max_tokens"] == 32
        assert body["output_config"]["format"] == {
            "type": "json_schema",
            "schema": rig.request.output_schema,
        }
        assert "response_format" not in body
    if flavor.startswith("openai"):
        assert body["tools"] == [] and body["tool_choice"] == "none" and body["store"] is False


@pytest.mark.parametrize("change", ["schema", "model", "temperature", "reasoning"])
def test_unsupported_capabilities_are_named_preflight_refusals(rig, change):
    if change == "schema":
        request = rig.request.model_copy(
            update={"output_schema": {"$ref": "https://example.test/schema"}}
        )
    elif change == "model":
        request = rig.request.model_copy(update={"model": "silent-upgrade-model"})
    elif change == "temperature":
        request = rig.request.model_copy(update={"temperature": 0.5})
    else:
        request = rig.request.model_copy(update={"reasoning_effort": "unsupported-effort"})
    with pytest.raises((AdapterError, SchemaError), match="unsupported"):
        rig.prepared(request)


@pytest.mark.parametrize(
    "mutation", ["missing_model", "refusal", "incomplete", "tool_action", "schema_violation"]
)
def test_response_errors_preserve_usage_and_never_become_usable_output(rig, mutation):
    body = rig.body()
    if mutation == "missing_model":
        del body["model"]
    elif mutation == "refusal":
        body["output"][0]["content"] = [{"type": "refusal", "refusal": "SYNTHETIC_REFUSAL_CANARY"}]
    elif mutation == "incomplete":
        body["status"] = "incomplete"
    elif mutation == "tool_action":
        body["output"] = [
            {"type": "function_call", "name": "execute", "arguments": "SYNTHETIC_ACTION_CANARY"}
        ]
    else:
        body["output"][0]["content"][0]["text"] = '{"tier":"unexpected"}'
    result = decode_outcome(
        json.dumps(body).encode(), prepared=rig.prepared(), config=rig.config, max_bytes=64000
    )
    assert result.status == ("refused" if mutation == "refusal" else "invalid_output")
    assert result.parsed is None and result.typed is None and result.text is None
    assert (
        result.normalized_usage.input_tokens == 100
        and result.normalized_usage.output_tokens is None
    )
    if mutation == "missing_model":
        assert result.model_reported is None


@pytest.mark.parametrize("invalid", [False, True])
def test_six_option_sum_never_normalized_and_billed_usage_conserved(
    factory, spy, reply, tmp_path, invalid
):
    rig = factory(tmp_path / "ledger.sqlite3", "typesafe", True)
    data = rig.request.model_dump(mode="json")
    data["questions"]["category"]["criteria"] = {str(i): None for i in range(6)}
    rig.request = type(rig.request).model_validate(data)
    rig.register(rig.request)
    body = rig.body()
    probabilities = {
        str(i): value
        for i, value in enumerate([0.3] * 6 if invalid else [0.4, 0.2, 0.1, 0.1, 0.1, 0.1])
    }
    body["answers"]["category"] = {
        "type": "choice",
        "choice": "0",
        "probabilities": probabilities,
        "confidence": 0.28,
    }
    transport = spy(rig, [reply(body)])
    provider = rig.provider(transport=transport)
    with rig.open() as ledger:
        allocation = provider.admit_operation(
            rig.plan(),
            ledger=ledger,
            budget=rig.authority,
            context=rig.context(),
            limits=rig.limits,
        )
        result = provider.run(rig.request, **rig.kwargs(ledger, allocation))
        assert result.status == ("invalid_output" if invalid else "ok")
        assert Decimal(ledger.totals()["known_spend_usd"]) == Decimal("0.01")
        assert (
            len(transport.calls) == 1
            and probabilities == body["answers"]["category"]["probabilities"]
        )
        if not invalid:
            assert result.typed.answers["category"].probabilities == probabilities


def test_local_strict_schema_subset_positive_and_adversarial_values():
    schema = {
        "type": "object",
        "properties": {
            "count": {"type": "integer", "minimum": 0},
            "tag": {"anyOf": [{"type": "null"}, {"type": "string", "enum": ["ok"]}]},
            "items": {"type": "array", "items": {"type": "number"}, "maxItems": 2},
        },
        "required": ["count", "tag", "items"],
        "additionalProperties": False,
    }
    check_schema(schema)
    validate_output({"count": 1, "tag": None, "items": [1.0, 2.0]}, schema)
    for data in [
        {"count": True, "tag": None, "items": []},
        {"count": 1, "tag": "bad", "items": []},
        {"count": 1, "tag": None, "items": [float("inf")]},
        {"count": 1, "tag": None, "items": [], "extra": 1},
    ]:
        with pytest.raises(SchemaError, match="invalid_output"):
            validate_output(data, schema)
    with pytest.raises(SchemaError, match="unsupported_schema"):
        check_schema(
            {"type": "object", "properties": {}, "required": [], "additionalProperties": True}
        )
