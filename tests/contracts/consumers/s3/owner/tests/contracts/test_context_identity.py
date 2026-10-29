"""what_bug_this_catches: unbound calls or machine paths weakening public identity."""

import copy

import pytest
from pydantic import ValidationError

from issue_triage.shared.providers import models as wire


@pytest.mark.parametrize(
    "field", ["purpose", "ledger_ref", "budget", "context", "limits", "allocation"]
)
def test_explicit_accounting_fields_are_required(envelope_data, field):
    del envelope_data[field]
    with pytest.raises(ValidationError):
        wire.ExecutionEnvelope.model_validate(envelope_data)


@pytest.mark.parametrize(
    "change", ["purpose", "authority", "operation", "run_quota", "deadline", "questions"]
)
def test_context_cannot_enlarge_or_change_authority(envelope_data, change):
    if change == "purpose":
        envelope_data["purpose"] = "other"
    elif change == "authority":
        envelope_data["context"]["authority_id"] = "other"
    elif change == "operation":
        envelope_data["allocation"]["operation_id"] = "other"
    elif change == "run_quota":
        envelope_data["limits"]["max_outbound_attempts"] = 11
    elif change == "deadline":
        envelope_data["limits"]["run_deadline_utc"] = "2026-10-15T00:00:00Z"
    else:
        envelope_data["limits"]["max_questions"] = 1
    with pytest.raises(ValidationError):
        wire.ExecutionEnvelope.model_validate(envelope_data)


def test_semantic_identity_excludes_ephemeral_execution_ids(envelope_data):
    original = wire.ExecutionEnvelope.model_validate(envelope_data)
    changed = copy.deepcopy(envelope_data)
    changed["context"].update(run_id="run2", task_id="task2", span_id="span2")
    assert (
        wire.ExecutionEnvelope.model_validate(changed).request_identity_sha256
        == original.request_identity_sha256
    )


@pytest.mark.parametrize("change", ["purpose", "source", "options", "instructions", "nonce"])
def test_actual_public_semantics_change_identity(envelope_data, change):
    original = wire.ExecutionEnvelope.model_validate(envelope_data).request_identity_sha256
    if change == "purpose":
        envelope_data["purpose"] = "other"
        envelope_data["context"]["purpose"] = "other"
    elif change == "source":
        envelope_data["context"]["source_generation"] = "g2"
    elif change == "options":
        envelope_data["request"]["questions"]["category"]["criteria"] = {"b": None, "a": None}
    elif change == "instructions":
        envelope_data["request"]["questions"]["condition"]["instructions"] = (
            "Different public criterion"
        )
    else:
        envelope_data["request"]["state"] = {"text": "Synthetic input", "nonce": "new-observation"}
    assert wire.ExecutionEnvelope.model_validate(envelope_data).request_identity_sha256 != original


def image_request(image_data):
    return wire.GenerateRequest.model_validate(
        dict(
            schema_version=1,
            kind="generate",
            model="synthetic-vision",
            messages=[{"role": "user", "content": [image_data]}],
            max_output_tokens=512,
            stream=False,
        )
    )


def test_image_semantic_identity_is_portable_but_dispatch_reference_changes(image_data):
    original = image_request(image_data)
    image_data["execution_ref"] = "D:/moved/renamed.png"
    moved = image_request(image_data)
    assert original.identity_payload() == moved.identity_payload()
    assert original.model_dump(mode="json") != moved.model_dump(mode="json")


@pytest.mark.parametrize(
    "field", ["detail", "content_sha256", "source_generation", "transform_sha256"]
)
def test_image_content_and_rendition_affect_identity(image_data, field):
    original = image_request(image_data).identity_payload()
    image_data[field] = (
        "high" if field == "detail" else ("g2" if field == "source_generation" else "a" * 64)
    )
    assert image_request(image_data).identity_payload() != original


@pytest.mark.parametrize(
    "path", ["https://example.test/x.png", "file:///x.png", "../x.png", "C:\\x\\..\\x.png"]
)
def test_image_reference_is_not_url_or_traversal_authority(image_data, path):
    image_data["execution_ref"] = path
    with pytest.raises(ValidationError):
        wire.ImagePart.model_validate(image_data)


def test_image_model_cannot_enter_typed_json_state(image_data, typed_request):
    data = typed_request.model_dump(mode="json")
    data["state"] = wire.ImagePart.model_validate(image_data)
    with pytest.raises(ValidationError):
        wire.TypedJudgmentRequest.model_validate(data)
