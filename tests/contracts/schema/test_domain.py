"""Original contract controls, independent of sealed fixture/GitHub/model data."""

import json

import pytest
from pydantic import ValidationError

from issue_triage.contracts import DomainError, IssueInput, IssueKey, WebhookEnvelope, utc_epoch_us


def issue():
    return IssueInput(
        key=IssueKey(
            installation_id=1, repository_id=2, issue_number=3, owner="synthetic", repository="demo"
        ),
        title="Original synthetic title",
        body="A local contract probe.",
        updated_at="2026-10-14T10:00:00Z",
        author_id=9,
        author_login="synthetic-author",
    )


def envelope():
    return WebhookEnvelope(
        delivery_id="test-delivery",
        event="issues",
        action="opened",
        raw_body_sha256="a" * 64,
        received_at="2026-10-14T10:00:01Z",
        issue=issue(),
    )


def test_closed_roundtrip_and_canonical_digest():
    value = envelope()
    assert WebhookEnvelope.parse_json(value.canonical_bytes()) == value
    assert (
        value.sha256 == WebhookEnvelope.parse_json(json.dumps(value.model_dump()).encode()).sha256
    )
    assert value.issue.key.stable_id == "1:2:3"
    assert value.issue.model_bound_text == "Original synthetic title\n\nA local contract probe."
    with pytest.raises(ValidationError):
        value.delivery_id = "changed"
    schema = WebhookEnvelope.model_json_schema()
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("installation_id", True),
        ("repository_id", "2"),
        ("issue_number", 0),
        ("owner", "evil/host"),
        ("repository", ".."),
        ("repository", "x?token=y"),
        ("schema_version", True),
        ("schema_version", 2),
    ],
)
def test_identity_rejects_coercions_and_path_components(field, value):
    data = issue().key.model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        IssueKey.model_validate(data)


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-14T10:00:00",
        "2026-10-14T10:00:00+01:00",
        "2026-13-14T10:00:00Z",
        "2026-10-14T10:00:60Z",
        "2026-10-14T10:00:00.0000001Z",
        True,
    ],
)
def test_utc_timestamp_validation(value):
    with pytest.raises((ValueError, TypeError)):
        utc_epoch_us(value)


def test_time_comparison_has_exact_microseconds():
    assert utc_epoch_us("1970-01-01T00:00:00Z") == 0
    assert utc_epoch_us("2026-10-14T10:00:00.1Z") == utc_epoch_us("2026-10-14T10:00:00.100000Z")
    assert utc_epoch_us("2026-10-14T10:00:00.000001Z") + 1 == utc_epoch_us(
        "2026-10-14T10:00:00.000002Z"
    )


@pytest.mark.parametrize(
    "bad", [b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}', b"not json", b"[]", b"{}"]
)
def test_untrusted_json_errors_are_closed(bad):
    with pytest.raises(DomainError, match="^invalid_domain_json$"):
        WebhookEnvelope.parse_json(bad)


def test_untrusted_body_unknown_fields_and_encoding_do_not_leak():
    data = envelope().model_dump()
    data["PRIVATE_CANARY_581"] = "PRIVATE_CANARY_581"
    with pytest.raises(DomainError) as error:
        WebhookEnvelope.parse_json(json.dumps(data).encode())
    assert "PRIVATE_CANARY" not in str(error.value)
    text = issue().model_copy(update={"title": "PRIVATE_CANARY_581", "body": "PRIVATE_CANARY_581"})
    assert "PRIVATE_CANARY" not in repr(text)
    bad = issue().model_dump()
    bad["body"] = "\ud800"
    with pytest.raises(ValidationError):
        IssueInput.model_validate(bad)
    with pytest.raises(DomainError, match="invalid_json_size"):
        WebhookEnvelope.parse_json(b"x" * 1048577)


def test_complete_body_is_preserved_not_prefix_authorized():
    data = issue().model_dump()
    data["body"] = "a" * 32769 + "tail control"
    actual = IssueInput.model_validate(data)
    assert actual.body == data["body"]
    # Screen policy, not the serialization model, decides whether the complete input fits.
    assert actual.model_bound_text.endswith("tail control")
