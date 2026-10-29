"""what_bug_this_catches: metadata projection leaking bodies or silently losing billed usage."""

import pytest
from pydantic import ValidationError

from issue_triage.shared.callledger.ledger import LedgerError
from issue_triage.shared.callledger.models import MetadataRecord, NormalizedUsage
from issue_triage.shared.callledger.projection import project_usage

CANARY = b"SYNTHETIC_SECRET_PAYLOAD_CANARY_20261014"


def assert_no_canary(paths):
    for path in paths:
        assert CANARY not in path.read_bytes(), f"Planted payload leaked in {path.name}"


def test_projection_redacts_strings_and_privacy_scanner_positive_control(factory, tmp_path):
    projection, redacted, digest = project_usage(
        dict(
            input_tokens=100,
            details={"input_tokens": 100, "body": CANARY.decode()},
            headers={"Authorization": CANARY.decode()},
            error=CANARY.decode(),
            output_tokens=CANARY.decode(),
        )
    )
    assert redacted and projection.input_tokens == 100 and projection.output_tokens is None
    assert CANARY.decode() not in projection.model_dump_json()
    target = tmp_path / "metadata.jsonl"
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        attempt = factory.begin(ledger, allocation)
        metadata = factory.metadata(allocation)["metadata"].model_copy(
            update=dict(
                usage=projection,
                usage_projection_sha256=digest,
                usage_redacted_fields=redacted,
            )
        )
        ledger.settle(attempt, metadata=metadata, usage=NormalizedUsage(input_tokens=100))
        ledger.export_jsonl(target)
        paths = [p for p in tmp_path.iterdir() if p.is_file() and p.name != "metadata.jsonl"] + [
            target
        ]
        assert_no_canary(paths)
        target.write_bytes(target.read_bytes() + CANARY)
        with pytest.raises(AssertionError, match="Planted payload leaked"):
            assert_no_canary([target])
        ledger.export_jsonl(target)
        assert_no_canary(paths)


def test_required_billed_usage_cannot_be_replaced_by_unrelated_projection(factory):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        attempt = factory.begin(ledger, allocation)
        with pytest.raises(LedgerError, match="usage_binding"):
            ledger.settle(
                attempt,
                metadata=factory.metadata(allocation)["metadata"],
                usage=NormalizedUsage(input_tokens=1),
            )
        assert ledger.totals()["known_spend_usd"] == "0"
        assert ledger.totals()["active_holds_usd"] == "0.1"


def test_raw_error_payload_fields_fail_closed_without_secret_in_exception(factory):
    metadata = factory.metadata(type("Allocation", (), {"operation_id": "op1"})())[
        "metadata"
    ].model_dump()
    metadata["error_message"] = CANARY.decode()
    with pytest.raises(ValidationError) as error:
        MetadataRecord.model_validate(metadata)
    assert CANARY.decode() not in str(error.value)
    # Structured Pydantic errors can include input. The logger must not serialize them.
    assert CANARY.decode() in str(error.value.errors())


def test_projection_filesystem_exception_has_only_closed_code(factory, tmp_path, monkeypatch):
    import issue_triage.shared.callledger.ledger as implementation

    def fail_replace(*_):
        raise OSError(CANARY.decode())

    with factory.open() as ledger:
        monkeypatch.setattr(implementation.os, "replace", fail_replace)
        with pytest.raises(LedgerError, match="^projection_io$") as error:
            ledger.export_jsonl(tmp_path / "projection.jsonl")
        assert CANARY.decode() not in str(error.value)
        assert ledger.connection.execute("SELECT SUM(projected) FROM outbox").fetchone()[0] == 0
        assert not list(tmp_path.glob(".ledger-projection-*"))
