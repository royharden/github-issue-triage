"""what_bug_this_catches: inventing a capture to encode an actual strict offline miss."""

import pytest
from pydantic import ValidationError

from issue_triage.shared.callledger.models import NormalizedUsage
from issue_triage.shared.providers.models import Result


def missing_capture(typed_request):
    return dict(
        schema_version=1,
        kind="typed",
        status="cache_miss",
        text=None,
        parsed=None,
        typed=None,
        error={"code": "cache_miss"},
        model_requested=typed_request.model,
        model_reported=None,
        usage_raw=None,
        normalized_usage=NormalizedUsage().model_dump(mode="json"),
        accounting_ref="allocation",
        attempt_ids=[],
        origin="replay",
        source_capture=None,
        latency_ms=1.0,
        first_output_ms=None,
        first_output_kind="unavailable",
        current_external_cost_usd="0",
    )


def test_no_dispatch_failure_may_have_unavailable_capture(typed_request):
    data = missing_capture(typed_request)
    result = Result.model_validate(data).validate_for(typed_request)
    assert (
        result.source_capture is None
        and result.attempt_ids == []
        and result.current_external_cost_usd == "0"
    )


@pytest.mark.parametrize(
    "change",
    [
        {"status": "ok"},
        {"current_external_cost_usd": "0.1"},
        {"attempt_ids": ["attempt1"]},
        {"parsed": {"invented": "output"}},
    ],
)
def test_missing_capture_is_not_success_paid_or_usable_output(typed_request, change):
    with pytest.raises(ValidationError):
        Result.model_validate({**missing_capture(typed_request), **change})
