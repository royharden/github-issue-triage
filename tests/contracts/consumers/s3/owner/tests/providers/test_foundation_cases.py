"""what_bug_this_catches: foundation fixtures bypassing actual accounting."""

import json
from decimal import Decimal
from pathlib import Path

import pytest

from issue_triage.shared.providers.models import GenerateRequest, TypedJudgmentRequest

MANIFEST = Path(__file__).parents[1] / "provider_payloads/foundation-cases.v1.json"
CASES = json.loads(MANIFEST.read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_authored_contract_case_uses_one_actual_funded_controller_attempt(
    factory, spy, reply, tmp_path, case
):
    rig = factory(tmp_path / "fixture.sqlite3", case["flavor"], case["flavor"] == "typesafe")
    cls = TypedJudgmentRequest if case["request"]["kind"] == "typed_judgment" else GenerateRequest
    rig.request = cls.model_validate(case["request"])
    rig.register(rig.request)
    transport = spy(rig, [reply(case["response"])])
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
        assert result.status == case["expected_status"] and result.parsed == case["expected_parsed"]
        assert (
            result.origin == "mock"
            and result.source_capture.origin == "synthetic"
            and result.current_external_cost_usd == "0"
        )
        assert len(transport.calls) == ledger.totals()["dispatched_attempts"] == 1
        assert Decimal(ledger.totals()["known_spend_usd"]) == Decimal("0.01")
