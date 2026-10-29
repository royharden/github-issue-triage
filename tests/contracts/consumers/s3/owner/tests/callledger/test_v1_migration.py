"""what_bug_this_catches: new caller-limit state resetting an actual version1 liability."""

import hashlib
import json
import sqlite3
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from issue_triage.shared.callledger import Ledger
from issue_triage.shared.callledger.models import (
    Allocation,
    BudgetAuthority,
    CallContext,
    Limits,
)
from issue_triage.shared.callledger.pricing import (
    FundingEvidence,
    PriceSnapshot,
    RequestEvidence,
)


def test_actual_wp02_v1_fixture_migrates_without_reset_or_reprice(tmp_path):
    fixture = Path(__file__).parent / "fixtures"
    data = json.loads((fixture / "wp02-schema-v1-case.json").read_text(encoding="utf-8"))
    sql = (fixture / "wp02-schema-v1.sql").read_bytes()
    assert hashlib.sha256(sql).hexdigest() == data["schema_sql_sha256"]
    path = tmp_path / "migrated.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript(sql.decode("utf-8"))
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
    connection.close()
    with Ledger(
        path,
        authority=BudgetAuthority.model_validate(data["authority"]),
        price_snapshot=PriceSnapshot.model_validate(data["snapshot"]),
        trusted_bounds=[FundingEvidence.model_validate(x) for x in data["bounds"]],
        trusted_requests=[RequestEvidence.model_validate(x) for x in data["requests"]],
        clock=lambda: datetime.fromisoformat(data["clock_utc"]),
        monotonic=lambda: 100.0,
    ) as ledger:
        assert ledger.connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert ledger.totals() == data["v1_totals"]
        assert ledger.totals()["dispatched_attempts"] == 1
        assert Decimal(ledger.totals()["unknown_liability_usd"]) == Decimal("0.1")
        view = ledger.validate_allocation(
            Allocation.model_validate(data["allocation"]),
            context=CallContext.model_validate(data["child_context"]),
            limits=Limits.model_validate(data["limits"]),
            request=RequestEvidence.model_validate(data["requests"][0]),
        )
        assert view.used_attempts == view.remaining_attempts == 1
