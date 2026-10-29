"""what_bug_this_catches: race admission, process-crash loss and projection-as-authority."""

import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from threading import Barrier

import pytest

from issue_triage.shared.callledger.ledger import LedgerError


def test_concurrent_whole_admissions_have_exactly_one_winner(factory):
    factory.open().close()
    barrier = Barrier(2)

    def admit(name):
        with factory.open() as ledger:
            barrier.wait(timeout=5)
            try:
                factory.admit(ledger, name, count=2)
                return "admitted"
            except LedgerError as error:
                return str(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(admit, ["one", "two"]))
    assert sorted(results) == ["admitted", "budget_rejected"]
    with factory.open() as ledger:
        assert Decimal(ledger.totals()["future_holds_usd"]) == Decimal("0.4")
        assert ledger.totals()["dispatched_attempts"] == 0


@pytest.mark.parametrize("cut,used", [("before_commit", 0), ("after_commit", 1)])
def test_real_process_exit_at_attempt_commit_preserves_atomic_funds(factory, tmp_path, cut, used):
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
    config = dict(
        path=str(factory.path),
        authority=factory.authority.model_dump(mode="json"),
        snapshot=factory.snapshot.model_dump(mode="json"),
        bound=factory.bound.model_dump(mode="json"),
        request=factory.request.model_dump(mode="json"),
        allocation=allocation.model_dump(mode="json"),
        context=factory.context(child="child0").model_dump(mode="json"),
        now=factory.now.isoformat(),
        cut=cut,
    )
    config_path = tmp_path / "crash-config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    code = """
import json,os,sys
from datetime import datetime
from pathlib import Path
from issue_triage.shared.callledger.ledger import Ledger
from issue_triage.shared.callledger.models import BudgetAuthority,Allocation,CallContext
from issue_triage.shared.callledger.pricing import PriceSnapshot,FundingEvidence,RequestEvidence
c=json.loads(Path(sys.argv[1]).read_text())
l=Ledger(Path(c['path']),authority=BudgetAuthority.model_validate(c['authority']),
 price_snapshot=PriceSnapshot.model_validate(c['snapshot']),
 trusted_bounds=[FundingEvidence.model_validate(c['bound'])],
 trusted_requests=[RequestEvidence.model_validate(c['request'])],
 clock=lambda:datetime.fromisoformat(c['now']),monotonic=lambda:100.)
def die(phase):
 if phase==c['cut']: os._exit(71)
l._checkpoint=die
l.begin_attempt(Allocation.model_validate(c['allocation']),context=CallContext.model_validate(c['context']),
 request=RequestEvidence.model_validate(c['request']))
raise AssertionError('crash seam was not reached')
"""
    crash = subprocess.run(
        [sys.executable, "-c", code, str(config_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert crash.returncode == 71, crash.stderr
    with factory.open() as restarted:
        totals = restarted.totals()
        assert totals["dispatched_attempts"] == used
        assert Decimal(totals["total_exposure_usd"]) == Decimal("0.2")
        assert Decimal(totals["active_holds_usd"]) == Decimal("0.1") * used
        assert Decimal(totals["future_holds_usd"]) == Decimal("0.2") - Decimal("0.1") * used
        # No missing/duplicate atomic event+outbox rows after either abrupt process exit.
        assert (
            restarted.connection.execute(
                "SELECT COUNT(*) FROM events e LEFT JOIN outbox o ON e.sequence=o.sequence "
                "WHERE o.sequence IS NULL"
            ).fetchone()[0]
            == 0
        )


def test_projection_crash_torn_file_and_duplicate_export_rebuild_from_sqlite(factory, tmp_path):
    projection = tmp_path / "events.jsonl"
    with factory.open() as ledger:
        allocation = factory.admit(ledger)
        factory.begin(ledger, allocation)
        count = ledger.export_jsonl(projection)
        original = projection.read_bytes()
        assert count == len(original.splitlines())
        assert ledger.export_jsonl(projection) == count and projection.read_bytes() == original

        def cut(phase):
            if phase == "projection_after_replace":
                raise RuntimeError("synthetic projection interruption")

        ledger._checkpoint = cut
        ledger.connection.execute("UPDATE outbox SET projected=0")
        with pytest.raises(RuntimeError):
            ledger.export_jsonl(projection)
        assert ledger.connection.execute("SELECT SUM(projected) FROM outbox").fetchone()[0] == 0
        ledger._checkpoint = lambda _: None
    projection.write_bytes(b'{"torn":')
    with factory.open() as restarted:
        assert restarted.export_jsonl(projection) == count
        assert projection.read_bytes() == original
        sequences = [json.loads(line)["sequence"] for line in projection.read_bytes().splitlines()]
        assert len(set(sequences)) == len(sequences)
        assert Decimal(restarted.totals()["active_holds_usd"]) == Decimal("0.1")


def test_event_checksum_corruption_refuses_projection_without_overwriting(factory, tmp_path):
    """what_bug_this_catches: altered event contents exported under an unchanged digest."""
    target = tmp_path / "projection.jsonl"
    with factory.open() as ledger:
        ledger.export_jsonl(target)
        original = target.read_bytes()
        ledger.connection.execute("UPDATE events SET payload='{}'")
        with pytest.raises(LedgerError, match="event_integrity"):
            ledger.export_jsonl(target)
        assert target.read_bytes() == original


def test_moved_ledger_and_price_copy_runs_without_owner_namespace_or_network(factory, tmp_path):
    import issue_triage.shared.callledger as callledger

    package = tmp_path / "detached"
    package.mkdir()
    (package / "__init__.py").write_text("")
    shutil.copytree(
        Path(callledger.__file__).parent,
        package / "callledger",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    snapshot = tmp_path / "prices.json"
    snapshot.write_text(json.dumps(factory.snapshot.model_dump(mode="json")))
    authority = tmp_path / "authority.json"
    authority.write_text(json.dumps(factory.authority.model_dump(mode="json")))
    code = """
import builtins,json,socket
from datetime import datetime,UTC
from pathlib import Path
def blocked(*a,**k):raise RuntimeError('network positive control')
socket.socket=blocked;socket.create_connection=blocked
try:socket.socket()
except RuntimeError:pass
else:raise AssertionError('failed positive control')
original=builtins.__import__
def importing(name,*a,**k):
 if name.startswith('llm_router_eval'):raise AssertionError('owner import forbidden')
 return original(name,*a,**k)
builtins.__import__=importing
from detached.callledger.ledger import Ledger
from detached.callledger.models import BudgetAuthority,NormalizedUsage
from detached.callledger.pricing import load_snapshot
s=load_snapshot(Path('prices.json'))
charge=s.policies[0].price(NormalizedUsage(input_tokens=100),reservation_usd='0.1')
assert charge.computed_cost_usd=='0.01'
authority=BudgetAuthority.model_validate(json.loads(Path('authority.json').read_text()))
with Ledger(Path('moved.sqlite3'),authority=authority,
 price_snapshot=s,clock=lambda:datetime(2026,10,14,22,30,tzinfo=UTC)) as ledger:
 assert ledger.totals()['dispatched_attempts']==0
 ledger.export_jsonl(Path('moved.jsonl'))
print('moved ledger/pricing core executed without owner app/network')
"""
    run = subprocess.run(
        [sys.executable, "-c", code], cwd=tmp_path, capture_output=True, text=True, timeout=30
    )
    assert run.returncode == 0, run.stderr
    assert "moved ledger/pricing core executed" in run.stdout
