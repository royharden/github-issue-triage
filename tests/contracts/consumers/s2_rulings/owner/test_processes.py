"""Actual bounded OS workers exercise process locking/CAS and unknown append acknowledgement."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from _s2_rulings_synthetic_intents import CurrentGeneration, scalar

from issue_triage.shared.rulings.store import JournalStore, LockTimeout

ROOT = Path(__file__).resolve().parents[5]


WORKER = """
import json,os,socket,sys,time
from pathlib import Path
from issue_triage.shared.rulings.models import RulingIntent
from issue_triage.shared.rulings.store import JournalStore,JournalError
def no_network(*args,**kwargs): raise RuntimeError("network disabled in test process")
socket.create_connection=no_network
socket.socket.connect=no_network
root=Path(sys.argv[1]);tag=sys.argv[2];mode=sys.argv[3]
store=JournalStore(root,lock_deadline_s=1.)
intent=RulingIntent.model_validate_json((root/(tag+".input.json")).read_bytes())
class Validator:
    def validate(self,subject,generation):
        if generation!=intent.generation_identity: raise ValueError("fixture generation changed")
if mode=="hold":
    with store._critical():
        (root/(tag+".ready")).write_text("locked")
        end=time.monotonic()+5
        while not (root/"release").exists():
            if time.monotonic()>end: raise RuntimeError("bounded hold expired")
            time.sleep(.01)
    raise SystemExit(0)
(root/(tag+".ready")).write_text("ready")
end=time.monotonic()+5
while not (root/"go").exists():
    if time.monotonic()>end: raise RuntimeError("bounded start expired")
    time.sleep(.01)
if mode=="crash-after-fsync":
    class CrashStore(JournalStore):
        def _sync(self,fd):
            os.fsync(fd)
            os._exit(77)
    CrashStore(root).append(intent,Validator())
    raise AssertionError("worker unexpectedly acknowledged")
try:
    result=store.append(intent,Validator())
    record={"status":"accepted","sequence":result.sequence,"outcome":result.outcome,"platform":os.name}
except JournalError as error:
    record={"status":"refused","reason":str(error),"platform":os.name}
(root/(tag+".result.json")).write_text(json.dumps(record))
"""


def start(root, tag, intent, mode="append"):
    (root / (tag + ".input.json")).write_text(intent.model_dump_json(), encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.Popen(
        [sys.executable, "-c", WORKER, str(root), tag, mode],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def wait_for(path, workers):
    end = time.monotonic() + 5
    while not path.exists():
        assert all(w.poll() is None for w in workers), "test worker exited before barrier"
        assert time.monotonic() < end, "test process barrier deadline"
        time.sleep(0.01)


def stop(workers):
    for worker in workers:
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=5)


@pytest.mark.parametrize("case", ["same-head-CAS", "different-subjects", "same-intent-retry"])
def test_two_actual_processes_cas_sequence_and_idempotency(tmp_path, case):
    first = scalar("first")
    second = (
        scalar("second")
        if case == "same-head-CAS"
        else scalar("second", item="other-item")
        if case == "different-subjects"
        else first
    )
    workers = [start(tmp_path, "a", first), start(tmp_path, "b", second)]
    try:
        for tag in ("a", "b"):
            wait_for(tmp_path / (tag + ".ready"), workers)
        (tmp_path / "go").write_text("start")
        for worker in workers:
            out, err = worker.communicate(timeout=10)
            assert worker.returncode == 0, (out, err)
        results = [
            json.loads((tmp_path / (tag + ".result.json")).read_text()) for tag in ("a", "b")
        ]
        assert {r["platform"] for r in results} == {os.name}
        snapshot = JournalStore(tmp_path).replay()
        if case == "same-head-CAS":
            assert sorted(r["status"] for r in results) == ["accepted", "refused"]
            assert (
                next(r["reason"] for r in results if r["status"] == "refused")
                == "stable_head_conflict"
            )
            assert len(snapshot.events) == 1
        elif case == "different-subjects":
            assert sorted(r["sequence"] for r in results) == [1, 2]
            assert len(snapshot.events) == 2
        else:
            assert sorted(r["outcome"] for r in results) == ["appended", "exact_retry"]
            assert [r["sequence"] for r in results] == [1, 1] and len(snapshot.events) == 1
    finally:
        stop(workers)


def test_actual_held_process_lock_times_out_then_releases(tmp_path):
    intent = scalar()
    worker = start(tmp_path, "holder", intent, "hold")
    try:
        wait_for(tmp_path / "holder.ready", [worker])
        began = time.monotonic()
        with pytest.raises(LockTimeout):
            JournalStore(tmp_path, lock_deadline_s=0.05).replay()
        assert 0.04 <= time.monotonic() - began < 1
        (tmp_path / "release").write_text("release")
        out, err = worker.communicate(timeout=10)
        assert worker.returncode == 0, (out, err)
        assert (
            JournalStore(tmp_path)
            .append(intent, CurrentGeneration(intent.generation_identity))
            .sequence
            == 1
        )
    finally:
        stop([worker])


def test_real_process_death_after_fsync_before_ack_retries_one_historical_event(tmp_path):
    intent = scalar()
    worker = start(tmp_path, "crash", intent, "crash-after-fsync")
    try:
        wait_for(tmp_path / "crash.ready", [worker])
        (tmp_path / "go").write_text("start")
        worker.communicate(timeout=10)
        assert worker.returncode == 77 and not (tmp_path / "crash.result.json").exists()
        store = JournalStore(tmp_path)
        before = store.path.read_bytes()
        wrong_current = CurrentGeneration(scalar(raw="now-changed").generation_identity)
        receipt = store.append(intent, wrong_current)
        assert receipt.sequence == 1 and receipt.historical and receipt.outcome == "exact_retry"
        assert wrong_current.calls == 0 and store.path.read_bytes() == before
        assert len(store.replay().events) == 1
    finally:
        stop([worker])


def test_same_process_two_threads_also_have_one_cas_winner(tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from issue_triage.shared.rulings.store import PriorConflict

    store = JournalStore(tmp_path, lock_deadline_s=1.0)
    barrier = threading.Barrier(2)

    def attempt(event_id):
        intent = scalar(event_id)
        barrier.wait(timeout=3)
        try:
            return store.append(intent, CurrentGeneration(intent.generation_identity)).outcome
        except PriorConflict:
            return "stale_head"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ("thread-1", "thread-2")))
    assert sorted(results) == ["appended", "stale_head"]
    assert len(store.replay().events) == 1
