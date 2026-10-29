"""Move the actual rulings runtime without application/domain/provider dependencies."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from _s2_rulings_synthetic_intents import scalar

ROOT = Path(__file__).resolve().parents[5]


def test_detached_real_journal_append_restart_projection_and_import_canary(tmp_path):
    shutil.copytree(
        ROOT / "src/issue_triage/shared/rulings",
        tmp_path / "independent_rulings",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    private = tmp_path / "private"
    private.mkdir()
    first = scalar()
    (tmp_path / "fixture.json").write_text(first.model_dump_json(), encoding="utf-8")
    script = f"""
import importlib,importlib.abc,json,socket,sys
from pathlib import Path
sys.path.insert(0,{str(tmp_path)!r})
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name.split(".")[0] in {{"rfr","issue_triage","openai","typesafe","typesafeai","PIL","pytesseract","entity_matcher","fastapi","httpx","requests","aiohttp"}}:
            raise RuntimeError("forbidden original/domain import")
sys.meta_path.insert(0,Guard())
def denied(*args,**kwargs): raise RuntimeError("network disabled")
socket.create_connection=denied;socket.socket.connect=denied
from independent_rulings.models import RulingIntent
from independent_rulings.store import JournalStore,subject_key
from independent_rulings.projection import export_labels
intent=RulingIntent.model_validate_json(Path({str(tmp_path / "fixture.json")!r}).read_bytes())
class Validator:
    def validate(self,subject,generation): assert generation==intent.generation_identity
store=JournalStore(Path({str(private)!r}))
assert store.append(intent,Validator()).sequence==1
snapshot=JournalStore(Path({str(private)!r})).replay()
labels=export_labels(snapshot,{{subject_key(intent.namespace,intent.subject):intent.generation_identity}})
assert len(labels)==1 and labels[0].label_source=="agent_provisional"
assert store.append(intent,Validator()).outcome=="exact_retry"
try: importlib.import_module("rfr.pipeline")
except RuntimeError: pass
else: raise AssertionError("forbidden import control not detected")
for forbidden in ("issue_triage", "openai", "typesafe"):
    try: importlib.import_module(forbidden)
    except RuntimeError: pass
    else: raise AssertionError("consumer/provider import canary failed")
try: socket.create_connection(("synthetic.invalid",443))
except RuntimeError: pass
else: raise AssertionError("network denial canary failed")
assert not any(name=="rfr" or name.startswith("rfr.") for name in sys.modules)
print(json.dumps({{"status":"passed","platform":sys.platform,"events":len(snapshot.events),"network_calls":0,"original_import_control":"detected"}}))
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    run = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    receipt = json.loads(run.stdout)
    assert receipt["status"] == "passed" and receipt["events"] == 1
    assert receipt["original_import_control"] == "detected"
