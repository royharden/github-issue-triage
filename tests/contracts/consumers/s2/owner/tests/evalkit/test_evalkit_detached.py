"""Move the actual evalkit runtime; original app/provider imports and network fail closed."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = next(
    parent for parent in Path(__file__).resolve().parents
    if (parent / "src/issue_triage/shared/evalkit").is_dir()
    or (parent / "portable_evalkit").is_dir()
)


def test_detached_actual_corpus_runner_math_resampling_report_and_negative_canaries(tmp_path):
    shutil.copytree(
        ROOT / "src/issue_triage/shared/evalkit",
        tmp_path / "portable_evalkit",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    # Explicitly move tiny authored dev controls. They are not private data or held-out Gold.
    for name in ("test_corpus.py", "test_runner.py", "test_statistics.py", "test_resampling.py"):
        content = (Path(__file__).parent / name).read_text(encoding="utf-8")
        (tmp_path / name).write_text(
            content.replace("issue_triage.shared.evalkit", "portable_evalkit"), encoding="utf-8"
        )
    script = f"""
import importlib,importlib.abc,json,socket,sys
from pathlib import Path
sys.path.insert(0,{str(tmp_path)!r})
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name.split('.')[0] in {{'rfr','issue_triage','openai','typesafe','PIL','pytesseract','fastapi'}}:
            raise RuntimeError('original/domain/provider import forbidden')
sys.meta_path.insert(0,Guard())
def denied(*args,**kwargs): raise RuntimeError('network disabled')
socket.create_connection=denied;socket.socket.connect=denied
from test_corpus import fixture
from test_runner import Adapter,Runner,lookup,H
from test_statistics import outcome
from test_resampling import spec
from portable_evalkit.corpus import load_corpus,FrozenCorpusError
from portable_evalkit.runner import compare,MethodConfig
from portable_evalkit.statistics import accuracy,wilson_interval,typed_equal
from portable_evalkit.resampling import paired_group_resample
from portable_evalkit.reporting import not_measured_row
from portable_evalkit.models import MetricSpec
root=Path({str(tmp_path)!r}); rows,manifest,file=fixture(root)
assert load_corpus(root,manifest,'dev',Adapter())==rows
result=compare({{'baseline':MethodConfig('fixture/1',H,'synthetic',Runner())}},
    manifest,'dev',rows,Adapter(),None,lookup)
assert accuracy(result.methods['baseline'].outcomes).value==1
assert typed_equal(False,0) is False and wilson_interval(40,40)[0]<.95
sample=(outcome(0,True,True),outcome(2,False,False))
other=tuple(r.model_copy(update={{'method':'other'}}) for r in sample)
res=paired_group_resample({{'baseline':sample,'other':other}},spec(),accuracy)
assert res.methods['baseline'].valid_draws==2000
assert res.differences['baseline','other'].interval.low==0
metric=MetricSpec(metric='accuracy',population='as_frozen',
    statistic_version='synthetic/1',denominator_policy='all-eligible/1',
    zero_denominator_reason='zero_support',averaging='none')
never=not_measured_row(('0','1'),('0',),metric,method='never',dataset_alias='synthetic',
    split='dev',config_ref='config/1')
assert never.measurement_status=='not_measured' and never.value is None
file.write_bytes(file.read_bytes()+b' ')
try: load_corpus(root,manifest,'dev',Adapter())
except FrozenCorpusError: pass
else: raise AssertionError('changed frozen bytes not detected')
try: importlib.import_module('issue_triage')
except RuntimeError: pass
else: raise AssertionError('consumer app import canary not detected')
try: importlib.import_module('rfr.pipeline')
except RuntimeError: pass
else: raise AssertionError('original import canary not detected')
try: socket.create_connection(('example.invalid',443))
except RuntimeError: pass
else: raise AssertionError('network canary not detected')
assert not any(n=='rfr' or n.startswith('rfr.') for n in sys.modules)
assert not any(n=='issue_triage' or n.startswith('issue_triage.') for n in sys.modules)
print(json.dumps({{'status':'passed','draws':2000,'fixed_cases':len(rows),
    'original_import_control':'detected','network_control':'detected'}}))
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    run = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    receipt = json.loads(run.stdout)
    assert receipt["draws"] == 2000 and receipt["fixed_cases"] == 2
    assert receipt["network_control"] == receipt["original_import_control"] == "detected"
