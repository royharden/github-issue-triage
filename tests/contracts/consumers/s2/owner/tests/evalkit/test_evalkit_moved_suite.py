"""Execute the complete declared runtime control suite after an actual namespace move."""

import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = next(
    parent for parent in Path(__file__).resolve().parents
    if (parent / "src/issue_triage/shared/evalkit").is_dir()
    or (parent / "portable_evalkit").is_dir()
)


def test_entire_moved_runtime_controls_without_original_app_or_provider(tmp_path):
    shutil.copytree(
        ROOT / "src/issue_triage/shared/evalkit",
        tmp_path / "portable_evalkit",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    target = tmp_path / "tests/evalkit"
    target.mkdir(parents=True)
    moved = []
    for source in sorted((Path(__file__).parent).glob("*.py")):
        if source.name == Path(__file__).name:
            continue  # Prevent recursively launching this same isolation harness.
        original = source.read_text(encoding="utf-8")
        content = original.replace("issue_triage.shared.evalkit", "portable_evalkit")
        content = content.replace('ROOT / "src/issue_triage/shared/evalkit"', 'ROOT / "portable_evalkit"')
        (target / source.name).write_text(content, encoding="utf-8")
        moved.append(source.name)
    assert len(moved) == 8  # Seven test files and their explicit no-network conftest.
    script = f"""
import importlib,importlib.abc,json,socket,sys
from pathlib import Path
sys.path.insert(0,{str(tmp_path)!r})
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name.split('.')[0] in {{'rfr','issue_triage','openai','typesafe','PIL','pytesseract','fastapi'}}:
            raise RuntimeError('forbidden original/domain/provider import')
sys.meta_path.insert(0,Guard())
def denied(*args,**kwargs): raise RuntimeError('network disabled')
socket.create_connection=denied;socket.socket.connect=denied
try: importlib.import_module('issue_triage')
except RuntimeError: pass
else: raise AssertionError('consumer app import canary not detected')
try: importlib.import_module('rfr.pipeline')
except RuntimeError: pass
else: raise AssertionError('original import control did not fire')
try: socket.create_connection(('example.invalid',443))
except RuntimeError: pass
else: raise AssertionError('network control did not fire')
import pytest
code=pytest.main([{str(target)!r},'-q','--tb=short',
    '--junitxml='+{str(tmp_path / "moved.xml")!r}])
for name,module in tuple(sys.modules.items()):
    if name=='portable_evalkit' or name.startswith('portable_evalkit.'):
        Path(module.__file__).resolve().relative_to(Path({str(tmp_path / "portable_evalkit")!r}))
assert not any(n=='rfr' or n.startswith('rfr.') for n in sys.modules)
assert not any(n=='issue_triage' or n.startswith('issue_triage.') for n in sys.modules)
print(json.dumps({{'pytest_exit':code,'import_canary':'detected','network_canary':'detected'}}))
raise SystemExit(code)
"""
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    run = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    proof = json.loads(run.stdout.strip().splitlines()[-1])
    assert proof["pytest_exit"] == 0
    suites = list(ET.parse(tmp_path / "moved.xml").getroot().iter("testsuite"))
    assert sum(int(s.attrib["tests"]) for s in suites) == 53
    assert all(
        int(s.attrib.get(k, 0)) == 0 for s in suites for k in ["failures", "errors", "skipped"]
    )
