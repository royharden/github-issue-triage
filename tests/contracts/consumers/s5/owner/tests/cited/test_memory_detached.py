"""what_bug_this_catches: a declared text route has no real relocated source resolver."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_actual_detached_memory_consumer_requires_no_node_or_owner_app(tmp_path):
    root = next(parent for parent in Path(__file__).resolve().parents if (parent / "src/issue_triage/shared/cited").is_dir())
    namespace = tmp_path / "portable"
    namespace.mkdir()
    (namespace / "__init__.py").write_text("", encoding="utf-8")
    destination = namespace / "cited"
    destination.mkdir()
    for name in (
        "__init__.py",
        "models.py",
        "registry.py",
        "schema.py",
        "memory.py",
        "assessment.py",
    ):
        shutil.copyfile(
            root / "src" / "issue_triage" / "shared" / "cited" / name, destination / name
        )
    script = r"""
import sys,json,os,socket,subprocess,builtins
from pathlib import Path
from pydantic import BaseModel
owner=Path(sys.argv[2]).resolve()
sys.path=[path for path in sys.path if Path(path).resolve() not in (owner,owner/"src")]
sys.path.insert(0,sys.argv[1])
class DependencyProbe(BaseModel):
    count:int
assert DependencyProbe(count=1).count==1
original_getenv=os.getenv
def forbidden(*args,**kwargs):
    raise AssertionError("source consumer attempted ungranted effect")
def guarded_getenv(name,*args):
    if name=="PYDANTIC_DISABLE_PLUGINS":return original_getenv(name,*args)
    return forbidden(name,*args)
os.getenv=guarded_getenv
socket.create_connection=forbidden
socket.socket=forbidden
original_import=builtins.__import__
def guarded_import(name,*args,**kwargs):
    if name.split(".")[0] in {"changelog_advisor","issue_triage","openai","typesafe","requests","httpx"}:
        return forbidden(name)
    return original_import(name,*args,**kwargs)
builtins.__import__=guarded_import
for canary in (lambda:__import__("changelog_advisor"),lambda:__import__("issue_triage"),lambda:socket.socket()):
    try:canary()
    except AssertionError:pass
    else:raise AssertionError("detached denial guard absent")
subprocess.run=forbidden
Path.read_bytes=forbidden
Path.read_text=forbidden
from portable.cited import ArtifactRef,Finding,POINTER_ADAPTER,Registry,ResolutionContext
from portable.cited.memory import MemorySource,MemoryTextResolver,SectionSpan,install_supplied_text
from portable.cited.assessment import assess_required_evidence
data=MemorySource.from_bytes(namespace_id="notes-1",source_id="notes",source_revision="raw-1",
    raw="Release\r\nActual é change\r\n".encode(),newline_policy="crlf-to-lf",
    sections=(SectionSpan("release-1",1,2),))
class Access:
    reference=ArtifactRef(artifact_id="access",artifact_sha256="a"*64,profile_id="access/1")
    def decision(self,namespace_id,source_id):
        return "allow" if (namespace_id,source_id)==("notes-1","notes") else "unknown"
class Generation:
    reference=ArtifactRef(artifact_id="generation",artifact_sha256="b"*64,profile_id="generation/1")
    def current(self,namespace_id,source_id):
        return data.metadata if (namespace_id,source_id)==("notes-1","notes") else None
access,generation=Access(),Generation()
context=ResolutionContext(namespace_id="notes-1",access_policy_ref=access.reference,
    generation_policy_ref=generation.reference,required_scope="text")
registry=Registry()
install_supplied_text(registry,MemoryTextResolver((data,),access=access,generation=generation))
common=dict(schema_version=1,source_type="supplied_text",source_id="notes",
    source_sha256=data.metadata.source_sha256,source_revision="raw-1",
    evidence_artifact_sha256=data.metadata.evidence_artifact_sha256)
line=POINTER_ADAPTER.validate_python(dict(**common,kind="file:line",locator_subtype="line",
    locator=dict(line_start=2,line_end=2)))
section=POINTER_ADAPTER.validate_python(dict(**common,kind="doc:section",locator_subtype="section",
    locator=dict(section_id="release-1")))
assert registry.resolve(line,context).excerpt=="Actual é change\n"
assert registry.resolve(section,context).excerpt=="Release\nActual é change\n"
finding=Finding(id="claim-1",text="A potential semantic change",verdict="partial",
    probability=1.0,evidence=[line,section])
assessment=assess_required_evidence(finding,registry,context)
assert assessment.finding.verdict=="partial" and assessment.resolved_count==2
assert not any(name.startswith(("changelog_advisor","issue_triage","openai","typesafe","requests","httpx"))
    for name in sys.modules)
print(json.dumps(dict(actual_resolved=2,semantic_verdict=assessment.finding.verdict,
    owner_app_imported=False,node_calls=0)))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path), str(root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "actual_resolved": 2,
        "semantic_verdict": "partial",
        "owner_app_imported": False,
        "node_calls": 0,
    }
