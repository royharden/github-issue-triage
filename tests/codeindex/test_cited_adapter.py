"""what_bug_this_catches: generic dispatch bypasses actual source/policy/report evidence."""

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from issue_triage.shared.cited import ArtifactRef, Finding, Registry, ResolutionContext
from issue_triage.shared.cited.assessment import assess_required_evidence
from issue_triage.shared.cited.registry import DuplicateResolverError
from issue_triage.shared.codeindex.canonical import CodeIndexError, canonical_bytes, digest
from issue_triage.shared.codeindex.cited_adapter import (
    FILE_KEY,
    REPORT_KEY,
    BridgeBounds,
    CodeIndexCitedResolver,
    install_codeindex,
    to_cited_file,
    to_cited_report,
)
from issue_triage.shared.codeindex.index import build_index
from issue_triage.shared.codeindex.inventory import InventoryReader, inventory_from_files
from issue_triage.shared.codeindex.models import SnapshotRef
from issue_triage.shared.codeindex.report import build_existence_report
from issue_triage.shared.codeindex.resolution import MappingAuthority, TrustedMapping


def make_index(files=None):
    files = (
        {"a.py": "# é original\r\ndef target():\r\n return 7\r\n".encode()}
        if files is None
        else files
    )
    inventory = inventory_from_files(files)
    return build_index(
        SnapshotRef(
            "original-bridge-controls",
            "fixture_inventory",
            inventory.sha256,
            inventory.sha256,
            "2026-10-15T00:00:00Z",
            True,
        ),
        InventoryReader(inventory, files),
    )


class Access:
    reference = ArtifactRef(
        artifact_id="synthetic-access",
        artifact_sha256=digest("access fixture"),
        profile_id="synthetic-access/1",
    )

    def __init__(self):
        self.answers, self.calls = ["allow"], 0

    def decision(self, namespace, repository):
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return answer


class Generation:
    reference = ArtifactRef(
        artifact_id="synthetic-generation",
        artifact_sha256=digest("generation fixture"),
        profile_id="synthetic-generation/1",
    )

    def __init__(self, snapshot):
        self.answers, self.calls = [snapshot], 0

    def current(self, namespace, repository):
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return answer


def setup(files=None, *, text=None, installed=True, bounds=None, prior=None):
    index = make_index(files)
    access, generation = Access(), Generation(index.snapshot)
    context = ResolutionContext(
        namespace_id="original-namespace",
        access_policy_ref=access.reference,
        generation_policy_ref=generation.reference,
        required_scope="text",
    )
    report = build_existence_report(index, text, prior=prior) if text is not None else None
    resolver = CodeIndexCitedResolver(
        index,
        namespace_id=context.namespace_id,
        access=access,
        generation=generation,
        reports=(report,) if report else (),
        prior=prior,
        **({"bounds": bounds} if bounds is not None else {}),
    )
    registry = Registry()
    if installed:
        install_codeindex(registry, resolver)
    definition = next((item for item in index.definitions if item.name == "target"), None)
    file = to_cited_file(definition.pointer) if definition else None
    pointer = (
        to_cited_report(report.item_ref(report.wire()["items"][0]["item_id"])) if report else file
    )
    return SimpleNamespace(**locals())


def test_default_unsupported_exact_install_and_original_crlf_excerpt():
    rig = setup(installed=False)
    assert rig.registry.resolve(rig.file, rig.context).status == "unsupported"
    install_codeindex(rig.registry, rig.resolver)
    assert rig.registry.installed_domains == {FILE_KEY, REPORT_KEY}
    result = rig.registry.resolve(rig.file, rig.context)
    assert result.status == "resolved" and result.scope == "text"
    assert result.excerpt == "def target():\r\n return 7\r\n"
    assert result.excerpt_sha256 == hashlib.sha256(result.excerpt.encode()).hexdigest()
    assert result.checked_source_sha256 == result.checked_artifact_sha256 == rig.file.source_sha256
    assert rig.file.source_revision == rig.index.snapshot.source_revision
    assert rig.access.calls == rig.generation.calls == 2
    assert result.provenance.profile_ref.profile_id == "codeindex-to-cited/1"


@pytest.mark.parametrize(
    "mutation", ["hash", "case", "line", "path_escape", "snapshot", "fixture_as_git"]
)
def test_stale_invalid_or_forged_pointer_cannot_disclose(mutation):
    rig = setup()
    wire = rig.file.model_dump()
    if mutation == "hash":
        wire["source_sha256"] = wire["evidence_artifact_sha256"] = digest("wrong bytes")
    elif mutation == "case":
        wire["locator"]["path"] = "A.py"
    elif mutation == "line":
        wire["locator"]["line_start"] = wire["locator"]["line_end"] = 999
    elif mutation == "path_escape":
        wire["locator"]["path"] = "../a.py"
    elif mutation == "snapshot":
        wire["locator"]["snapshot_id"] = wire["locator"]["inventory_sha256"] = digest(
            "wrong inventory"
        )
        wire["source_revision"] = "snapshot:fixture_inventory:" + wire["locator"]["snapshot_id"]
    else:
        wire["locator"]["source_kind"], wire["locator"]["snapshot_id"] = "git_commit", "a" * 40
        wire["source_revision"] = "snapshot:git_commit:" + "a" * 40
    result = rig.registry.resolve(wire, rig.context)
    assert result.status in {"stale", "invalid", "unsupported"} and result.excerpt is None


@pytest.mark.parametrize(
    "mutation",
    [
        "namespace",
        "access_ref",
        "generation_ref",
        "deny",
        "unknown_generation",
        "spatial",
        "revoke",
        "change_generation",
    ],
)
def test_real_policy_refs_generation_and_revocation_are_rechecked(mutation):
    rig = setup()
    context = rig.context
    if mutation == "namespace":
        context = context.model_copy(update={"namespace_id": "foreign-namespace"})
    elif mutation in {"access_ref", "generation_ref"}:
        field = "access_policy_ref" if mutation == "access_ref" else "generation_policy_ref"
        context = context.model_copy(
            update={
                field: ArtifactRef(
                    artifact_id="foreign",
                    artifact_sha256=digest("foreign policy"),
                    profile_id="foreign/1",
                )
            }
        )
    elif mutation == "deny":
        rig.access.answers = ["deny"]
    elif mutation == "unknown_generation":
        rig.generation.answers = [None]
    elif mutation == "spatial":
        context = context.model_copy(update={"required_scope": "text_and_spatial"})
    elif mutation == "revoke":
        rig.access.answers = ["allow", "deny"]
    else:
        rig.generation.answers = [rig.index.snapshot, make_index({"a.py": b"# changed\n"}).snapshot]
    result = rig.registry.resolve(rig.file, context)
    assert result.status in {"unsupported", "stale"} and result.excerpt is None


def test_report_is_actual_recorded_item_not_an_imaginary_file_quote():
    rig = setup(text="missing()")
    result = rig.registry.resolve(rig.pointer, rig.context)
    assert result.status == "resolved" and result.reason == "recorded_search_scope"
    item = json.loads(result.excerpt)
    assert item["status"] == "not_found" and item["current_pointers"] == []
    assert result.provenance.coverage.status == "complete"
    assert result.excerpt.encode() in rig.report.preimage
    assert result.checked_source_sha256 == rig.index.snapshot.inventory_sha256
    assert result.checked_artifact_sha256 == rig.report.sha256


def test_incomplete_record_resolves_only_partial_scope_and_never_semantic_upgrade():
    rig = setup({"unknown.custom": b"opaque"}, text="missing()")
    result = rig.registry.resolve(rig.pointer, rig.context)
    assert result.status == "resolved" and result.provenance.coverage.status == "partial"
    assert json.loads(result.excerpt)["status"] == "ambiguous"
    finding = Finding(
        id="original-finding",
        text="Recorded search needs human interpretation",
        verdict="partial",
        evidence=[rig.pointer],
    )
    assessment = assess_required_evidence(finding, rig.registry, rig.context)
    assert assessment.finding.verdict == "partial" and assessment.resolved_count == 1
    empty = Registry()
    assert assess_required_evidence(finding, empty, rig.context).finding.verdict == "unsupported"


@pytest.mark.parametrize("field", ["query_sha256", "coverage_sha256", "evidence_artifact_sha256"])
def test_report_common_and_locator_mismatches_have_no_fallback(field):
    rig = setup(text="missing()")
    wire = rig.pointer.model_dump()
    if field == "evidence_artifact_sha256":
        wire[field] = digest("missing report artifact")
    else:
        wire["locator"][field] = digest("bad join")
    result = rig.registry.resolve(wire, rig.context)
    assert result.status in {"stale", "missing", "invalid"} and result.excerpt is None
    wire["locator_subtype"] = "section"
    assert rig.registry.resolve(wire, rig.context).status == "unsupported"


def test_report_prior_artifact_is_required_and_duplicate_install_is_atomic():
    rig = setup({"now.py": b"# removed\n"}, text="target()", prior=make_index())
    resolver = CodeIndexCitedResolver(
        rig.index,
        namespace_id=rig.context.namespace_id,
        access=rig.access,
        generation=rig.generation,
        reports=(rig.report,),
    )
    assert resolver.resolve(rig.pointer, rig.context).status == "missing"
    registry = Registry()
    registry.register(REPORT_KEY, resolver)
    with pytest.raises(DuplicateResolverError):
        install_codeindex(registry, resolver)
    assert registry.installed_domains == {REPORT_KEY}


def test_retained_artifact_and_excerpt_bounds_do_not_silently_truncate():
    rig = setup(bounds=BridgeBounds(max_excerpt_characters=5))
    result = rig.registry.resolve(rig.file, rig.context)
    assert result.status == "unsupported" and result.reason == "excerpt_limit_exceeded"
    report = build_existence_report(rig.index, "target()")
    with pytest.raises(CodeIndexError, match="duplicate_bridge_report"):
        CodeIndexCitedResolver(
            rig.index,
            namespace_id=rig.context.namespace_id,
            access=rig.access,
            generation=rig.generation,
            reports=(report, report),
        )
    with pytest.raises(CodeIndexError, match="bridge_retained_report_limit"):
        CodeIndexCitedResolver(
            rig.index,
            namespace_id=rig.context.namespace_id,
            access=rig.access,
            generation=rig.generation,
            reports=(report,),
            bounds=BridgeBounds(max_retained_report_bytes=1),
        )


def test_retained_source_change_before_disclosure_is_rejected():
    rig = setup()
    original = rig.generation.current

    def changing(*args):
        if rig.generation.calls == 1:
            # Simulate corruption beyond the immutable reader's ordinary public API.
            object.__setattr__(rig.index.reader, "_files", {"a.py": b"changed retained bytes"})
        return original(*args)

    rig.generation.current = changing
    result = rig.registry.resolve(rig.file, rig.context)
    assert result.status == "stale" and result.excerpt is None


def test_source_view_and_character_limits_are_explicit_and_profile_bound():
    rig = setup(bounds=BridgeBounds(max_source_view_bytes=5))
    result = rig.registry.resolve(rig.file, rig.context)
    assert result.status == "unsupported" and result.reason == "source_view_limit_exceeded"
    normal = setup()
    tighter = setup(bounds=BridgeBounds(max_excerpt_characters=100))
    left = normal.registry.resolve(normal.file, normal.context)
    right = tighter.registry.resolve(tighter.file, tighter.context)
    assert left.status == right.status == "resolved" and left.excerpt == right.excerpt
    assert (
        left.provenance.profile_ref.artifact_sha256 != right.provenance.profile_ref.artifact_sha256
    )


def test_verified_move_report_needs_separate_host_mapping_authority_at_bridge():
    prior = make_index({"a.py": b"def target(): pass\n"})
    current = make_index({"b.py": b"def renamed(): pass\n"})
    old = next(item for item in prior.definitions if item.name == "target")
    new = next(item for item in current.definitions if item.name == "renamed")
    payload = {
        "mapping_schema_version": 1,
        "prior_pointer": old.pointer.wire(),
        "current_pointer": new.pointer.wire(),
        "prior_qualified_name": old.qualified_name,
        "current_qualified_name": new.qualified_name,
    }
    mapping = TrustedMapping(
        MappingAuthority(
            "synthetic-map-host", digest(payload), digest("synthetic approval fixture")
        ),
        canonical_bytes(payload),
    )
    report = build_existence_report(current, "target()", prior=prior, trusted_mappings=[mapping])
    access, generation = Access(), Generation(current.snapshot)
    context = ResolutionContext(
        namespace_id="original-namespace",
        access_policy_ref=access.reference,
        generation_policy_ref=generation.reference,
    )
    pointer = to_cited_report(report.item_ref(report.wire()["items"][0]["item_id"]))
    options = dict(
        namespace_id=context.namespace_id,
        access=access,
        generation=generation,
        reports=(report,),
        prior=prior,
    )
    assert (
        CodeIndexCitedResolver(current, **options).resolve(pointer, context).status == "unsupported"
    )
    result = CodeIndexCitedResolver(current, trusted_mappings=[mapping], **options).resolve(
        pointer, context
    )
    assert (
        result.status == "resolved"
        and json.loads(result.excerpt)["evidence_kind"] == "verified_move"
    )


def test_actual_detached_two_profile_bridge_requires_no_owner_app_or_provider(tmp_path):
    root = Path(__file__).resolve().parents[2]
    package = tmp_path / "portable/shared"
    package.mkdir(parents=True)
    (package.parent / "__init__.py").write_bytes(b"")
    (package / "__init__.py").write_bytes(b"")
    for name in ("codeindex", "cited"):
        shutil.copytree(
            root / "src/issue_triage/shared" / name,
            package / name,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    script = r"""
import sys,builtins,socket,subprocess
sys.path.insert(0,sys.argv[1])
original=builtins.__import__
denied_roots={'issue_triage','changelog_advisor','openai','typesafe','requests','httpx'}
def guarded(name,*args,**kwargs):
 if name.split('.')[0] in denied_roots:
  raise AssertionError('app/provider forbidden')
 return original(name,*args,**kwargs)
def denied(*args,**kwargs):raise AssertionError('external effect forbidden')
builtins.__import__=guarded
socket.socket=denied
subprocess.run=denied
from portable.shared.cited import ArtifactRef,Registry,ResolutionContext
from portable.shared.codeindex import inventory_from_files,InventoryReader,SnapshotRef,build_index
from portable.shared.codeindex.cited_adapter import (
 CodeIndexCitedResolver,install_codeindex,to_cited_file,to_cited_report)
from portable.shared.codeindex.report import build_existence_report
f={'a.py':b'def target(): pass\n'}
i=inventory_from_files(f)
s=SnapshotRef('detached-control','fixture_inventory',i.sha256,i.sha256,'2026-10-15T00:00:00Z',True)
x=build_index(s,InventoryReader(i,f))
class Access:
 reference=ArtifactRef(artifact_id='access',artifact_sha256='a'*64,profile_id='synthetic/1')
 def decision(self,*args):return 'allow'
class Generation:
 reference=ArtifactRef(artifact_id='generation',artifact_sha256='b'*64,profile_id='synthetic/1')
 def current(self,*args):return s
a,g=Access(),Generation()
c=ResolutionContext(namespace_id='namespace',access_policy_ref=a.reference,generation_policy_ref=g.reference)
r=build_existence_report(x,'missing()')
p=to_cited_file(x.exists('target','function'))
q=to_cited_report(r.item_ref(r.wire()['items'][0]['item_id']))
registry=Registry()
assert registry.resolve(p,c).status=='unsupported'
install_codeindex(registry,CodeIndexCitedResolver(x,namespace_id='namespace',access=a,generation=g,reports=(r,)))
assert registry.resolve(p,c).excerpt=='def target(): pass\n'
assert registry.resolve(q,c).status=='resolved'
assert not any(n.split('.')[0] in denied_roots for n in sys.modules)
print('detached-two-profiles-passed')
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "detached-two-profiles-passed"
