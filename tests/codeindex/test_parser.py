"""what_bug_this_catches: usages-as-definitions or confident existence under incomplete scope."""

import hashlib
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from issue_triage.shared.codeindex import InventoryReader, inventory_from_files
from issue_triage.shared.codeindex.canonical import CodeIndexError
from issue_triage.shared.codeindex.index import build_index, resolve_pointer
from issue_triage.shared.codeindex.models import IndexPolicy, SnapshotRef


def index_for(files, policy=None):
    inventory = inventory_from_files(files)
    reader = InventoryReader(inventory, files)
    snapshot = SnapshotRef(
        "original-controls",
        "fixture_inventory",
        inventory.sha256,
        inventory.sha256,
        "2026-10-14T23:00:00Z",
        True,
    )
    return build_index(snapshot, reader, policy or IndexPolicy())


def test_python_original_crlf_unicode_nested_decorated_definitions_and_usage_rejection():
    raw = (
        "# é original\r\nfrom elsewhere import Imaginary\r\n@decorator\r\n"
        "class Box:\r\n    def work(self):\r\n        def inner():\r\n            return 1\r\n"
        "        return inner()\r\n\r\nfn = lambda x: x\r\nImaginary()\r\n"
    ).encode()
    index = index_for({"pkg/api.py": raw, "README.md": b"Original documentation"})
    definitions = {value.qualified_name: value for value in index.definitions}
    assert "pkg.api.Box.work.inner" in definitions and "pkg.api.fn" in definitions
    assert not any(value.name == "Imaginary" for value in index.definitions)
    pointer = index.exists("pkg.api.Box.work", "function")
    assert pointer.line_start == 5 and pointer.line_end == 8
    assert pointer.source_sha256 == hashlib.sha256(raw).hexdigest()
    assert pointer.snapshot_id == index.snapshot.inventory_sha256
    assert index.exists("Box", "class").line_start == 4
    assert index.exists("Imaginary", "class") is None
    assert all(
        resolve_pointer(value.pointer, index.snapshot, index.reader) == "verified"
        for value in index.definitions
    )
    # Python literal profiles are now explicit; completeness concerns supported static syntax.
    assert "http_route" in index.coverage[1].complete_kinds


@pytest.mark.parametrize(
    "path,raw,expected",
    [
        (
            "src/api.js",
            b'import Missing from "x"; export class Box { work() {} }; const fn=()=>1;',
            {("Box", "class"), ("work", "function"), ("fn", "function")},
        ),
        (
            "src/api.ts",
            b"interface Shape { run(): void; }; "
            b"export class Box { work(): void {} }; const fn=()=>1;",
            {("Box", "class"), ("work", "function"), ("fn", "function")},
        ),
        ("src/view.tsx", b"export function View() { return <div/>; }", {("View", "function")}),
        ("src/view.jsx", b"const View = () => <div/>;", {("View", "function")}),
        (
            "src/class.js",
            b"const Box = class { work() {} };",
            {("Box", "class"), ("work", "function")},
        ),
    ],
)
def test_actual_pinned_js_ts_tsx_grammars_named_definitions(path, raw, expected):
    index = index_for({path: raw})
    actual = {
        (value.name, value.pointer.definition_kind)
        for value in index.definitions
        if value.pointer.definition_kind in {"function", "class"}
    }
    assert actual == expected
    assert index.coverage[0].state == "parsed"
    assert all(
        resolve_pointer(value.pointer, index.snapshot, index.reader) == "verified"
        for value in index.definitions
    )


@pytest.mark.parametrize(
    "path,raw,state",
    [
        ("broken.py", b"def broken(:\n pass", "parse_error"),
        ("binary.py", b"\0\xff", "binary"),
        ("encoding.py", b"\xff", "invalid_utf8"),
        ("unknown.go", b"func Missing() {}", "unsupported_language"),
        ("vendor/dep.py", b"def Missing(): pass", "excluded"),
        ("generated.py", b"# @generated\ndef Missing(): pass", "generated"),
    ],
)
def test_missing_scope_never_establishes_absence_or_uniqueness(path, raw, state):
    index = index_for({"real.py": b"def Found(): pass", path: raw})
    row = next(value for value in index.coverage if value.path == path)
    assert row.state == state and "function" not in row.complete_kinds
    assert index.exists("Found", "function") is None
    if state in {"empty", "binary", "invalid_utf8"}:
        assert not any(value.pointer.path == path for value in index.definitions)


@pytest.mark.parametrize(
    "policy,expected",
    [
        (IndexPolicy(max_file_bytes=10), "oversize"),
        (IndexPolicy(max_total_parse_bytes=10), "parse_budget"),
        (IndexPolicy(max_nodes_per_file=1), "node_limit"),
        (IndexPolicy(max_definitions=1), "definition_limit"),
    ],
)
def test_parser_and_global_budgets_record_actual_limitation(policy, expected):
    index = index_for({"bounded.py": b"def work():\n    return 1\n"}, policy)
    assert index.coverage[0].state == expected
    assert "function" not in index.coverage[0].complete_kinds
    assert len(index.definitions) <= policy.max_definitions
    assert index.coverage[0].nodes_seen <= policy.max_nodes_per_file
    assert index.exists("work", "function") is None


@pytest.mark.parametrize(
    "path,raw",
    [
        ("dynamic.py", b'exec("untrusted code is data only")\ndef work(): pass'),
        ("dynamic.js", b'eval("untrusted code is data only"); function work() {}'),
        ("dynamic.ts", b"const obj = { work() {} }; function found() {}"),
        ("dynamic.ts", b"const obj = { work: () => 1 }; function found() {}"),
    ],
)
def test_dynamic_constructs_stay_explicit_incomplete_not_executed(path, raw):
    index = index_for({path: raw})
    assert "function" not in index.coverage[0].complete_kinds
    assert any(reason.startswith("dynamic") for reason in index.coverage[0].reasons)


def test_exact_duplicate_definitions_and_pointer_identity_lines():
    index = index_for({"a.py": b"def work(): pass\n", "b.py": b"def work(): pass\n"})
    assert index.exists("work", "function") is None
    pointer = index.exists("a.work", "function")
    assert pointer.path == "a.py"
    assert resolve_pointer(pointer, index.snapshot, index.reader) == "verified"
    for changed in (
        replace(pointer, path="A.py"),
        replace(pointer, line_end=2),
        replace(pointer, source_sha256="f" * 64),
        replace(pointer, repository_id="other-repo"),
    ):
        assert resolve_pointer(changed, index.snapshot, index.reader) == "stale"


def test_fixture_inventory_and_capture_time_never_fabricate_git_authority():
    inventory = inventory_from_files({"a.py": b"pass\n"})
    for snapshot_id in ("a" * 40, "a" * 64):
        with pytest.raises(CodeIndexError, match="capture_authority_unavailable"):
            SnapshotRef(
                "repo", "git_commit", snapshot_id, inventory.sha256, "2026-10-14T23:00:00Z", True
            )
    with pytest.raises(CodeIndexError, match="fixture_identity_mismatch"):
        SnapshotRef(
            "repo", "fixture_inventory", "a" * 64, inventory.sha256, "2026-10-14T23:00:00Z", True
        )


@pytest.mark.parametrize(
    "path,raw",
    [
        ("field.js", b"class Box { work = () => 1; }"),
        ("field.ts", b"class Box { work = (): number => 1; }"),
    ],
)
def test_literal_class_field_arrow_binding_has_a_qualified_definition(path, raw):
    index = index_for({path: raw})
    assert any(
        value.name == "work" and value.pointer.definition_kind == "function"
        for value in index.definitions
    )
    assert index.exists("work", "function") is not None


@pytest.mark.parametrize("raw", [b"function f\\u006fo() {}", "function Ｆoo() {}".encode()])
def test_identifier_escapes_or_compatibility_spelling_do_not_authorize_absence(raw):
    index = index_for({"spell.js": raw})
    assert "unsupported_identifier_spelling" in index.coverage[0].reasons
    assert "function" not in index.coverage[0].complete_kinds


def test_package_module_name_and_zero_line_source_pointer_behavior():
    index = index_for({"pkg/__init__.py": b"# package\n", "empty.txt": b""})
    assert index.exists("pkg", "module").path == "pkg/__init__.py"
    assert index.exists("empty.txt", "path") is None
    assert index.exists("pkg", []) is None


def test_empty_python_package_does_not_erase_unambiguous_function_evidence():
    index = index_for({"pkg/__init__.py": b"", "pkg/api.py": b"def work(): pass\n"})
    assert index.exists("work", "function").path == "pkg/api.py"
    empty = next(row for row in index.coverage if row.path == "pkg/__init__.py")
    assert empty.state == "empty" and "function" in empty.complete_kinds
    assert not any(value.pointer.path == "pkg/__init__.py" for value in index.definitions)


def test_oversize_text_validation_preserves_utf8_across_bounded_decode_chunks():
    raw = b"#" + b"a" * 65534 + "é".encode() + b"\n"
    index = index_for({"large.py": raw}, IndexPolicy(max_file_bytes=10))
    assert index.coverage[0].state == "oversize"
    pointer = index.exists("large.py", "path")
    assert resolve_pointer(pointer, index.snapshot, index.reader) == "verified"
    invalid = index_for({"large.py": raw + b"\xc3"}, IndexPolicy(max_file_bytes=10))
    assert invalid.coverage[0].state == "invalid_utf8"
    assert invalid.exists("large.py", "path") is None


@pytest.mark.parametrize("change", [{"language": []}, {"state": 42}])
def test_invalid_coverage_types_fail_closed(change):
    row = index_for({"file.py": b"pass\n"}).coverage[0]
    with pytest.raises(CodeIndexError):
        replace(row, **change)


def test_detached_parser_closure_denies_owner_imports_network_and_repository_execution(tmp_path):
    source = Path(__file__).parents[2] / "src/issue_triage/shared/codeindex"
    shutil.copytree(source, tmp_path / "codeindex", ignore=shutil.ignore_patterns("__pycache__"))
    script = r"""
import builtins, socket, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
original = builtins.__import__
def importing(name, *a, **k):
    if name.startswith(("issue_triage", "llm_router_eval", "openai", "typesafe")):
        raise AssertionError("owner/provider import forbidden")
    return original(name, *a, **k)
builtins.__import__ = importing
def blocked(*a, **k): raise RuntimeError("network forbidden")
socket.socket = blocked
socket.create_connection = blocked
try: socket.socket()
except RuntimeError: pass
else: raise AssertionError("network positive control missing")
try: __import__("issue_triage")
except AssertionError: pass
else: raise AssertionError("owner positive control missing")
from codeindex import inventory_from_files, InventoryReader, SnapshotRef
from codeindex import build_index, resolve_pointer
raw = (b'from pathlib import Path\nPath("EXECUTION-CANARY").write_text("forbidden")\n'
    b'def work(): pass\n')
inventory = inventory_from_files({"owned.py": raw})
snapshot = SnapshotRef("original-detached", "fixture_inventory", inventory.sha256,
    inventory.sha256, "2026-10-14T23:00:00Z", True)
reader = InventoryReader(inventory, {"owned.py": raw})
index = build_index(snapshot, reader)
pointer = index.exists("work", "function")
assert pointer is not None and resolve_pointer(pointer, snapshot, reader) == "verified"
assert not Path("EXECUTION-CANARY").exists()
print("detached actual grammar and verified pointer; repository never executed")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert "detached actual grammar and verified pointer" in result.stdout
