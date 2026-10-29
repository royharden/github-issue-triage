"""what_bug_this_catches: parser-dependent raw identity or unverifiable/escaped source bytes."""

import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from issue_triage.shared.codeindex import (
    CodeIndexError,
    InventoryEntry,
    InventoryReader,
    RawInventory,
    inventory_from_files,
)
from issue_triage.shared.codeindex.canonical import canonical_bytes, decode_canonical
from issue_triage.shared.codeindex.inventory import physical_line_count


def test_raw_inventory_exact_preimage_includes_crlf_empty_binary_and_utf8_path_order():
    files = {"z.bin": b"\xff\0", "é.py": b"e", "A.py": b"a\r\n", "empty": b""}
    inventory = inventory_from_files(files)
    expected = {
        "files": [
            {
                "byte_length": len(files[path]),
                "path": path,
                "source_sha256": hashlib.sha256(files[path]).hexdigest(),
            }
            for path in ("A.py", "empty", "z.bin", "é.py")
        ],
        "inventory_schema_version": 1,
    }
    data = json.dumps(expected, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    assert inventory.canonical_bytes() == data
    assert not data.endswith(b"\n") and not data.startswith(b"\xef\xbb\xbf")
    assert inventory.sha256 == hashlib.sha256(data).hexdigest() == inventory.fixture_snapshot_id
    assert RawInventory.parse_canonical(data) == inventory
    assert inventory_from_files(dict(reversed(list(files.items())))) == inventory
    assert inventory_from_files({**files, "A.py": b"a\n"}).sha256 != inventory.sha256
    # Parsing, exclusions, policy, labels and model configuration are absent from raw identity.
    assert set(json.loads(data)) == {"files", "inventory_schema_version"}


@pytest.mark.parametrize(
    "wire",
    [
        b'{"files":[],"inventory_schema_version":true}',
        b'{"files":[],"inventory_schema_version":2}',
        b'{"files":[],"inventory_schema_version":1,"parser":"pretend"}',
        b'{"files":[],"inventory_schema_version":1,"inventory_schema_version":1}',
        b'{"files":[],"inventory_schema_version":1.0}',
        b'{"files":[],"inventory_schema_version":NaN}',
        b' {"files":[],"inventory_schema_version":1}',
        b'{"files":[],"inventory_schema_version":1}\n',
        b'\xef\xbb\xbf{"files":[],"inventory_schema_version":1}',
        b'{"files":null,"inventory_schema_version":1}',
        b'{"files":[{}],"inventory_schema_version":1}',
    ],
)
def test_closed_raw_wire_rejects_duplicate_float_unknown_or_noncanonical_bytes(wire):
    with pytest.raises(CodeIndexError):
        RawInventory.parse_canonical(wire)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/root.py",
        "../escape.py",
        "a/../x.py",
        "a//x.py",
        "a/./x.py",
        "C:/x.py",
        "a\\x.py",
        "//server/x.py",
        "a/",
        "file. ",
        "nul.py",
        "COM1",
        "a\x00b.py",
        "a\x7fb.py",
        "a/" * 64 + "x.py",
        "x" * 4097,
        "bad\ud800.py",
    ],
)
def test_inventory_path_failures_never_become_surviving_partial_inventory(path):
    with pytest.raises(CodeIndexError):
        inventory_from_files({path: b""})


@pytest.mark.parametrize(
    "files",
    [
        {"A.py": b"", "a.py": b""},
        {"é.py": b"", "e\u0301.py": b""},
        {"a": b"", "a/x.py": b""},
        {"Dir": b"", "dir/x.py": b""},
    ],
)
def test_inventory_case_unicode_and_file_directory_collisions(files):
    with pytest.raises(CodeIndexError, match="collision"):
        inventory_from_files(files)


def test_inventory_order_schema_types_and_bounds():
    entry = InventoryEntry("a", "a" * 64, 0)
    with pytest.raises(CodeIndexError, match="file_limit"):
        RawInventory((entry,) * 5001)
    with pytest.raises(CodeIndexError, match="collision"):
        RawInventory((entry, entry))
    with pytest.raises(CodeIndexError, match="path_order"):
        RawInventory((InventoryEntry("z", "a" * 64, 0), entry))
    with pytest.raises(CodeIndexError, match="raw_byte_limit"):
        RawInventory(
            (InventoryEntry("a", "a" * 64, 100 * 1024 * 1024), InventoryEntry("b", "b" * 64, 1))
        )
    for length in (True, -1, 0.0, 100 * 1024 * 1024 + 1):
        with pytest.raises(CodeIndexError):
            InventoryEntry("a", "a" * 64, length)
    with pytest.raises(CodeIndexError, match="inventory_byte_limit"):
        RawInventory(
            tuple(InventoryEntry(f"{index:04}-" + "x" * 1000, "a" * 64, 0) for index in range(2100))
        )


def test_reader_exact_immutable_whole_mapping_and_original_bytes():
    files = {"A.py": b"hello\r\n", "empty": b"", "binary": b"\0\xff"}
    inventory = inventory_from_files(files)
    reader = InventoryReader(inventory, files)
    files["A.py"] = b"changed"
    assert reader.read("A.py") == b"hello\r\n"
    assert reader.read("empty") == b"" and reader.read("binary") == b"\0\xff"
    assert "hello" not in repr(reader)
    with pytest.raises(FrozenInstanceError):
        reader.inventory = inventory
    for wrong in ({}, {**files, "extra": b""}, files, {**files, "A.py": b"hella\r\n"}):
        with pytest.raises(CodeIndexError):
            InventoryReader(inventory, wrong)
    for path in ("a.py", "../A.py", "not-listed"):
        with pytest.raises(CodeIndexError):
            reader.read(path)
    with pytest.raises(CodeIndexError):
        inventory_from_files({"mutable": bytearray(b"x")})


@pytest.mark.parametrize(
    "data,expected",
    [(b"", 0), (b"a", 1), (b"a\n", 1), (b"a\r\n", 1), (b"\n", 1), (b"a\n\n", 2), (b"a\nb", 2)],
)
def test_physical_original_lines_have_no_phantom_final_line(data, expected):
    assert physical_line_count(data) == expected


def test_bounded_scalar_canonical_codec():
    assert canonical_bytes({"null": None, "bool": False, "int": 2, "text": "é"}) == (
        '{"bool":false,"int":2,"null":null,"text":"é"}'.encode()
    )
    for value in (1.0, float("nan"), (1,), {1: "key"}, "\ud800"):
        with pytest.raises(CodeIndexError):
            canonical_bytes(value)
    cycle = []
    cycle.append(cycle)
    with pytest.raises(CodeIndexError, match="structure_limit"):
        canonical_bytes(cycle)
    with pytest.raises(CodeIndexError, match="byte_limit"):
        decode_canonical(b"123", max_bytes=2)


def test_codeindex_moves_as_stdlib_only_with_network_and_file_reader_denied(tmp_path):
    source = Path(__file__).parents[2] / "src/issue_triage/shared/codeindex"
    shutil.copytree(source, tmp_path / "codeindex", ignore=shutil.ignore_patterns("__pycache__"))
    script = """
import sys, socket
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import codeindex
def forbidden(*a, **k): raise AssertionError("resource forbidden")
socket.socket = forbidden
socket.create_connection = forbidden
Path.read_bytes = forbidden
Path.read_text = forbidden
files = {"a.py": b"def f(): pass\\r\\n"}
inventory = codeindex.inventory_from_files(files)
reader = codeindex.InventoryReader(inventory, files)
assert reader.read("a.py") == files["a.py"]
assert codeindex.extract_references("f() and a.py")[0].kind == "function"
assert not any(name.startswith(("issue_triage", "openai", "typesafe", "pydantic"))
    for name in sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
