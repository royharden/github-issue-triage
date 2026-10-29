"""what_bug_this_catches: config values-as-keys, phantom lines or partial parse-as-absence."""

import socket
import subprocess
from pathlib import Path

import pytest

from issue_triage.shared.codeindex import InventoryReader, inventory_from_files
from issue_triage.shared.codeindex.config_literals import extract_config_literals
from issue_triage.shared.codeindex.index import build_index, resolve_pointer
from issue_triage.shared.codeindex.models import IndexPolicy, SnapshotRef


def indexed(files, policy=None):
    inventory = inventory_from_files(files)
    snapshot = SnapshotRef(
        "original-config-controls",
        "fixture_inventory",
        inventory.sha256,
        inventory.sha256,
        "2026-10-14T23:00:00Z",
        True,
    )
    return build_index(snapshot, InventoryReader(inventory, files), policy or IndexPolicy())


def test_json_keys_nested_arrays_escapes_crlf_and_values_not_definitions():
    raw = (
        b'{\r\n "app": {\r\n  "debug": true,\r\n  "caf\\u00e9": "VALUE_ONLY_CANARY"\r\n },\r\n'
        b' "servers": [{"port": 3}],\r\n "empty": {}\r\n}\r\n'
    )
    result = extract_config_literals(raw, "settings.json", IndexPolicy())
    assert result.complete
    assert [(value.name, value.line_start) for value in result.literals] == [
        ("app", 2),
        ("app.debug", 3),
        ("app.café", 4),
        ("servers", 6),
        ("servers[0].port", 6),
        ("empty", 7),
    ]
    assert "VALUE_ONLY_CANARY" not in repr(result)
    index = indexed({"settings.json": raw})
    pointer = index.exists("app.café", "config_key")
    assert pointer.line_start == pointer.line_end == 4
    assert resolve_pointer(pointer, index.snapshot, index.reader) == "verified"


def test_toml_tables_dotted_implicit_parents_and_physical_lf_only():
    raw = 'text="value\u2028not_a_key=3"\r\n[app]\r\ndebug=true\r\nlimits.max=4\r\n'.encode()
    result = extract_config_literals(raw, "settings.toml", IndexPolicy())
    assert result.complete
    assert [(value.name, value.line_start) for value in result.literals] == [
        ("text", 1),
        ("app", 2),
        ("app.debug", 3),
        ("app.limits", 4),
        ("app.limits.max", 4),
    ]
    index = indexed({"settings.toml": raw})
    assert index.exists("app.debug", "config_key").line_start == 3
    assert all(
        resolve_pointer(value.pointer, index.snapshot, index.reader) == "verified"
        for value in index.definitions
    )


def test_env_named_declarations_comments_export_values_and_duplicate_ambiguity():
    raw = b'# comment\r\nexport API_TOKEN = "VALUE_ONLY_CANARY"\r\nNEXT=3\r\n'
    index = indexed({".env.example": raw})
    assert index.exists("API_TOKEN", "config_key").line_start == 2
    assert index.exists("NEXT", "config_key").line_start == 3
    assert index.coverage[0].state == "config_parsed"
    duplicate = indexed({"settings.env": b"API_TOKEN=x\nAPI_TOKEN=y\n"})
    assert duplicate.exists("API_TOKEN", "config_key") is None
    assert len([value for value in duplicate.definitions if value.name == "API_TOKEN"]) == 2


@pytest.mark.parametrize(
    "path,raw,reason",
    [
        ("bad.json", b'{"a":1,"a":2}', "duplicate_config_key"),
        ("bad.json", b'{"a":1,}', "config_parse_error"),
        ("bad.json", b'{"a":NaN}', "invalid_config_json"),
        ("bad.json", b"[1,2]", "unsupported_config_shape"),
        ("bad.json", b'{"":1}', "unsupported_config_key"),
        ("bad.toml", b"a=1\na=2", "config_parse_error"),
        ("bad.toml", b'a="""start\nFAKE=3\nend"""', "unsupported_multiline_toml"),
        ("bad.toml", b'"quoted key"=1', "unsupported_toml_key"),
        ("bad.toml", b"obj={inner=3}", "unsupported_toml_inline_table"),
        ("bad.toml", b"[[servers]]\nport=3", "unsupported_toml_table"),
        ("settings.env", b'TEXT="open\nFAKE_KEY=3\nclose"', "unsupported_multiline_env"),
        ("settings.env", b"${PREFIX}_KEY=3", "unsupported_env_declaration"),
    ],
)
def test_unsupported_or_malformed_configs_never_establish_complete_negative_scope(
    path, raw, reason
):
    result = extract_config_literals(raw, path, IndexPolicy())
    assert not result.complete and reason in result.reasons
    index = indexed({path: raw})
    assert "config_key" not in index.coverage[0].complete_kinds
    assert index.exists("FAKE_KEY", "config_key") is None
    assert index.exists("not_present", "config_key") is None


@pytest.mark.parametrize(
    "policy",
    [
        IndexPolicy(max_file_bytes=5),
        IndexPolicy(max_total_parse_bytes=5),
        IndexPolicy(max_nodes_per_file=1),
        IndexPolicy(max_definitions=2),
    ],
)
def test_config_caps_bind_whole_source_and_do_not_change_raw_inventory(policy):
    files = {"settings.json": b'{"a":{"b":1},"c":2}'}
    limited = indexed(files, policy)
    complete = indexed(files)
    assert limited.snapshot.inventory_sha256 == complete.snapshot.inventory_sha256
    assert "config_key" not in limited.coverage[0].complete_kinds
    assert limited.exists("a", "config_key") is None
    assert len(limited.definitions) <= policy.max_definitions
    assert limited.coverage[0].nodes_seen <= policy.max_nodes_per_file


def test_config_values_are_never_executed_or_returned_as_runtime_metadata(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Config parser attempted an external effect")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    raw = b'API_TOKEN="$(curl VALUE_ONLY_CANARY)"\n'
    result = extract_config_literals(raw, ".env", IndexPolicy())
    assert result.complete and [value.name for value in result.literals] == ["API_TOKEN"]
    assert "VALUE_ONLY_CANARY" not in repr(result)


def test_empty_env_and_toml_have_no_lines_but_complete_named_key_scope():
    for path in (".env", "settings.toml"):
        index = indexed({path: b""})
        assert "config_key" in index.coverage[0].complete_kinds
        assert index.definitions == ()


def test_nul_encoding_and_json_nested_structure_limit_remain_explicit():
    invalid = extract_config_literals(b"KEY=abc\0tail", ".env", IndexPolicy())
    assert not invalid.complete and invalid.literals == ()
    nested = b'{"a":' * 66 + b"{}" + b"}" * 66
    result = extract_config_literals(nested, "deep.json", IndexPolicy())
    assert not result.complete and "config_structure_limit" in result.reasons


def test_unsupported_empty_parent_cannot_promote_nested_key_to_root():
    result = extract_config_literals(
        b'{"":{"wrong_root":1},"good":2}', "settings.json", IndexPolicy()
    )
    assert not result.complete
    assert [value.name for value in result.literals] == ["good"]
