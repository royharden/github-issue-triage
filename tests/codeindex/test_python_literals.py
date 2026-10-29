"""what_bug_this_catches: arbitrary getters, shadowed names or dynamic flags-as-declarations."""

import socket
import subprocess
from pathlib import Path

import pytest

from issue_triage.shared.codeindex.models import IndexPolicy
from issue_triage.shared.codeindex.python_literals import extract_python_literals


def literals(source, **changes):
    return extract_python_literals(source.encode(), IndexPolicy(**changes))


def test_fastapi_literal_decorators_aliases_prefixes_methods_and_original_lines():
    source = (
        "# é original\r\nfrom fastapi import FastAPI as F, APIRouter\r\n"
        "Alias = F\r\napp = Alias()\r\nrouter = APIRouter(prefix='/v1')\r\n"
        "@app.get('/items')\r\ndef items(): return []\r\n"
        "@router.api_route('/items', methods=['POST', 'TRACE'])\r\n"
        "def create(): return {}\r\n"
    )
    result = literals(source)
    assert result.complete_kinds == ("cli_flag", "config_key", "http_route")
    assert [
        (value.name, value.kind, value.line_start, value.line_end) for value in result.literals
    ] == [
        ("GET /items", "http_route", 6, 6),
        ("POST /v1/items", "http_route", 8, 8),
        ("TRACE /v1/items", "http_route", 8, 8),
    ]


def test_flask_explicit_methods_and_argparse_group_options_inside_function():
    source = (
        "from flask import Flask\nimport argparse as ap\napp = Flask(__name__)\n"
        "@app.route('/items', methods=['GET', 'POST'])\ndef items(): pass\n"
        "def main():\n p=ap.ArgumentParser()\n group=p.add_argument_group('tuning')\n"
        " group.add_argument('-v', '--verbose', action='store_true')\n"
        " p.add_argument('input_file')\n p.parse_args()\n"
    )
    result = literals(source)
    assert [value.name for value in result.literals] == [
        "GET /items",
        "POST /items",
        "-v",
        "--verbose",
    ]
    assert "cli_flag" in result.complete_kinds
    assert result.literals[-1].line_start == 9


def test_click_option_and_explicit_env_assignment_without_read_usage_as_definition():
    source = (
        "import click as c\nfrom os import environ as env\nimport os\n"
        "env['DECLARED_KEY']='VALUE_ONLY_CANARY'\n"
        "old=os.getenv('READ_ONLY_KEY')\n"
        "@c.option('--verbose', '-v', is_flag=True)\n"
        "def main(): pass\n"
    )
    result = literals(source)
    assert [value.name for value in result.literals] == ["DECLARED_KEY", "--verbose", "-v"]
    assert "VALUE_ONLY_CANARY" not in repr(result) and "READ_ONLY_KEY" not in repr(result)


@pytest.mark.parametrize(
    "tail",
    [
        "def handler(app):\n app.get('/fake')\n",
        "def handler():\n app.get('/fake')\n app={}\n",
        "app={}\napp.get('/fake')\n",
        "if condition:\n app=FastAPI()\nelse:\n app={}\napp.get('/fake')\n",
        "f=lambda app: app.get('/fake')\n",
        "items=[app.get('/fake') for app in unknown]\n",
        "with unknown as app:\n app.get('/fake')\n",
        "try:\n pass\nexcept Exception as app:\n app.get('/fake')\napp.get('/fake')\n",
        "del app\napp.get('/fake')\n",
        "app.get=unknown\napp.get('/fake')\n",
    ],
)
def test_shadowing_rebinding_unbound_locals_and_unknown_flow_cannot_mint_route(tail):
    result = literals("from fastapi import FastAPI\napp=FastAPI()\n" + tail)
    assert result.literals == ()
    assert "http_route" not in result.complete_kinds


@pytest.mark.parametrize(
    "source,kind",
    [
        (
            "from fastapi import FastAPI\napp=FastAPI()\n@app.get(dynamic)\ndef f(): pass",
            "http_route",
        ),
        (
            "from fastapi import APIRouter\nr=APIRouter(prefix=dynamic)\n"
            "@r.get('/x')\ndef f(): pass",
            "http_route",
        ),
        (
            "from flask import Flask\napp=Flask(__name__)\n@app.route('/x')\ndef f(): pass",
            "http_route",
        ),
        ("import argparse\np=argparse.ArgumentParser()\np.add_argument(*FLAGS)", "cli_flag"),
        (
            "import argparse\np=argparse.ArgumentParser(prefix_chars='+')\n"
            "p.add_argument('--fake')",
            "cli_flag",
        ),
        (
            "import argparse\np=argparse.ArgumentParser(parents=[parent])\n"
            "p.add_argument('--known')",
            "cli_flag",
        ),
        ("import click\n@click.option('--upper/--lower')\ndef main(): pass", "cli_flag"),
        ("import os\nos.environ[dynamic]='x'", "config_key"),
    ],
)
def test_dynamic_or_unsupported_registrations_remain_explicit_incomplete(source, kind):
    result = literals(source)
    assert kind not in result.complete_kinds and result.reasons


def test_same_known_type_in_both_branches_is_still_an_explicit_route_binding():
    result = literals(
        "from fastapi import FastAPI\nif condition:\n app=FastAPI()\n"
        "else:\n app=FastAPI()\n@app.get('/x')\ndef f(): pass\n"
    )
    assert [value.name for value in result.literals] == ["GET /x"]


def test_annotations_do_not_execute_registration_or_make_alias_binding_certain():
    result = literals(
        "from __future__ import annotations\nimport argparse\np=argparse.ArgumentParser()\n"
        "def f(arg: p.add_argument('--fake')): pass\n"
    )
    assert result.literals == () and "cli_flag" not in result.complete_kinds


def test_source_owned_framework_module_shadowing_never_loads_or_trusts_that_import():
    source = b"from fastapi import FastAPI\napp=FastAPI()\n@app.get('/fake')\ndef f(): pass\n"
    result = extract_python_literals(source, IndexPolicy(), blocked_modules=("fastapi",))
    assert result.literals == () and "http_route" not in result.complete_kinds


def test_literal_traversal_and_definition_budgets_close_scope():
    source = "import argparse\np=argparse.ArgumentParser()\np.add_argument('--a', '--b')\n"
    for policy in (IndexPolicy(max_nodes_per_file=1), IndexPolicy(max_definitions=1)):
        result = extract_python_literals(source.encode(), policy)
        assert result.complete_kinds == () and result.reasons
        assert result.nodes_seen <= policy.max_nodes_per_file
        assert len(result.literals) <= policy.max_definitions


def test_retained_python_is_parsed_never_imported_or_executed(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("retained source execution or resource access")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    result = literals(
        "import fastapi\nfrom pathlib import Path\nPath('EXECUTION-CANARY').write_text('bad')\n"
        "app=fastapi.FastAPI()\n@app.get('/x')\ndef f(): pass\n"
    )
    assert [value.name for value in result.literals] == ["GET /x"]


def test_unrelated_relative_import_is_not_a_registration_and_does_not_erase_known_receiver():
    result = literals(
        "from .helpers import helper\nfrom fastapi import FastAPI\napp=FastAPI()\n"
        "@app.get('/x')\ndef f(): return helper()\n"
    )
    assert [value.name for value in result.literals] == ["GET /x"]
    assert "http_route" in result.complete_kinds


def test_index_integrates_literal_pointers_and_charges_both_parser_entrypoints():
    from issue_triage.shared.codeindex import InventoryReader, inventory_from_files
    from issue_triage.shared.codeindex.index import build_index, resolve_pointer
    from issue_triage.shared.codeindex.models import SnapshotRef

    raw = (
        b"from fastapi import FastAPI\nimport argparse\napp=FastAPI()\n"
        b"@app.get('/items')\ndef items(): pass\n"
        b"p=argparse.ArgumentParser()\np.add_argument('--dry-run')\n"
    )
    files = {"app.py": raw, "settings.json": b'{"debug":true}', "README.md": b"Original docs\n"}
    inventory = inventory_from_files(files)
    snapshot = SnapshotRef(
        "original-literal-index",
        "fixture_inventory",
        inventory.sha256,
        inventory.sha256,
        "2026-10-14T23:00:00Z",
        True,
    )
    reader = InventoryReader(inventory, files)
    index = build_index(snapshot, reader)
    pointer = index.exists("GET /items", "http_route")
    assert pointer.line_start == pointer.line_end == 4
    assert resolve_pointer(pointer, snapshot, reader) == "verified"
    assert index.exists("--dry-run", "cli_flag").line_start == 7
    row = next(value for value in index.coverage if value.path == "app.py")
    assert row.parsed_bytes == 2 * len(raw)
    assert row.nodes_seen <= index.policy.max_nodes_per_file
    limited = build_index(snapshot, reader, IndexPolicy(max_total_parse_bytes=len(raw)))
    assert limited.exists("GET /items", "http_route") is None
    assert (
        "http_route"
        not in next(value for value in limited.coverage if value.path == "app.py").complete_kinds
    )
