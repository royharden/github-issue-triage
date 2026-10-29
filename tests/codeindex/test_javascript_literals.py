"""what_bug_this_catches: JS use-sites/dynamic/shadowed methods promoted to declarations."""

import socket
import subprocess

import pytest

from issue_triage.shared.codeindex.javascript_literals import extract_javascript_literals
from issue_triage.shared.codeindex.models import IndexPolicy


def literals(source, language="javascript", **limits):
    return extract_javascript_literals(source.encode(), language, IndexPolicy(**limits))


@pytest.mark.parametrize("language", ["javascript", "typescript", "tsx"])
def test_esm_express_router_aliases_methods_and_crlf_lines(language):
    result = literals(
        "// é original\r\nimport express, {Router as R} from 'express';\r\n"
        "const app=express();\r\nconst router=R();\r\nconst alias=app;\r\n"
        "alias.get('/items', handler);\r\nrouter.post('/items', handler);\r\n"
        "app.trace('/probe', handler);\r\nfunction handler(req,res) {}\r\n",
        language,
    )
    assert result.complete_kinds == ("cli_flag", "config_key", "http_route")
    assert [(item.name, item.line_start) for item in result.literals] == [
        ("GET /items", 6),
        ("POST /items", 7),
        ("TRACE /probe", 8),
    ]


def test_cjs_constructor_and_router_factory():
    result = literals(
        "const express=require('express'); const app=express();"
        "const r=express.Router(); app.get('/one', handler); r.put('/two', handler);"
    )
    assert [item.name for item in result.literals] == ["GET /one", "PUT /two"]
    assert "http_route" in result.complete_kinds


def test_commander_aliases_and_env_writes_never_return_values_or_reads():
    result = literals(
        "import {Command as C,program} from 'commander';"
        "const p=new C(); const alias=p;"
        "alias.option('-v, --verbose'); program.requiredOption('-n|--name <text>');"
        "const read=process.env.READ_ONLY; process.env.SETTING='VALUE_CANARY';"
        "process.env['OTHER_KEY']='SECOND_VALUE';"
    )
    assert [item.name for item in result.literals] == [
        "-v",
        "--verbose",
        "-n",
        "--name",
        "SETTING",
        "OTHER_KEY",
    ]
    assert "VALUE_CANARY" not in repr(result) and "READ_ONLY" not in repr(result)


@pytest.mark.parametrize(
    "source",
    [
        "import express from 'express'; const app=express(); app={}; app.get('/fake', h);",
        "import express from 'express'; const app=express(); function f(app){app.get('/fake',h);}",
        "import express from 'express'; const app=express();"
        " function f(){const app={};app.get('/fake',h);}",
        "import express from 'express'; const app=express();"
        " const alias=app; alias.get=fake;app.get('/fake',h);",
        "import express from 'express'; app.get('/fake',h); const app=express();",
        "import express from 'express'; const app=express(); const f=app=>app.get('/fake',h);",
        "import express from 'express'; const app=express();"
        " try{}catch({app}){app.get('/fake',h);}",
        "import express from 'express'; const app=express();"
        " for(app of values){app.get('/fake',h);}",
        "import express from 'express'; const app=express(); delete app.get; app.get('/fake',h);",
        "import express from 'express'; const app=express(); patch(app); app.get('/fake',h);",
        "import express from 'express'; if(flag){const app=express();app.get('/fake',h);}",
        "const express=unknown; const app=express(); app.get('/fake',h);",
        "import express from 'express'; const app=express(); ({app}=unknown);app.get('/fake',h);",
    ],
)
def test_shadowing_reassignment_mutation_cannot_establish_exact_route(source):
    result = literals(source)
    assert "http_route" not in result.complete_kinds
    assert not any(item.name == "GET /fake" for item in result.literals)


@pytest.mark.parametrize(
    "tail",
    [
        "app.get(dynamic,h);",
        "app.get(`/items/${id}`,h);",
        "app.get(/items/,h);",
        "app.get('/items');",
        "app.route('/items').get(h);",
        "app.use('/prefix', router);",
        "app.all('/items',h);",
        "app.get('/escaped\\u0020path',h);",
        "app['get']('/items',h);",
        "const method=app.get; method('/items',h);",
        "app.get.bind(app)('/items',h);",
    ],
)
def test_dynamic_or_unimplemented_routes_keep_coverage_incomplete(tail):
    result = literals("import express from 'express'; const app=express();" + tail)
    assert "http_route" not in result.complete_kinds and not result.literals


@pytest.mark.parametrize(
    "source,kind",
    [
        ("import p from 'fastify';", "http_route"),
        ("import y from 'yargs';", "cli_flag"),
        ("const p=require(dynamic);", "http_route"),
        ("const env=process.env; env.KEY='x';", "config_key"),
        ("process.env[key]='x';", "config_key"),
        ("process.env={KEY:'x'};", "config_key"),
        ("import {program} from 'commander'; program.option(flags);", "cli_flag"),
        ("import {program} from 'commander'; program.option('-vv');", "cli_flag"),
    ],
)
def test_unsupported_forms_cannot_prove_absence(source, kind):
    assert kind not in literals(source).complete_kinds


def test_env_global_and_import_shadowing_do_not_create_declarations():
    for source in (
        "const process={env:{}}; process.env.FAKE='x';",
        "function f(process){process.env.FAKE='x';}",
        "import process from 'node:process'; process={env:{}};process.env.FAKE='x';",
    ):
        result = literals(source)
        assert not result.literals and "config_key" not in result.complete_kinds
    assert [
        item.name
        for item in literals("import proc from 'node:process'; proc.env.KEY='x';").literals
    ] == ["KEY"]


def test_usage_comment_strings_and_unrelated_getters_never_become_declarations():
    result = literals("// app.get('/fake',h)\nconst s=\"--fake\"; map.get('/value');")
    assert not result.literals and "http_route" not in result.complete_kinds


def test_limits_errors_and_empty_source_are_explicit():
    result = literals(
        "import express from 'express'; const app=express(); app.get('/x',h);", max_nodes_per_file=3
    )
    assert not result.literals and not result.complete_kinds
    assert result.reasons == ("literal_node_limit",)
    result = literals(
        "import {program} from 'commander'; program.option('-v, --verbose');", max_definitions=1
    )
    assert len(result.literals) == 1 and not result.complete_kinds
    assert not literals("const app = ;").complete_kinds
    assert literals("").complete_kinds == ("cli_flag", "config_key", "http_route")


@pytest.mark.parametrize("source", ["eval(code);", "new Function(code);", "import(dynamic);"])
def test_dynamic_code_prevents_confident_literal_absence(source):
    assert not literals(source).complete_kinds


def test_captured_javascript_cannot_start_process_or_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("captured source execution forbidden")

    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket, "socket", denied)
    result = literals("require('child_process').execSync('NEVER_RUN'); fetch('https://invalid');")
    assert not result.literals


def test_index_literals_share_budgets_and_current_physical_pointers():
    from issue_triage.shared.codeindex.index import build_index, resolve_pointer
    from issue_triage.shared.codeindex.inventory import InventoryReader, inventory_from_files
    from issue_triage.shared.codeindex.models import SnapshotRef

    files = {
        "app.ts": b"import express from 'express';\r\nconst app=express();\r\napp.get('/x',h);\r\n"
    }
    inventory = inventory_from_files(files)
    reader = InventoryReader(inventory, files)
    snapshot = SnapshotRef(
        "original-js-controls",
        "fixture_inventory",
        inventory.sha256,
        inventory.sha256,
        "2026-10-15T00:00:00Z",
        True,
    )
    index = build_index(snapshot, reader)
    pointer = index.exists("GET /x", "http_route")
    assert pointer is not None and pointer.line_start == 3
    assert resolve_pointer(pointer, snapshot, reader) == "verified"
    assert index.coverage[0].parsed_bytes == len(files["app.ts"]) * 2
    limited = build_index(snapshot, reader, IndexPolicy(max_total_parse_bytes=len(files["app.ts"])))
    assert limited.exists("GET /x", "http_route") is None
    assert limited.coverage[0].state == "parse_budget"
