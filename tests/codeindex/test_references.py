"""what_bug_this_catches: prose-as-symbols, normalized offsets or repeated-query ID collision."""

from dataclasses import replace

import pytest

from issue_triage.shared.codeindex import (
    CodeIndexError,
    ExtractionPolicy,
    Query,
    extract_references,
)
from issue_triage.shared.codeindex.canonical import canonical_bytes


def test_seven_required_explicit_kinds_keep_original_unicode_byte_intervals():
    text = (
        "é🙂 src/é.py, module `pkg.client`, call client.fetch(), class Widget, "
        "--dry-run, GET /api/items, env API_TOKEN"
    )
    references = extract_references(text)
    assert [value.kind for value in references] == [
        "path",
        "module",
        "function",
        "class",
        "cli_flag",
        "http_route",
        "config_key",
    ]
    assert [value.normalized_query for value in references] == [
        "src/é.py",
        "pkg.client",
        "client.fetch",
        "Widget",
        "--dry-run",
        "GET /api/items",
        "API_TOKEN",
    ]
    raw = text.encode()
    for value in references:
        assert raw[value.original_start_byte : value.original_end_byte].decode() == value.verbatim
        assert value.validates_original(text)
        assert not value.validates_original("prefix " + text)
    assert references[0].original_start_byte > text.index("src/")
    assert references[2].qualifier_hint == "client"


def test_plain_prose_import_url_and_path_suffix_do_not_create_spurious_symbols():
    assert (
        extract_references(
            "The function fails. The module loads. This class breaks. A config file."
        )
        == []
    )
    assert extract_references("See https://example.test/src/a.py and https://x.test/b.py") == []
    values = extract_references("`src/a.py`:17 then a.py and get /items and config key `app.debug`")
    assert [(value.kind, value.normalized_query) for value in values] == [
        ("path", "src/a.py"),
        ("path", "a.py"),
        ("http_route", "GET /items"),
        ("config_key", "app.debug"),
    ]


def test_query_preimage_has_explicit_nulls_and_occurrence_ids_are_distinct():
    query = Query("function", "fetch")
    assert canonical_bytes(query.wire()) == (
        b'{"kind":"function","language_hint":null,"normalized_query":"fetch",'
        b'"path_hint":null,"qualifier_hint":null}'
    )
    values = extract_references("fetch() then fetch()")
    assert len(values) == 2 and values[0].query.sha256 == values[1].query.sha256 == query.sha256
    assert values[0].id != values[1].id
    assert values == extract_references("fetch() then fetch()")
    assert extract_references("Fetch()")[0].query.sha256 != query.sha256
    assert replace(values[0], id="0" * 64).validates_original("fetch() then fetch()") is False


def test_route_prose_punctuation_is_syntax_but_quoted_literal_is_preserved():
    text = "GET /api/x, then `GET /api/x,` and get /api/v1.0."
    references = extract_references(text)
    assert [value.normalized_query for value in references] == [
        "GET /api/x",
        "GET /api/x,",
        "GET /api/v1.0",
    ]
    assert all(value.validates_original(text) for value in references)


def test_trace_and_short_alphabetic_flags_are_explicit_but_negative_numbers_are_not():
    values = extract_references("TRACE /api/items and -v, --verbose, minus -1 or -200")
    assert [(value.kind, value.normalized_query) for value in values] == [
        ("http_route", "TRACE /api/items"),
        ("cli_flag", "-v"),
        ("cli_flag", "--verbose"),
    ]


def test_reference_limits_hold_whole_input_and_never_trim_to_authorized_prefix():
    with pytest.raises(CodeIndexError, match="count_limit"):
        extract_references(" ".join("f()" for _ in range(129)))
    assert len(extract_references(" ".join("f()" for _ in range(128)))) == 128
    with pytest.raises(CodeIndexError, match="input_limit"):
        extract_references("é", ExtractionPolicy(max_input_bytes=1))
    with pytest.raises(CodeIndexError, match="invalid_utf8"):
        extract_references("bad\ud800")
    for limit in (0, 129, True):
        with pytest.raises(CodeIndexError):
            ExtractionPolicy(max_references=limit)


@pytest.mark.parametrize(
    "query",
    [
        {"kind": "guess", "normalized_query": "thing"},
        {"kind": "path", "normalized_query": "../bad.py"},
        {"kind": "function", "normalized_query": ""},
        {"kind": "function", "normalized_query": "a", "language_hint": "unknown"},
        {"kind": "function", "normalized_query": "a", "path_hint": "/root"},
    ],
)
def test_closed_query_fields(query):
    with pytest.raises(CodeIndexError):
        Query(**query)
