"""what_bug_this_catches: partial, ambiguous or redirected labels become an apply allowlist."""

import json

import pytest

from issue_triage.contracts.domain import IssueKey
from issue_triage.ingest.labels import (
    LabelError,
    LabelInventory,
    LabelReadBounds,
    labels_request,
    read_label_inventory,
)
from issue_triage.shared.ghapp.reader import ReadResponse


def key():
    return IssueKey(
        installation_id=12,
        repository_id=7,
        issue_number=9,
        owner="synthetic-owner",
        repository="original-label-controls",
    )


def row(number=1, name="kind: bug", **extra):
    return {"id": number, "name": name, "archived_at": None} | extra


def response(values, headers=None):
    return ReadResponse(200, headers or {}, json.dumps(values, ensure_ascii=False).encode())


class Transport:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def get(self, request, **bounds):
        self.calls.append((request, bounds))
        return self.replies.pop(0)


def read(replies, **limits):
    transport = Transport(replies)
    inventory = read_label_inventory(
        key(),
        token="synthetic-unit-token",
        transport=transport,
        clock=lambda: 0.0,
        captured_at="2026-10-15T00:00:00Z",
        bounds=LabelReadBounds(**limits),
    )
    return inventory, transport


def test_fixed_get_and_no_response_urls_or_tokens_in_repr():
    inventory, transport = read([response([row(url="https://invalid.example/no-fetch")])])
    assert (
        inventory.labels[0].name == "kind: bug" and inventory.labels[0].archival_state == "active"
    )
    request, bounds = transport.calls[0]
    assert request.method == "GET" and request.url.startswith("https://api.github.com/repos/")
    assert request.url.endswith("/labels?per_page=100&page=1")
    assert "synthetic-unit-token" not in repr(request)
    assert bounds == {"max_bytes": 262144, "timeout_seconds": 30.0}
    assert inventory.observation == "injected_read_port"
    assert LabelInventory.parse_json(inventory.canonical_bytes()) == inventory


def test_full_page_requires_terminal_page_and_link_only_selects_numeric_next_page():
    values = [row(number, f"label-{number}") for number in range(1, 101)]
    inventory, transport = read([response(values), response([])])
    assert len(inventory.labels) == 100 and len(transport.calls) == 2
    inventory, transport = read(
        [
            response([row()], {"Link": '<https://evil.invalid>; rel = "next alternate"'}),
            response([]),
        ]
    )
    assert len(inventory.labels) == 1 and transport.calls[-1][0].url.endswith("page=2")
    assert all("evil.invalid" not in request.url for request, _ in transport.calls)


def test_semantic_label_set_hash_excludes_capture_time_and_page_encoding_order():
    first, _ = read([response([row(2, "priority: normal"), row()])])
    second = read_label_inventory(
        key(),
        token="synthetic-unit-token",
        clock=lambda: 0.0,
        captured_at="2026-10-15T00:00:01Z",
        transport=Transport([response([row(), row(2, "priority: normal")])]),
    )
    assert first.label_set_sha256 == second.label_set_sha256 and first.sha256 != second.sha256


def test_archive_and_unknown_status_are_retained_separately():
    missing = row(3, "legacy")
    del missing["archived_at"]
    inventory, _ = read(
        [response([row(), row(2, "old", archived_at="2026-10-14T00:00:00Z"), missing])]
    )
    assert [label.archival_state for label in inventory.labels] == ["active", "archived", "unknown"]


@pytest.mark.parametrize(
    "values",
    [
        [row(), row(1, "other")],
        [row(), row(2, "KIND: BUG")],
        [row(1, "é"), row(2, "e\u0301")],
        [row(id=True)],
        [row(name="bad\nname")],
        [row(name="x" * 257)],
        [row(archived_at="not-time")],
        {"not": "an array"},
    ],
)
def test_malformed_or_ambiguous_inventory_is_rejected_as_a_whole(values):
    with pytest.raises(LabelError):
        read([response(values)])


@pytest.mark.parametrize(
    "raw", [b'[{"id":1,"id":2,"name":"x"}]', b'[{"id":NaN}]', b"\xff", b'[{"id":1.5}]']
)
def test_duplicate_keys_nonfinite_numbers_and_invalid_utf8_fail(raw):
    with pytest.raises(LabelError):
        read([ReadResponse(200, {}, raw)])


@pytest.mark.parametrize("limit", ["pages", "labels", "page_bytes", "total_bytes"])
def test_resource_bounds_never_return_a_prefix_allowlist(limit):
    values = [row(number, f"label-{number}") for number in range(1, 101)]
    replies, bounds = [response(values), response([])], {}
    if limit == "pages":
        bounds["max_pages"] = 1
    elif limit == "labels":
        bounds["max_labels"] = 2
    elif limit == "page_bytes":
        bounds["max_page_bytes"] = 10
    else:
        bounds["max_total_bytes"] = 10
    with pytest.raises(LabelError):
        read(replies, **bounds)


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.invalid/labels",
        "https://codeload.github.com/a",
        "https://api.github.com/repos/other/repo/labels",
    ],
)
def test_any_label_redirect_stops_before_a_second_transport_call(target):
    transport = Transport([ReadResponse(302, {"Location": target}, b"")])
    with pytest.raises(LabelError, match="labels_read_unavailable"):
        read_label_inventory(
            key(),
            token="synthetic-unit-token",
            transport=transport,
            clock=lambda: 0.0,
            captured_at="2026-10-15T00:00:00Z",
        )
    assert len(transport.calls) == 1


def test_deadline_clock_and_bad_identity_or_header_do_not_get_permission():
    transport = Transport([response([row()])])
    clock = iter([0.0, 0.0, 0.0, 0.0, 29.9, 30.0])
    with pytest.raises(LabelError, match="label_deadline"):
        read_label_inventory(
            key(),
            token="synthetic-unit-token",
            transport=transport,
            clock=lambda: next(clock),
            captured_at="2026-10-15T00:00:00Z",
        )
    for token in ("bad\r\nheader", "bad token", "bad\0token"):
        with pytest.raises(LabelError, match="reader_token_unavailable"):
            labels_request(key(), 1, token=token)
    with pytest.raises(LabelError, match="invalid_repository_identity"):
        labels_request(
            key().model_copy(update={"repository": "../bad"}), 1, token="synthetic-unit-token"
        )


def test_complete_thousand_label_inventory_includes_the_empty_terminal_page():
    replies = [
        response([row(number, f"label-{number}") for number in range(start, start + 100)])
        for start in range(1, 1001, 100)
    ] + [response([])]
    inventory, transport = read(replies)
    assert len(inventory.labels) == 1000 and len(transport.calls) == 11


def test_total_byte_limit_is_passed_to_transport_before_reading():
    transport = Transport([response([row()])])
    with pytest.raises(LabelError):
        read_label_inventory(
            key(),
            token="synthetic-unit-token",
            transport=transport,
            clock=lambda: 0.0,
            captured_at="2026-10-15T00:00:00Z",
            bounds=LabelReadBounds(max_total_bytes=10),
        )
    assert transport.calls[0][1]["max_bytes"] == 10
