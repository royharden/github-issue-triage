"""Synthetic signer/transport responses only; not account/token authentication proof."""

import json
from datetime import UTC, datetime

import pytest

from issue_triage.shared.ghapp.reader import ReadResponse
from issue_triage.shared.ghapp.tokens import TokenError, acquire_reader_token

NOW = 1792512000
PERMISSIONS = {"contents": "read", "issues": "read", "metadata": "read"}


class Signer:
    def sign(self, data, *, algorithm):
        assert algorithm == "RS256" and type(data) is bytes
        return b"invented-signature-not-rsa"


def response(**changes):
    value = {
        "token": "invented-reader-token",
        "expires_at": datetime.fromtimestamp(NOW + 3600, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "permissions": PERMISSIONS,
        "repository_selection": "selected",
        "repositories": [{"id": 2}],
    }
    value.update(changes)
    return ReadResponse(201, {}, json.dumps(value).encode())


class Transport:
    def __init__(self, value):
        self.value = value
        self.calls = []

    def post_token(self, request, **bounds):
        self.calls.append((request, bounds))
        return self.value


def acquire(transport, **changes):
    options = dict(
        issuer="synthetic-app",
        signer=Signer(),
        registered_permissions={**PERMISSIONS, "issues": "write"},
        transport=transport,
        now_seconds=NOW,
        clock=lambda: 0,
    )
    options.update(changes)
    return acquire_reader_token(1, 2, **options)


def test_one_narrowed_request_and_hidden_token():
    transport = Transport(response())
    value = acquire(transport)
    assert value.token == "invented-reader-token" and value.repository_id == 2
    assert "invented-reader-token" not in repr(value)
    assert value.installation_id == 1 and value.expires_at_seconds == NOW + 3600
    assert len(transport.calls) == 1
    request, bounds = transport.calls[0]
    assert request.payload() == {"repository_ids": [2], "permissions": PERMISSIONS}
    assert bounds["max_bytes"] == 1048576 and bounds["timeout_seconds"] == 30
    assert bounds["jwt"].token not in repr(bounds["jwt"])


@pytest.mark.parametrize("expiry_offset", [3605, 3606])
def test_delayed_issuance_uses_acquisition_time_for_maximum_lifetime(expiry_offset):
    # Catches false refusal when signing/POST takes time and the server issues
    # its one-hour token five seconds after the caller's initial UTC epoch.
    stamps = iter([0, 5, 6, 6])
    expiry = datetime.fromtimestamp(NOW + expiry_offset, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    transport = Transport(response(expires_at=expiry))
    value = acquire(transport, clock=lambda: next(stamps))
    assert value.expires_at_seconds == NOW + expiry_offset
    assert len(transport.calls) == 1
    assert transport.calls[0][1]["timeout_seconds"] == 25


def test_delayed_issuance_refuses_beyond_current_plus_one_hour():
    stamps = iter([0, 5, 6, 6])
    expiry = datetime.fromtimestamp(NOW + 3607, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    transport = Transport(response(expires_at=expiry))
    with pytest.raises(TokenError, match="reader_token_unavailable"):
        acquire(transport, clock=lambda: next(stamps))
    assert len(transport.calls) == 1


def test_delayed_issuance_retains_thirty_second_safety_margin():
    stamps = iter([0, 5, 6, 6])
    expiry = datetime.fromtimestamp(NOW + 36, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    transport = Transport(response(expires_at=expiry))
    with pytest.raises(TokenError, match="reader_token_unavailable"):
        acquire(transport, clock=lambda: next(stamps))
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"token": ""},
        {"token": "line\r\nbreak"},
        {"token": "space separated"},
        {"token": "x" * 32769},
        {"permissions": {**PERMISSIONS, "issues": "write"}},
        {"permissions": {**PERMISSIONS, "actions": "read"}},
        {"permissions": {"contents": "read", "issues": "read"}},
        {"repository_selection": "all"},
        {"repositories": None},
        {"repositories": [{"id": 3}]},
        {"repositories": [{"id": True}]},
        {"repositories": [{"id": 2}, {"id": 3}]},
        {"expires_at": "not-a-time"},
        {"expires_at": "2026-02-30T00:00:00Z"},
        {"expires_at": datetime.fromtimestamp(NOW, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")},
        {"expires_at": datetime.fromtimestamp(NOW + 3601, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")},
    ],
)
def test_scope_token_and_expiry_refusals(changes):
    transport = Transport(response(**changes))
    with pytest.raises(TokenError, match="reader_token_unavailable"):
        acquire(transport)
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b"null",
        b"{} trailing",
        b"\xff",
        b'{"token":"a","token":"b"}',
        b'{"n":NaN}',
        b'{"n":1.5}',
    ],
)
def test_strict_json_refusal(raw):
    with pytest.raises(TokenError, match="reader_token_unavailable"):
        acquire(Transport(ReadResponse(201, {}, raw)))


@pytest.mark.parametrize("status", [200, 301, 302, 307, 401, 403, 429, 500, True])
def test_status_refused_without_retry(status):
    transport = Transport(ReadResponse(status, {}, response().body))
    with pytest.raises(TokenError, match="reader_token_unavailable"):
        acquire(transport)
    assert len(transport.calls) == 1


def test_deadline_includes_signing_before_transport():
    values = iter([0, 30])
    transport = Transport(response())
    with pytest.raises(TokenError, match="reader_token_unavailable"):
        acquire(transport, clock=lambda: next(values))
    assert transport.calls == []


def test_deadline_includes_transport_and_backward_clock():
    for stamps in ([0, 0, 30], [0, 0, -1]):
        values = iter(stamps)
        transport = Transport(response())
        with pytest.raises(TokenError, match="reader_token_unavailable"):
            acquire(transport, clock=lambda values=values: next(values))
        assert len(transport.calls) == 1


def test_permission_refusal_precedes_signing_and_post():
    transport = Transport(response())
    with pytest.raises(TokenError, match="reader_token_unavailable"):
        acquire(transport, registered_permissions={})
    assert transport.calls == []


def test_signer_exception_does_not_disclose_input():
    class BadSigner:
        def sign(self, *args, **kwargs):
            raise RuntimeError("invented-private-key-fragment")

    transport = Transport(response())
    with pytest.raises(TokenError) as caught:
        acquire(transport, signer=BadSigner())
    assert str(caught.value) == "reader_token_unavailable"
    assert "invented-private-key-fragment" not in repr(caught.value)
    assert transport.calls == []
