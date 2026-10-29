"""Invented connection controls; no sockets or credential material are used."""

import ssl

import pytest

from issue_triage.shared.ghapp.auth import AppJwt, installation_token_request
from issue_triage.shared.ghapp.http import HttpError, HttpsTransport
from issue_triage.shared.ghapp.reader import ReadRequest, bounded_read


class Clock:
    value = 0.0

    def __call__(self):
        return self.value


class Response:
    def __init__(self, body=b"ok", *, status=200, headers=()):
        self.body, self.status, self.headers = body, status, headers
        self.closed = False

    def getheaders(self):
        return self.headers

    def read1(self, count):
        result, self.body = self.body[:count], self.body[count:]
        return result

    def close(self):
        self.closed = True


class Connection:
    sock = None

    def __init__(self, response):
        self.response = response
        self.closed = False
        self.sent = []
        self.connected = False

    def connect(self):
        self.connected = True

    def request(self, method, path, *, body, headers):
        self.sent.append((method, path, body, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def transport(response, *, clock=None):
    connection = Connection(response)
    observed = []

    def factory(host, *, timeout, context):
        observed.append((host, timeout, context))
        return connection

    return HttpsTransport(connection_factory=factory, clock=clock or Clock()), connection, observed


def request():
    return ReadRequest(
        "https://api.github.com/repos/synthetic/demo", {"authorization": "Bearer fake"}
    )


def test_fixed_host_get_tls_and_close(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://synthetic.invalid:1")
    adapter, connection, observed = transport(Response(headers=(("Content-Length", "2"),)))
    response = adapter.get(request(), max_bytes=20, timeout_seconds=10)
    assert response.body == b"ok"
    host, timeout, context = observed[0]
    assert host == "api.github.com" and 0 < timeout <= 10
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert connection.sent[0][:3] == ("GET", "/repos/synthetic/demo", None)
    assert connection.sent[0][3]["accept-encoding"] == "identity"
    assert connection.closed and connection.response.closed


@pytest.mark.parametrize(
    ("body", "headers", "reason"),
    [
        (b"abcdef", (), "http_byte_limit"),
        (b"ok", (("Content-Length", "6"),), "http_byte_limit"),
        (b"ok", (("Content-Length", "3"),), "http_length_mismatch"),
        (b"ok", (("Content-Length", "-1"),), "invalid_http_length"),
        (b"ok", (("Content-Encoding", "gzip"),), "http_encoding_refused"),
        (b"ok", (("Content-Length", "2"), ("content-length", "2")), "invalid_http_headers"),
        (b"ok", (("Location", "x\r\ny"),), "invalid_http_headers"),
        (
            b"ok",
            (("Content-Length", "2"), ("Transfer-Encoding", "chunked")),
            "invalid_http_framing",
        ),
        (b"ok", (("Transfer-Encoding", "other"),), "invalid_http_framing"),
        (b"ok", (("X-Large", "x" * 32769),), "http_header_limit"),
    ],
)
def test_stream_and_header_refusals_close(body, headers, reason):
    adapter, connection, _ = transport(Response(body, headers=headers))
    with pytest.raises(HttpError, match=reason):
        adapter.get(request(), max_bytes=5, timeout_seconds=10)
    assert connection.closed and connection.response.closed


def test_read1_timeout_and_no_retry():
    clock = Clock()
    response = Response()

    def late(count):
        clock.value = 11
        return b"ok"

    response.read1 = late
    adapter, connection, observed = transport(response, clock=clock)
    with pytest.raises(HttpError, match="http_deadline"):
        adapter.get(request(), max_bytes=5, timeout_seconds=10)
    assert len(observed) == len(connection.sent) == 1
    assert connection.closed and response.closed


def test_transport_error_is_closed_and_sanitized():
    adapter, connection, observed = transport(Response())

    def broken():
        raise OSError("Bearer invented-sensitive-value")

    connection.getresponse = broken
    with pytest.raises(HttpError) as caught:
        adapter.get(request(), max_bytes=5, timeout_seconds=10)
    assert str(caught.value) == "http_transport_unavailable"
    assert "invented-sensitive-value" not in repr(caught.value)
    assert connection.closed and len(observed) == 1


def test_redirect_is_returned_to_existing_policy_and_strips_auth():
    connections = []

    def factory(host, **options):
        response = (
            Response(b"", status=302, headers=(("Location", "https://codeload.github.com/a/b"),))
            if not connections
            else Response()
        )
        connection = Connection(response)
        connections.append(connection)
        return connection

    response = bounded_read(
        request(),
        transport=HttpsTransport(connection_factory=factory, clock=Clock()),
        max_bytes=10,
        deadline_seconds=10,
        clock=Clock(),
    )
    assert response.body == b"ok" and len(connections) == 2
    assert "authorization" in connections[0].sent[0][3]
    assert "authorization" not in connections[1].sent[0][3]
    assert all(item.closed for item in connections)


def test_reader_token_post_only_and_no_redirect_follow():
    adapter, connection, observed = transport(Response(b"", status=302))
    descriptor = installation_token_request(
        1,
        2,
        role="reader",
        registered_permissions={"contents": "read", "issues": "write", "metadata": "read"},
    )
    response = adapter.post_token(
        descriptor, jwt=AppJwt("invented-jwt", 1000), max_bytes=1024, timeout_seconds=10
    )
    assert response.status == 302 and len(observed) == 1
    method, path, body, _ = connection.sent[0]
    assert (method, path) == ("POST", "/app/installations/1/access_tokens")
    assert b'"repository_ids":[2]' in body and b'"write"' not in body
    writer = installation_token_request(
        1, 2, role="apply", registered_permissions={"issues": "write", "metadata": "read"}
    )
    with pytest.raises(HttpError, match="invalid_token_request"):
        adapter.post_token(writer, jwt=AppJwt("invented", 1000), max_bytes=1024, timeout_seconds=10)
    assert len(observed) == 1


@pytest.mark.parametrize("timeout", [0, -1, 31, True, float("inf"), float("nan")])
def test_bad_bounds_never_connect(timeout):
    adapter, _, observed = transport(Response())
    with pytest.raises(HttpError, match="invalid_http_bounds"):
        adapter.get(request(), max_bytes=5, timeout_seconds=timeout)
    assert observed == []


def test_mutated_host_descriptor_never_connects():
    value = request()
    object.__setattr__(value, "url", "https://synthetic.invalid/leak")
    adapter, _, observed = transport(Response())
    with pytest.raises(HttpError, match="invalid_http_request"):
        adapter.get(value, max_bytes=5, timeout_seconds=10)
    assert observed == []


@pytest.mark.parametrize("value", ["Bearer a\x00b", "Bearer a\tb", "Bearer non-ascii-\u00e9"])
def test_control_or_non_ascii_header_never_connects(value):
    descriptor = ReadRequest("https://api.github.com/", {"authorization": value})
    adapter, _, observed = transport(Response())
    with pytest.raises(HttpError, match="invalid_http_request"):
        adapter.get(descriptor, max_bytes=5, timeout_seconds=10)
    assert observed == []


def test_explicit_tls_port_preserves_existing_url_policy():
    adapter, connection, observed = transport(Response())
    descriptor = ReadRequest("https://api.github.com:443/", {})
    assert adapter.get(descriptor, max_bytes=5, timeout_seconds=10).status == 200
    assert observed[0][0] == "api.github.com" and connection.sent[0][1] == "/"
