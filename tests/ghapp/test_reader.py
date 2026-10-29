"""Injected read-port probes; no real HTTP request, token or Git capture claim."""

import pytest

from issue_triage.shared.ghapp.reader import (
    ReadError,
    ReadRequest,
    ReadResponse,
    archive_request,
    bounded_read,
    redirected,
    validate_url,
)


def request():
    return archive_request("synthetic", "demo", "a" * 40, token="SYNTHETIC_READER_CANARY")


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com/x",
        "https://evil.example/x",
        "https://api.github.com.evil.example/x",
        "https://api.github.com:444/x",
        "https://user:secret@api.github.com/x",
        "https://api.github.com/x#fragment",
        "https://api.github.com/x\r\nheader",
        "https://127.0.0.1/x",
    ],
)
def test_fixed_https_hosts_only(url):
    with pytest.raises(ReadError, match="unsafe_github_url"):
        validate_url(url)


@pytest.mark.parametrize("userinfo", ["", ":", "user:", ":secret"])
@pytest.mark.parametrize("host", ["api.github.com", "codeload.github.com"])
@pytest.mark.parametrize("boundary", ["url", "descriptor"])
def test_any_userinfo_presence_is_rejected(userinfo, host, boundary):
    """Present empty userinfo must not pass the no-credentials URL boundary."""
    url = f"https://{userinfo}@{host}/x"
    with pytest.raises(ReadError, match="unsafe_github_url"):
        if boundary == "url":
            validate_url(url)
        else:
            ReadRequest(url, {})


def test_fixed_archive_path_and_no_issue_url_selection_or_secret_repr():
    value = request()
    assert value.url == "https://api.github.com/repos/synthetic/demo/tarball/" + "a" * 40
    assert value.method == "GET" and "CANARY" not in repr(value)
    for owner, repository, sha in [
        ("https://evil.example", "demo", "a" * 40),
        ("synthetic", "../escape", "a" * 40),
        ("synthetic", "demo", "a" * 64),
    ]:
        with pytest.raises(ReadError):
            archive_request(owner, repository, sha, token="synthetic")
    with pytest.raises(ReadError, match="invalid_read_request"):
        ReadRequest(value.url, value.headers, method="POST")


def test_cross_host_authorization_removed_and_never_restored():
    start = request()
    same = redirected(start, "/next")
    assert "authorization" in same.headers
    cross = redirected(
        start, "https://codeload.github.com/synthetic/demo/legacy.tar.gz/" + "a" * 40
    )
    assert "authorization" not in cross.headers
    back = redirected(cross, "https://api.github.com/next")
    assert "authorization" not in back.headers
    with pytest.raises(ReadError, match="cross_host_authorization"):
        ReadRequest("https://codeload.github.com/x", {"authorization": "synthetic"})


class Transport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, value, **limits):
        self.calls.append((value, limits))
        return self.responses.pop(0)


@pytest.mark.parametrize("userinfo", ["", ":"])
@pytest.mark.parametrize("host", ["api.github.com", "codeload.github.com"])
@pytest.mark.parametrize("prefix", ["https:", ""])
def test_empty_userinfo_redirect_is_rejected_before_second_read(userinfo, host, prefix):
    """Absolute and scheme-relative redirects cannot bypass the direct URL guard."""
    location = f"{prefix}//{userinfo}@{host}/next"
    port = Transport(ReadResponse(302, {"Location": location}, b""))
    with pytest.raises(ReadError, match="unsafe_github_url"):
        bounded_read(request(), transport=port, max_bytes=10, deadline_seconds=10, clock=lambda: 0)
    assert len(port.calls) == 1


def test_redirect_port_keeps_one_total_deadline_and_same_byte_bound():
    port = Transport(
        ReadResponse(302, {"Location": "https://codeload.github.com/x"}, b""),
        ReadResponse(200, {}, b"tiny archive"),
    )
    times = iter([0, 1, 2, 3, 4])
    result = bounded_read(
        request(), transport=port, max_bytes=100, deadline_seconds=10, clock=lambda: next(times)
    )
    assert result.body == b"tiny archive" and len(port.calls) == 2
    assert port.calls[0][1] == {"max_bytes": 100, "timeout_seconds": 9}
    assert port.calls[1][1] == {"max_bytes": 100, "timeout_seconds": 7}
    assert "authorization" not in port.calls[1][0].headers


@pytest.mark.parametrize(
    "response,code",
    [
        (ReadResponse(429, {}, b""), "github_rate_or_permission_refusal"),
        (ReadResponse(500, {}, b""), "github_read_failed"),
        (ReadResponse(200, {}, b"x" * 11), "read_byte_limit"),
        (ReadResponse(302, {"Location": "https://evil.example"}, b""), "unsafe_github_url"),
    ],
)
def test_refusal_failure_overflow_and_hostile_redirect_hold(response, code):
    port = Transport(response)
    with pytest.raises(ReadError, match=code):
        bounded_read(request(), transport=port, max_bytes=10, deadline_seconds=10, clock=lambda: 0)
    assert len(port.calls) == 1


def test_deadline_backward_clock_and_redirect_loop():
    times = iter([0, 0, 11])
    with pytest.raises(ReadError, match="read_deadline"):
        bounded_read(
            request(),
            transport=Transport(ReadResponse(200, {}, b"")),
            max_bytes=10,
            deadline_seconds=10,
            clock=lambda: next(times),
        )
    times = iter([5, 4])
    port = Transport()
    with pytest.raises(ReadError, match="invalid_read_clock"):
        bounded_read(
            request(), transport=port, max_bytes=10, deadline_seconds=10, clock=lambda: next(times)
        )
    assert port.calls == []
    port = Transport(*[ReadResponse(302, {"location": "/again"}, b"") for _ in range(6)])
    with pytest.raises(ReadError, match="redirect_limit"):
        bounded_read(request(), transport=port, max_bytes=10, deadline_seconds=10, clock=lambda: 0)
    assert len(port.calls) == 6
