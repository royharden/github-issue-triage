"""Pure fixed-host GET/redirect descriptors and explicit injected bounded read composition."""

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import quote, urljoin, urlsplit

HOSTS = frozenset({"api.github.com", "codeload.github.com"})


class ReadError(ValueError):
    pass


def validate_url(url: str):
    if type(url) is not str or not url or any(ord(char) < 33 for char in url):
        raise ReadError("unsafe_github_url")
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.fragment
        ):
            raise ReadError("unsafe_github_url")
    except ValueError:
        raise ReadError("unsafe_github_url") from None
    return parsed


@dataclass(frozen=True, slots=True)
class ReadRequest:
    url: str = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)
    method: str = "GET"

    def __post_init__(self):
        validate_url(self.url)
        if self.method != "GET" or not isinstance(self.headers, Mapping):
            raise ReadError("invalid_read_request")
        allowed = {"accept", "user-agent", "x-github-api-version", "authorization"}
        lowered = {}
        for name, value in self.headers.items():
            if (
                type(name) is not str
                or type(value) is not str
                or name.lower() not in allowed
                or name.lower() in lowered
                or "\r" in value
                or "\n" in value
            ):
                raise ReadError("invalid_read_header")
            lowered[name.lower()] = value
        if urlsplit(self.url).hostname != "api.github.com" and "authorization" in lowered:
            raise ReadError("cross_host_authorization")
        object.__setattr__(self, "headers", MappingProxyType(lowered))


def archive_request(owner: str, repository: str, commit_sha: str, *, token: str) -> ReadRequest:
    if type(owner) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", owner) is None:
        raise ReadError("invalid_repository_identity")
    if (
        type(repository) is not str
        or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repository) is None
        or repository in (".", "..")
    ):
        raise ReadError("invalid_repository_identity")
    if type(commit_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", commit_sha) is None:
        raise ReadError("unsupported_git_object_format")
    if type(token) is not str or not token or "\r" in token or "\n" in token:
        raise ReadError("reader_token_unavailable")
    url = (
        f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repository, safe='')}"
        f"/tarball/{commit_sha}"
    )
    return ReadRequest(
        url,
        {
            "accept": "application/vnd.github+json",
            "authorization": "Bearer " + token,
            "x-github-api-version": "2022-11-28",
            "user-agent": "issue-triage-local/1",
        },
    )


def redirected(request: ReadRequest, location: str) -> ReadRequest:
    if type(location) is not str or not location:
        raise ReadError("invalid_redirect")
    target = urljoin(request.url, location)
    parsed = validate_url(target)
    headers = dict(request.headers)
    if parsed.hostname != urlsplit(request.url).hostname:
        headers.pop("authorization", None)
    return ReadRequest(target, headers)


@dataclass(frozen=True, slots=True)
class ReadResponse:
    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)


def bounded_read(
    request: ReadRequest, *, transport, max_bytes: int, deadline_seconds: float, clock
) -> ReadResponse:
    """The injected transport must enforce each supplied byte/time bound while reading.

    No transport is constructed, no sleep/retry occurs, and no syntax check proves real Git origin.
    """
    if (
        type(max_bytes) is not int
        or not 1 <= max_bytes <= 20 * 1024 * 1024
        or type(deadline_seconds) not in (int, float)
        or not math.isfinite(deadline_seconds)
        or not 0 < deadline_seconds <= 30
        or transport is None
        or not callable(clock)
    ):
        raise ReadError("invalid_read_limits")
    last = None

    def tick():
        nonlocal last
        value = clock()
        if (
            type(value) not in (int, float)
            or not math.isfinite(value)
            or (last is not None and value < last)
        ):
            raise ReadError("invalid_read_clock")
        last = value
        return value

    stop = tick() + deadline_seconds
    current = request
    for _ in range(6):
        remaining = stop - tick()
        if remaining <= 0:
            raise ReadError("read_deadline")
        try:
            response = transport.get(current, max_bytes=max_bytes, timeout_seconds=remaining)
        except Exception:
            raise ReadError("read_transport_error") from None
        if (
            type(response) is not ReadResponse
            or type(response.status) is not int
            or type(response.body) is not bytes
            or not isinstance(response.headers, Mapping)
        ):
            raise ReadError("invalid_read_response")
        if len(response.body) > max_bytes:
            raise ReadError("read_byte_limit")
        if tick() >= stop:
            raise ReadError("read_deadline")
        if response.status in (301, 302, 303, 307, 308):
            headers = {}
            for name, value in response.headers.items():
                if (
                    type(name) is not str
                    or type(value) is not str
                    or name.lower() in headers
                    or "\r" in value
                    or "\n" in value
                ):
                    raise ReadError("invalid_read_response")
                headers[name.lower()] = value
            current = redirected(current, headers.get("location"))
            continue
        if response.status in (403, 429):
            raise ReadError("github_rate_or_permission_refusal")
        if response.status != 200:
            raise ReadError("github_read_failed")
        return response
    raise ReadError("redirect_limit")
