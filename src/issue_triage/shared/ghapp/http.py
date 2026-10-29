"""Explicit synchronous HTTPS adapter; construction never opens a connection.

No proxy discovery, retries or automatic redirects. Existing bounded_read owns GET
redirect policy. Socket timeouts and elapsed checks bound cooperative operations;
stdlib DNS/header parsing is not OS-preempted. A hard wall-clock bound requires an
external owned controller. Injected factories/clocks are trusted test/config ports.
"""

import http.client
import math
import ssl
import time
from urllib.parse import urlsplit

from .auth import AppJwt, AuthError, InstallationTokenRequest, installation_token_request
from .reader import ReadError, ReadRequest, ReadResponse


class HttpError(ValueError):
    pass


def _bearer(value):
    return (
        type(value) is str
        and 1 <= len(value) <= 32768
        and all(33 <= ord(char) <= 126 for char in value)
    )


class HttpsTransport:
    def __init__(self, *, connection_factory=None, clock=time.monotonic):
        if not callable(clock) or (
            connection_factory is not None and not callable(connection_factory)
        ):
            raise HttpError("invalid_http_configuration")
        self._factory = connection_factory
        self._clock = clock

    def get(self, request, *, max_bytes, timeout_seconds):
        if type(request) is not ReadRequest:
            raise HttpError("invalid_http_request")
        try:
            # Recheck even an explicitly mutated frozen descriptor.
            checked = ReadRequest(request.url, request.headers, request.method)
        except ReadError:
            raise HttpError("invalid_http_request") from None
        return self._exchange(
            checked.url, "GET", dict(checked.headers), None, max_bytes, timeout_seconds
        )

    def post_token(self, request, *, jwt, max_bytes, timeout_seconds):
        """Only the canonical one-repository reader profile can reach a POST."""
        if type(request) is not InstallationTokenRequest or type(jwt) is not AppJwt:
            raise HttpError("invalid_token_request")
        try:
            expected = installation_token_request(
                request.installation_id,
                request.repository_id,
                role="reader",
                registered_permissions=dict(request.permissions),
            )
            if request != expected or not _bearer(jwt.token):
                raise AuthError("invalid_token_request")
        except (AuthError, TypeError, ValueError):
            raise HttpError("invalid_token_request") from None
        import json

        body = json.dumps(request.payload(), sort_keys=True, separators=(",", ":")).encode("ascii")
        return self._exchange(
            "https://api.github.com" + expected.path,
            "POST",
            {
                "accept": "application/vnd.github+json",
                "authorization": "Bearer " + jwt.token,
                "content-type": "application/json",
                "user-agent": "issue-triage-local/1",
                "x-github-api-version": "2022-11-28",
            },
            body,
            max_bytes,
            timeout_seconds,
        )

    def _exchange(self, url, method, headers, body, maximum, timeout):
        if (
            type(maximum) is not int
            or not 1 <= maximum <= 20 * 1024 * 1024
            or type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or not 0 < timeout <= 30
        ):
            raise HttpError("invalid_http_bounds")
        connection = response = None
        last = None

        def tick():
            nonlocal last
            stamp = self._clock()
            if (
                type(stamp) not in (int, float)
                or not math.isfinite(stamp)
                or (last is not None and stamp < last)
            ):
                raise HttpError("invalid_http_clock")
            last = stamp
            return stamp

        try:
            stop = tick() + timeout

            def remaining():
                value = stop - tick()
                if value <= 0:
                    raise HttpError("http_deadline")
                return value

            def arm():
                value = remaining()
                connection.timeout = value
                if connection.sock is not None:
                    connection.sock.settimeout(value)

            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or parsed.netloc
                not in (
                    "api.github.com",
                    "api.github.com:443",
                    "codeload.github.com",
                    "codeload.github.com:443",
                )
                or parsed.fragment
                or not parsed.path.startswith("/")
                or any(not 33 <= ord(char) <= 126 for char in url)
                or len(url) > 8192
                or any(
                    type(name) is not str
                    or type(value) is not str
                    or not name
                    or any(
                        not (char.isascii() and (char.isalnum() or char == "-")) for char in name
                    )
                    or any(not 32 <= ord(char) <= 126 for char in value)
                    for name, value in headers.items()
                )
                or sum(len(k) + len(v) for k, v in headers.items()) > 49152
                or (parsed.hostname != "api.github.com" and "authorization" in headers)
            ):
                raise HttpError("invalid_http_request")
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            headers["accept-encoding"] = "identity"
            context = ssl.create_default_context()
            factory = self._factory or http.client.HTTPSConnection
            connection = factory(parsed.hostname, timeout=remaining(), context=context)
            arm()
            connection.connect()
            arm()
            connection.request(method, path, body=body, headers=headers)
            arm()
            response = connection.getresponse()
            remaining()
            if type(response.status) is not int or not 100 <= response.status <= 599:
                raise HttpError("invalid_http_response")
            received = {}
            total_headers = 0
            for name, value in response.getheaders():
                if (
                    type(name) is not str
                    or type(value) is not str
                    or not name
                    or any(
                        not (char.isascii() and (char.isalnum() or char == "-")) for char in name
                    )
                    or any(ord(char) < 32 or ord(char) == 127 for char in value)
                    or name.lower() in received
                ):
                    raise HttpError("invalid_http_headers")
                total_headers += len(name) + len(value)
                if total_headers > 32768 or len(received) >= 100:
                    raise HttpError("http_header_limit")
                received[name.lower()] = value
            if received.get("content-encoding", "identity").lower() != "identity":
                raise HttpError("http_encoding_refused")
            length = received.get("content-length")
            if length is not None and (
                not length.isascii() or not length.isdecimal() or len(length) > 10
            ):
                raise HttpError("invalid_http_length")
            if length is not None and int(length) > maximum:
                raise HttpError("http_byte_limit")
            if "transfer-encoding" in received:
                if received["transfer-encoding"].lower() != "chunked" or length is not None:
                    raise HttpError("invalid_http_framing")
            chunks = []
            size = 0
            while True:
                arm()
                count = min(65536, maximum + 1 - size)
                chunk = response.read1(count)
                remaining()
                if type(chunk) is not bytes or len(chunk) > count:
                    raise HttpError("invalid_http_body")
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    raise HttpError("http_byte_limit")
                chunks.append(chunk)
            if length is not None and size != int(length):
                raise HttpError("http_length_mismatch")
            return ReadResponse(response.status, received, b"".join(chunks))
        except HttpError:
            raise
        except Exception:
            # Never expose connection/SSL exception text containing credential-bearing input.
            raise HttpError("http_transport_unavailable") from None
        finally:
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        pass
