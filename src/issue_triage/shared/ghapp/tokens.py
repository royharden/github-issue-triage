"""Explicit reader-token acquisition; no key discovery, caching or capture admission.

Only trusted host code supplies signer/transport/clock. Synthetic transport responses
are not account authentication. Missing repository/permission evidence fails closed.
"""

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime

from .auth import AuthError, app_jwt, installation_token_request
from .http import _bearer
from .reader import ReadResponse


class TokenError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReaderToken:
    installation_id: int
    repository_id: int
    expires_at_seconds: int
    token: str = field(repr=False)


def acquire_reader_token(
    installation_id,
    repository_id,
    *,
    issuer,
    signer,
    registered_permissions,
    transport,
    now_seconds,
    clock,
    timeout_seconds=30,
):
    """One attempt, no retries/redirects; total elapsed budget includes signing/parsing.

    The transport must enforce supplied bounds while reading. Clocks are explicit:
    now_seconds is UTC epoch time, clock is monotonic. No OS-preemption claim.
    """
    if (
        not callable(clock)
        or transport is None
        or type(timeout_seconds) not in (int, float)
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 30
    ):
        raise TokenError("invalid_token_input")
    try:
        start = clock()
        if type(start) not in (int, float) or not math.isfinite(start):
            raise ValueError
        request = installation_token_request(
            installation_id,
            repository_id,
            role="reader",
            registered_permissions=registered_permissions,
        )
        jwt = app_jwt(issuer, now_seconds=now_seconds, signer=signer)
        last = start

        def elapsed():
            nonlocal last
            stamp = clock()
            if (
                type(stamp) not in (int, float)
                or not math.isfinite(stamp)
                or stamp < last
                or stamp - start >= timeout_seconds
            ):
                raise ValueError
            last = stamp
            return stamp - start

        response = transport.post_token(
            request,
            jwt=jwt,
            max_bytes=1048576,
            timeout_seconds=timeout_seconds - elapsed(),
        )
        elapsed()
        if (
            type(response) is not ReadResponse
            or type(response.status) is not int
            or response.status != 201
            or type(response.body) is not bytes
            or not 1 <= len(response.body) <= 1048576
        ):
            raise ValueError

        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError
                value[key] = item
            return value

        def invalid(_):
            raise ValueError

        wire = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=invalid,
            parse_float=invalid,
        )
        if type(wire) is not dict:
            raise ValueError
        permissions = wire.get("permissions")
        repos = wire.get("repositories")
        expiry = wire.get("expires_at")
        if (
            not _bearer(wire.get("token"))
            or permissions != dict(request.permissions)
            or wire.get("repository_selection") != "selected"
            or type(repos) is not list
            or len(repos) != 1
            or type(repos[0]) is not dict
            or type(repos[0].get("id")) is not int
            or repos[0]["id"] != repository_id
            or type(expiry) is not str
            or re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", expiry) is None
        ):
            raise ValueError
        expires = int(datetime.fromisoformat(expiry[:-1] + "+00:00").timestamp())
        spent = elapsed()
        # Issuance can occur after signing/request latency. Bound lifetime at
        # acquisition completion, retaining the original elapsed budget and margin.
        current_seconds = now_seconds + spent
        if not current_seconds + 30 < expires <= current_seconds + 3600:
            raise ValueError
        return ReaderToken(installation_id, repository_id, expires, wire["token"])
    except (AuthError, ValueError, TypeError, KeyError, OverflowError, OSError):
        raise TokenError("reader_token_unavailable") from None
    except Exception:
        raise TokenError("reader_token_unavailable") from None
