"""Transport-independent local review boundary; never reads credentials or authenticates a human."""

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..suggest.envelope import FIELDS


class BoundaryError(ValueError):
    """Closed public refusal codes, never raw credential, cookie or decision values."""


@dataclass(frozen=True, slots=True)
class BrowserMutation:
    """An adapter must supply actual headers/method, reject duplicates and bound input bytes.

    This is not an HTTP parser, cookie policy, listener or claim of browser protection.
    """

    method: str
    origin: str | None
    session: str | None = field(default=None, repr=False)
    csrf: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class OperatorSession:
    value: str = field(repr=False)
    expires_at: int


def _time(value):
    if type(value) is not int or not 0 <= value <= 9007199254737391:
        raise BoundaryError("clock_unavailable")
    return value


def _target(issue_key, revision, field_name, prior):
    if (
        type(issue_key) is not str
        or re.fullmatch(r"[1-9][0-9]{0,18}:[1-9][0-9]{0,18}:[1-9][0-9]{0,18}", issue_key) is None
        or type(revision) is not str
        or re.fullmatch(r"[0-9a-f]{64}", revision) is None
        or type(field_name) is not str
        or field_name not in FIELDS
        or (
            prior is not None
            and (type(prior) is not str or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", prior) is None)
        )
    ):
        raise BoundaryError("invalid_review_target")
    return {"issue_key": issue_key, "revision": revision, "field": field_name, "prior": prior}


class OperatorBoundary:
    """A trusted host injects exact local origin and distinct operator/session keys.

    Synthetic sessions cannot establish real human identity. The HTTP adapter supplies
    header/cookie/body policy and authenticated rendering. Durable admission/revocation is
    separate in web_auth; this signing component alone cannot establish an active session.
    """

    def __init__(self, *, origin, operator_credential, session_key, lifetime=900):
        if type(origin) is not str:
            raise BoundaryError("invalid_trusted_origin")
        try:
            parsed = urlsplit(origin)
            valid_origin = (
                type(origin) is str
                and len(origin) <= 256
                and parsed.scheme in {"http", "https"}
                and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                and parsed.port is not None
                and 1 <= parsed.port <= 65535
                and parsed.username is None
                and parsed.password is None
                and not (parsed.path or parsed.query or parsed.fragment)
                and parsed.geturl() == origin
                and origin.isascii()
            )
        except (TypeError, ValueError):
            valid_origin = False
        if not valid_origin:
            raise BoundaryError("invalid_trusted_origin")
        if (
            type(operator_credential) is not bytes
            or not 32 <= len(operator_credential) <= 256
            or type(session_key) is not bytes
            or not 32 <= len(session_key) <= 256
            or hmac.compare_digest(operator_credential, session_key)
            or type(lifetime) is not int
            or not 1 <= lifetime <= 3600
        ):
            raise BoundaryError("boundary_configuration_unavailable")
        self.origin = origin
        self.lifetime = lifetime
        self._operator_credential = operator_credential
        self._session_key = session_key

    def _mutation_origin(self, method, origin):
        if type(method) is not str or method != "POST":
            raise BoundaryError("post_required")
        if (
            type(origin) is not str
            or not origin.isascii()
            or len(origin) > 256
            or not hmac.compare_digest(origin, self.origin)
        ):
            raise BoundaryError("exact_origin_required")

    def _sign(self, domain, value):
        return hmac.new(
            self._session_key,
            domain + b"\0" + self.origin.encode("ascii") + b"\0" + value.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def login(self, *, method, origin, credential, now):
        self._mutation_origin(method, origin)
        stamp = _time(now)
        if (
            type(credential) is not bytes
            or len(credential) > 256
            or not hmac.compare_digest(credential, self._operator_credential)
        ):
            raise BoundaryError("operator_auth_required")
        expires = stamp + self.lifetime
        body = f"v1.{stamp}.{expires}.{secrets.token_hex(16)}"
        return OperatorSession(body + "." + self._sign(b"local-review-session/1", body), expires)

    def require_session(self, session, *, now):
        stamp = _time(now)
        if type(session) is not str or len(session) > 256:
            raise BoundaryError("operator_session_required")
        match = re.fullmatch(
            r"v1\.([0-9]{1,16})\.([0-9]{1,16})\.([0-9a-f]{32})\.([0-9a-f]{64})", session
        )
        if match is None:
            raise BoundaryError("operator_session_required")
        issued, expires = int(match[1]), int(match[2])
        if (
            issued > stamp
            or stamp >= expires
            or expires - issued != self.lifetime
            or not hmac.compare_digest(
                match[4], self._sign(b"local-review-session/1", session.rsplit(".", 1)[0])
            )
        ):
            raise BoundaryError("operator_session_required")

    def challenge(self, session, *, issue_key, revision, field_name, prior, now):
        self.require_session(session, now=now)
        target = _target(issue_key, revision, field_name, prior)
        body = json.dumps(
            {"action": "provisional_review", "session": session, **target},
            sort_keys=True,
            separators=(",", ":"),
        )
        return self._sign(b"local-review-csrf/1", body)

    def authorize(self, transport, decision, *, now):
        if type(transport) is not BrowserMutation:
            raise BoundaryError("unverified_transport")
        self._mutation_origin(transport.method, transport.origin)
        expected = self.challenge(
            transport.session,
            issue_key=decision.issue_key,
            revision=decision.expected_revision,
            field_name=decision.field,
            prior=decision.expected_prior_event_id,
            now=now,
        )
        if (
            type(transport.csrf) is not str
            or re.fullmatch(r"[0-9a-f]{64}", transport.csrf) is None
            or not hmac.compare_digest(expected, transport.csrf)
        ):
            raise BoundaryError("csrf_required")

    def form_seal(self, session, *, action, payload, now):
        """Seal server-issued form metadata; values do not confer Human authority."""
        self.require_session(session, now=now)
        if (
            action not in {"review_form", "dry_run", "logout"}
            or type(payload) is not str
            or not payload.isascii()
            or len(payload) > 16384
        ):
            raise BoundaryError("form_invalid")
        body = json.dumps([session, action, payload], separators=(",", ":"))
        return self._sign(b"local-review-form/1", body)

    def verify_form(self, session, *, action, payload, seal, now):
        expected = self.form_seal(session, action=action, payload=payload, now=now)
        if (
            type(seal) is not str
            or re.fullmatch(r"[0-9a-f]{64}", seal) is None
            or not hmac.compare_digest(expected, seal)
        ):
            raise BoundaryError("form_invalid")
