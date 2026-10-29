"""Least-privilege request construction with an explicit RS256 signer port.

No private key loader, default signer, transport or actual token minting is installed here.
"""

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field


class AuthError(ValueError):
    pass


def positive_id(value):
    if type(value) is not int or not 0 < value <= 9223372036854775807:
        raise AuthError("invalid_github_id")
    return value


@dataclass(frozen=True, slots=True)
class AppJwt:
    token: str = field(repr=False)
    expires_at_seconds: int


def app_jwt(issuer: str, *, now_seconds: int, signer) -> AppJwt:
    if type(issuer) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", issuer) is None:
        raise AuthError("invalid_issuer")
    if type(now_seconds) is not int or not 60 <= now_seconds <= 253402300000:
        raise AuthError("invalid_clock")
    if signer is None:
        raise AuthError("signer_unavailable")

    def encode(value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    expires = now_seconds + 540
    signing_input = (
        encode({"alg": "RS256", "typ": "JWT"})
        + b"."
        + encode({"iat": now_seconds - 60, "exp": expires, "iss": issuer})
    )
    try:
        signature = signer.sign(signing_input, algorithm="RS256")
    except Exception:
        raise AuthError("signing_failed") from None
    if type(signature) is not bytes or not 1 <= len(signature) <= 16384:
        raise AuthError("invalid_signature_result")
    token = signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")
    return AppJwt(token.decode("ascii"), expires)


@dataclass(frozen=True, slots=True)
class InstallationTokenRequest:
    installation_id: int
    repository_id: int
    permissions: tuple[tuple[str, str], ...]

    @property
    def path(self):
        return f"/app/installations/{self.installation_id}/access_tokens"

    def payload(self):
        return {"repository_ids": [self.repository_id], "permissions": dict(self.permissions)}


def installation_token_request(
    installation_id: int,
    repository_id: int,
    *,
    role: str,
    registered_permissions: Mapping[str, str],
) -> InstallationTokenRequest:
    positive_id(installation_id)
    positive_id(repository_id)
    profiles = {
        "reader": {"contents": "read", "issues": "read", "metadata": "read"},
        "apply": {"issues": "write", "metadata": "read"},
    }
    if (
        type(role) is not str
        or role not in profiles
        or not isinstance(registered_permissions, Mapping)
    ):
        raise AuthError("invalid_permission_profile")
    requested = profiles[role]
    ranks = {"read": 1, "write": 2}
    for permission, level in requested.items():
        granted = registered_permissions.get(permission)
        if type(granted) is not str or granted not in ranks or ranks[granted] < ranks[level]:
            raise AuthError("permission_not_registered")
    return InstallationTokenRequest(
        installation_id, repository_id, tuple(sorted(requested.items()))
    )
