"""Explicit in-memory RSA signer for the existing GitHub App JWT port.

No credential discovery, file reads, token exchange or transport occurs here.
"""

import re
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .auth import AuthError

MAX_PEM_BYTES = 65536
MAX_SIGNING_BYTES = 4096
_PEM = re.compile(
    rb"\s*-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY)-----\r?\n"
    rb"[A-Za-z0-9+/=\r\n]+-----END \1-----\s*"
)


@dataclass(frozen=True, slots=True, init=False)
class RS256Signer:
    """Caller supplies one unencrypted PKCS#1/PKCS#8 PEM RSA private key.

    Retains the parsed key in process memory, never its source path or PEM input.
    This is not key erasure, OS isolation, or evidence of GitHub account access.
    """

    _key: rsa.RSAPrivateKey = field(repr=False)

    def __init__(self, pem: bytes):
        if (
            type(pem) is not bytes
            or not 1 <= len(pem) <= MAX_PEM_BYTES
            or _PEM.fullmatch(pem) is None
        ):
            raise AuthError("invalid_signing_key")
        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except Exception:
            raise AuthError("invalid_signing_key") from None
        if not isinstance(key, rsa.RSAPrivateKey) or not 2048 <= key.key_size <= 8192:
            raise AuthError("unsupported_signing_key")
        object.__setattr__(self, "_key", key)

    def sign(self, signing_input: bytes, *, algorithm: str) -> bytes:
        if type(algorithm) is not str or algorithm != "RS256":
            raise AuthError("unsupported_signing_algorithm")
        if type(signing_input) is not bytes or not 1 <= len(signing_input) <= MAX_SIGNING_BYTES:
            raise AuthError("invalid_signing_input")
        try:
            # RS256 requires RSA PKCS#1 v1.5 with SHA-256, rather than RSA-PSS.
            return self._key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            raise AuthError("rsa_signing_failed") from None
