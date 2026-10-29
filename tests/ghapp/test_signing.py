"""Real local crypto with ephemeral synthetic keys; no account, file or HTTP access."""

import base64
import json
import socket
import traceback
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from issue_triage.shared.ghapp import signing
from issue_triage.shared.ghapp.auth import AuthError, app_jwt
from issue_triage.shared.ghapp.signing import RS256Signer


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    attempts = []

    def denied(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("local signing must not open a network connection")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    yield
    assert attempts == []


@pytest.fixture(scope="module")
def synthetic_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def pem(key, form=serialization.PrivateFormat.PKCS8):
    return key.private_bytes(serialization.Encoding.PEM, form, serialization.NoEncryption())


def decode(part):
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


@pytest.mark.parametrize(
    "form", [serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.TraditionalOpenSSL]
)
def test_real_jwt_signature_and_existing_claims_verify_with_public_key(synthetic_key, form):
    """what_bug_this_catches: a signer double or wrong padding/hash produces unusable JWTs."""
    signer = RS256Signer(pem(synthetic_key, form))
    value = app_jwt("synthetic-client-id", now_seconds=1800000000, signer=signer)
    header, payload, signature = value.token.split(".")
    assert json.loads(decode(header)) == {"alg": "RS256", "typ": "JWT"}
    assert json.loads(decode(payload)) == {
        "iss": "synthetic-client-id",
        "iat": 1799999940,
        "exp": 1800000540,
    }
    assert value.expires_at_seconds == 1800000540
    message = (header + "." + payload).encode("ascii")
    synthetic_key.public_key().verify(
        decode(signature), message, padding.PKCS1v15(), hashes.SHA256()
    )
    with pytest.raises(InvalidSignature):
        synthetic_key.public_key().verify(
            decode(signature), message + b"changed", padding.PKCS1v15(), hashes.SHA256()
        )
    assert value.token not in repr(value) and value.token not in repr(signer)
    assert "PRIVATE KEY" not in repr(signer)


def test_signature_mutation_and_unrelated_public_key_refuse(synthetic_key):
    signer = RS256Signer(pem(synthetic_key))
    signature = signer.sign(b"synthetic signing input", algorithm="RS256")
    changed = bytes([signature[0] ^ 1]) + signature[1:]
    with pytest.raises(InvalidSignature):
        synthetic_key.public_key().verify(
            changed, b"synthetic signing input", padding.PKCS1v15(), hashes.SHA256()
        )
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(InvalidSignature):
        other.public_key().verify(
            signature, b"synthetic signing input", padding.PKCS1v15(), hashes.SHA256()
        )


@pytest.mark.parametrize(
    "bad",
    [None, "not-bytes", bytearray(b"key"), b"", b"bad-key", b"x" * 65537],
    ids=["none", "text", "mutable", "empty", "malformed", "oversize"],
)
def test_malformed_or_unbounded_key_input_refuses(bad):
    with pytest.raises(AuthError, match="^invalid_signing_key$"):
        RS256Signer(bad)


def test_non_rsa_weak_public_encrypted_and_multiple_keys_refuse(synthetic_key):
    ec_key = ec.generate_private_key(ec.SECP256R1())
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    for key in (ec_key, weak):
        with pytest.raises(AuthError, match="^unsupported_signing_key$"):
            RS256Signer(pem(key))
    public = synthetic_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    encrypted = synthetic_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"synthetic-passphrase"),
    )
    for bad in (public, encrypted, pem(synthetic_key) * 2, pem(synthetic_key) + b"extra"):
        with pytest.raises(AuthError, match="^invalid_signing_key$"):
            RS256Signer(bad)


@pytest.mark.parametrize("algorithm", [None, "none", "HS256", "PS256", "rs256", b"RS256"])
def test_algorithm_is_fixed(synthetic_key, algorithm):
    with pytest.raises(AuthError, match="^unsupported_signing_algorithm$"):
        RS256Signer(pem(synthetic_key)).sign(b"synthetic", algorithm=algorithm)


@pytest.mark.parametrize(
    "message",
    [None, "text", bytearray(b"mutable"), b"", b"x" * 4097],
    ids=["none", "text", "mutable", "empty", "oversize"],
)
def test_signing_input_is_immutable_and_bounded(synthetic_key, message):
    with pytest.raises(AuthError, match="^invalid_signing_input$"):
        RS256Signer(pem(synthetic_key)).sign(message, algorithm="RS256")


def test_provider_load_failure_has_only_closed_public_error(synthetic_key, monkeypatch):
    def failed(*args, **kwargs):
        raise ValueError("synthetic-private-canary-that-must-not-escape")

    monkeypatch.setattr(signing.serialization, "load_pem_private_key", failed)
    with pytest.raises(AuthError) as error:
        RS256Signer(pem(synthetic_key))
    assert str(error.value) == "invalid_signing_key"
    assert "synthetic-private-canary" not in "".join(traceback.format_exception(error.value))


def test_signer_key_cannot_be_reassigned_and_sign_failure_is_closed(synthetic_key, monkeypatch):
    signer = RS256Signer(pem(synthetic_key))
    with pytest.raises(FrozenInstanceError):
        signer._key = synthetic_key

    class FailedKey:
        def sign(self, *args):
            raise ValueError("synthetic-signing-payload-canary")

    # Fault injection bypasses frozen assignment only inside this synthetic control.
    object.__setattr__(signer, "_key", FailedKey())
    with pytest.raises(AuthError) as error:
        signer.sign(b"synthetic", algorithm="RS256")
    assert str(error.value) == "rsa_signing_failed"
    assert "synthetic-signing-payload-canary" not in "".join(
        traceback.format_exception(error.value)
    )


@pytest.mark.parametrize("now", [True, 59, 1.5, "1800000000", 253402300001])
def test_existing_jwt_clock_refuses_before_signing(synthetic_key, now):
    with pytest.raises(AuthError, match="^invalid_clock$"):
        app_jwt("synthetic-client-id", now_seconds=now, signer=RS256Signer(pem(synthetic_key)))


@pytest.mark.parametrize("issuer", [None, "", "with space", "x" * 129])
def test_existing_jwt_issuer_refuses(synthetic_key, issuer):
    with pytest.raises(AuthError, match="^invalid_issuer$"):
        app_jwt(issuer, now_seconds=1800000000, signer=RS256Signer(pem(synthetic_key)))


def test_in_memory_signing_ignores_credential_paths_and_environment(synthetic_key, monkeypatch):
    """what_bug_this_catches: a default loader ignores the explicit supplied key boundary."""
    encoded = pem(synthetic_key)
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_FILE", "synthetic-unreadable-credential-path")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "synthetic-environment-key-must-be-ignored")
    attempts = []

    def denied(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("signer must not discover or read a credential file")

    monkeypatch.setattr("builtins.open", denied)
    monkeypatch.setattr(Path, "read_bytes", denied)
    monkeypatch.setattr(Path, "read_text", denied)
    value = app_jwt("synthetic-client-id", now_seconds=1800000000, signer=RS256Signer(encoded))
    head, body, signature = value.token.split(".")
    synthetic_key.public_key().verify(
        decode(signature),
        (head + "." + body).encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    assert attempts == []
