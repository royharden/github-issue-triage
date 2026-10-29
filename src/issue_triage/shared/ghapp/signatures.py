"""Standalone stdlib original-byte HMAC boundary; no app/model/key loader imports."""

import hashlib
import hmac
import re


class WebhookError(ValueError):
    pass


def verify_signature(raw_body: bytes, signature_header: str, secret: bytes) -> None:
    if type(raw_body) is not bytes or len(raw_body) > 1048576:
        raise WebhookError("body_too_large_or_invalid")
    if type(secret) is not bytes or len(secret) < 16:
        raise WebhookError("webhook_secret_unavailable")
    if (
        type(signature_header) is not str
        or re.fullmatch(r"sha256=[0-9a-f]{64}", signature_header) is None
    ):
        raise WebhookError("bad_signature")
    expected = "sha256=" + hmac.new(secret, raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise WebhookError("bad_signature")
