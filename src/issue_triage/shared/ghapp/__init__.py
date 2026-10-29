"""GitHub boundary helpers; imports start no transport, signing or key access."""

from .auth import AppJwt, AuthError, app_jwt, installation_token_request
from .signatures import WebhookError, verify_signature

__all__ = [
    "AppJwt",
    "AuthError",
    "Delivery",
    "WebhookError",
    "app_jwt",
    "installation_token_request",
    "parse_delivery",
    "verify_signature",
]


def __getattr__(name):
    if name in ("ArchiveError", "ArchiveLimits", "ValidatedArchive", "validate_archive"):
        from .archive import ArchiveError, ArchiveLimits, ValidatedArchive, validate_archive

        return {
            "ArchiveError": ArchiveError,
            "ArchiveLimits": ArchiveLimits,
            "ValidatedArchive": ValidatedArchive,
            "validate_archive": validate_archive,
        }[name]
    if name in ("Delivery", "parse_delivery"):
        from .webhook import Delivery, parse_delivery

        return {"Delivery": Delivery, "parse_delivery": parse_delivery}[name]
    raise AttributeError(name)
