"""Authenticate original bytes before decoding, then project only supported issue events."""

import hashlib
import json
import re
from dataclasses import dataclass, field

from ...contracts import IssueInput, IssueKey, WebhookEnvelope, utc_epoch_us
from .auth import positive_id
from .signatures import WebhookError, verify_signature


@dataclass(frozen=True, slots=True)
class Delivery:
    delivery_id: str
    raw_body_sha256: str
    received_at: str
    event: str
    action: str | None
    disposition: str
    reason: str
    envelope: WebhookEnvelope | None = field(default=None, repr=False)

    def __post_init__(self):
        if (
            type(self.delivery_id) is not str
            or re.fullmatch(r"[A-Za-z0-9-]{1,128}", self.delivery_id) is None
        ):
            raise WebhookError("invalid_delivery_id")
        if (
            type(self.raw_body_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.raw_body_sha256) is None
        ):
            raise WebhookError("invalid_delivery_digest")
        utc_epoch_us(self.received_at)
        reasons = {
            "verified_issue",
            "unsupported_event",
            "unsupported_action",
            "pull_request_not_supported",
            "app_self_event",
        }
        if (
            type(self.disposition) is not str
            or type(self.reason) is not str
            or self.disposition not in ("supported", "ignored")
            or self.reason not in reasons
        ):
            raise WebhookError("invalid_delivery_metadata")
        if type(self.event) is not str or re.fullmatch(r"[a-z_]{1,64}", self.event) is None:
            raise WebhookError("invalid_event_header")
        if self.action is not None and (
            type(self.action) is not str or re.fullmatch(r"[a-z_]{1,64}", self.action) is None
        ):
            raise WebhookError("invalid_delivery_metadata")
        if self.disposition == "supported":
            if self.reason != "verified_issue":
                raise WebhookError("invalid_delivery_metadata")
            value = self.envelope
            if type(value) is not WebhookEnvelope or (
                value.delivery_id,
                value.raw_body_sha256,
                value.received_at,
                value.event,
                value.action,
            ) != (
                self.delivery_id,
                self.raw_body_sha256,
                self.received_at,
                self.event,
                self.action,
            ):
                raise WebhookError("delivery_binding_mismatch")
        elif self.envelope is not None or self.reason == "verified_issue":
            raise WebhookError("invalid_ignored_delivery")


def parse_delivery(
    raw_body: bytes,
    *,
    signature_header: str,
    secret: bytes,
    delivery_id: str,
    event: str,
    received_at: str,
    installation_id: int,
    repository_id: int,
    app_actor_id: int | None = None,
) -> Delivery:
    verify_signature(raw_body, signature_header, secret)
    if type(delivery_id) is not str or re.fullmatch(r"[A-Za-z0-9-]{1,128}", delivery_id) is None:
        raise WebhookError("invalid_delivery_id")
    if type(event) is not str or re.fullmatch(r"[a-z_]{1,64}", event) is None:
        raise WebhookError("invalid_event_header")
    try:
        utc_epoch_us(received_at)
        positive_id(installation_id)
        positive_id(repository_id)
        if app_actor_id is not None:
            positive_id(app_actor_id)
    except (ValueError, TypeError):
        raise WebhookError("invalid_trusted_context") from None

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError("nonfinite_json")

    try:
        payload = json.loads(
            raw_body, object_pairs_hook=unique_pairs, parse_constant=invalid_constant
        )
        if type(payload) is not dict:
            raise ValueError
    except Exception:
        raise WebhookError("invalid_payload") from None
    digest = hashlib.sha256(raw_body).hexdigest()
    action = payload.get("action")
    action_metadata = (
        action if type(action) is str and re.fullmatch(r"[a-z_]{1,64}", action) else None
    )

    def ignored(reason):
        return Delivery(delivery_id, digest, received_at, event, action_metadata, "ignored", reason)

    if event != "issues":
        return ignored("unsupported_event")
    if action not in ("opened", "edited"):
        return ignored("unsupported_action")
    try:
        installation = payload["installation"]
        repository = payload["repository"]
        issue = payload["issue"]
        if (
            positive_id(installation["id"]) != installation_id
            or positive_id(repository["id"]) != repository_id
        ):
            raise WebhookError("repository_not_allowed")
        if "pull_request" in issue:
            return ignored("pull_request_not_supported")
        sender_id = payload.get("sender", {}).get("id")
        if app_actor_id is not None and type(sender_id) is int and sender_id == app_actor_id:
            return ignored("app_self_event")
        source = IssueInput(
            key=IssueKey(
                installation_id=installation_id,
                repository_id=repository_id,
                issue_number=issue["number"],
                owner=repository["owner"]["login"],
                repository=repository["name"],
            ),
            title=issue["title"],
            body="" if issue.get("body") is None else issue["body"],
            updated_at=issue["updated_at"],
            author_id=issue["user"]["id"],
            author_login=issue["user"]["login"],
        )
        envelope = WebhookEnvelope(
            delivery_id=delivery_id,
            event="issues",
            action=action,
            raw_body_sha256=digest,
            received_at=received_at,
            issue=source,
        )
    except WebhookError:
        raise
    except Exception:
        raise WebhookError("invalid_issue_payload") from None
    return Delivery(
        delivery_id, digest, received_at, event, action, "supported", "verified_issue", envelope
    )
