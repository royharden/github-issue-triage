"""Closed app-local JSON values. Validation errors must not expose rejected issue text."""

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
PositiveId = Annotated[int, Field(gt=0, le=9223372036854775807)]


class DomainError(ValueError):
    pass


def utc_epoch_us(value: str) -> int:
    if type(value) is not str or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value
    ):
        raise ValueError("invalid_utc_timestamp")
    try:
        stamp = datetime.fromisoformat(value[:-1] + "+00:00")
        delta = stamp - datetime(1970, 1, 1, tzinfo=UTC)
    except ValueError:
        raise ValueError("invalid_utc_timestamp") from None
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)
    schema_version: Literal[1] = 1

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value):
        if type(value) is not int or value != 1:
            raise ValueError("unsupported_schema")
        return value

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def parse_json(cls, data: bytes):
        if type(data) is not bytes or len(data) > 1048576:
            raise DomainError("invalid_json_size")

        def unique_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise DomainError("duplicate_json_key")
                result[key] = value
            return result

        def invalid_constant(_):
            raise DomainError("nonfinite_json")

        try:
            value = json.loads(
                data, object_pairs_hook=unique_pairs, parse_constant=invalid_constant
            )
            return cls.model_validate(value)
        except Exception:
            # Do not return Pydantic .errors() input values or arbitrary JSON error excerpts.
            raise DomainError("invalid_domain_json") from None


class IssueKey(ClosedModel):
    installation_id: PositiveId
    repository_id: PositiveId
    issue_number: PositiveId
    owner: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")]
    repository: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,100}$")]

    @field_validator("repository")
    @classmethod
    def repository_component(cls, value):
        if value in (".", ".."):
            raise ValueError("invalid_repository_component")
        return value

    @property
    def stable_id(self) -> str:
        # Display-name changes do not create another actual repository/issue identity.
        return f"{self.installation_id}:{self.repository_id}:{self.issue_number}"


class IssueInput(ClosedModel):
    key: IssueKey
    title: Annotated[str, Field(max_length=4096, repr=False)]
    body: Annotated[str, Field(max_length=1048576, repr=False)]
    updated_at: str
    author_id: PositiveId
    author_login: Annotated[str, Field(pattern=r"^[A-Za-z0-9_\[\]-]{1,100}$")]

    @field_validator("updated_at")
    @classmethod
    def valid_time(cls, value):
        utc_epoch_us(value)
        return value

    @field_validator("title", "body")
    @classmethod
    def valid_text(cls, value):
        try:
            if len(value.encode("utf-8", errors="strict")) > 1048576:
                raise ValueError("issue_text_too_large")
        except UnicodeError:
            raise ValueError("invalid_utf8") from None
        return value

    @property
    def model_bound_text(self) -> str:
        return self.title + "\n\n" + self.body


class WebhookEnvelope(ClosedModel):
    delivery_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9-]{1,128}$")]
    event: Literal["issues"]
    action: Literal["opened", "edited"]
    raw_body_sha256: Digest
    received_at: str
    issue: IssueInput = Field(repr=False)

    @field_validator("received_at")
    @classmethod
    def valid_time(cls, value):
        utc_epoch_us(value)
        return value
