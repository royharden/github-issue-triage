"""Bounded label read observations. Transport and repository authority belong to the broker."""

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Annotated, Literal, Self
from urllib.parse import quote

from pydantic import ConfigDict, Field, field_validator, model_validator

from ..contracts.domain import ClosedModel, Digest, IssueKey, PositiveId, utc_epoch_us
from ..shared.codeindex.canonical import digest
from ..shared.ghapp.reader import ReadError, ReadRequest, ReadResponse, bounded_read


class LabelError(ValueError):
    pass


class LabelWire(ClosedModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )


class RepositoryLabel(LabelWire):
    id: PositiveId
    name: Annotated[str, Field(min_length=1, max_length=256)]
    archival_state: Literal["active", "archived", "unknown"]
    archived_at: str | None = None

    @field_validator("name")
    @classmethod
    def exact_safe_name(cls, value):
        if (
            value.isspace()
            or len(value.encode("utf-8", errors="strict")) > 256
            or any(unicodedata.category(char) == "Cc" for char in value)
        ):
            raise ValueError("invalid_label_name")
        return value

    @model_validator(mode="after")
    def archive_binding(self) -> Self:
        if self.archival_state == "archived":
            if self.archived_at is None:
                raise ValueError("archive_time_required")
            utc_epoch_us(self.archived_at)
        elif self.archived_at is not None:
            raise ValueError("unexpected_archive_time")
        return self


class LabelInventory(LabelWire):
    repository_id: PositiveId
    labels: Annotated[tuple[RepositoryLabel, ...], Field(max_length=1000)]
    captured_at: str
    page_sha256: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=11)]
    observation: Literal["injected_read_port"] = "injected_read_port"

    @field_validator("labels", "page_sha256", mode="before")
    @classmethod
    def immutable_arrays(cls, value):
        return tuple(value) if type(value) is list else value

    @field_validator("captured_at")
    @classmethod
    def captured_time(cls, value):
        utc_epoch_us(value)
        return value

    @model_validator(mode="after")
    def unique_ordered_labels(self) -> Self:
        identities = [label.id for label in self.labels]
        names = [unicodedata.normalize("NFC", label.name).casefold() for label in self.labels]
        if identities != sorted(set(identities)) or len(names) != len(set(names)):
            raise ValueError("duplicate_or_unordered_labels")
        return self

    @property
    def label_set_sha256(self):
        # Fetch time, page order/encoding and irrelevant description/color do not rerun judgments.
        return digest(
            {
                "label_set_schema_version": 1,
                "repository_id": self.repository_id,
                "labels": [
                    {
                        "id": label.id,
                        "name": label.name,
                        "archival_state": label.archival_state,
                        "archived_at": label.archived_at,
                    }
                    for label in self.labels
                ],
            }
        )


@dataclass(frozen=True, slots=True)
class LabelReadBounds:
    max_labels: int = 1000
    max_pages: int = 11
    max_page_bytes: int = 262144
    max_total_bytes: int = 1048576
    deadline_seconds: int = 30

    def __post_init__(self):
        for value, limit in (
            (self.max_labels, 1000),
            (self.max_pages, 11),
            (self.max_page_bytes, 262144),
            (self.max_total_bytes, 1048576),
            (self.deadline_seconds, 30),
        ):
            if type(value) is not int or not 1 <= value <= limit:
                raise LabelError("invalid_label_limits")


DEFAULT_LABEL_BOUNDS = LabelReadBounds()


def labels_request(key, page, *, token):
    try:
        if type(key) is not IssueKey:
            raise ValueError
        key = IssueKey.model_validate(key.model_dump(mode="python"))
    except Exception:
        raise LabelError("invalid_repository_identity") from None
    if type(page) is not int or not 1 <= page <= 11:
        raise LabelError("invalid_label_page")
    if (
        type(token) is not str
        or not token
        or not token.isascii()
        or any(ord(char) <= 32 for char in token)
    ):
        raise LabelError("reader_token_unavailable")
    url = (
        f"https://api.github.com/repos/{quote(key.owner, safe='')}/"
        f"{quote(key.repository, safe='')}/labels?per_page=100&page={page}"
    )
    return ReadRequest(
        url,
        {
            "accept": "application/vnd.github+json",
            "authorization": "Bearer " + token,
            "x-github-api-version": "2022-11-28",
            "user-agent": "issue-triage-local/1",
        },
    )


def _decode_page(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise LabelError("duplicate_label_json_key")
            result[key] = value
        return result

    def unsupported(_):
        raise LabelError("invalid_label_json_number")

    try:
        values = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=unsupported,
            parse_float=unsupported,
        )
        if type(values) is not list or len(values) > 100:
            raise LabelError("invalid_label_page_shape")
        labels = []
        for value in values:
            if type(value) is not dict:
                raise LabelError("invalid_label_record")
            archive = value.get("archived_at")
            state = (
                "unknown"
                if "archived_at" not in value
                else ("active" if archive is None else "archived")
            )
            labels.append(
                RepositoryLabel(
                    id=value.get("id"),
                    name=value.get("name"),
                    archival_state=state,
                    archived_at=archive,
                )
            )
        return labels
    except LabelError:
        raise
    except Exception:
        raise LabelError("invalid_label_response") from None


def read_label_inventory(key, *, token, transport, clock, captured_at, bounds=DEFAULT_LABEL_BOUNDS):
    if type(bounds) is not LabelReadBounds or not callable(clock):
        raise LabelError("invalid_label_limits")
    bounds.__post_init__()
    try:
        if type(key) is not IssueKey:
            raise ValueError
        key = IssueKey.model_validate(key.model_dump(mode="python"))
    except Exception:
        raise LabelError("invalid_repository_identity") from None
    utc_epoch_us(captured_at)
    last = None

    def tick():
        nonlocal last
        value = clock()
        if (
            type(value) not in (int, float)
            or not math.isfinite(value)
            or (last is not None and value < last)
        ):
            raise LabelError("invalid_label_clock")
        last = value
        return value

    stop, labels, pages, total = tick() + bounds.deadline_seconds, [], [], 0
    for page in range(1, bounds.max_pages + 1):
        request = labels_request(key, page, token=token)
        remaining = stop - tick()
        if remaining <= 0:
            raise LabelError("label_deadline")
        remaining_bytes = bounds.max_total_bytes - total
        if remaining_bytes <= 0:
            raise LabelError("label_total_byte_limit")

        class FixedPageTransport:
            def __init__(self, expected_url, reader):
                self.expected_url, self.reader = expected_url, reader

            def get(self, actual, *, max_bytes, timeout_seconds):
                # Labels do not inherit the archive reader's codeload or changed-path redirects.
                if actual.url != self.expected_url:
                    raise LabelError("label_redirect_not_allowed")
                response = self.reader.get(
                    actual, max_bytes=max_bytes, timeout_seconds=timeout_seconds
                )
                if type(response) is ReadResponse and response.status in {301, 302, 303, 307, 308}:
                    raise LabelError("label_redirect_not_allowed")
                return response

        try:
            response = bounded_read(
                request,
                transport=FixedPageTransport(request.url, transport),
                max_bytes=min(bounds.max_page_bytes, remaining_bytes),
                deadline_seconds=remaining,
                clock=tick,
            )
        except (ReadError, LabelError):
            raise LabelError("labels_read_unavailable") from None
        if tick() >= stop:
            raise LabelError("label_deadline")
        total += len(response.body)
        if total > bounds.max_total_bytes:
            raise LabelError("label_total_byte_limit")
        additions = _decode_page(response.body)
        labels.extend(additions)
        if len(labels) > bounds.max_labels:
            raise LabelError("label_count_limit")
        pages.append(hashlib.sha256(response.body).hexdigest())
        headers = {}
        for name, value in response.headers.items():
            if (
                type(name) is not str
                or type(value) is not str
                or name.lower() in headers
                or "\r" in value
                or "\n" in value
            ):
                raise LabelError("invalid_label_response_header")
            headers[name.lower()] = value
        relations = re.findall(
            r"""\brel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s,;]+))""",
            headers.get("link", ""),
            flags=re.I,
        )
        has_next = any("next" in value.lower().split() for group in relations for value in group)
        if len(additions) < 100 and not has_next:
            try:
                return LabelInventory(
                    repository_id=key.repository_id,
                    labels=tuple(sorted(labels, key=lambda label: label.id)),
                    captured_at=captured_at,
                    page_sha256=tuple(pages),
                )
            except Exception:
                raise LabelError("ambiguous_label_inventory") from None
    raise LabelError("label_page_limit")
