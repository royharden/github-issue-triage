"""Explicit bounded repository capture port; never constructs an HTTP transport.

Supplied transport/provenance is a trusted-process configuration, not proof of GitHub origin.
This value does not widen fixture-only codeindex admission or authorize an account operation.
"""

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import quote

from .archive import DEFAULT_LIMITS, ArchiveError, ArchiveLimits, validate_archive
from .auth import AuthError, positive_id
from .reader import ReadError, ReadRequest, archive_request, bounded_read


class CaptureError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RepositoryIdentity:
    installation_id: int
    repository_id: int
    owner: str
    repository: str

    def __post_init__(self):
        try:
            positive_id(self.installation_id)
            positive_id(self.repository_id)
            archive_request(self.owner, self.repository, "0" * 40, token="validation-only")
        except (AuthError, ReadError):
            raise CaptureError("invalid_capture_repository") from None

    @property
    def full_name(self):
        return self.owner + "/" + self.repository


@dataclass(frozen=True, slots=True)
class CapturedRepository:
    identity: RepositoryIdentity
    commit_sha: str
    provenance: str
    compressed_sha256: str
    expanded_tar_sha256: str
    files: Mapping[str, bytes] = field(repr=False)

    def __post_init__(self):
        if (
            type(self.identity) is not RepositoryIdentity
            or type(self.commit_sha) is not str
            or re.fullmatch(r"[0-9a-f]{40}", self.commit_sha) is None
            or type(self.provenance) is not str
            or self.provenance not in ("synthetic_transport", "configured_transport")
            or any(
                type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
                for value in (self.compressed_sha256, self.expanded_tar_sha256)
            )
            or not isinstance(self.files, Mapping)
        ):
            raise CaptureError("invalid_captured_value")
        retained = dict(self.files)
        if (
            not 1 <= len(retained) <= 5000
            or any(
                type(path) is not str or type(body) is not bytes for path, body in retained.items()
            )
            or sum(len(body) for body in retained.values()) > 100 * 1024 * 1024
        ):
            raise CaptureError("invalid_captured_value")
        object.__setattr__(self, "files", MappingProxyType(retained))

    def manifest_bytes(self) -> bytes:
        """Deterministic content binding, not a signature or account-authentication receipt."""
        return json.dumps(
            {
                "schema": "repository-capture/1",
                "installation_id": self.identity.installation_id,
                "repository_id": self.identity.repository_id,
                "repository": self.identity.full_name,
                "commit_sha": self.commit_sha,
                "provenance": self.provenance,
                "compressed_sha256": self.compressed_sha256,
                "expanded_tar_sha256": self.expanded_tar_sha256,
                "files": [
                    {"path": path, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                    for path, body in sorted(self.files.items())
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")

    @property
    def manifest_sha256(self):
        return hashlib.sha256(self.manifest_bytes()).hexdigest()


def _json_object(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("nonfinite")

    try:
        result = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=constant,
            parse_float=constant,
        )
        if type(result) is not dict:
            raise ValueError("object_required")
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise CaptureError("invalid_capture_metadata") from None


def capture_repository(
    identity: RepositoryIdentity,
    *,
    token: str,
    transport,
    clock,
    provenance: str,
    limits: ArchiveLimits = DEFAULT_LIMITS,
    cached=None,
) -> CapturedRepository:
    """Resolve the approved default branch once, then read only that exact SHA archive.

    Each injected GET must enforce the supplied byte/time bound during reading. The total
    30s budget is checked across metadata, redirects, ref resolution and archive parsing;
    parsing is size-bounded but is not preempted by an OS timer. No retry or sleep occurs.
    """
    if (
        type(identity) is not RepositoryIdentity
        or type(limits) is not ArchiveLimits
        or type(provenance) is not str
        or provenance not in ("synthetic_transport", "configured_transport")
        or transport is None
        or not callable(clock)
        or (cached is not None and not callable(cached))
    ):
        raise CaptureError("invalid_capture_input")
    try:
        prototype = archive_request(identity.owner, identity.repository, "0" * 40, token=token)
    except ReadError:
        raise CaptureError("capture_reader_unavailable") from None
    last = None

    def tick():
        nonlocal last
        try:
            value = clock()
        except Exception:
            raise CaptureError("invalid_capture_clock") from None
        if (
            type(value) not in (int, float)
            or not math.isfinite(value)
            or (last is not None and value < last)
        ):
            raise CaptureError("invalid_capture_clock")
        last = value
        return value

    stop = tick() + 30
    api_root = f"https://api.github.com/repos/{identity.owner}/{identity.repository}"

    def read(url, maximum, allowed):
        class ScopedTransport:
            def get(self, request, **bounds):
                if request.url not in allowed:
                    raise CaptureError("capture_redirect_refused")
                return transport.get(request, **bounds)

        remaining = stop - tick()
        if remaining <= 0:
            raise CaptureError("capture_deadline")
        try:
            response = bounded_read(
                ReadRequest(url, prototype.headers),
                transport=ScopedTransport(),
                max_bytes=maximum,
                deadline_seconds=min(30, remaining),
                clock=tick,
            )
        except (ReadError, CaptureError):
            raise CaptureError("capture_read_failed") from None
        return response.body

    metadata = _json_object(read(api_root, 1048576, {api_root}))
    if (
        type(metadata.get("id")) is not int
        or metadata["id"] != identity.repository_id
        or type(metadata.get("full_name")) is not str
        or metadata["full_name"].casefold() != identity.full_name.casefold()
    ):
        raise CaptureError("capture_repository_mismatch")
    branch = metadata.get("default_branch")
    if (
        type(branch) is not str
        or not 1 <= len(branch.encode("utf-8", errors="replace")) <= 255
        or any(ord(char) < 33 or ord(char) == 127 for char in branch)
        or any(part in ("", ".", "..") for part in branch.split("/"))
        or any(char in branch for char in ("\\", "?", "#", "%"))
        or any(0xD800 <= ord(char) <= 0xDFFF for char in branch)
    ):
        raise CaptureError("invalid_capture_branch")
    ref_url = api_root + "/commits/" + quote(branch, safe="")
    revision = _json_object(read(ref_url, 1048576, {ref_url})).get("sha")
    if type(revision) is not str or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise CaptureError("invalid_capture_revision")
    if cached is not None:
        try:
            prior = cached(identity, revision, provenance)
        except Exception:
            raise CaptureError("capture_cache_failed") from None
        if prior is not None:
            if (
                type(prior) is not CapturedRepository
                or prior.identity != identity
                or prior.commit_sha != revision
                or prior.provenance != provenance
            ):
                raise CaptureError("capture_cache_mismatch")
            if tick() >= stop:
                raise CaptureError("capture_deadline")
            return prior
    archive_url = archive_request(identity.owner, identity.repository, revision, token=token).url
    codeload = f"https://codeload.github.com/{identity.full_name}/legacy.tar.gz/{revision}"
    raw = read(archive_url, limits.max_compressed_bytes, {archive_url, codeload})
    try:
        archive = validate_archive(raw, limits=limits)
    except ArchiveError:
        raise CaptureError("capture_archive_refused") from None
    if tick() >= stop:
        raise CaptureError("capture_deadline")
    return CapturedRepository(
        identity,
        revision,
        provenance,
        archive.compressed_sha256,
        archive.expanded_tar_sha256,
        archive.files,
    )
