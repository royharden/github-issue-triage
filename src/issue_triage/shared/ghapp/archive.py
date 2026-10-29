"""Bounded in-memory tar.gz validation. Never extract to disk or execute a snapshot."""

import gzip
import hashlib
import io
import re
import tarfile
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType


class ArchiveError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_compressed_bytes: int = 20 * 1024 * 1024
    max_expanded_bytes: int = 100 * 1024 * 1024
    max_files: int = 5000

    def __post_init__(self):
        for value, ceiling in (
            (self.max_compressed_bytes, 20 * 1024 * 1024),
            (self.max_expanded_bytes, 100 * 1024 * 1024),
            (self.max_files, 5000),
        ):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ArchiveError("invalid_archive_limits")


DEFAULT_LIMITS = ArchiveLimits()


@dataclass(frozen=True, slots=True)
class ValidatedArchive:
    files: Mapping[str, bytes] = field(repr=False)
    compressed_sha256: str
    expanded_tar_sha256: str
    total_file_bytes: int

    def __post_init__(self):
        object.__setattr__(self, "files", MappingProxyType(dict(self.files)))


def _preflight_headers(data: bytes, limits: ArchiveLimits):
    """Bound extension records before tarfile can allocate/interpret PAX/long names."""
    offset = count = metadata = 0
    extension_types = {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME}
    ordinary_types = {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}
    while offset + 512 <= len(data):
        block = data[offset : offset + 512]
        if block == b"\0" * 512:
            if len(data) < offset + 1024 or any(data[offset:]):
                raise ArchiveError("invalid_archive_end")
            return
        info = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
        count += 1
        if count > 2 * limits.max_files + 100:
            raise ArchiveError("archive_entry_limit")
        if info.size < 0 or info.size > limits.max_expanded_bytes:
            raise ArchiveError("archive_size_limit")
        if info.type in extension_types:
            metadata += info.size
            per_record = 4096 if info.type == tarfile.GNUTYPE_LONGNAME else 65536
            if info.size > per_record or metadata > 1048576:
                raise ArchiveError("archive_metadata_limit")
        elif info.type not in ordinary_types:
            raise ArchiveError("unsupported_archive_type")
        following = offset + 512 + ((info.size + 511) // 512) * 512
        if following > len(data):
            raise ArchiveError("truncated_archive")
        offset = following
    raise ArchiveError("missing_archive_end")


def _parts(name: str, is_directory: bool) -> list[str]:
    if type(name) is not str or not name or "\\" in name or "\x00" in name or name.startswith("/"):
        raise ArchiveError("unsafe_archive_path")
    if is_directory and name.endswith("/"):
        name = name[:-1]
    if len(name.encode("utf-8", errors="strict")) > 4096:
        raise ArchiveError("archive_path_limit")
    parts = name.split("/")
    if len(parts) > 64:
        raise ArchiveError("archive_path_limit")
    for part in parts:
        if not part or part in (".", "..") or ":" in part or part.endswith((".", " ")):
            raise ArchiveError("unsafe_archive_path")
        if re.fullmatch(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part, re.I):
            raise ArchiveError("unsafe_archive_path")
        if any(ord(char) < 32 for char in part):
            raise ArchiveError("unsafe_archive_path")
    return parts


def validate_archive(raw: bytes, *, limits: ArchiveLimits = DEFAULT_LIMITS) -> ValidatedArchive:
    if type(raw) is not bytes or type(limits) is not ArchiveLimits:
        raise ArchiveError("invalid_archive_input")
    if len(raw) > limits.max_compressed_bytes:
        raise ArchiveError("compressed_archive_limit")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
            expanded = stream.read(limits.max_expanded_bytes + 1)
        if len(expanded) > limits.max_expanded_bytes:
            raise ArchiveError("expanded_archive_limit")
        _preflight_headers(expanded, limits)
        files = {}
        seen = {}
        parents = set()
        root = None
        total = 0
        allowed_pax = {"path", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname", "comment"}
        with tarfile.open(
            fileobj=io.BytesIO(expanded), mode="r:", encoding="utf-8", errors="strict"
        ) as archive:
            for member in archive:
                if not (member.isfile() or member.isdir()) or member.sparse is not None:
                    raise ArchiveError("unsupported_archive_type")
                if set(member.pax_headers) - allowed_pax:
                    raise ArchiveError("unsupported_archive_metadata")
                parts = _parts(member.name, member.isdir())
                if root is None:
                    root = parts[0]
                if parts[0] != root:
                    raise ArchiveError("multiple_archive_roots")
                if len(parts) == 1 and not member.isdir():
                    raise ArchiveError("missing_archive_root_directory")
                full = "/".join(parts)
                folded = unicodedata.normalize("NFC", full).casefold()
                if folded in seen:
                    raise ArchiveError("duplicate_or_case_colliding_path")
                folded_parents = [
                    unicodedata.normalize("NFC", "/".join(parts[:index])).casefold()
                    for index in range(1, len(parts))
                ]
                if any(seen.get(parent) == "file" for parent in folded_parents) or (
                    member.isfile() and folded in parents
                ):
                    raise ArchiveError("file_directory_collision")
                seen[folded] = "directory" if member.isdir() else "file"
                parents.update(folded_parents)
                if member.isdir():
                    if member.size != 0:
                        raise ArchiveError("invalid_directory_size")
                    continue
                if len(files) >= limits.max_files:
                    raise ArchiveError("archive_file_limit")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ArchiveError("unreadable_archive_member")
                content = stream.read(member.size + 1)
                if len(content) != member.size:
                    raise ArchiveError("truncated_archive")
                total += len(content)
                if total > limits.max_expanded_bytes:
                    raise ArchiveError("expanded_archive_limit")
                files["/".join(parts[1:])] = content
        if not files:
            raise ArchiveError("empty_archive")
        return ValidatedArchive(
            files, hashlib.sha256(raw).hexdigest(), hashlib.sha256(expanded).hexdigest(), total
        )
    except ArchiveError:
        raise
    except (OSError, EOFError, tarfile.TarError, UnicodeError, ValueError, OverflowError):
        raise ArchiveError("archive_decode_failed") from None
