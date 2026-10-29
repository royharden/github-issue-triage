"""Raw retained-byte identity, independent of parsing, query policy or Git-like strings."""

import hashlib
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .canonical import CodeIndexError, canonical_bytes, decode_canonical

MAX_FILES = 5000
MAX_RAW_BYTES = 100 * 1024 * 1024
MAX_INVENTORY_BYTES = 2 * 1024 * 1024


def validate_path(path):
    if type(path) is not str or not path or path.startswith("/") or "\\" in path:
        raise CodeIndexError("invalid_inventory_path")
    try:
        if len(path.encode("utf-8", errors="strict")) > 4096:
            raise CodeIndexError("inventory_path_limit")
    except UnicodeError:
        raise CodeIndexError("invalid_inventory_path") from None
    parts = path.split("/")
    if len(parts) > 64:
        raise CodeIndexError("inventory_path_limit")
    for part in parts:
        if (
            not part
            or part in (".", "..")
            or ":" in part
            or part.endswith((".", " "))
            or any(ord(char) < 32 or ord(char) == 127 for char in part)
            or re.fullmatch(r"(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part, re.I)
        ):
            raise CodeIndexError("invalid_inventory_path")
    return path


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    path: str
    source_sha256: str
    byte_length: int

    def __post_init__(self):
        validate_path(self.path)
        if type(self.source_sha256) is not str or not re.fullmatch(
            r"[0-9a-f]{64}", self.source_sha256
        ):
            raise CodeIndexError("invalid_source_digest")
        if type(self.byte_length) is not int or not 0 <= self.byte_length <= MAX_RAW_BYTES:
            raise CodeIndexError("raw_byte_limit")

    def wire(self):
        return {
            "path": self.path,
            "source_sha256": self.source_sha256,
            "byte_length": self.byte_length,
        }


@dataclass(frozen=True, slots=True)
class RawInventory:
    files: tuple[InventoryEntry, ...]

    def __post_init__(self):
        if type(self.files) is not tuple or len(self.files) > MAX_FILES:
            raise CodeIndexError("inventory_file_limit")
        if any(type(entry) is not InventoryEntry for entry in self.files):
            raise CodeIndexError("invalid_inventory_entry")
        paths = [entry.path for entry in self.files]
        if paths != sorted(paths, key=lambda path: path.encode("utf-8")):
            raise CodeIndexError("inventory_path_order")
        identities = [unicodedata.normalize("NFC", path).casefold() for path in paths]
        if len(set(identities)) != len(identities):
            raise CodeIndexError("inventory_path_collision")
        present = set(identities)
        for identity in identities:
            parts = identity.split("/")
            if any("/".join(parts[:index]) in present for index in range(1, len(parts))):
                raise CodeIndexError("inventory_file_directory_collision")
        if sum(entry.byte_length for entry in self.files) > MAX_RAW_BYTES:
            raise CodeIndexError("raw_byte_limit")
        if len(self.canonical_bytes()) > MAX_INVENTORY_BYTES:
            raise CodeIndexError("inventory_byte_limit")

    def canonical_bytes(self):
        return canonical_bytes(
            {"inventory_schema_version": 1, "files": [entry.wire() for entry in self.files]}
        )

    @property
    def sha256(self):
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @property
    def fixture_snapshot_id(self):
        """Construction identity only. No Git capture claim is made by a matching hex string."""
        return self.sha256

    @classmethod
    def parse_canonical(cls, data):
        value = decode_canonical(data, max_bytes=MAX_INVENTORY_BYTES)
        if (
            type(value) is not dict
            or set(value) != {"files", "inventory_schema_version"}
            or type(value["inventory_schema_version"]) is not int
            or value["inventory_schema_version"] != 1
            or type(value["files"]) is not list
            or len(value["files"]) > MAX_FILES
        ):
            raise CodeIndexError("invalid_inventory_schema")
        entries = []
        for item in value["files"]:
            if type(item) is not dict or set(item) != {"path", "source_sha256", "byte_length"}:
                raise CodeIndexError("invalid_inventory_schema")
            entries.append(InventoryEntry(**item))
        return cls(tuple(entries))


def inventory_from_files(files: Mapping[str, bytes]) -> RawInventory:
    if not isinstance(files, Mapping) or len(files) > MAX_FILES:
        raise CodeIndexError("inventory_file_limit")
    entries = []
    total = 0
    for path, data in files.items():
        validate_path(path)
        if type(data) is not bytes:
            raise CodeIndexError("invalid_retained_bytes")
        total += len(data)
        if total > MAX_RAW_BYTES:
            raise CodeIndexError("raw_byte_limit")
        entries.append(InventoryEntry(path, hashlib.sha256(data).hexdigest(), len(data)))
    return RawInventory(tuple(sorted(entries, key=lambda entry: entry.path.encode("utf-8"))))


@dataclass(frozen=True, slots=True, init=False)
class InventoryReader:
    inventory: RawInventory
    _files: Mapping[str, bytes] = field(repr=False)

    def __init__(self, inventory: RawInventory, files: Mapping[str, bytes]):
        if type(inventory) is not RawInventory or not isinstance(files, Mapping):
            raise CodeIndexError("invalid_inventory_reader")
        expected = {entry.path for entry in inventory.files}
        if set(files) != expected:
            raise CodeIndexError("retained_inventory_mismatch")
        retained = {}
        for entry in inventory.files:
            data = files[entry.path]
            if (
                type(data) is not bytes
                or len(data) != entry.byte_length
                or hashlib.sha256(data).hexdigest() != entry.source_sha256
            ):
                raise CodeIndexError("retained_source_mismatch")
            retained[entry.path] = data
        object.__setattr__(self, "inventory", inventory)
        object.__setattr__(self, "_files", MappingProxyType(retained))

    def read(self, path: str) -> bytes:
        validate_path(path)
        if path not in self._files:
            raise CodeIndexError("unavailable_inventory_path")
        return self._files[path]


def physical_line_count(data: bytes):
    if type(data) is not bytes:
        raise CodeIndexError("invalid_retained_bytes")
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
