"""Immutable local values; retained capture identity is distinct from fixtures and Git auth."""

import re
from dataclasses import asdict, dataclass
from datetime import datetime

from .canonical import CodeIndexError, digest
from .inventory import MAX_RAW_BYTES, validate_path
from .references import KINDS


def valid_digest(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CodeIndexError("invalid_digest")


def valid_name(value):
    if type(value) is not str or not value:
        raise CodeIndexError("invalid_name")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise CodeIndexError("invalid_name") from None
    if len(encoded) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise CodeIndexError("invalid_name")


@dataclass(frozen=True, slots=True)
class SnapshotRef:
    repository_id: str
    source_kind: str
    snapshot_id: str
    inventory_sha256: str
    captured_at: str
    resolved_at_ingestion: bool
    coverage: str = "complete_retained_inventory"

    def __post_init__(self):
        valid_name(self.repository_id)
        valid_digest(self.inventory_sha256)
        if self.source_kind not in ("fixture_inventory", "retained_capture"):
            # A plausible Git OID or a source-kind label is never authentication.
            raise CodeIndexError("capture_authority_unavailable")
        if self.source_kind == "fixture_inventory" and self.snapshot_id != self.inventory_sha256:
            raise CodeIndexError("fixture_identity_mismatch")
        if self.source_kind == "retained_capture":
            valid_digest(self.snapshot_id)
        if self.resolved_at_ingestion is not True or self.coverage != "complete_retained_inventory":
            raise CodeIndexError("invalid_capture_scope")
        try:
            if (
                type(self.captured_at) is not str
                or re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", self.captured_at)
                is None
            ):
                raise ValueError
            datetime.fromisoformat(self.captured_at[:-1] + "+00:00")
        except ValueError:
            raise CodeIndexError("invalid_capture_time") from None

    @property
    def source_revision(self):
        return f"snapshot:{self.source_kind}:{self.snapshot_id}"

    def wire(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CodePointer:
    repository_id: str
    source_kind: str
    snapshot_id: str
    inventory_sha256: str
    path: str
    line_start: int
    line_end: int
    source_sha256: str
    definition_kind: str

    def __post_init__(self):
        valid_name(self.repository_id)
        validate_path(self.path)
        valid_digest(self.source_sha256)
        valid_digest(self.inventory_sha256)
        if self.source_kind not in ("fixture_inventory", "retained_capture") or (
            self.source_kind == "fixture_inventory" and self.snapshot_id != self.inventory_sha256
        ):
            raise CodeIndexError("capture_authority_unavailable")
        if self.source_kind == "retained_capture":
            valid_digest(self.snapshot_id)
        if type(self.definition_kind) is not str or self.definition_kind not in KINDS:
            raise CodeIndexError("unsupported_reference_kind")
        if (
            type(self.line_start) is not int
            or type(self.line_end) is not int
            or not 1 <= self.line_start <= self.line_end <= MAX_RAW_BYTES
        ):
            raise CodeIndexError("invalid_line_range")

    def wire(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Definition:
    name: str
    qualified_name: str
    language: str
    pointer: CodePointer
    body_sha256: str

    def __post_init__(self):
        valid_name(self.name)
        valid_name(self.qualified_name)
        valid_name(self.language)
        valid_digest(self.body_sha256)
        if type(self.pointer) is not CodePointer:
            raise CodeIndexError("invalid_definition_pointer")


@dataclass(frozen=True, slots=True)
class SourceCoverage:
    path: str
    source_sha256: str
    language: str
    state: str
    complete_kinds: tuple[str, ...]
    reasons: tuple[str, ...]
    parsed_bytes: int = 0
    nodes_seen: int = 0
    definitions: int = 0

    def __post_init__(self):
        validate_path(self.path)
        valid_digest(self.source_sha256)
        if type(self.language) is not str or self.language not in {
            "python",
            "javascript",
            "typescript",
            "tsx",
            "non_code",
            "unsupported",
        }:
            raise CodeIndexError("invalid_coverage_language")
        if type(self.state) is not str or self.state not in {
            "parsed",
            "definition_limit",
            "empty",
            "binary",
            "invalid_utf8",
            "non_code",
            "unsupported_language",
            "excluded",
            "generated",
            "oversize",
            "parse_budget",
            "parse_error",
            "node_limit",
            "config_parsed",
            "config_partial",
        }:
            raise CodeIndexError("invalid_coverage_state")
        if type(self.complete_kinds) is not tuple or any(
            type(kind) is not str or kind not in KINDS for kind in self.complete_kinds
        ):
            raise CodeIndexError("invalid_coverage_kinds")
        if type(self.reasons) is not tuple or any(
            type(reason) is not str for reason in self.reasons
        ):
            raise CodeIndexError("invalid_coverage_reasons")
        if (
            tuple(sorted(set(self.complete_kinds))) != self.complete_kinds
            or tuple(sorted(set(self.reasons))) != self.reasons
        ):
            raise CodeIndexError("invalid_coverage_order")
        for value in (self.parsed_bytes, self.nodes_seen, self.definitions):
            if type(value) is not int or value < 0:
                raise CodeIndexError("invalid_coverage_count")

    def wire(self):
        value = asdict(self)
        value["complete_kinds"] = list(self.complete_kinds)
        value["reasons"] = list(self.reasons)
        return value


@dataclass(frozen=True, slots=True)
class IndexPolicy:
    version: str = "static-definitions/1"
    max_file_bytes: int = 1024 * 1024
    max_total_parse_bytes: int = 10 * 1024 * 1024
    max_nodes_per_file: int = 50000
    max_definitions: int = 20000
    excluded_prefixes: tuple[str, ...] = (".git/", "node_modules/", "vendor/", "dist/", "build/")

    def __post_init__(self):
        for value, ceiling in (
            (self.max_file_bytes, 1024 * 1024),
            (self.max_total_parse_bytes, MAX_RAW_BYTES),
            (self.max_nodes_per_file, 100000),
            (self.max_definitions, 20000),
        ):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise CodeIndexError("invalid_index_policy")
        if self.version != "static-definitions/1" or type(self.excluded_prefixes) is not tuple:
            raise CodeIndexError("invalid_index_policy")
        for prefix in self.excluded_prefixes:
            if type(prefix) is not str or not prefix.endswith("/"):
                raise CodeIndexError("invalid_index_policy")
            validate_path(prefix[:-1])

    @property
    def sha256(self):
        value = asdict(self)
        value["excluded_prefixes"] = list(self.excluded_prefixes)
        return digest(value)
