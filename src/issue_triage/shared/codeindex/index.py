"""Bounded raw-byte-verified index. Missing coverage never becomes confident uniqueness."""

import codecs
import hashlib
from dataclasses import dataclass, replace

from .canonical import CodeIndexError
from .config_literals import config_format, extract_config_literals
from .inventory import InventoryReader, physical_line_count
from .javascript_literals import extract_javascript_literals
from .models import CodePointer, Definition, IndexPolicy, SnapshotRef, SourceCoverage
from .parser import language_for, parse_definitions
from .python_literals import LITERAL_KINDS, extract_python_literals
from .references import KINDS

DEFAULT_INDEX_POLICY = IndexPolicy()
BASE_KINDS = ("class", "function", "module", "path")


def _pointer(snapshot, entry, kind, first, last):
    return CodePointer(
        snapshot.repository_id,
        snapshot.source_kind,
        snapshot.snapshot_id,
        snapshot.inventory_sha256,
        entry.path,
        first,
        last,
        entry.source_sha256,
        kind,
    )


def _readable_text(data):
    if not data or b"\0" in data:
        return False
    try:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
        for start in range(0, len(data), 65536):
            decoder.decode(data[start : start + 65536], final=False)
        decoder.decode(b"", final=True)
        return True
    except UnicodeError:
        return False


@dataclass(frozen=True, slots=True)
class CodeIndex:
    snapshot: SnapshotRef
    reader: InventoryReader
    policy: IndexPolicy
    definitions: tuple[Definition, ...]
    coverage: tuple[SourceCoverage, ...]

    def resolve(self, reference, prior=None, trusted_mappings=(), *, candidate_policy=None):
        from .resolution import DEFAULT_CANDIDATE_POLICY, resolve_reference

        return resolve_reference(
            self,
            reference,
            prior,
            trusted_mappings,
            DEFAULT_CANDIDATE_POLICY if candidate_policy is None else candidate_policy,
        )

    def exists(self, name, kind=None):
        if type(name) is not str or (
            kind is not None and (type(kind) is not str or kind not in KINDS)
        ):
            return None
        matches = [
            definition
            for definition in self.definitions
            if (kind is None or definition.pointer.definition_kind == kind)
            and name in (definition.name, definition.qualified_name)
        ]
        if len(matches) != 1:
            return None
        needed = (kind,) if kind else tuple(sorted(KINDS))
        if not all(set(needed) <= set(row.complete_kinds) for row in self.coverage):
            return None
        return matches[0].pointer


def build_index(snapshot, reader, policy=DEFAULT_INDEX_POLICY):
    if (
        type(snapshot) is not SnapshotRef
        or type(reader) is not InventoryReader
        or type(policy) is not IndexPolicy
    ):
        raise CodeIndexError("invalid_index_input")
    if reader.inventory.sha256 != snapshot.inventory_sha256:
        raise CodeIndexError("snapshot_inventory_mismatch")
    definitions, coverage, total_parsed = [], [], 0
    framework_modules = {"fastapi", "flask", "argparse", "click", "os"}
    blocked = set()
    for entry in reader.inventory.files:
        if entry.path.endswith(".py"):
            components = entry.path[:-3].split("/")
            blocked.update(set(components) & framework_modules)
    for entry in reader.inventory.files:
        data = reader.read(entry.path)
        if (
            len(data) != entry.byte_length
            or hashlib.sha256(data).hexdigest() != entry.source_sha256
        ):
            raise CodeIndexError("retained_source_mismatch")
        language = language_for(entry.path)
        reasons = {"literal_extractors_pending"}
        complete = set()
        state = "parsed"
        parsed_bytes = nodes = 0
        before = len(definitions)
        text_readable = _readable_text(data)
        if len(definitions) >= policy.max_definitions:
            state = "definition_limit"
        elif not text_readable:
            state = "empty" if not data else ("binary" if b"\0" in data else "invalid_utf8")
            complete.add("path")  # Inventory knows presence, but supplies no text pointer.
            if language == "non_code":
                complete.update(BASE_KINDS)
                if not data and config_format(entry.path) in {"env", "toml"}:
                    complete.add("config_key")
                if not data:
                    complete.update({"cli_flag", "http_route"})
            elif not data and language in {"python", "javascript", "typescript", "tsx"}:
                # Empty retained source contains no named function/class definitions, yet has
                # no physical line for a file/module pointer. These are separate facts.
                complete.update({"function", "class"})
                complete.update(LITERAL_KINDS)
        else:
            complete.add("path")
            definitions.append(
                Definition(
                    entry.path,
                    entry.path,
                    language,
                    _pointer(snapshot, entry, "path", 1, 1),
                    entry.source_sha256,
                )
            )
            if config_format(entry.path) is not None:
                complete.update(BASE_KINDS)
                if any(entry.path.startswith(prefix) for prefix in policy.excluded_prefixes):
                    state = "excluded"
                elif b"@generated" in data[:2048] or b"DO NOT EDIT" in data[:2048]:
                    state = "generated"
                elif len(data) > policy.max_file_bytes:
                    state = "oversize"
                elif total_parsed + len(data) > policy.max_total_parse_bytes:
                    state = "parse_budget"
                else:
                    parsed_bytes = len(data)
                    total_parsed += parsed_bytes
                    result = extract_config_literals(data, entry.path, policy)
                    nodes = result.nodes_seen
                    reasons.update(result.reasons)
                    state = "config_parsed" if result.complete else "config_partial"
                    room = policy.max_definitions - len(definitions)
                    additions = [
                        Definition(
                            item.name,
                            item.name,
                            "non_code",
                            _pointer(snapshot, entry, "config_key", item.line_start, item.line_end),
                            entry.source_sha256,
                        )
                        for item in result.literals
                    ]
                    definitions.extend(additions[:room])
                    if len(additions) > room:
                        state = "definition_limit"
                    elif result.complete:
                        complete.add("config_key")
                        complete.add("cli_flag")
                        if any(item.name in {"openapi", "swagger"} for item in result.literals):
                            reasons.add("unsupported_openapi_routes")
                        else:
                            complete.add("http_route")
            elif language == "non_code":
                state = "non_code"
                complete.update(BASE_KINDS)
                if not entry.path.endswith((".yaml", ".yml", ".ini", ".cfg")):
                    complete.update(LITERAL_KINDS)
            elif language == "unsupported":
                state = "unsupported_language"
            elif any(entry.path.startswith(prefix) for prefix in policy.excluded_prefixes):
                state = "excluded"
            elif b"@generated" in data[:2048] or b"DO NOT EDIT" in data[:2048]:
                state = "generated"
            elif len(data) > policy.max_file_bytes:
                state = "oversize"
            elif total_parsed + len(data) > policy.max_total_parse_bytes:
                state = "parse_budget"
            else:
                parsed_bytes = len(data)
                total_parsed += parsed_bytes
                parsed = parse_definitions(data, language, policy)
                nodes = parsed.nodes_seen
                reasons.update(parsed.reasons)
                if "parse_error" in parsed.reasons:
                    state = "parse_error"
                else:
                    module = entry.path.rsplit(".", 1)[0].replace("/", ".")
                    if language == "python" and module.endswith(".__init__"):
                        module = module[:-9]
                    additions = [
                        Definition(
                            module.rsplit(".", 1)[-1],
                            module,
                            language,
                            _pointer(snapshot, entry, "module", 1, 1),
                            entry.source_sha256,
                        )
                    ]
                    additions.extend(
                        Definition(
                            item.name,
                            ".".join((module, *item.qualifiers, item.name)),
                            language,
                            _pointer(snapshot, entry, item.kind, item.line_start, item.line_end),
                            item.body_sha256,
                        )
                        for item in parsed.definitions
                    )
                    room = policy.max_definitions - len(definitions)
                    definitions.extend(additions[:room])
                    if len(additions) > room or "definition_limit" in parsed.reasons:
                        state = "definition_limit"
                    elif "node_limit" in parsed.reasons:
                        state = "node_limit"
                    elif parsed.complete:
                        complete.update(BASE_KINDS)
                    else:
                        complete.add("module")
                    if (
                        language in {"python", "javascript", "typescript", "tsx"}
                        and state == "parsed"
                    ):
                        remaining_nodes = policy.max_nodes_per_file - nodes
                        remaining_definitions = policy.max_definitions - len(definitions)
                        if remaining_nodes <= 0:
                            state = "node_limit"
                            reasons.add("literal_node_limit")
                        elif remaining_definitions <= 0:
                            state = "definition_limit"
                        elif total_parsed + len(data) > policy.max_total_parse_bytes:
                            state = "parse_budget"
                            reasons.add("literal_parse_budget")
                        else:
                            literal_policy = replace(
                                policy,
                                max_nodes_per_file=remaining_nodes,
                                max_definitions=remaining_definitions,
                            )
                            literal = (
                                extract_python_literals(data, literal_policy, blocked)
                                if language == "python"
                                else extract_javascript_literals(data, language, literal_policy)
                            )
                            total_parsed += len(data)
                            parsed_bytes += len(data)
                            nodes += literal.nodes_seen
                            reasons.update(literal.reasons)
                            complete.update(literal.complete_kinds)
                            definitions.extend(
                                Definition(
                                    item.name,
                                    item.name,
                                    language,
                                    _pointer(
                                        snapshot, entry, item.kind, item.line_start, item.line_end
                                    ),
                                    entry.source_sha256,
                                )
                                for item in literal.literals
                            )
        if set(LITERAL_KINDS) <= complete:
            reasons.discard("literal_extractors_pending")
        if state != "parsed":
            reasons.add(state)
        coverage.append(
            SourceCoverage(
                entry.path,
                entry.source_sha256,
                language,
                state,
                tuple(sorted(complete)),
                tuple(sorted(reasons)),
                parsed_bytes,
                nodes,
                len(definitions) - before,
            )
        )
    return CodeIndex(snapshot, reader, policy, tuple(definitions), tuple(coverage))


def resolve_pointer(pointer, snapshot, reader):
    if (
        type(pointer) is not CodePointer
        or type(snapshot) is not SnapshotRef
        or type(reader) is not InventoryReader
    ):
        return "unsupported"
    if (
        pointer.repository_id,
        pointer.source_kind,
        pointer.snapshot_id,
        pointer.inventory_sha256,
    ) != (
        snapshot.repository_id,
        snapshot.source_kind,
        snapshot.snapshot_id,
        snapshot.inventory_sha256,
    ) or reader.inventory.sha256 != snapshot.inventory_sha256:
        return "stale"
    entry = next((entry for entry in reader.inventory.files if entry.path == pointer.path), None)
    if entry is None or entry.source_sha256 != pointer.source_sha256:
        return "stale"
    data = reader.read(pointer.path)
    if len(data) != entry.byte_length or hashlib.sha256(data).hexdigest() != pointer.source_sha256:
        return "stale"
    if not _readable_text(data):
        return "unsupported"
    if pointer.line_end > physical_line_count(data):
        return "stale"
    return "verified"
