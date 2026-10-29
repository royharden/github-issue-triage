"""Pinned grammar syntax only. Never import, compile or execute the retained repository."""

import hashlib
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from importlib.metadata import version

from .canonical import CodeIndexError
from .config_literals import CONFIG_EXTRACTOR_VERSION
from .javascript_literals import JAVASCRIPT_LITERAL_VERSION
from .models import IndexPolicy
from .python_literals import PYTHON_LITERAL_VERSION

PARSER_VERSION = "tree-sitter/0.26.0;python/0.25.0;javascript/0.25.0;typescript/0.23.2"
EXTRACTOR_VERSION = (
    "static-named-definitions/1;"
    + CONFIG_EXTRACTOR_VERSION
    + ";"
    + PYTHON_LITERAL_VERSION
    + ";"
    + JAVASCRIPT_LITERAL_VERSION
)
EXTENSIONS = {
    "py": "python",
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "tsx": "tsx",
}
NON_CODE = frozenset(
    {
        "md",
        "txt",
        "rst",
        "json",
        "toml",
        "yaml",
        "yml",
        "ini",
        "cfg",
        "lock",
        "env",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "bin",
        "csv",
    }
)


def language_for(path):
    name = path.rsplit("/", 1)[-1]
    if name == ".env" or name.startswith(".env."):
        return "non_code"
    suffix = path.rsplit("/", 1)[-1].rsplit(".", 1)[-1]
    return EXTENSIONS.get(suffix, "non_code" if suffix in NON_CODE else "unsupported")


@lru_cache(maxsize=4)
def _language(name):
    from tree_sitter import Language

    expected = {
        "tree-sitter": "0.26.0",
        "tree-sitter-python": "0.25.0",
        "tree-sitter-javascript": "0.25.0",
        "tree-sitter-typescript": "0.23.2",
    }
    if any(version(package) != pinned for package, pinned in expected.items()):
        raise CodeIndexError("parser_version_mismatch")

    if name == "python":
        import tree_sitter_python

        return Language(tree_sitter_python.language())
    if name == "javascript":
        import tree_sitter_javascript

        return Language(tree_sitter_javascript.language())
    if name in ("typescript", "tsx"):
        import tree_sitter_typescript

        factory = (
            tree_sitter_typescript.language_tsx
            if name == "tsx"
            else tree_sitter_typescript.language_typescript
        )
        return Language(factory())
    raise CodeIndexError("unsupported_language")


@dataclass(frozen=True, slots=True)
class ParsedDefinition:
    name: str
    qualifiers: tuple[str, ...]
    kind: str
    line_start: int
    line_end: int
    body_sha256: str


@dataclass(frozen=True, slots=True)
class ParseResult:
    definitions: tuple[ParsedDefinition, ...]
    nodes_seen: int
    complete: bool
    reasons: tuple[str, ...]


def parse_definitions(data: bytes, language: str, policy: IndexPolicy) -> ParseResult:
    from tree_sitter import Parser

    if (
        type(data) is not bytes
        or type(policy) is not IndexPolicy
        or len(data) > policy.max_file_bytes
    ):
        raise CodeIndexError("parser_input_limit")
    try:
        tree = Parser(_language(language)).parse(data)
    except Exception:
        raise CodeIndexError("parser_unavailable") from None
    if tree.root_node.has_error:
        return ParseResult((), 0, False, ("parse_error",))
    definitions, reasons, seen = [], set(), 0
    stack = [(tree.root_node, (), False)]
    callable_values = {"arrow_function", "function_expression", "generator_function", "lambda"}
    class_values = {"class"}
    while stack:
        if seen >= policy.max_nodes_per_file:
            reasons.add("node_limit")
            break
        node, qualifiers, inside_class = stack.pop()
        seen += 1
        name_node, kind = None, None
        if node.type in {
            "function_definition",
            "function_declaration",
            "generator_function_declaration",
        }:
            name_node, kind = node.child_by_field_name("name"), "function"
        elif node.type in {"class_definition", "class_declaration"}:
            name_node, kind = node.child_by_field_name("name"), "class"
        elif node.type in {"function_expression", "generator_function", "class"}:
            name_node = node.child_by_field_name("name")
            kind = "class" if node.type == "class" else "function"
        elif node.type == "method_definition":
            candidate = node.child_by_field_name("name")
            if (
                inside_class
                and candidate is not None
                and candidate.type
                in {"identifier", "property_identifier", "private_property_identifier"}
            ):
                name_node, kind = candidate, "function"
            else:
                reasons.add("dynamic_or_object_method")
        elif node.type in {"variable_declarator", "assignment"}:
            candidate = node.child_by_field_name(
                "name" if node.type == "variable_declarator" else "left"
            )
            value = node.child_by_field_name(
                "value" if node.type == "variable_declarator" else "right"
            )
            if value is not None and value.type in callable_values | class_values:
                if candidate is not None and candidate.type == "identifier":
                    name_node = candidate
                    kind = "class" if value.type in class_values else "function"
                else:
                    reasons.add("dynamic_callable_binding")
        elif node.type in {"field_definition", "public_field_definition", "pair"}:
            value = node.child_by_field_name("value")
            if value is not None and value.type in callable_values | class_values:
                candidate = node.child_by_field_name("property") or node.child_by_field_name("name")
                if (
                    inside_class
                    and candidate is not None
                    and candidate.type in {"property_identifier", "private_property_identifier"}
                ):
                    name_node, kind = (
                        candidate,
                        "class" if value.type in class_values else "function",
                    )
                else:
                    reasons.add("dynamic_callable_binding")
        if node.type in {"call", "call_expression", "new_expression"}:
            target = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            if target is not None:
                spelling = data[target.start_byte : target.end_byte]
                if spelling in {
                    b"exec",
                    b"eval",
                    b"setattr",
                    b"type",
                    b"Function",
                    b"Object.assign",
                    b"Object.defineProperty",
                    b"Reflect.defineProperty",
                    b"globals().update",
                    b"locals().update",
                }:
                    reasons.add("dynamic_definitions")
        if node.type == "assignment_expression":
            value = node.child_by_field_name("right")
            if value is not None and value.type in callable_values | class_values:
                reasons.add("dynamic_callable_binding")
        following = qualifiers
        following_class = inside_class
        if name_node is not None:
            name = data[name_node.start_byte : name_node.end_byte].decode("utf-8", errors="strict")
            if "\\" in name or unicodedata.normalize("NFKC", name) != name:
                reasons.add("unsupported_identifier_spelling")
            end_row, end_column = node.end_point
            definitions.append(
                ParsedDefinition(
                    name,
                    qualifiers,
                    kind,
                    node.start_point.row + 1,
                    end_row if end_column == 0 else end_row + 1,
                    hashlib.sha256(data[node.start_byte : node.end_byte]).hexdigest(),
                )
            )
            following = (*qualifiers, name)
            following_class = kind == "class"
            if len(definitions) >= policy.max_definitions:
                reasons.add("definition_limit")
                break
        for child in reversed(node.named_children):
            stack.append((child, following, following_class))
    return ParseResult(tuple(definitions), seen, not reasons, tuple(sorted(reasons)))
