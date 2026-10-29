"""Explicit source mentions, original UTF-8 intervals and occurrence-specific query identity."""

import hashlib
import re
from dataclasses import asdict, dataclass, field

from .canonical import CodeIndexError, digest
from .inventory import validate_path

KINDS = frozenset({"path", "module", "function", "class", "cli_flag", "http_route", "config_key"})
LANGUAGES = frozenset({"python", "javascript", "typescript", "tsx"})


def _text(value, *, nullable=False, max_bytes=4096):
    if value is None and nullable:
        return
    if type(value) is not str or not value:
        raise CodeIndexError("invalid_reference_text")
    try:
        if len(value.encode("utf-8", errors="strict")) > max_bytes:
            raise CodeIndexError("reference_text_limit")
    except UnicodeError:
        raise CodeIndexError("invalid_utf8") from None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise CodeIndexError("invalid_reference_text")


@dataclass(frozen=True, slots=True)
class Query:
    kind: str
    normalized_query: str
    language_hint: str | None = None
    path_hint: str | None = None
    qualifier_hint: str | None = None

    def __post_init__(self):
        if type(self.kind) is not str or self.kind not in KINDS:
            raise CodeIndexError("unsupported_reference_kind")
        _text(self.normalized_query)
        if self.language_hint is not None and (
            type(self.language_hint) is not str or self.language_hint not in LANGUAGES
        ):
            raise CodeIndexError("unsupported_reference_language")
        _text(self.qualifier_hint, nullable=True)
        if self.path_hint is not None:
            validate_path(self.path_hint)
        if self.kind == "path":
            validate_path(self.normalized_query)

    def wire(self):
        # Explicit nulls are part of Query v1's preimage.
        return asdict(self)

    @property
    def sha256(self):
        return digest(self.wire())


@dataclass(frozen=True, slots=True)
class Reference:
    schema_version: int
    id: str
    kind: str
    verbatim: str = field(repr=False)
    original_start_byte: int
    original_end_byte: int
    normalized_query: str
    language_hint: str | None = None
    path_hint: str | None = None
    qualifier_hint: str | None = None

    def __post_init__(self):
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise CodeIndexError("unsupported_reference_schema")
        if type(self.id) is not str or not re.fullmatch(r"[0-9a-f]{64}", self.id):
            raise CodeIndexError("invalid_reference_id")
        _text(self.verbatim)
        if (
            type(self.original_start_byte) is not int
            or type(self.original_end_byte) is not int
            or not 0 <= self.original_start_byte < self.original_end_byte <= 2 * 1024 * 1024
            or self.original_end_byte - self.original_start_byte
            != len(self.verbatim.encode("utf-8"))
        ):
            raise CodeIndexError("invalid_reference_offset")
        _ = self.query  # Validate the same closed query fields without another serialized truth.

    @property
    def query(self):
        return Query(
            self.kind,
            self.normalized_query,
            self.language_hint,
            self.path_hint,
            self.qualifier_hint,
        )

    def wire(self):
        return asdict(self)

    def validates_original(self, original_text):
        try:
            data = original_text.encode("utf-8", errors="strict")
            return data[self.original_start_byte : self.original_end_byte].decode(
                "utf-8"
            ) == self.verbatim and self.id == reference_id(
                hashlib.sha256(data).hexdigest(),
                self.original_start_byte,
                self.original_end_byte,
                self.query.sha256,
            )
        except (UnicodeError, AttributeError):
            return False


def reference_id(input_sha256, start, end, query_sha256):
    return digest(
        {
            "input_sha256": input_sha256,
            "original_start_byte": start,
            "original_end_byte": end,
            "query_sha256": query_sha256,
        }
    )


@dataclass(frozen=True, slots=True)
class ExtractionPolicy:
    version: str = "explicit-reference/1"
    max_references: int = 128
    max_input_bytes: int = 2 * 1024 * 1024

    def __post_init__(self):
        if (
            self.version != "explicit-reference/1"
            or type(self.max_references) is not int
            or not 1 <= self.max_references <= 128
            or type(self.max_input_bytes) is not int
            or not 1 <= self.max_input_bytes <= 2 * 1024 * 1024
        ):
            raise CodeIndexError("invalid_extraction_policy")

    @property
    def sha256(self):
        return digest(asdict(self))


# Earlier patterns own overlapping intervals. Delimiters and explicit syntax keep ordinary prose
# from becoming a symbol. Query normalization removes only syntax, preserving exact case/Unicode.
PATTERNS = (
    (
        "http_route",
        re.compile(
            r"\b(?P<value>(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)[ \t]+"
            r"(?P<route>/[^\s`\"'<>]{0,4095}))",
            re.I,
        ),
    ),
    (
        "path",
        re.compile(
            r"(?<![\w./:\\-])(?P<value>(?:[\w.-]+/)*[\w.-]+\."
            r"(?:py|js|ts|tsx|jsx|json|toml|yaml|yml|ini|cfg|md|sh))(?![\w.-])"
        ),
    ),
    ("cli_flag", re.compile(r"(?<![\w-])(?P<value>--[A-Za-z][A-Za-z0-9_-]*|-[A-Za-z])(?![\w-])")),
    (
        "config_key",
        re.compile(
            r"(?i:\b(?:config(?: key)?|env(?:ironment variable)?)[ \t]+)"
            r"[`\"'](?P<value>[A-Za-z_][A-Za-z0-9_.-]*)[`\"']"
        ),
    ),
    (
        "config_key",
        re.compile(
            r"(?i:\b(?:config(?: key)?|env(?:ironment variable)?)[ \t]+)"
            r"(?P<value>[A-Z][A-Z0-9_]*)(?![\w])"
        ),
    ),
    ("config_key", re.compile(r"`(?P<value>[A-Z][A-Z0-9]*_[A-Z0-9_]+)`")),
    (
        "module",
        re.compile(r"(?i:\bmodule[ \t]+)(?:`(?P<quoted>[\w.]+)`|(?P<dotted>\w+(?:\.\w+)+))"),
    ),
    ("class", re.compile(r"(?i:\bclass[ \t]+)(?:`(?P<quoted>\w+)`|(?P<named>[A-Z]\w*))")),
    ("function", re.compile(r"(?<![\w.])(?P<value>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\(\))")),
)


DEFAULT_EXTRACTION_POLICY = ExtractionPolicy()


def extract_references(original_text: str, policy: ExtractionPolicy = DEFAULT_EXTRACTION_POLICY):
    if type(original_text) is not str or type(policy) is not ExtractionPolicy:
        raise CodeIndexError("invalid_reference_input")
    try:
        raw = original_text.encode("utf-8", errors="strict")
    except UnicodeError:
        raise CodeIndexError("invalid_utf8") from None
    if len(raw) > policy.max_input_bytes:
        raise CodeIndexError("reference_input_limit")
    input_sha = hashlib.sha256(raw).hexdigest()
    selected = []
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(original_text):
            group = next(
                (
                    name
                    for name in ("value", "quoted", "dotted", "named")
                    if name in match.re.groupindex and match.group(name) is not None
                ),
                None,
            )
            start, end = match.span(group)
            if any(start < old_end and end > old_start for old_start, old_end, *_ in selected):
                continue
            verbatim = original_text[start:end]
            normalized = verbatim
            qualifier = None
            if kind == "http_route":
                route = match.group("route")
                quoted = (
                    start > 0
                    and end < len(original_text)
                    and original_text[start - 1] in "`\"'"
                    and original_text[end] == original_text[start - 1]
                )
                if not quoted:
                    clean = route.rstrip(".,;)]")
                    end -= len(route) - len(clean)
                    route = clean
                    verbatim = original_text[start:end]
                normalized = match.group("method").upper() + " " + route
            elif kind == "function":
                normalized = verbatim[:-2]
                qualifier = normalized.rpartition(".")[0] or None
            query = Query(kind, normalized, qualifier_hint=qualifier)
            selected.append((start, end, verbatim, query))
            if len(selected) > policy.max_references:
                raise CodeIndexError("reference_count_limit")
    # One linear char->UTF8-byte map; repeated Unicode prefixes do not cause quadratic slicing.
    offsets = [0]
    for char in original_text:
        offsets.append(offsets[-1] + len(char.encode("utf-8")))
    references = []
    for start, end, verbatim, query in sorted(selected, key=lambda item: (item[0], item[1])):
        left, right = offsets[start], offsets[end]
        references.append(
            Reference(
                1,
                reference_id(input_sha, left, right, query.sha256),
                query.kind,
                verbatim,
                left,
                right,
                query.normalized_query,
                query.language_hint,
                query.path_hint,
                query.qualifier_hint,
            )
        )
    return references
