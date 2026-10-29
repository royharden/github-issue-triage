"""Bounded config-key declarations, never evaluated values or executed environment files."""

import bisect
import json
import re
import shlex
import tomllib
from dataclasses import dataclass

from .canonical import CodeIndexError
from .inventory import validate_path
from .models import IndexPolicy, valid_name

CONFIG_EXTRACTOR_VERSION = "literal-json-toml-env/1;python-stdlib/3.12"


@dataclass(frozen=True, slots=True)
class ConfigLiteral:
    name: str
    line_start: int
    line_end: int


@dataclass(frozen=True, slots=True)
class ConfigResult:
    literals: tuple[ConfigLiteral, ...]
    complete: bool
    reasons: tuple[str, ...]
    nodes_seen: int


class _Limited(ValueError):
    pass


def config_format(path):
    name = path.rsplit("/", 1)[-1]
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return "env"
    suffix = name.rsplit(".", 1)[-1]
    return suffix if suffix in {"json", "toml"} else None


def _joined(parts):
    result = ""
    for part in parts:
        if part == "":
            # An unsupported empty parent must not collapse its children into root keys.
            return "\0"
        if type(part) is int:
            result += f"[{part}]"
        else:
            result += ("." if result else "") + part
    return result


class _Collector:
    def __init__(self, policy, text):
        self.policy, self.text = policy, text
        self.facts, self.reasons, self.nodes = [], set(), 0
        self.newlines = [match.start() for match in re.finditer("\n", text)]

    def step(self, depth=0):
        if self.nodes >= self.policy.max_nodes_per_file or depth > 64:
            raise _Limited("config_structure_limit")
        self.nodes += 1

    def add(self, name, first, last=None):
        if len(self.facts) >= self.policy.max_definitions:
            raise _Limited("config_definition_limit")
        try:
            valid_name(name)
        except CodeIndexError:
            self.reasons.add("unsupported_config_key")
            return
        self.facts.append(ConfigLiteral(name, first, last or first))

    def line(self, offset):
        return bisect.bisect_right(self.newlines, offset) + 1

    def result(self):
        return ConfigResult(
            tuple(self.facts), not self.reasons, tuple(sorted(self.reasons)), self.nodes
        )


def _json_keys(collector):
    text = collector.text

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise _Limited("duplicate_config_key")
            result[key] = value
        return result

    def forbidden(_):
        raise _Limited("invalid_config_json")

    # Validate the whole document first. Numeric values need no conversion or evaluation.
    value = json.loads(
        text,
        object_pairs_hook=unique,
        parse_float=lambda _: None,
        parse_int=lambda _: None,
        parse_constant=forbidden,
    )
    if type(value) is not dict:
        raise _Limited("unsupported_config_shape")

    def whitespace(position):
        while position < len(text) and text[position] in " \t\r\n":
            position += 1
        return position

    def parse(position, parts, depth):
        collector.step(depth)
        position = whitespace(position)
        char = text[position]
        if char == "{":
            position = whitespace(position + 1)
            while text[position] != "}":
                start = position
                key, position = json.decoder.scanstring(text, position + 1, True)
                position = whitespace(position)
                name = (*parts, key)
                collector.add(_joined(name), collector.line(start), collector.line(position))
                position = whitespace(parse(position + 1, name, depth + 1))
                if text[position] == "}":
                    break
                position = whitespace(position + 1)
            return position + 1
        if char == "[":
            position, index = whitespace(position + 1), 0
            while text[position] != "]":
                position = whitespace(parse(position, (*parts, index), depth + 1))
                index += 1
                if text[position] == "]":
                    break
                position = whitespace(position + 1)
            return position + 1
        if char == '"':
            _, position = json.decoder.scanstring(text, position + 1, True)
            return position
        while position < len(text) and text[position] not in ",]} \t\r\n":
            position += 1
        return position

    parse(0, (), 0)


BARE_KEY = r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*"
TABLE = re.compile(r"^\s*\[(" + BARE_KEY + r")\]\s*(?:#.*)?$")
ASSIGNMENT = re.compile(r"^\s*(" + BARE_KEY + r")\s*=")


def _toml_keys(collector):
    text = collector.text
    parsed = tomllib.loads(text)
    if '"""' in text or "'''" in text:
        raise _Limited("unsupported_multiline_toml")
    table, recorded = (), set()

    def add_parts(parts, line):
        current = parsed
        for count, part in enumerate(parts, 1):
            if type(current) is not dict or part not in current:
                collector.reasons.add("unsupported_toml_key")
                return
            current = current[part]
            name = _joined(parts[:count])
            if name not in recorded:
                collector.add(name, line)
                recorded.add(name)

    for line, raw in enumerate(text.split("\n"), 1):
        collector.step()
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        header = TABLE.fullmatch(raw)
        if header:
            table = tuple(header.group(1).split("."))
            add_parts(table, line)
            continue
        if raw.lstrip().startswith("["):
            table = None
            collector.reasons.add("unsupported_toml_table")
            continue
        key = ASSIGNMENT.match(raw)
        if key is None or table is None:
            collector.reasons.add("unsupported_toml_key")
            continue
        add_parts((*table, *key.group(1).split(".")), line)
        # Inline table keys have distinct locations; never invent their lines from the outer key.
        if "{" in raw or "}" in raw:
            collector.reasons.add("unsupported_toml_inline_table")


ENV_KEY = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def _env_keys(collector):
    for line, raw in enumerate(collector.text.split("\n"), 1):
        collector.step()
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        try:
            shlex.split(raw, comments=True, posix=True)
        except ValueError:
            # A following physical line may be data inside an unsupported multiline value.
            collector.facts.clear()
            raise _Limited("unsupported_multiline_env") from None
        key = ENV_KEY.match(raw)
        if key is None:
            collector.reasons.add("unsupported_env_declaration")
        else:
            collector.add(key.group(1), line)


def extract_config_literals(data, path, policy):
    if (
        type(data) is not bytes
        or type(policy) is not IndexPolicy
        or len(data) > policy.max_file_bytes
    ):
        raise CodeIndexError("config_input_limit")
    validate_path(path)
    if b"\0" in data:
        return ConfigResult((), False, ("invalid_config_encoding",), 0)
    profile = config_format(path)
    if profile is None:
        return ConfigResult((), False, ("unsupported_config_format",), 0)
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        return ConfigResult((), False, ("invalid_config_utf8",), 0)
    collector = _Collector(policy, text)
    try:
        {"json": _json_keys, "toml": _toml_keys, "env": _env_keys}[profile](collector)
    except _Limited as error:
        collector.reasons.add(str(error))  # Only locally authored closed constants reach this type.
    except (ValueError, IndexError, RecursionError):
        collector.facts.clear()
        collector.reasons.add("config_parse_error")
    return collector.result()
