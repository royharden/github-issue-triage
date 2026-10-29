"""Bounded static registration occurrences; never load captured JS or its dependencies."""

import re
from collections import Counter
from dataclasses import dataclass

from .canonical import CodeIndexError
from .models import IndexPolicy, valid_name

JAVASCRIPT_LITERAL_VERSION = "tree-sitter-literal-express-commander-env/1"
KINDS = ("cli_flag", "config_key", "http_route")
METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})
FLAG = re.compile(r"(?:--[A-Za-z][A-Za-z0-9_-]*|-[A-Za-z0-9])\Z")


@dataclass(frozen=True, slots=True)
class JavascriptLiteral:
    name: str
    kind: str
    line_start: int
    line_end: int


@dataclass(frozen=True, slots=True)
class JavascriptLiteralResult:
    literals: tuple[JavascriptLiteral, ...]
    complete_kinds: tuple[str, ...]
    reasons: tuple[str, ...]
    nodes_seen: int


def extract_javascript_literals(data, language, policy):
    from tree_sitter import Parser

    from .parser import _language

    if (
        type(data) is not bytes
        or type(policy) is not IndexPolicy
        or len(data) > policy.max_file_bytes
        or language not in {"javascript", "typescript", "tsx"}
    ):
        raise CodeIndexError("literal_input_limit")
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeError:
        return JavascriptLiteralResult((), (), ("literal_invalid_utf8",), 0)
    tree = Parser(_language(language)).parse(data)
    if tree.root_node.has_error:
        return JavascriptLiteralResult((), (), ("literal_parse_error",), 0)
    nodes, stack = [], [tree.root_node]
    while stack:
        if len(nodes) >= policy.max_nodes_per_file:
            return JavascriptLiteralResult((), (), ("literal_node_limit",), len(nodes))
        node = stack.pop()
        nodes.append(node)
        stack.extend(reversed(node.named_children))
    complete, reasons, facts = set(KINDS), set(), []

    def hold(kind, reason):
        complete.discard(kind)
        reasons.add(kind + "_" + reason)

    def text(node):
        return data[node.start_byte : node.end_byte].decode() if node else ""

    def string(node):
        if node is None or node.type != "string":
            return None
        raw = text(node)
        # Escapes/template interpolation are explicitly unsupported, never guessed or executed.
        if len(raw) < 2 or raw[0] not in "\"'" or raw[-1] != raw[0] or "\\" in raw:
            return None
        return raw[1:-1]

    def chain(node):
        if node is None:
            return ()
        if node.type in {"identifier", "property_identifier"}:
            spelling = text(node)
            return (spelling,) if "\\" not in spelling else ()
        if node.type == "member_expression":
            left = chain(node.child_by_field_name("object"))
            right = chain(node.child_by_field_name("property"))
            return left + right if left and right else ()
        return ()

    def module_level(node):
        parent = node.parent
        while parent is not None:
            if parent.type not in {
                "program",
                "lexical_declaration",
                "variable_declaration",
                "export_statement",
                "import_clause",
                "named_imports",
                "import_statement",
            }:
                return False
            parent = parent.parent
        return True

    def assignment_parts(target):
        parts = chain(target)
        if target and target.type == "subscript_expression":
            parent = chain(target.child_by_field_name("object"))
            key = string(target.child_by_field_name("index"))
            if len(parent) == 2 and parent[1] == "env" and key is not None:
                return (*parent, key)
        return parts

    def args(node):
        value = node.child_by_field_name("arguments")
        return value.named_children if value else []

    counts, declarations, imports = Counter(), [], []
    invalid, mutated, non_env_mutated = set(), set(), set()
    for node in nodes:
        if node.type in {"arrow_function", "catch_clause", "for_in_statement"}:
            target = (
                node.child_by_field_name("parameter")
                or node.child_by_field_name("parameters")
                or node.child_by_field_name("left")
            )
            pending = [target] if target else []
            while pending:
                child = pending.pop()
                if child.type in {"identifier", "shorthand_property_identifier_pattern"}:
                    invalid.add(text(child))
                pending.extend(child.named_children)
        if node.type == "unary_expression" and text(node).startswith("delete "):
            parts = chain(node.child_by_field_name("argument"))
            if parts:
                mutated.add(parts[0])
                non_env_mutated.add(parts[0])
        if node.type in {"identifier", "property_identifier"} and "\\" in text(node):
            for kind in KINDS:
                hold(kind, "escaped_identifier")
        if node.type == "import_statement":
            source = string(node.child_by_field_name("source"))
            clause = next(
                (child for child in node.named_children if child.type == "import_clause"), None
            )
            if source is None:
                for kind in KINDS:
                    hold(kind, "dynamic_import")
            if source in {"fastify", "koa", "@koa/router", "hono", "next", "restify"}:
                hold("http_route", "unsupported_framework")
            if source in {"yargs", "minimist", "arg", "meow", "@commander-js/extra-typings"}:
                hold("cli_flag", "unsupported_framework")
            if clause:
                for child in clause.named_children:
                    if child.type == "identifier":
                        name = text(child)
                        counts[name] += 1
                        imports.append((name, source, "default"))
                    elif child.type == "named_imports":
                        for spec in child.named_children:
                            local = spec.child_by_field_name("alias") or spec.child_by_field_name(
                                "name"
                            )
                            name = text(local)
                            counts[name] += 1
                            imports.append((name, source, text(spec.child_by_field_name("name"))))
                    else:
                        for kind in KINDS:
                            hold(kind, "unsupported_import_binding")
        elif node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            if name and name.type == "identifier":
                spelling = text(name)
                counts[spelling] += 1
                declarations.append((spelling, node.child_by_field_name("value"), node))
                if not module_level(node):
                    invalid.add(spelling)
            else:
                for kind in KINDS:
                    hold(kind, "destructuring_binding")
                # Every identifier in a binding pattern can shadow a framework/global.
                pending = [name] if name else []
                while pending:
                    child = pending.pop()
                    if child.type in {"identifier", "shorthand_property_identifier_pattern"}:
                        invalid.add(text(child))
                    pending.extend(child.named_children)
        elif node.type in {"formal_parameters", "required_parameter", "optional_parameter"}:
            pending = list(node.named_children)
            while pending:
                child = pending.pop()
                if child.type in {"identifier", "shorthand_property_identifier_pattern"}:
                    invalid.add(text(child))
                pending.extend(child.named_children)
        elif node.type in {"function_declaration", "class_declaration", "catch_clause"}:
            name = node.child_by_field_name("name") or node.child_by_field_name("parameter")
            if name:
                invalid.add(text(name))
        elif node.type in {
            "assignment_expression",
            "augmented_assignment_expression",
            "update_expression",
        }:
            target = node.child_by_field_name("left") or node.child_by_field_name("argument")
            parts = assignment_parts(target)
            if len(parts) == 1:
                invalid.add(parts[0])
            elif parts:
                mutated.add(parts[0])
                if len(parts) != 3 or parts[1] != "env":
                    non_env_mutated.add(parts[0])
            else:
                pending = [target] if target else []
                while pending:
                    child = pending.pop()
                    if child.type in {"identifier", "shorthand_property_identifier_pattern"}:
                        invalid.add(text(child))
                    pending.extend(child.named_children)
                for kind in KINDS:
                    hold(kind, "dynamic_assignment")
    invalid.update(name for name, count in counts.items() if count != 1)
    bindings = {}
    for name, source, member in imports:
        if name in invalid:
            continue
        if source == "express" and member in {"default", "Router"}:
            bindings[name] = ("express_factory" if member == "default" else "router_factory", name)
        elif source == "commander" and member in {"Command", "program"}:
            bindings[name] = ("command_factory" if member == "Command" else "command", name)
        elif source == "node:process" and member == "default":
            bindings[name] = ("process", name)

    def value(node):
        parts = chain(node)
        if len(parts) == 1:
            return bindings.get(parts[0])
        if len(parts) == 2 and parts[-1] == "Router":
            parent = bindings.get(parts[0])
            if parent and parent[0] == "express_factory":
                return ("router_factory", parent[1])
        if node and node.type in {"call_expression", "new_expression"}:
            function = node.child_by_field_name("function") or node.child_by_field_name(
                "constructor"
            )
            if (
                chain(function) == ("require",)
                and "require" not in counts
                and "require" not in invalid
            ):
                arguments = args(node)
                source = string(arguments[0]) if len(arguments) == 1 else None
                if source == "express":
                    return ("express_factory", "require-express")
                for kind in KINDS:
                    hold(kind, "unsupported_require")
            target = value(function)
            if target and target[0] in {"express_factory", "router_factory", "command_factory"}:
                return ("command" if target[0] == "command_factory" else "router", text(node))
        return None

    available = dict.fromkeys(bindings, 0)
    for name, node, declaration in declarations:
        if chain(node) == ("process", "env"):
            hold("config_key", "unsupported_env_alias")
        if name not in invalid:
            bound = value(node)
            if bound:
                bindings[name] = bound
                available[name] = declaration.end_byte
    # Reject the entire object family on mutation; an alias cannot restore trust.
    damaged = {
        bindings[name]
        for name in mutated
        if name in bindings and (bindings[name][0] != "process" or name in non_env_mutated)
    }
    for node in nodes:
        if node.type == "call_expression":
            for argument in args(node):
                parts = chain(argument)
                binding = bindings.get(parts[0]) if len(parts) == 1 else None
                if binding and binding[0] in {"router", "command"}:
                    damaged.add(binding)
                    hold("http_route" if binding[0] == "router" else "cli_flag", "escaped_object")
    for name, bound in tuple(bindings.items()):
        if bound in damaged:
            hold(
                "http_route"
                if bound[0] in {"router", "express_factory", "router_factory"}
                else "cli_flag",
                "mutated_binding",
            )
            del bindings[name]
    if invalid & (set(counts) | {"process", "require"}):
        for kind in KINDS:
            hold(kind, "shadowed_or_reassigned_binding")

    def add(name, kind, node):
        try:
            valid_name(name)
        except CodeIndexError:
            hold(kind, "unsafe_literal")
            return
        if len(facts) >= policy.max_definitions:
            for item in KINDS:
                hold(item, "definition_limit")
            return
        facts.append(
            JavascriptLiteral(name, kind, node.start_point.row + 1, node.end_point.row + 1)
        )

    for node in nodes:
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            parts = chain(function)
            arguments = args(node)
            target = (
                bindings.get(parts[0])
                if len(parts) == 2 and node.start_byte >= available.get(parts[0], 0)
                else None
            )
            method = parts[-1] if parts else ""
            if parts in {("eval",), ("Function",)} or (function and function.type == "import"):
                for kind in KINDS:
                    hold(kind, "dynamic_code")
            if function and function.type == "subscript_expression":
                parent = chain(function.child_by_field_name("object"))
                binding = bindings.get(parent[0]) if len(parent) == 1 else None
                if binding and binding[0] in {"router", "command"}:
                    hold("http_route" if binding[0] == "router" else "cli_flag", "computed_method")
            if target and target[0] == "router" and method in METHODS:
                path = string(arguments[0]) if arguments else None
                if path is not None and path.startswith("/") and len(arguments) >= 2:
                    add(method.upper() + " " + path, "http_route", node)
                else:
                    hold("http_route", "dynamic_route")
            elif target and target[0] == "command" and method in {"option", "requiredOption"}:
                spelling = string(arguments[0]) if arguments else None
                flags = re.findall(
                    r"(?<!\S)-{1,2}[A-Za-z0-9][A-Za-z0-9_-]*(?=\s|$)",
                    (spelling or "").replace(",", " ").replace("|", " "),
                )
                if spelling is None or not flags or any(not FLAG.fullmatch(flag) for flag in flags):
                    hold("cli_flag", "dynamic_option")
                else:
                    for flag in flags:
                        add(flag, "cli_flag", node)
            elif method in METHODS | {"route", "all", "use", "register"}:
                hold("http_route", "unsupported_registration")
            elif method in {"option", "requiredOption", "addOption", "command", "addCommand"}:
                hold("cli_flag", "unsupported_registration")
        elif node.type in {"assignment_expression", "augmented_assignment_expression"}:
            target = node.child_by_field_name("left")
            parts = assignment_parts(target)
            if (
                len(parts) == 3
                and parts[1] == "env"
                and (
                    parts[0] == "process"
                    and "process" not in counts
                    and "process" not in invalid
                    or bindings.get(parts[0], (None,))[0] == "process"
                )
            ):
                add(parts[-1], "config_key", node)
            elif parts[:2] == ("process", "env") or (
                target and target.type == "subscript_expression"
            ):
                hold("config_key", "dynamic_env_write")
        elif node.type == "member_expression":
            parts = chain(node)
            binding = bindings.get(parts[0]) if len(parts) == 2 else None
            parent = node.parent
            direct_call = (
                parent
                and parent.type == "call_expression"
                and parent.child_by_field_name("function") == node
            )
            if binding and not direct_call:
                if binding[0] == "router" and parts[-1] in METHODS:
                    hold("http_route", "unresolved_method_alias")
                elif binding[0] == "command" and parts[-1] in {"option", "requiredOption"}:
                    hold("cli_flag", "unresolved_method_alias")
        elif node.type == "new_expression" and chain(node.child_by_field_name("constructor")) == (
            "Function",
        ):
            for kind in KINDS:
                hold(kind, "dynamic_code")
    return JavascriptLiteralResult(
        tuple(facts), tuple(sorted(complete)), tuple(sorted(reasons)), len(nodes)
    )
