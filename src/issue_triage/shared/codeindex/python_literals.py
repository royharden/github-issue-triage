"""Static Python registration syntax profiles; never import or run captured code."""

import ast
import re
from dataclasses import dataclass

from .canonical import CodeIndexError
from .models import IndexPolicy, valid_name

PYTHON_LITERAL_VERSION = "python-ast/3.12;literal-fastapi-flask-argparse-click-environ/1"
LITERAL_KINDS = ("cli_flag", "config_key", "http_route")
ROUTERS = frozenset(
    {
        "fastapi.FastAPI",
        "fastapi.APIRouter",
        "fastapi.routing.APIRouter",
        "flask.Flask",
        "flask.Blueprint",
    }
)
METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})
FLAG = re.compile(r"(?:--[A-Za-z][A-Za-z0-9_-]*|-[A-Za-z0-9])\Z")


@dataclass(frozen=True, slots=True)
class PythonLiteral:
    name: str
    kind: str
    line_start: int
    line_end: int


@dataclass(frozen=True, slots=True)
class PythonLiteralResult:
    literals: tuple[PythonLiteral, ...]
    complete_kinds: tuple[str, ...]
    reasons: tuple[str, ...]
    nodes_seen: int


class _Limited(ValueError):
    pass


def _string(node):
    return node.value if isinstance(node, ast.Constant) and type(node.value) is str else None


class _Registrations(ast.NodeVisitor):
    def __init__(self, policy, blocked):
        self.policy, self.blocked = policy, set(blocked)
        self.scopes = [("module", {})]
        self.facts, self.reasons, self.complete, self.nodes = [], set(), set(LITERAL_KINDS), 0
        self.annotation_context = 0

    def visit(self, node):
        if self.nodes >= self.policy.max_nodes_per_file:
            raise _Limited("literal_node_limit")
        self.nodes += 1
        return super().visit(node)

    def hold(self, kind, reason):
        self.complete.discard(kind)
        self.reasons.add(kind + "_" + reason)

    def add(self, name, kind, node):
        if self.annotation_context:
            self.hold(kind, "annotation_semantics")
            return
        try:
            valid_name(name)
        except CodeIndexError:
            self.hold(kind, "unsafe_literal")
            return
        if len(self.facts) >= self.policy.max_definitions:
            raise _Limited("literal_definition_limit")
        self.facts.append(PythonLiteral(name, kind, node.lineno, node.end_lineno))

    def lookup(self, name):
        inside_function = self.scopes[-1][0] == "function"
        for kind, bindings in reversed(self.scopes):
            if inside_function and kind == "class":
                continue
            if name in bindings:
                return bindings[name]
        return None

    def imported(self, spelling):
        root = spelling.split(".")[0]
        if root in self.blocked:
            for kind in LITERAL_KINDS:
                self.hold(kind, "shadowed_framework_import")
            return None
        if root in {"django", "tornado", "aiohttp", "starlette", "sanic", "bottle"}:
            self.hold("http_route", "unsupported_framework")
        if root in {"typer", "fire", "docopt", "optparse"}:
            self.hold("cli_flag", "unsupported_framework")
        return ("import", spelling, "")

    def binding(self, node):
        if isinstance(node, ast.Name):
            return self.lookup(node.id)
        if isinstance(node, ast.Attribute):
            parent = self.binding(node.value)
            if parent and parent[0] == "import":
                return ("import", parent[1] + "." + node.attr, "")
        if isinstance(node, ast.Call):
            target = self.binding(node.func)
            if target and target[0] == "import" and target[1] in ROUTERS:
                prefix = ""
                for keyword in node.keywords:
                    if keyword.arg in {"prefix", "url_prefix"}:
                        prefix = _string(keyword.value)
                if prefix is None or (prefix and not prefix.startswith("/")):
                    self.hold("http_route", "dynamic_prefix")
                    prefix = None
                return ("route", target[1], prefix)
            if target and target[:2] == ("import", "argparse.ArgumentParser"):
                for keyword in node.keywords:
                    if keyword.arg == "prefix_chars":
                        prefix = _string(keyword.value)
                        if prefix is None or "-" not in prefix:
                            self.hold("cli_flag", "unsupported_prefix")
                            return None
                    if keyword.arg == "parents" and not (
                        isinstance(keyword.value, (ast.List, ast.Tuple)) and not keyword.value.elts
                    ):
                        self.hold("cli_flag", "inherited_flags")
                return ("cli", "argparse.ArgumentParser", "")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "add_argument_group",
                "add_mutually_exclusive_group",
            }:
                receiver = self.binding(node.func.value)
                if receiver and receiver[0] == "cli":
                    return receiver
        return None

    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.scopes[-1][1][name] = self.imported(alias.name if alias.asname else name)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name == "*":
                for kind in LITERAL_KINDS:
                    self.hold(kind, "unresolved_import")
                continue
            if node.level:
                self.scopes[-1][1][alias.asname or alias.name] = None
                continue
            self.scopes[-1][1][alias.asname or alias.name] = self.imported(
                (node.module or "") + "." + alias.name
            )

    def target(self, target, binding, node):
        if isinstance(target, ast.Name):
            self.scopes[-1][1][target.id] = binding
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.target(item, None, node)
        elif isinstance(target, ast.Subscript):
            receiver = self.binding(target.value)
            if receiver and receiver[:2] == ("import", "os.environ"):
                key = _string(target.slice)
                if key is None:
                    self.hold("config_key", "dynamic_env_key")
                else:
                    self.add(key, "config_key", node)
            elif isinstance(target.value, ast.Attribute) and target.value.attr == "environ":
                self.hold("config_key", "unresolved_env_receiver")
        elif isinstance(target, ast.Attribute):
            receiver = self.binding(target.value)
            if receiver and (
                receiver[0] in {"route", "cli"}
                or receiver[1].split(".")[0] in {"fastapi", "flask", "argparse", "click", "os"}
            ):
                for kind in LITERAL_KINDS:
                    self.hold(kind, "mutated_framework_binding")
                for _, frame in self.scopes:
                    for name in frame:
                        if frame[name] is not None:
                            frame[name] = None

    def visit_Assign(self, node):
        self.visit(node.value)
        binding = self.binding(node.value)
        for target in node.targets:
            self.target(target, binding, node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
        self.target(node.target, self.binding(node.value), node)
        self.annotation(node.annotation)

    def visit_Delete(self, node):
        for target in node.targets:
            self.target(target, None, node)

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self.target(node.target, self.binding(node.value), node)

    def visit_AugAssign(self, node):
        self.visit(node.value)
        self.target(node.target, None, node)

    def function(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)
        self.visit(node.args)
        if node.returns is not None:
            self.annotation(node.returns)
        self.scopes[-1][1][node.name] = None
        parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        parameters += [value for value in (node.args.vararg, node.args.kwarg) if value is not None]
        names = self.local_names(node.body) | {value.arg for value in parameters}
        self.scopes.append(("function", dict.fromkeys(names)))
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.scopes.pop()

    visit_FunctionDef = function
    visit_AsyncFunctionDef = function

    def local_names(self, statements):
        names, pending = set(), list(statements)
        while pending:
            if self.nodes >= self.policy.max_nodes_per_file:
                raise _Limited("literal_node_limit")
            self.nodes += 1
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
                pending.extend(node.decorator_list)
                if isinstance(node, ast.ClassDef):
                    pending.extend([*node.bases, *node.keywords])
                else:
                    pending.append(node.args)
                    if node.returns is not None:
                        pending.append(node.returns)
                continue
            if isinstance(node, ast.Lambda):
                pending.append(node.args)
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                names.add(node.id)
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
            if isinstance(node, ast.ExceptHandler) and node.name:
                names.add(node.name)
            if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
                names.add(node.name)
            pending.extend(ast.iter_child_nodes(node))
        return names

    def annotation(self, node):
        kind, bindings = self.scopes[-1]
        before = dict(bindings)
        self.annotation_context += 1
        try:
            self.visit(node)
        finally:
            self.annotation_context -= 1
            after = self.scopes[-1][1]
            changed = {
                key for key in before.keys() | after.keys() if before.get(key) != after.get(key)
            }
            if changed:
                for literal_kind in LITERAL_KINDS:
                    self.hold(literal_kind, "annotation_binding")
            self.scopes[-1] = (kind, {**before, **dict.fromkeys(changed)})

    def visit_arg(self, node):
        if node.annotation is not None:
            self.annotation(node.annotation)

    def visit_Lambda(self, node):
        self.visit(node.args)
        parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        parameters += [value for value in (node.args.vararg, node.args.kwarg) if value is not None]
        names = self.local_names([node.body]) | {value.arg for value in parameters}
        self.scopes.append(("function", dict.fromkeys(names)))
        try:
            self.visit(node.body)
        finally:
            self.scopes.pop()

    def comprehension(self, node):
        # A walrus can bind the containing scope, unlike ordinary comprehension targets.
        pending, assigned = [node], set()
        while pending:
            if self.nodes >= self.policy.max_nodes_per_file:
                raise _Limited("literal_node_limit")
            self.nodes += 1
            current = pending.pop()
            if isinstance(current, ast.NamedExpr):
                assigned.add(current.target.id)
            pending.extend(ast.iter_child_nodes(current))
        if assigned:
            for kind in LITERAL_KINDS:
                self.hold(kind, "comprehension_assignment")
            self.scopes[-1][1].update(dict.fromkeys(assigned))
        names = self.local_names([generator.target for generator in node.generators])
        self.scopes.append(("function", dict.fromkeys(names)))
        try:
            for generator in node.generators:
                self.visit(generator.iter)
                for condition in generator.ifs:
                    self.visit(condition)
            for value in (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,):
                self.visit(value)
        finally:
            self.scopes.pop()

    visit_ListComp = comprehension
    visit_SetComp = comprehension
    visit_DictComp = comprehension
    visit_GeneratorExp = comprehension

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self.target(item.optional_vars, None, node)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_ClassDef(self, node):
        for child in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(child)
        self.scopes[-1][1][node.name] = None
        self.scopes.append(("class", {}))
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.scopes.pop()

    def branches(self, groups, seeds=None, cleanup=None):
        kind, initial = self.scopes[-1]
        outcomes = []
        for index, statements in enumerate(groups):
            self.scopes[-1] = (kind, {**initial, **(seeds[index] if seeds else {})})
            for statement in statements:
                self.visit(statement)
            outcome = self.scopes[-1][1]
            for name in cleanup[index] if cleanup else ():
                outcome[name] = None
            outcomes.append(outcome)
        keys = set().union(*(set(outcome) for outcome in outcomes))
        merged = {
            key: outcomes[0].get(key)
            if all(outcome.get(key) == outcomes[0].get(key) for outcome in outcomes)
            else None
            for key in keys
        }
        self.scopes[-1] = (kind, merged)

    def visit_If(self, node):
        self.visit(node.test)
        self.branches((node.body, node.orelse))

    def visit_For(self, node):
        self.visit(node.iter)
        self.target(node.target, None, node)
        self.branches((node.body, []))
        for child in node.orelse:
            self.visit(child)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.visit(node.test)
        self.branches((node.body, []))
        for child in node.orelse:
            self.visit(child)

    def visit_Try(self, node):
        groups = (node.body, *[handler.body for handler in node.handlers], [])
        names = [(), *[(handler.name,) if handler.name else () for handler in node.handlers], ()]
        self.branches(groups, [dict.fromkeys(group) for group in names], names)
        for child in [*node.orelse, *node.finalbody]:
            self.visit(child)

    visit_TryStar = visit_Try

    def visit_Global(self, node):
        for kind in LITERAL_KINDS:
            self.hold(kind, "global_or_nonlocal_binding")

    visit_Nonlocal = visit_Global

    def visit_Match(self, node):
        names = self.local_names([case.pattern for case in node.cases])
        self.scopes[-1][1].update(dict.fromkeys(names))
        for kind in LITERAL_KINDS:
            self.hold(kind, "unsupported_match_binding")
        self.generic_visit(node)

    def visit_Call(self, node):
        target = self.binding(node.func)
        attribute = node.func.attr if isinstance(node.func, ast.Attribute) else None
        receiver = self.binding(node.func.value) if attribute else None
        if isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval", "setattr"}:
            for kind in LITERAL_KINDS:
                self.hold(kind, "dynamic_definitions")
        path_node = (
            node.args[0]
            if node.args
            else next(
                (keyword.value for keyword in node.keywords if keyword.arg in {"path", "rule"}),
                None,
            )
        )
        path = _string(path_node)
        if (
            receiver
            and receiver[0] == "route"
            and attribute in METHODS | {"route", "api_route", "add_api_route"}
        ):
            methods = [attribute.upper()] if attribute in METHODS else None
            if methods is None:
                keyword = next(
                    (keyword.value for keyword in node.keywords if keyword.arg == "methods"), None
                )
                if isinstance(keyword, (ast.List, ast.Tuple)):
                    methods = [_string(item) for item in keyword.elts]
            if (
                path is None
                or not path.startswith("/")
                or receiver[2] is None
                or not methods
                or any(
                    type(method) is not str or method.lower() not in METHODS for method in methods
                )
            ):
                self.hold("http_route", "dynamic_registration")
            else:
                for method in methods:
                    self.add(
                        method.upper() + " " + receiver[2].rstrip("/") + path, "http_route", node
                    )
        elif (
            attribute in METHODS | {"route", "api_route", "add_api_route"}
            and path
            and path.startswith("/")
        ):
            self.hold("http_route", "unresolved_receiver")
        elif (
            receiver
            and receiver[0] == "route"
            and attribute in {"include_router", "register_blueprint", "mount"}
        ):
            self.hold("http_route", "unsupported_composition")
        option = target and target[:2] == ("import", "click.option")
        if (receiver and receiver[0] == "cli" and attribute == "add_argument") or option:
            if any(
                isinstance(argument, ast.Starred) or _string(argument) is None
                for argument in node.args
            ):
                self.hold("cli_flag", "dynamic_option")
            for argument in node.args:
                value = _string(argument)
                if value and value.startswith("-"):
                    if FLAG.fullmatch(value):
                        self.add(value, "cli_flag", node)
                    else:
                        self.hold("cli_flag", "unsupported_option_spelling")
        elif attribute in {"add_argument", "option", "add_parser", "add_subparsers"}:
            self.hold("cli_flag", "unresolved_option_receiver")
        self.generic_visit(node)


def extract_python_literals(data, policy, blocked_modules=()):
    if (
        type(data) is not bytes
        or type(policy) is not IndexPolicy
        or len(data) > policy.max_file_bytes
    ):
        raise CodeIndexError("python_literal_input_limit")
    visitor = _Registrations(policy, blocked_modules)
    try:
        tree = ast.parse(data.decode("utf-8", errors="strict"), mode="exec")
        visitor.visit(tree)
    except _Limited as error:
        visitor.complete.clear()
        visitor.reasons.add(str(error))
    except (SyntaxError, UnicodeError, ValueError, RecursionError):
        visitor.facts.clear()
        visitor.complete.clear()
        visitor.reasons.add("python_literal_parse_error")
    return PythonLiteralResult(
        tuple(visitor.facts),
        tuple(sorted(visitor.complete)),
        tuple(sorted(visitor.reasons)),
        visitor.nodes,
    )
