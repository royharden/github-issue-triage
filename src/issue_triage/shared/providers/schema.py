"""Small, explicit strict-schema subset; unsupported schema features fail before dispatch."""

import math


class SchemaError(ValueError):
    """Closed error codes only; schema/output contents are never interpolated."""


TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}
KEYS = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "anyOf",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "description",
    "title",
}


def check_schema(schema: dict, *, root: bool = True, depth: int = 0) -> None:
    if not isinstance(schema, dict) or depth > 16 or not schema or set(schema) - KEYS:
        raise SchemaError("unsupported_schema")
    if root and schema.get("type") != "object":
        raise SchemaError("unsupported_schema")
    for key in ["title", "description"]:
        if key in schema and not isinstance(schema[key], str):
            raise SchemaError("unsupported_schema")
    if "anyOf" in schema:
        if set(schema) - {"anyOf", "title", "description"} or not isinstance(schema["anyOf"], list):
            raise SchemaError("unsupported_schema")
        if not 1 <= len(schema["anyOf"]) <= 8:
            raise SchemaError("unsupported_schema")
        for branch in schema["anyOf"]:
            check_schema(branch, root=False, depth=depth + 1)
        return
    kind = schema.get("type")
    if not isinstance(kind, str) or kind not in TYPES:
        raise SchemaError("unsupported_schema")
    allowed = {"type", "enum", "const", "description", "title"}
    if kind == "object":
        allowed |= {"properties", "required", "additionalProperties"}
        properties = schema.get("properties")
        required = schema.get("required")
        if (
            not isinstance(properties, dict)
            or not isinstance(required, list)
            or any(not isinstance(key, str) or not key for key in properties)
            or any(not isinstance(key, str) for key in required)
            or len(set(required)) != len(required)
            or set(required) != set(properties)
            or schema.get("additionalProperties") is not False
            or len(properties) > 256
        ):
            raise SchemaError("unsupported_schema")
        for child in properties.values():
            check_schema(child, root=False, depth=depth + 1)
    elif kind == "array":
        allowed |= {"items", "minItems", "maxItems"}
        check_schema(schema.get("items"), root=False, depth=depth + 1)
    elif kind == "string":
        allowed |= {"minLength", "maxLength"}
    elif kind in {"integer", "number"}:
        allowed |= {"minimum", "maximum"}
    if set(schema) - allowed:
        raise SchemaError("unsupported_schema")
    for key in ["minLength", "maxLength", "minItems", "maxItems"]:
        if key in schema and (type(schema[key]) is not int or schema[key] < 0):
            raise SchemaError("unsupported_schema")
    for key in ["minimum", "maximum"]:
        if key in schema and (
            type(schema[key]) not in {int, float} or not math.isfinite(schema[key])
        ):
            raise SchemaError("unsupported_schema")
    for lower, upper in [
        ("minimum", "maximum"),
        ("minItems", "maxItems"),
        ("minLength", "maxLength"),
    ]:
        if lower in schema and upper in schema and schema[lower] > schema[upper]:
            raise SchemaError("unsupported_schema")
    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        raise SchemaError("unsupported_schema")


def _equal(a, b):
    return (isinstance(a, bool) == isinstance(b, bool)) and a == b


def validate_output(value, schema: dict) -> None:
    """Execute only the preflight-checked subset, with strict finite primitive types."""
    if "anyOf" in schema:
        for branch in schema["anyOf"]:
            try:
                validate_output(value, branch)
                return
            except SchemaError:
                pass
        raise SchemaError("invalid_output")
    kind = schema["type"]
    matches = {
        "object": type(value) is dict,
        "array": type(value) is list,
        "string": type(value) is str,
        "integer": type(value) is int,
        "number": type(value) in {int, float},
        "boolean": type(value) is bool,
        "null": value is None,
    }
    if not matches[kind] or (type(value) is float and not math.isfinite(value)):
        raise SchemaError("invalid_output")
    if "enum" in schema and not any(_equal(value, item) for item in schema["enum"]):
        raise SchemaError("invalid_output")
    if "const" in schema and not _equal(value, schema["const"]):
        raise SchemaError("invalid_output")
    if kind == "object":
        if set(value) != set(schema["properties"]):
            raise SchemaError("invalid_output")
        for key, child in schema["properties"].items():
            validate_output(value[key], child)
    elif kind == "array":
        for item in value:
            validate_output(item, schema["items"])
    for lower, upper, metric in [
        ("minimum", "maximum", value if kind in {"integer", "number"} else None),
        ("minLength", "maxLength", len(value) if kind == "string" else None),
        ("minItems", "maxItems", len(value) if kind == "array" else None),
    ]:
        if metric is not None and (
            (lower in schema and metric < schema[lower])
            or (upper in schema and metric > schema[upper])
        ):
            raise SchemaError("invalid_output")
