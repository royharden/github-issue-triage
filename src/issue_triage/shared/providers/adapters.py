"""Offline payload contracts and response decoding; contains no HTTP/SDK/key access."""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Literal

from pydantic import Field

from ..callledger.models import (
    Digest,
    Identifier,
    NormalizedUsage,
    WireModel,
    canonical_digest,
    decode_wire_json,
)
from .images import ImageBuffer, validate_image
from .models import (
    CallContext,
    GenerateRequest,
    ImagePart,
    Limits,
    ProviderRequest,
    TypedJudgmentRequest,
    TypedJudgmentResult,
)
from .schema import check_schema, validate_output


class AdapterError(ValueError):
    """Closed preflight/output code; never includes payload or exception text."""


class ModelSupport(WireModel):
    generation: bool
    typed_judgment: bool
    structured_output: bool
    image_input: bool
    streaming: bool
    temperature: bool
    reasoning_efforts: list[str]
    reported_models: list[str]


class ProviderConfig(WireModel):
    schema_version: Literal[1]
    flavor: Literal["openai_responses", "openai_chat", "typesafe", "anthropic"]
    endpoint_id: Identifier
    revision_sha256: Digest
    models: dict[str, ModelSupport] = Field(min_length=1)

    @property
    def sha256(self):
        return canonical_digest(self.model_dump(mode="json"))


@dataclass(frozen=True)
class PreparedRequest:
    request: GenerateRequest | TypedJudgmentRequest = field(repr=False)
    request_identity_sha256: str
    inference_payload_sha256: str
    dispatched_envelope_sha256: str
    payload_json: bytes = field(repr=False)


@dataclass(frozen=True)
class Outcome:
    status: str
    model_reported: str | None
    normalized_usage: NormalizedUsage
    usage_raw: dict | None = field(repr=False)
    text: str | None = field(default=None, repr=False)
    parsed: object = field(default=None, repr=False)
    typed: TypedJudgmentResult | None = field(default=None, repr=False)


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )


def _bounded_depth(value):
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if isinstance(item, (dict, list)):
            if depth >= 64:
                raise AdapterError("request_depth")
            pending.extend(
                (child, depth + 1) for child in (item.values() if isinstance(item, dict) else item)
            )


def request_identity(request, *, context: CallContext, config: ProviderConfig) -> str:
    return canonical_digest(
        {
            "request": request.identity_payload(),
            "context": context.semantic_context(),
            "provider_config_sha256": config.sha256,
        }
    )


def prepare_request(
    request: ProviderRequest,
    *,
    config: ProviderConfig,
    context: CallContext,
    limits: Limits,
    images: dict[str, bytes] | None = None,
) -> PreparedRequest:
    # Copy through serialized wire data to detach mutable nested caller dictionaries.
    request = type(request).model_validate(
        request.model_dump(mode="python", by_alias=True, exclude_unset=True)
    )
    support = config.models.get(request.model)
    if support is None:
        raise AdapterError("unsupported_model")
    if not support.reported_models:
        raise AdapterError("unsupported_model_revision")
    if isinstance(request, TypedJudgmentRequest):
        _bounded_depth(request.state)
        for question in request.questions.values():
            _bounded_depth(question.instructions)
            if getattr(question, "criteria", None) is not None:
                _bounded_depth(question.model_dump(mode="json")["criteria"])
        if config.flavor != "typesafe" or not support.typed_judgment:
            raise AdapterError("unsupported_native_typed")
        if len(request.questions) > limits.max_questions or any(
            q.type == "choice" and len(q.criteria) > limits.max_choice_options
            for q in request.questions.values()
        ):
            raise AdapterError("request_shape")
        payload = {
            "state": request.state,
            "model": request.model,
            "questions": {
                key: q.model_dump(mode="json", exclude_unset=True)
                for key, q in request.questions.items()
            },
        }
    else:
        if not support.generation or config.flavor == "typesafe":
            raise AdapterError("unsupported_generation")
        if request.stream and not support.streaming:
            raise AdapterError("unsupported_stream")
        if request.temperature is not None and not support.temperature:
            raise AdapterError("unsupported_temperature")
        if (
            request.reasoning_effort is not None
            and request.reasoning_effort not in support.reasoning_efforts
        ):
            raise AdapterError("unsupported_reasoning")
        if request.output_schema is not None:
            if not support.structured_output:
                raise AdapterError("unsupported_schema")
            check_schema(request.output_schema)
        if (
            limits.max_total_output_tokens is not None
            and request.max_output_tokens > limits.max_total_output_tokens
        ):
            raise AdapterError("output_bound")
        converted = []
        for message in request.messages:
            parts = []
            for part in message.content:
                if isinstance(part, ImagePart):
                    if not support.image_input:
                        raise AdapterError("unsupported_image")
                    if images is None or part.execution_ref not in images:
                        raise AdapterError("untrusted_image")
                    buffer: ImageBuffer = validate_image(part, images[part.execution_ref])
                    if config.flavor == "openai_responses":
                        parts.append(
                            {
                                "type": "input_image",
                                "image_url": buffer.data_url(),
                                "detail": part.detail,
                            }
                        )
                    elif config.flavor == "openai_chat":
                        parts.append(
                            {
                                "type": "image_url",
                                "image_url": {"url": buffer.data_url(), "detail": part.detail},
                            }
                        )
                    else:
                        raise AdapterError("unsupported_image")
                elif config.flavor == "openai_responses":
                    parts.append({"type": "input_text", "text": part.text})
                else:
                    parts.append({"type": "text", "text": part.text})
            converted.append({"role": message.role, "content": parts})
        if config.flavor == "openai_responses":
            payload = {
                "model": request.model,
                "input": converted,
                "max_output_tokens": request.max_output_tokens,
                "stream": request.stream,
                "store": False,
                "tools": [],
                "tool_choice": "none",
            }
            if request.output_schema is not None:
                payload["text"] = {
                    "format": {
                        "type": "json_schema",
                        "name": "response",
                        "strict": True,
                        "schema": request.output_schema,
                    }
                }
            if request.reasoning_effort is not None:
                payload["reasoning"] = {"effort": request.reasoning_effort}
        elif config.flavor == "openai_chat":
            payload = {
                "model": request.model,
                "messages": converted,
                "max_completion_tokens": request.max_output_tokens,
                "stream": request.stream,
                "store": False,
                "tools": [],
                "tool_choice": "none",
            }
            if request.output_schema is not None:
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "response",
                        "strict": True,
                        "schema": request.output_schema,
                    },
                }
            if request.reasoning_effort is not None:
                payload["reasoning_effort"] = request.reasoning_effort
        else:
            systems = []
            messages = []
            for message in converted:
                if message["role"] == "system":
                    if messages:
                        raise AdapterError("unsupported_system_order")
                    systems.extend(message["content"])
                else:
                    messages.append(message)
            if not messages:
                raise AdapterError("unsupported_generation")
            payload = {
                "model": request.model,
                "system": systems,
                "messages": messages,
                "max_tokens": request.max_output_tokens,
                "stream": request.stream,
            }
            if request.output_schema is not None:
                payload["output_config"] = {
                    "format": {"type": "json_schema", "schema": request.output_schema}
                }
            if request.reasoning_effort is not None:
                raise AdapterError("unsupported_reasoning")
        if request.temperature is not None:
            payload["temperature"] = request.temperature
    serialized = _json_bytes(payload)
    if len(serialized) > min(limits.max_request_bytes, 32 * 1024 * 1024):
        raise AdapterError("request_bytes")
    return PreparedRequest(
        request,
        request_identity(request, context=context, config=config),
        canonical_digest(request.identity_payload()),
        hashlib.sha256(serialized).hexdigest(),
        serialized,
    )


def _count(value):
    return value if type(value) is int and value >= 0 else None


def normalize_usage(raw, flavor: str) -> NormalizedUsage:
    if not isinstance(raw, dict):
        return NormalizedUsage()
    if flavor == "openai_chat":
        inp, out = _count(raw.get("prompt_tokens")), _count(raw.get("completion_tokens"))
        incoming, outgoing = raw.get("prompt_tokens_details"), raw.get("completion_tokens_details")
    else:
        inp, out = _count(raw.get("input_tokens")), _count(raw.get("output_tokens"))
        incoming, outgoing = raw.get("input_tokens_details"), raw.get("output_tokens_details")
    read = _count(incoming.get("cached_tokens")) if isinstance(incoming, dict) else None
    write = None
    reasoning = _count(outgoing.get("reasoning_tokens")) if isinstance(outgoing, dict) else None
    if flavor == "anthropic":
        read, write = (
            _count(raw.get("cache_read_input_tokens")),
            _count(raw.get("cache_creation_input_tokens")),
        )
        inp = inp + read + write if all(v is not None for v in [inp, read, write]) else None
        reasoning = _count(outgoing.get("thinking_tokens")) if isinstance(outgoing, dict) else None
    try:
        return NormalizedUsage(
            input_tokens=inp,
            output_tokens=out,
            cache_read_input_tokens=read,
            cache_write_input_tokens=write,
            reasoning_output_tokens=reasoning,
        )
    except ValueError:
        return NormalizedUsage()


def decode_outcome(
    body: bytes, *, prepared: PreparedRequest, config: ProviderConfig, max_bytes: int
) -> Outcome:
    request = prepared.request
    data = decode_wire_json(body.decode("utf-8"), max_bytes=max_bytes)
    if not isinstance(data, dict):
        raise AdapterError("invalid_output")
    raw = data.get("usage") if isinstance(data.get("usage"), dict) else None
    usage = normalize_usage(raw, config.flavor)
    model = (
        data.get("model")
        if isinstance(data.get("model"), str) and 1 <= len(data["model"]) <= 255
        else None
    )

    def result(status, **kwargs):
        return Outcome(status, model, usage, raw, **kwargs)

    if model is None:
        return result("invalid_output")
    if isinstance(request, TypedJudgmentRequest):
        try:
            typed = TypedJudgmentResult(
                schema_version=1,
                model_reported=model,
                question_spec_sha256=request.question_spec_sha256,
                answers=data.get("answers"),
            ).validate_for(request)
            return result("ok", typed=typed)
        except ValueError:
            return result("invalid_output")
    text = None
    if config.flavor == "openai_responses":
        output = data.get("output")
        if not isinstance(output, list):
            return result("invalid_output")
        parts = []
        for item in output:
            if not isinstance(item, dict):
                return result("invalid_output")
            if item.get("type") == "reasoning":
                continue
            if item.get("type") != "message" or not isinstance(item.get("content"), list):
                return result("invalid_output")
            for piece in item["content"]:
                if not isinstance(piece, dict):
                    return result("invalid_output")
                if piece.get("type") == "refusal":
                    return result("refused")
                if piece.get("type") != "output_text" or not isinstance(piece.get("text"), str):
                    return result("invalid_output")
                parts.append(piece["text"])
        if data.get("status") != "completed" or not parts:
            return result("invalid_output")
        text = "".join(parts)
    elif config.flavor == "openai_chat":
        choices = data.get("choices")
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
            return result("invalid_output")
        message = choices[0].get("message")
        if not isinstance(message, dict):
            return result("invalid_output")
        if message.get("refusal"):
            return result("refused")
        if (
            message.get("tool_calls")
            or choices[0].get("finish_reason") != "stop"
            or not isinstance(message.get("content"), str)
        ):
            return result("invalid_output")
        text = message["content"]
    else:
        details = data.get("stop_details")
        if (
            data.get("stop_reason") == "refusal"
            or isinstance(details, dict)
            and details.get("type") == "refusal"
        ):
            return result("refused")
        content = data.get("content")
        if data.get("stop_reason") != "end_turn" or not isinstance(content, list) or not content:
            return result("invalid_output")
        if any(
            not isinstance(part, dict)
            or part.get("type") != "text"
            or not isinstance(part.get("text"), str)
            for part in content
        ):
            return result("invalid_output")
        text = "".join(part["text"] for part in content)
    if request.output_schema is None:
        return result("ok", text=text)
    try:
        parsed = decode_wire_json(text, max_bytes=max_bytes)
        validate_output(parsed, request.output_schema)
        return result("ok", text=text, parsed=parsed)
    except ValueError:
        return result("invalid_output")
