"""Explicit protocol-only dispatch. No resolver is installed by this module."""

from typing import Protocol

from pydantic import ValidationError

from .models import (
    DOMAIN_KEYS,
    POINTER_ADAPTER,
    Pointer,
    Resolution,
    ResolutionContext,
    pointer_key,
)

DomainKey = tuple[str, str, str]


class Resolver(Protocol):
    def resolve(self, pointer: Pointer, context: ResolutionContext) -> Resolution: ...


class DuplicateResolverError(ValueError):
    pass


class Registry:
    def __init__(self) -> None:
        self._resolvers: dict[DomainKey, Resolver] = {}

    @property
    def installed_domains(self) -> frozenset[DomainKey]:
        return frozenset(self._resolvers)

    def register(self, key: DomainKey, resolver: Resolver) -> None:
        if (
            type(key) is not tuple
            or len(key) != 3
            or any(type(part) is not str for part in key)
            or key not in DOMAIN_KEYS
        ):
            raise ValueError("registration requires an exact declared domain triple")
        if key in self._resolvers:
            raise DuplicateResolverError("domain tuple already registered")
        if not callable(getattr(resolver, "resolve", None)):
            raise TypeError("resolver must implement the explicit resolution protocol")
        self._resolvers[key] = resolver

    def resolve(self, pointer: Pointer, context: ResolutionContext) -> Resolution:
        key = pointer_key(pointer)
        if key not in DOMAIN_KEYS:
            return Resolution(status="unsupported", reason="unknown_domain")
        version = (
            pointer.get("schema_version", 1)
            if isinstance(pointer, dict)
            else pointer.schema_version
        )
        if type(version) is not int or version != 1:
            return Resolution(status="unsupported", reason="unsupported_schema_version")
        try:
            pointer = POINTER_ADAPTER.validate_python(pointer)
            context = ResolutionContext.model_validate(context)
        except ValidationError:
            return Resolution(status="invalid", reason="wire_contract_error")
        resolver = self._resolvers.get(key)
        if resolver is None or pointer.locator is None:
            return Resolution(status="unsupported", reason="domain_not_installed")
        try:
            # Revalidation prevents unchecked model_construct/model_copy values from passing.
            result = Resolution.model_validate(resolver.resolve(pointer, context))
        except Exception:
            # Do not expose arbitrary domain/provider errors or imported source payloads.
            return Resolution(status="invalid", reason="resolver_contract_error")
        if result.status != "resolved":
            return result
        if pointer.source_type == "configured_log" and (
            result.provenance is None
            or result.provenance.owner_resolution_scope != "redacted_text"
            or result.provenance.view_kind != "redacted_result"
        ):
            return Resolution(status="invalid", reason="redacted_provenance_required")
        if (
            result.checked_source_revision != pointer.source_revision
            or result.checked_source_sha256 != pointer.source_sha256
            or result.checked_artifact_sha256 != pointer.evidence_artifact_sha256
        ):
            return Resolution(status="invalid", reason="checked_identity_mismatch")
        required = context.required_scope
        accepted = {
            "text": {"text", "text_and_spatial"},
            "spatial": {"spatial", "text_and_spatial"},
            "text_and_spatial": {"text_and_spatial"},
        }
        if required is not None and result.scope not in accepted[required]:
            return Resolution(status="unsupported", reason="required_scope_unavailable")
        return result
