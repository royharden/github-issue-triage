"""Inert structural models and protocol dispatch; no concrete domain adapters."""

from .models import (
    DOMAIN_KEYS,
    POINTER_ADAPTER,
    ArtifactRef,
    Finding,
    Pointer,
    Resolution,
    ResolutionContext,
    SourceArtifact,
)
from .registry import DuplicateResolverError, Registry, Resolver

__all__ = [
    "DOMAIN_KEYS",
    "POINTER_ADAPTER",
    "ArtifactRef",
    "DuplicateResolverError",
    "Finding",
    "Pointer",
    "Registry",
    "Resolution",
    "ResolutionContext",
    "Resolver",
    "SourceArtifact",
]
