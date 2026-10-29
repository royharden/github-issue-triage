"""Closed, immutable screen values. Payloads have no automatic persistence API."""

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

HAZARDS = ("addresses_automated_agent", "asks_to_run_fetch_or_install", "asks_for_credentials")
TRANSFORM_VERSION = "nfkc-hidden-controls/1"
RULE_VERSION = "neutral-hazards/1"


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="strict")).hexdigest()


def canonical_digest(value: object) -> str:
    data = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return digest_text(data)


class ScreenValidationError(ValueError):
    """A closed error code; never interpolate rejected payloads."""

    def __init__(self, code: str = "invalid_input"):
        super().__init__(code)
        self.code = code


def _id(value: str) -> None:
    if type(value) is not str or not value or len(value) > 256:
        raise ScreenValidationError()


@dataclass(frozen=True, slots=True)
class UntrustedText:
    source_id: str
    source_generation: str
    text: str = field(repr=False)

    def __post_init__(self):
        _id(self.source_id)
        _id(self.source_generation)
        if type(self.text) is not str:
            raise ScreenValidationError()


@dataclass(frozen=True, slots=True)
class ScreenPolicy:
    version: str
    required_method: str
    max_input_bytes: int = 32768
    normalization_version: str = TRANSFORM_VERSION
    deterministic_rule_version: str = RULE_VERSION
    thresholds: Mapping[str, float] | None = None
    profile_id: str = "rules-baseline/1"
    threshold_provenance: str = "not_applicable"

    def __post_init__(self):
        for value in (self.version, self.profile_id):
            _id(value)
        if self.required_method not in ("rules", "typed"):
            raise ScreenValidationError("invalid_policy")
        if type(self.max_input_bytes) is not int or not 1 <= self.max_input_bytes <= 32768:
            raise ScreenValidationError("invalid_policy")
        if self.normalization_version != TRANSFORM_VERSION:
            raise ScreenValidationError("unsupported_transform")
        if self.deterministic_rule_version != RULE_VERSION:
            raise ScreenValidationError("unsupported_rules")
        if self.threshold_provenance not in (
            "not_applicable",
            "exploratory_seed",
            "dev_calibrated",
        ):
            raise ScreenValidationError("invalid_policy")
        if self.thresholds is not None:
            if not isinstance(self.thresholds, Mapping) or set(self.thresholds) != set(HAZARDS):
                raise ScreenValidationError("invalid_policy")
            for value in self.thresholds.values():
                if (
                    type(value) not in (int, float)
                    or not math.isfinite(value)
                    or not 0 <= value <= 1
                ):
                    raise ScreenValidationError("invalid_policy")
            object.__setattr__(self, "thresholds", MappingProxyType(dict(self.thresholds)))
        if self.required_method == "rules" and (
            self.thresholds is not None or self.threshold_provenance != "not_applicable"
        ):
            raise ScreenValidationError("invalid_policy")

    @property
    def sha256(self) -> str:
        return canonical_digest(
            {
                "version": self.version,
                "required_method": self.required_method,
                "max_input_bytes": self.max_input_bytes,
                "normalization_version": self.normalization_version,
                "deterministic_rule_version": self.deterministic_rule_version,
                "thresholds": dict(self.thresholds) if self.thresholds is not None else None,
                "profile_id": self.profile_id,
                "threshold_provenance": self.threshold_provenance,
            }
        )


@dataclass(frozen=True, slots=True)
class OffsetSegment:
    normalized_start_byte: int
    normalized_end_byte: int
    original_start_byte: int
    original_end_byte: int
    transform: str

    def __post_init__(self):
        numbers = (
            self.normalized_start_byte,
            self.normalized_end_byte,
            self.original_start_byte,
            self.original_end_byte,
        )
        if any(type(n) is not int or n < 0 for n in numbers):
            raise ScreenValidationError()
        if numbers[0] > numbers[1] or numbers[2] >= numbers[3]:
            raise ScreenValidationError()
        if self.transform not in (
            "identity",
            "nfkc",
            "control_removed",
            "html_marker_removed",
            "ambiguous",
        ):
            raise ScreenValidationError()


@dataclass(frozen=True, slots=True)
class PreparedText:
    source: UntrustedText = field(repr=False)
    original_sha256: str
    normalized_sha256: str
    original_byte_length: int
    normalized_byte_length: int
    normalized_text: str = field(repr=False)
    offset_segments: tuple[OffsetSegment, ...] = field(repr=False)
    transform_version: str
    policy_sha256: str
    notices: tuple[str, ...] = ()
    coverage: str = "complete"

    def __post_init__(self):
        if type(self.source) is not UntrustedText or self.coverage != "complete":
            raise ScreenValidationError()
        if self.transform_version != TRANSFORM_VERSION:
            raise ScreenValidationError("unsupported_transform")
        for value in (self.original_sha256, self.normalized_sha256, self.policy_sha256):
            if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ScreenValidationError()
        for n in (self.original_byte_length, self.normalized_byte_length):
            if type(n) is not int or not 0 <= n <= 32768:
                raise ScreenValidationError()
        if type(self.normalized_text) is not str or type(self.offset_segments) is not tuple:
            raise ScreenValidationError()
        if any(type(segment) is not OffsetSegment for segment in self.offset_segments):
            raise ScreenValidationError()


@dataclass(frozen=True, slots=True)
class HeldInput:
    source: UntrustedText = field(repr=False)
    original_sha256: str | None
    normalized_sha256: str | None
    policy_sha256: str
    reason: str
    notices: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WrappedData:
    state: Mapping[str, str] = field(repr=False)
    sha256: str

    def __post_init__(self):
        if not isinstance(self.state, Mapping) or set(self.state) != {
            "original_text",
            "normalized_text",
        }:
            raise ScreenValidationError("invalid_wrapper")
        if any(type(value) is not str for value in self.state.values()):
            raise ScreenValidationError("invalid_wrapper")
        if canonical_digest(dict(self.state)) != self.sha256:
            raise ScreenValidationError("invalid_wrapper")
        object.__setattr__(self, "state", MappingProxyType(dict(self.state)))


@dataclass(frozen=True, slots=True)
class ScreenResult:
    input_sha256: str | None
    normalized_sha256: str | None
    transform_version: str
    source_generation: str
    policy_sha256: str
    method: str
    coverage: str
    decision: str
    reason_codes: tuple[str, ...]
    deterministic_flags: tuple[str, ...] = ()
    diagnostic_notices: tuple[str, ...] = ()
    hazard_probabilities: Mapping[str, float] | None = None
    question_set_sha256: str | None = None
    model_requested: str | None = field(default=None, repr=False)
    model_reported: str | None = field(default=None, repr=False)
    adapter_status: str = "not_called"
    accounting_ref: object = field(default=None, repr=False)
    attempt_ids: tuple[str, ...] = ()
    source_capture_ref: object = field(default=None, repr=False)
    wrapped_state_sha256: str | None = None
    request_identity_sha256: str | None = None
    actual_dispatched_envelope_sha256: str | None = None
    offset_segments: tuple[OffsetSegment, ...] = field(default=(), repr=False)

    def __post_init__(self):
        if self.method not in ("rules", "typed_mock", "typed_replay", "typed_live"):
            raise ScreenValidationError()
        if self.decision not in ("pass", "needs_human") or self.coverage not in (
            "complete",
            "partial",
        ):
            raise ScreenValidationError()
        if self.decision == "pass" and (
            self.coverage != "complete" or self.deterministic_flags or self.reason_codes
        ):
            raise ScreenValidationError()
        if self.hazard_probabilities is not None:
            if set(self.hazard_probabilities) != set(HAZARDS):
                raise ScreenValidationError()
            for p in self.hazard_probabilities.values():
                if type(p) not in (int, float) or not math.isfinite(p) or not 0 <= p <= 1:
                    raise ScreenValidationError()
            object.__setattr__(
                self, "hazard_probabilities", MappingProxyType(dict(self.hazard_probabilities))
            )
        if self.method == "rules" and self.hazard_probabilities is not None:
            raise ScreenValidationError()

    def safe_metadata(self) -> dict[str, object]:
        """No payload, offset map, arbitrary error, nonce or reference-object serialization."""
        return {
            "schema_version": 1,
            "input_sha256": self.input_sha256,
            "normalized_sha256": self.normalized_sha256,
            "transform_version": self.transform_version,
            "source_generation": self.source_generation,
            "policy_sha256": self.policy_sha256,
            "method": self.method,
            "coverage": self.coverage,
            "decision": self.decision,
            "reason_codes": self.reason_codes,
            "deterministic_flags": self.deterministic_flags,
            "diagnostic_notices": self.diagnostic_notices,
            "hazard_probabilities": dict(self.hazard_probabilities)
            if self.hazard_probabilities
            else None,
            "adapter_status": self.adapter_status,
            "has_accounting_ref": self.accounting_ref is not None,
        }

    def permits_model_input(self, source: UntrustedText, policy: ScreenPolicy) -> bool:
        """Exact current text/policy binding only; never human approval or an effect grant."""
        if type(source) is not UntrustedText or type(policy) is not ScreenPolicy:
            return False
        try:
            current_sha = digest_text(source.text)
        except UnicodeError:
            return False
        method_matches = (
            self.method == "rules"
            if policy.required_method == "rules"
            else (self.method in ("typed_mock", "typed_replay", "typed_live"))
        )
        return (
            self.decision == "pass"
            and self.coverage == "complete"
            and method_matches
            and self.input_sha256 == current_sha
            and self.source_generation == source.source_generation
            and self.policy_sha256 == policy.sha256
            and self.transform_version == policy.normalization_version
        )
