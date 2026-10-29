"""Closed judgment outputs and explicitly exploratory uncertainty policy."""

import re
from dataclasses import asdict, dataclass
from decimal import Decimal
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from ..contracts.domain import ClosedModel, Digest
from ..shared.codeindex.canonical import digest

TYPE_NAMES = ("bug", "feature", "question", "needs_repro", "likely_invalid", "unclear")
TypeName = Literal["bug", "feature", "question", "needs_repro", "likely_invalid", "unclear"]
PRIORITY_LEGEND = (
    "Critical: urgent widespread outage, security exposure or data loss",
    "High: important functionality blocked without a reasonable workaround",
    "Normal: a limited defect or actionable ordinary task",
    "Low: informational question or optional improvement",
)
Probability = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]


class JudgeHold(ValueError):
    """A fixed diagnostic only; never include issue/provider payload text."""


@dataclass(frozen=True, slots=True)
class JudgmentPolicy:
    version: str = "s6-judgment/1"
    provenance: str = "exploratory_seed"
    minimum_type_concentration: str = "0.700"
    minimum_type_margin: str = "0.150"
    minimum_priority_concentration: str = "0.600"
    minimum_priority_margin: str = "0.100"
    noul_false_max: str = "0.350"
    noul_true_min: str = "0.650"

    def __post_init__(self):
        if self.version != "s6-judgment/1" or self.provenance != "exploratory_seed":
            raise JudgeHold("unadmitted_judgment_policy")
        for field, value in asdict(self).items():
            if field not in {"version", "provenance"} and (
                type(value) is not str or re.fullmatch(r"(?:0\.\d{3}|1\.000)", value) is None
            ):
                raise JudgeHold("invalid_judgment_threshold")
        if Decimal(self.noul_false_max) >= Decimal(self.noul_true_min):
            raise JudgeHold("invalid_noul_interval")

    @property
    def sha256(self):
        return digest(asdict(self))


DEFAULT_JUDGMENT_POLICY = JudgmentPolicy()


class JudgmentRecord(ClosedModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )
    status: Literal["proposal", "needs_human"]
    method: Literal["rules", "typed_mock", "typed_replay", "typed_live"]
    issue_sha256: Digest
    input_sha256: Digest
    report_sha256: Digest
    screen_policy_sha256: Digest
    judgment_policy_sha256: Digest
    type_decision: TypeName | None = None
    priority: Annotated[int, Field(ge=0, le=3)] | None = None
    priority_expected: Annotated[float, Field(ge=0, le=3, allow_inf_nan=False)] | None = None
    reproducibility_probability: Probability | None = None
    nonexistent_reference_probability: Probability | None = None
    type_concentration: Probability | None = None
    priority_concentration: Probability | None = None
    reason_codes: tuple[str, ...]
    provider_result_sha256: Digest | None = None
    current_external_cost_usd: str | None = None
    accounting_ref: str | None = None

    @field_validator("reason_codes", mode="before")
    @classmethod
    def immutable_json_reasons(cls, value):
        return tuple(value) if type(value) is list else value

    @model_validator(mode="after")
    def honest_output(self) -> Self:
        if any(re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None for code in self.reason_codes):
            raise ValueError("invalid_judgment_reason")
        predictions = (
            self.type_decision,
            self.priority,
            self.priority_expected,
            self.reproducibility_probability,
            self.nonexistent_reference_probability,
            self.type_concentration,
            self.priority_concentration,
        )
        if self.status == "needs_human" and any(value is not None for value in predictions):
            raise ValueError("held_judgment_cannot_expose_predictions")
        if self.status == "proposal" and (self.type_decision is None or self.priority is None):
            raise ValueError("proposal_requires_type_and_priority")
        if self.method == "rules":
            if (
                any(value is not None for value in predictions[2:])
                or self.provider_result_sha256 is not None
                or self.accounting_ref is not None
                or self.current_external_cost_usd != "0"
            ):
                raise ValueError("rules_cannot_invent_probabilities_or_provider_provenance")
        elif self.provider_result_sha256 is None or self.accounting_ref is None:
            raise ValueError("typed_observation_requires_provider_provenance")
        if (
            self.current_external_cost_usd is not None
            and re.fullmatch(r"(?:0|[1-9]\d*)(?:\.\d+)?", self.current_external_cost_usd) is None
        ):
            raise ValueError("invalid_observed_cost")
        return self
