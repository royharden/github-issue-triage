"""Domain adapters and later generic engine ports; no domain formulas or provider imports."""

from collections.abc import Callable, Mapping
from typing import Protocol

from .models import (
    ConfusionCounts,
    EvaluationRun,
    GoldRecord,
    Manifest,
    MetricSpec,
    Outcome,
    Prediction,
    PublicMethodInput,
    PublicProjectionPolicy,
    ResamplingSpec,
)


class DomainAdapter(Protocol):
    def validate_gold(self, record: GoldRecord) -> None: ...

    def to_public_input(self, record: GoldRecord, source_view: object) -> PublicMethodInput: ...

    def validate_prediction(self, prediction: Prediction) -> None: ...

    def to_outcomes(
        self, machine: Prediction, gold: GoldRecord, policy: object
    ) -> tuple[Outcome, ...]: ...

    def metric_specs(self) -> tuple[MetricSpec, ...]: ...

    def public_projection_policy(self) -> PublicProjectionPolicy: ...


class MethodRunner(Protocol):
    def predict(self, public_input: PublicMethodInput) -> Prediction: ...


class StatisticsPort(Protocol):
    def confusion_counts(
        self, outcomes: tuple[Outcome, ...], label: object, eligibility: str
    ) -> ConfusionCounts: ...

    def rate(self, numerator: int, denominator: int) -> float | None: ...

    def classification_summary(
        self, confusions: Mapping[str, ConfusionCounts], declared_averaging: str
    ) -> object: ...

    def exact_set_accuracy(self, outcomes: tuple[Outcome, ...]) -> float | None: ...

    def wilson_interval(
        self, correct: int, n: int, z: float = 1.96
    ) -> tuple[float, float] | None: ...

    def paired_group_resample(
        self,
        outcomes_by_method: Mapping[str, tuple[Outcome, ...]],
        spec: ResamplingSpec,
        statistic_callback: Callable[..., object],
    ) -> object: ...


class EvaluationRunner(Protocol):
    def compare(
        self,
        methods: Mapping[str, MethodRunner],
        manifest: Manifest,
        split: str,
        adapter: DomainAdapter,
        policy: object,
    ) -> EvaluationRun: ...
