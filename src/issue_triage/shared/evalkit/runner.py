"""Fixed-ID comparison through injected domain/method ports, with no provider implementation."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal

from .corpus import FrozenCorpusError, validate_records
from .identity import canonical_bytes
from .interfaces import DomainAdapter, MethodRunner
from .models import GoldRecord, Manifest, Outcome, Prediction, PublicMethodInput


@dataclass(frozen=True)
class SourceView:
    status: Literal["available", "stale", "unavailable"]
    input_sha256: str | None
    public_payload: dict[str, object]


@dataclass(frozen=True)
class MethodConfig:
    version: str
    config_sha256: str
    origin: Literal["synthetic", "recorded_replay", "agent_provisional", "live"]
    runner: MethodRunner | None


@dataclass(frozen=True)
class MethodEvaluation:
    status: Literal["executed", "not_run"]
    requested_item_ids: tuple[str, ...]
    actual_predictions: tuple[Prediction, ...]
    outcomes: tuple[Outcome, ...]
    calls_observed: int | None


@dataclass(frozen=True)
class Comparison:
    frozen_item_ids: tuple[str, ...]
    corpus_count: int
    methods: dict[str, MethodEvaluation]
    split: str


@dataclass(frozen=True)
class HeldoutAdmission:
    manifest_sha256: str
    independent_seal_sha256: str
    dev_config_sha256: str
    method_config_sha256: dict[str, str]
    candidate_commit: str
    history_ref: str
    rerun_reason: str | None


class HeldoutHistory:
    """Caller-owned durable exposure history. It must reject unapproved repeated admissions."""

    def record_exposure(self, admission: HeldoutAdmission) -> None:
        raise NotImplementedError


_PRIVATE_KEYS = {
    "gold",
    "label_payload",
    "label_source",
    "label_provenance_ref",
    "hidden_rubric",
    "family",
    "trap",
    "group_id",
}


def _public_input(value: PublicMethodInput) -> None:
    def visit(payload: object):
        if isinstance(payload, dict):
            if _PRIVATE_KEYS.intersection(payload):
                raise FrozenCorpusError("scorer_metadata_in_public_input")
            for item in payload.values():
                visit(item)
        elif isinstance(payload, list):
            for item in payload:
                visit(item)

    visit(value.public_payload)


def _status_metadata(
    gold: GoldRecord, method: str, config: MethodConfig, status: str, reason: str
) -> Prediction:
    """Adapter status metadata; never exported as an actual model response."""
    return Prediction.model_validate_json(
        canonical_bytes(
            {
                "schema_version": 1,
                "item_id": gold.item_id,
                "method": method,
                "method_version": config.version,
                "config_sha256": config.config_sha256,
                "model": None,
                "origin": config.origin,
                "status": status,
                "domain_payload": None,
                "machine_output": None,
                "human_effective_output": None,
                "human_provenance_ref": None,
                "issues": [reason],
                "ledger_refs": [],
                "source_refs": [],
            }
        )
    )


def compare(
    methods: Mapping[str, MethodConfig],
    manifest: Manifest,
    split: str,
    records: tuple[GoldRecord, ...],
    adapter: DomainAdapter,
    policy: object,
    source_lookup: Callable[[GoldRecord], SourceView],
    *,
    allow_live_dispatch: bool = False,
    heldout_admission: HeldoutAdmission | None = None,
    heldout_history: HeldoutHistory | None = None,
) -> Comparison:
    """The caller's trusted policy/S3 controller owns any actual effect authority and accounting.

    Live dispatch defaults off. Named never-run methods get metadata rows without fake predictions.
    Original source views are preflighted before methods; no source acquisition or hidden fallback.
    """
    if split == "heldout":
        if heldout_admission is None or heldout_history is None:
            raise FrozenCorpusError("heldout_admission_required")
        manifest_digest = hashlib.sha256(
            canonical_bytes(manifest.model_dump(mode="json"))
        ).hexdigest()
        expected_seal = manifest.experiment_refs.get("heldout_seal")
        expected_dev = manifest.experiment_refs.get("dev_config_lock")
        if (
            heldout_admission.manifest_sha256 != manifest_digest
            or expected_seal is None
            or expected_seal.status != "available"
            or expected_seal.sha256 != heldout_admission.independent_seal_sha256
            or expected_dev is None
            or expected_dev.status != "available"
            or expected_dev.sha256 != heldout_admission.dev_config_sha256
            or heldout_admission.history_ref != manifest.run_history_ref
            or heldout_admission.method_config_sha256
            != {name: cfg.config_sha256 for name, cfg in methods.items()}
        ):
            raise FrozenCorpusError("heldout_frozen_admission_changed")
        heldout_history.record_exposure(heldout_admission)
    validate_records(records, manifest, split, adapter)
    if not methods:
        raise ValueError("named expected methods required")
    expected = tuple(record.item_id for record in records)
    views = {}
    for gold in records:
        try:
            view = source_lookup(gold)
        except Exception:
            view = SourceView("unavailable", None, {})
        if not isinstance(view, SourceView):
            raise ValueError("trusted SourceView required")
        if view.status == "available" and view.input_sha256 != gold.input_sha256:
            view = SourceView("stale", view.input_sha256, {})
        views[gold.item_id] = view
    results = {}
    for method, config in methods.items():
        if config.runner is None or (config.origin == "live" and not allow_live_dispatch):
            results[method] = MethodEvaluation("not_run", expected, (), (), 0)
            continue
        actual = []
        all_outcomes = []
        for gold in records:
            view = views[gold.item_id]
            if view.status != "available":
                metadata = _status_metadata(
                    gold, method, config, view.status, "source_" + view.status
                )
                prediction = metadata
            else:
                public = adapter.to_public_input(gold, view)
                if not isinstance(public, PublicMethodInput) or (
                    public.item_id,
                    public.input_sha256,
                ) != (gold.item_id, gold.input_sha256):
                    raise FrozenCorpusError("public_input_identity_changed")
                _public_input(public)
                try:
                    prediction = config.runner.predict(public)
                except Exception:
                    prediction = _status_metadata(
                        gold, method, config, "provider_error", "runner_error"
                    )
                else:
                    if not isinstance(prediction, Prediction) or (
                        prediction.item_id,
                        prediction.method,
                        prediction.method_version,
                        prediction.config_sha256,
                    ) != (gold.item_id, method, config.version, config.config_sha256):
                        raise FrozenCorpusError("prediction_identity_changed")
                    if prediction.origin != config.origin or prediction.status == "not_run":
                        raise FrozenCorpusError("prediction_origin_changed")
                    try:
                        adapter.validate_prediction(prediction)
                    except Exception:
                        # Preserve charged/invalid output accounting from the actual response.
                        prediction = Prediction.model_validate_json(
                            canonical_bytes(
                                prediction.model_dump(mode="json")
                                | {
                                    "status": "invalid",
                                    "issues": [*prediction.issues, "invalid_domain_prediction"],
                                }
                            )
                        )
                    actual.append(prediction)
            outcomes = adapter.to_outcomes(prediction, gold, policy)
            if not outcomes or any(
                not isinstance(row, Outcome)
                or (row.item_id, row.method, row.dataset, row.group_id, row.split)
                != (gold.item_id, method, gold.dataset, gold.group_id, gold.split)
                for row in outcomes
            ):
                raise FrozenCorpusError("missing_or_wrong_expected_outcomes")
            if any(row.status != prediction.status for row in outcomes):
                raise FrozenCorpusError("adapter_status_mismatch")
            if any(
                row.evidence_origin != prediction.origin
                or row.human_touched_prediction != (prediction.human_effective_output is not None)
                for row in outcomes
            ):
                raise FrozenCorpusError("adapter_provenance_mismatch")
            all_outcomes.extend(outcomes)
        # Domain feature rows may share a case but must retain unique field/class axes.
        axes = [(o.item_id, o.field, o.class_name) for o in all_outcomes]
        if len(set(axes)) != len(axes):
            raise FrozenCorpusError("duplicate_outcome_axis")
        results[method] = MethodEvaluation(
            "executed", expected, tuple(actual), tuple(all_outcomes), None
        )
    return Comparison(expected, len(records), results, split)
