"""Private scorer/public input and fixed-ID failure accounting through actual injected ports."""

import pytest
from test_corpus import fixture

from issue_triage.shared.evalkit.corpus import FrozenCorpusError
from issue_triage.shared.evalkit.models import Outcome, Prediction, PublicMethodInput
from issue_triage.shared.evalkit.runner import MethodConfig, SourceView, compare
from issue_triage.shared.evalkit.statistics import accuracy, typed_equal

H = "a" * 64


class Adapter:
    def validate_gold(self, record):
        assert record.label_source == "synthetic"

    def to_public_input(self, record, view):
        return PublicMethodInput(
            item_id=record.item_id,
            public_payload=view.public_payload,
            input_sha256=record.input_sha256,
            public_config_refs=("public/1",),
        )

    def validate_prediction(self, prediction):
        if prediction.domain_payload is None or set(prediction.domain_payload) != {"target"}:
            raise ValueError("invalid domain")

    def to_outcomes(self, prediction, gold, policy):
        expected = gold.label_payload.payload["target"]
        # Raw machine output only; effective human corrections never replace the scored prediction.
        predicted = prediction.machine_output
        return (
            Outcome(
                item_id=gold.item_id,
                group_id=gold.group_id,
                dataset=gold.dataset,
                split=gold.split,
                method=prediction.method,
                field=None,
                **{"class": None},
                eligibility="eligible",
                status=prediction.status,
                correct=typed_equal(predicted, expected) if prediction.status == "ok" else None,
                predicted=predicted,
                expected=expected,
                human_touched_prediction=prediction.human_effective_output is not None,
                evidence_origin=prediction.origin,
                issues=prediction.issues,
                ledger_refs=prediction.ledger_refs,
            ),
        )


class Runner:
    def __init__(self, mode="normal"):
        self.inputs = []
        self.mode = mode

    def predict(self, public):
        self.inputs.append(public)
        if self.mode == "error":
            raise RuntimeError("private provider error CANARY")
        target = public.public_payload["observed"]
        return Prediction(
            item_id="unrequested" if self.mode == "wrong_id" else public.item_id,
            method="baseline",
            method_version="fixture/1",
            config_sha256=H,
            model=None,
            origin="synthetic",
            status="ok",
            domain_payload={} if self.mode == "invalid" else {"target": target},
            machine_output=target,
            human_effective_output=None,
            human_provenance_ref=None,
            issues=(),
            ledger_refs=("measured-attempt",),
            source_refs=(),
        )


def lookup(gold):
    return SourceView("available", gold.input_sha256, {"observed": gold.item_id == "case:1"})


def test_public_port_no_gold_fields_and_raw_correct_reference_comparison(tmp_path):
    rows, manifest, _ = fixture(tmp_path)
    runner = Runner()
    result = compare(
        {"baseline": MethodConfig("fixture/1", H, "synthetic", runner)},
        manifest,
        "dev",
        rows,
        Adapter(),
        None,
        lookup,
    )
    method = result.methods["baseline"]
    assert result.frozen_item_ids == ("case:0", "case:1") and len(method.actual_predictions) == 2
    assert accuracy(method.outcomes).value == 1
    assert all(set(p.public_payload) == {"observed"} for p in runner.inputs)
    assert all(
        not hasattr(p, "label_payload") and not hasattr(p, "group_id") for p in runner.inputs
    )


def test_never_run_and_live_disabled_have_rows_metadata_no_fake_predictions_or_calls(tmp_path):
    rows, manifest, _ = fixture(tmp_path)
    runner = Runner()
    result = compare(
        {
            "absent": MethodConfig("fixture/1", H, "synthetic", None),
            "live": MethodConfig("fixture/1", H, "live", runner),
        },
        manifest,
        "dev",
        rows,
        Adapter(),
        None,
        lookup,
    )
    assert runner.inputs == []
    for method in result.methods.values():
        assert (
            method.status == "not_run"
            and method.actual_predictions == ()
            and method.calls_observed == 0
        )
        assert method.requested_item_ids == result.frozen_item_ids


def test_stale_unavailable_source_keeps_requested_cases_and_zero_downstream_calls(tmp_path):
    rows, manifest, _ = fixture(tmp_path)
    runner = Runner()

    def stale(gold):
        return (
            SourceView("available", "b" * 64, {})
            if gold.item_id == "case:0"
            else SourceView("unavailable", None, {})
        )

    result = compare(
        {"baseline": MethodConfig("fixture/1", H, "synthetic", runner)},
        manifest,
        "dev",
        rows,
        Adapter(),
        None,
        stale,
    )
    method = result.methods["baseline"]
    assert runner.inputs == [] and method.actual_predictions == ()
    assert [o.status for o in method.outcomes] == ["stale", "unavailable"]
    assert accuracy(method.outcomes).denominator == 2 and accuracy(method.outcomes).value == 0


def test_actual_invalid_response_accounting_preserved_and_errors_counted(tmp_path):
    rows, manifest, _ = fixture(tmp_path)
    invalid = Runner("invalid")
    result = compare(
        {"baseline": MethodConfig("fixture/1", H, "synthetic", invalid)},
        manifest,
        "dev",
        rows,
        Adapter(),
        None,
        lookup,
    )
    method = result.methods["baseline"]
    assert all(
        p.status == "invalid" and p.ledger_refs == ("measured-attempt",)
        for p in method.actual_predictions
    )
    assert accuracy(method.outcomes).value == 0
    error = Runner("error")
    result = compare(
        {"baseline": MethodConfig("fixture/1", H, "synthetic", error)},
        manifest,
        "dev",
        rows,
        Adapter(),
        None,
        lookup,
    )
    assert result.methods["baseline"].actual_predictions == ()
    assert all(o.status == "provider_error" for o in result.methods["baseline"].outcomes)
    assert all("CANARY" not in str(o.issues) for o in result.methods["baseline"].outcomes)


def test_hidden_gold_key_wrong_id_or_missing_adapter_outcome_fail_closed(tmp_path):
    rows, manifest, _ = fixture(tmp_path)

    class Leaky(Adapter):
        def to_public_input(self, record, view):
            return PublicMethodInput(
                item_id=record.item_id,
                public_payload={"nested": {"label_payload": "private"}},
                input_sha256=record.input_sha256,
                public_config_refs=(),
            )

    class Missing(Adapter):
        def to_outcomes(self, *args):
            return ()

    for adapter, runner in (
        (Leaky(), Runner()),
        (Adapter(), Runner("wrong_id")),
        (Missing(), Runner()),
    ):
        with pytest.raises(FrozenCorpusError):
            compare(
                {"baseline": MethodConfig("fixture/1", H, "synthetic", runner)},
                manifest,
                "dev",
                rows,
                adapter,
                None,
                lookup,
            )


@pytest.mark.parametrize(
    "change",
    [
        {"evidence_origin": "live"},
        {"human_touched_prediction": True},
    ],
    ids=["synthetic-promoted-live", "invented-human-effective"],
)
def test_adapter_cannot_change_actual_origin_or_human_effective_state(tmp_path, change):
    rows, manifest, _ = fixture(tmp_path)

    class Relabel(Adapter):
        def to_outcomes(self, prediction, gold, policy):
            return tuple(
                r.model_copy(update=change) for r in super().to_outcomes(prediction, gold, policy)
            )

    with pytest.raises(FrozenCorpusError, match="adapter_provenance_mismatch"):
        compare(
            {"baseline": MethodConfig("fixture/1", H, "synthetic", Runner())},
            manifest,
            "dev",
            rows,
            Relabel(),
            None,
            lookup,
        )
