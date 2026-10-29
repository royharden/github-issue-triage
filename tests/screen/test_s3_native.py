"""what_bug_this_catches: nonce/digest drift or replay outside actual S3 admission.

Uses the relocated public S3 synthetic Rig. No sealed S6 corpus or model quality.
"""

import importlib.util
import shutil
import socket
import subprocess
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from issue_triage.shared.callledger.models import canonical_digest
from issue_triage.shared.providers.captures import FixtureIndex
from issue_triage.shared.screen import ScreenPolicy, UntrustedText, prepare_text
from issue_triage.shared.screen.models import HAZARDS, ScreenValidationError, WrappedData
from issue_triage.shared.screen.prepare import wrap_untrusted
from issue_triage.shared.screen.questions import QUESTION_SET_SHA256
from issue_triage.shared.screen.s3_adapter import (
    bind_native_request,
    native_binding_permits_model_input,
)
from issue_triage.shared.screen.typed import screen_typed

HELPER = Path(__file__).parents[1] / "contracts/consumers/s3/owner/tests/providers/conftest.py"
SPEC = importlib.util.spec_from_file_location("s3_public_synthetic_controls", HELPER)
PUBLIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLIC)


class ScreenRig(PUBLIC.Rig):
    def __init__(self, path, *, captured=True, hit=True, root_purpose=None):
        self.screen_policy = ScreenPolicy(
            "native-smoke/1",
            "typed",
            profile_id="S6-synthetic-smoke/native/1",
            thresholds=dict.fromkeys(HAZARDS, 0.35),
            threshold_provenance="exploratory_seed",
        )
        self.source = UntrustedText(
            "original-screen-control", "g1", "The label has the wrong color."
        )
        self.screen_prepared = prepare_text(self.source, self.screen_policy)
        self.wrapper = wrap_untrusted(self.screen_prepared) if captured else None
        self.binding = bind_native_request(
            self.screen_prepared,
            model="fixture-model",
            captured_wrapped=self.wrapper,
        )
        super().__init__(path, flavor="typesafe", typed=True)
        self.request = self.binding.request
        self.evidence = []
        self.register(self.request)
        self.native_prepared = self.prepared()
        self.provider_instance = self.provider(
            "strict_replay" if captured else "mock",
            capture_mode="fixture_replay",
            fixtures=FixtureIndex([self.capture()] if hit else []),
        )
        self.ledger = self.open(offline=True)
        root_context = self.context()
        if root_purpose is not None:
            root_context = root_context.model_copy(update={"purpose": root_purpose})
        plan = self.plan(offline=True).model_copy(
            update={"context_sha256": canonical_digest(root_context.model_dump(mode="json"))}
        )
        self.allocation = self.provider_instance.admit_operation(
            plan,
            ledger=self.ledger,
            budget=self.authority,
            context=root_context,
            limits=self.limits,
        )
        self.args = {
            **self.kwargs(self.ledger, self.allocation, offline=True),
            "model": self.request.model,
            "typed_gateway": self.provider_instance,
            "policy": self.screen_policy,
            "request_binding": self.binding,
            "captured_wrapped": self.wrapper,
        }
        self.observations, self.runs = [], []
        original_observe = self.provider_instance.validate_replay_allocation
        original_run = self.provider_instance.run

        def observe(request, **kwargs):
            self.observations.append((request, kwargs))
            return original_observe(request, **kwargs)

        def run(request, **kwargs):
            self.runs.append((request, kwargs))
            return original_run(request, **kwargs)

        self.provider_instance.validate_replay_allocation = observe
        self.provider_instance.run = run

    def context(self, *args, **kwargs):
        return (
            super()
            .context(*args, **kwargs)
            .model_copy(
                update={
                    "consumer_namespace": "s6-original-controls",
                    "policy_sha256": self.screen_policy.sha256,
                    "consumer_context_sha256": canonical_digest(
                        self.screen_prepared.original_sha256
                    ),
                }
            )
        )

    def body(self):
        return {
            "model": "fixture-model-reported",
            "answers": {key: {"type": "noul", "noul": 0.01} for key in HAZARDS},
            "usage": {"input_tokens": 100, "output_tokens": None},
        }

    def call(self, *, prepared=None, **changes):
        return screen_typed(prepared or self.screen_prepared, **{**self.args, **changes})


@pytest.fixture
def factory(tmp_path, monkeypatch):
    rigs = []

    def forbidden(*args, **kwargs):
        raise AssertionError("native screen controls cannot use network")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    with pytest.raises(AssertionError, match="cannot use network"):
        socket.socket()

    def create(**kwargs):
        rig = ScreenRig(tmp_path / "actual-native.sqlite3", **kwargs)
        rigs.append(rig)
        return rig

    yield create
    for rig in rigs:
        rig.ledger.close()


@pytest.mark.parametrize("captured", [False, True])
def test_native_packed_hit_same_six_objects_and_atomic_reuse(factory, captured):
    rig = factory(captured=captured)
    result = rig.call()
    assert result.decision == "pass" and result.method == "typed_mock"
    assert result.source_capture_ref.origin == "synthetic"
    assert result.source_capture_ref.cost_usd is None and result.attempt_ids == ()
    assert result.request_identity_sha256 == rig.native_prepared.request_identity_sha256
    assert (
        result.actual_dispatched_envelope_sha256 == rig.native_prepared.dispatched_envelope_sha256
    )
    assert result.question_set_sha256 == rig.binding.request.question_spec_sha256
    assert result.question_set_sha256 != QUESTION_SET_SHA256
    assert len(rig.observations) == len(rig.runs) == 1
    for request, forwarded in rig.observations + rig.runs:
        assert request is rig.binding.request
        assert set(forwarded) == {"purpose", "ledger", "budget", "context", "limits", "allocation"}
        assert all(forwarded[key] is rig.args[key] for key in forwarded)
    totals = rig.ledger.totals()
    assert totals["dispatched_attempts"] == 0
    again = rig.call()
    assert again.decision == "needs_human" and again.hazard_probabilities is None
    assert len(rig.runs) == 1 and rig.ledger.totals() == totals
    assert result.permits_model_input(rig.source, rig.screen_policy)
    for changed in (
        replace(rig.source, text="changed"),
        replace(rig.source, source_generation="deleted"),
        None,
    ):
        assert not result.permits_model_input(changed, rig.screen_policy)


@pytest.mark.parametrize("captured", [False, True])
def test_screen_child_purpose_can_differ_from_operation_root(factory, captured):
    """what_bug_this_catches: a valid screen stage is rejected against its root purpose."""
    rig = factory(captured=captured, root_purpose="synthetic.issue-triage-operation")
    result = rig.call()
    assert result.decision == "pass" and result.source_capture_ref.origin == "synthetic"
    assert rig.ledger.operation_state(rig.allocation) == "complete"
    assert rig.ledger.totals()["dispatched_attempts"] == 0
    assert result.attempt_ids == ()
    assert len(rig.observations) == len(rig.runs) == 1
    for request, forwarded in rig.observations + rig.runs:
        assert request is rig.binding.request
        assert all(forwarded[key] is rig.args[key] for key in forwarded)


def test_exact_capture_miss_stays_hold_and_never_falls_back(factory):
    rig = factory(hit=False)
    result = rig.call()
    assert result.reason_codes == ("cache_miss",) and result.decision == "needs_human"
    assert result.source_capture_ref is None and result.attempt_ids == ()
    assert len(rig.runs) == 1 and rig.ledger.totals()["dispatched_attempts"] == 0


@pytest.mark.parametrize(
    "change",
    [
        "state",
        "question_order",
        "criterion",
        "requested_model",
        "source_same_generation",
        "source_id",
        "generation",
        "policy",
        "context",
        "namespace",
        "budget",
        "allocation",
        "outbound",
        "wrapper_object",
        "missing_wrapper",
        "full_wrapper_cap",
        "question_cap",
        "stale_preparation",
        "wrong_mode",
    ],
)
def test_native_negative_controls_leave_allocation_and_quota_unchanged(factory, change):
    rig = factory()
    before = rig.ledger.totals()
    kwargs = {}
    prepared = rig.screen_prepared
    if change == "state":
        rig.request.state["normalized_text"] += " altered"
    elif change == "question_order":
        pairs = list(rig.request.questions.items())
        rig.request.questions.clear()
        rig.request.questions.update(reversed(pairs))
    elif change == "criterion":
        question = rig.request.questions[HAZARDS[0]]
        rig.request.questions[HAZARDS[0]] = question.model_copy(
            update={"criteria": question.criteria.model_copy(update={"true": "altered"})}
        )
    elif change == "requested_model":
        kwargs["model"] = "other-model"
    elif change in {"source_same_generation", "source_id", "generation"}:
        altered = {
            "source_same_generation": {"text": "different original text"},
            "source_id": {"source_id": "other-source"},
            "generation": {"source_generation": "generation-2"},
        }[change]
        prepared = prepare_text(replace(rig.source, **altered), rig.screen_policy)
    elif change == "policy":
        kwargs["policy"] = replace(rig.screen_policy, version="changed")
    elif change in {"context", "namespace"}:
        altered = (
            {"consumer_context_sha256": canonical_digest("wrong-context")}
            if change == "context"
            else {"consumer_namespace": "other-namespace"}
        )
        kwargs["context"] = rig.args["context"].model_copy(update=altered)
    elif change == "budget":
        kwargs["budget"] = rig.authority.model_copy(
            update={"scope_sha256": canonical_digest("other")}
        )
    elif change == "allocation":
        kwargs["allocation"] = rig.allocation.model_copy(update={"allocation_id": "invented"})
    elif change in {"outbound", "full_wrapper_cap", "question_cap"}:
        altered = {
            "outbound": {"max_outbound_attempts": 1},
            "full_wrapper_cap": {"max_request_bytes": len(rig.source.text.encode()) + 1},
            "question_cap": {"max_questions": 2},
        }[change]
        kwargs["limits"] = rig.args["limits"].model_copy(update=altered)
    elif change == "wrapper_object":
        kwargs["captured_wrapped"] = WrappedData(
            dict(rig.binding.wrapped.state), rig.binding.wrapped.sha256
        )
    elif change == "missing_wrapper":
        kwargs["captured_wrapped"] = None
    elif change == "stale_preparation":
        prepared = replace(prepared, source=replace(rig.source, text="stale"))
    elif change == "wrong_mode":
        rig.provider_instance.mode = "mock"
    result = rig.call(prepared=prepared, **kwargs)
    assert result.decision == "needs_human" and result.hazard_probabilities is None
    assert rig.runs == [] and rig.ledger.totals() == before


def test_factory_rejects_truncated_capture_without_replacement_nonce(factory):
    rig = factory()
    changed = dict(rig.binding.wrapped.state)
    changed["normalized_text"] = changed["normalized_text"][:-1]
    bad = WrappedData(changed, canonical_digest(changed))
    with pytest.raises(ScreenValidationError, match="invalid_capture"):
        bind_native_request(rig.screen_prepared, model=rig.binding.model, captured_wrapped=bad)


def test_expiry_after_observation_is_rechecked_by_actual_atomic_reuse(factory):
    rig = factory()
    original_run = rig.provider_instance.run

    def expired(request, **kwargs):
        rig.now += timedelta(seconds=31)
        rig.tick += 31
        return original_run(request, **kwargs)

    rig.provider_instance.run = expired
    result = rig.call()
    assert result.decision == "needs_human" and result.reason_codes == ("provider_error",)
    assert len(rig.observations) == len(rig.runs) == 1
    assert rig.ledger.totals()["dispatched_attempts"] == 0
    assert result.source_capture_ref is None


def test_native_source_deletion_or_same_generation_edit_rejects_late_save(factory):
    rig = factory()
    result = rig.call()
    assert native_binding_permits_model_input(rig.binding, result, rig.source, rig.screen_policy)
    for current in (
        None,
        replace(rig.source, text="same generation edited content"),
        replace(rig.source, source_id="different-source-with-same-text-and-generation"),
        replace(rig.source, source_generation="deleted-generation"),
    ):
        assert not native_binding_permits_model_input(
            rig.binding, result, current, rig.screen_policy
        )
    # Mutable native mappings are checked again at use time, even after a successful screen.
    rig.request.state["original_text"] += " changed after result"
    assert not native_binding_permits_model_input(
        rig.binding, result, rig.source, rig.screen_policy
    )


def test_native_screen_and_actual_ledger_move_without_either_owner_namespace(tmp_path):
    shared = Path(__file__).parents[2] / "src/issue_triage/shared"
    target = tmp_path / "detached"
    target.mkdir()
    (target / "__init__.py").write_text("", encoding="utf-8")
    shutil.copytree(shared, target / "shared", ignore=shutil.ignore_patterns("__pycache__"))
    script = r"""
import builtins, pathlib, socket, sys
sys.path.insert(0, sys.argv[1])
def blocked(*a, **k): raise RuntimeError("blocked network positive control")
socket.socket = blocked
socket.create_connection = blocked
try: socket.socket()
except RuntimeError: pass
else: raise AssertionError("network denial absent")
original = builtins.__import__
def importing(name, *a, **k):
    if name.startswith(("llm_router_eval", "issue_triage")):
        raise AssertionError("owner import forbidden")
    return original(name, *a, **k)
builtins.__import__ = importing
namespace = {"__name__": "detached_public_synthetic_rig"}
helper = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
exec(helper.replace("from issue_triage.", "from detached."), namespace)
from detached.shared.screen import ScreenPolicy, UntrustedText, prepare_text
from detached.shared.screen.models import HAZARDS
from detached.shared.screen.prepare import wrap_untrusted
from detached.shared.screen.s3_adapter import bind_native_request
from detached.shared.screen.typed import screen_typed
from detached.shared.providers.captures import FixtureIndex
policy = ScreenPolicy("detached/1", "typed", profile_id="synthetic-smoke/detached",
    thresholds=dict.fromkeys(HAZARDS, 0.35), threshold_provenance="exploratory_seed")
source = UntrustedText("detached-control", "g1", "A label has the wrong color")
prepared = prepare_text(source, policy)
wrapped = wrap_untrusted(prepared)
binding = bind_native_request(prepared, model="fixture-model", captured_wrapped=wrapped)
rig = namespace["Rig"](pathlib.Path(sys.argv[1]) / "detached.sqlite3",
    flavor="typesafe", typed=True)
context = rig.context
rig.context = lambda *a, **k: context(*a, **k).model_copy(update={"policy_sha256": policy.sha256})
rig.request = binding.request
rig.evidence = []
rig.register(rig.request)
rig.body = lambda: {"model": "fixture-model-reported", "usage": {"input_tokens": 100},
    "answers": {key: {"type": "noul", "noul": 0.01} for key in HAZARDS}}
provider = rig.provider("strict_replay", fixtures=FixtureIndex([rig.capture()]),
    capture_mode="fixture_replay")
with rig.open(offline=True) as ledger:
    allocation = provider.admit_operation(rig.plan(offline=True), ledger=ledger,
        budget=rig.authority, context=rig.context(), limits=rig.limits)
    result = screen_typed(prepared, model=binding.model, typed_gateway=provider,
        policy=policy, captured_wrapped=wrapped, request_binding=binding,
        **rig.kwargs(ledger, allocation, offline=True))
    assert result.decision == "pass" and result.method == "typed_mock"
    assert result.source_capture_ref.origin == "synthetic"
    assert ledger.totals()["dispatched_attempts"] == 0
print("detached native screen + actual Ledger pass; mock origin; zero dispatch")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path), str(HELPER)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert "detached native screen + actual Ledger pass" in result.stdout
