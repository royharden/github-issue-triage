"""what_bug_this_catches: subtotal-as-total, cache double billing and false price provenance."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from issue_triage.shared.callledger.models import NormalizedUsage
from issue_triage.shared.callledger.models import canonical_digest as digest
from issue_triage.shared.callledger.pricing import PricePolicy, PriceSnapshot, load_snapshot


def policy(**overrides):
    return PricePolicy.model_validate(
        {
            **dict(
                schema_version=1,
                provider="synthetic",
                model="fixture-model",
                context_sha256=digest("price-context"),
                cache_mode="flat_inclusive",
                input_usd_per_million="0.042",
                cache_read_usd_per_million=None,
                cache_write_usd_per_million=None,
                output_usd_per_million=None,
                fee_usd="0",
            ),
            **overrides,
        }
    )


def test_input_only_known_cost_keeps_unbilled_output_null():
    value = policy().price(NormalizedUsage(input_tokens=1000), reservation_usd="0.1")
    assert value.status == "known" and value.computed_cost_usd == "0.000042"
    assert value.usage.output_tokens is None


def test_partitioned_inclusive_cache_and_reasoning_not_double_counted():
    price = policy(
        cache_mode="partitioned",
        input_usd_per_million="1",
        cache_read_usd_per_million="0.1",
        cache_write_usd_per_million="2",
        output_usd_per_million="3",
        fee_usd="0.001",
    )
    value = price.price(
        NormalizedUsage(
            input_tokens=110,
            cache_read_input_tokens=20,
            cache_write_input_tokens=10,
            output_tokens=50,
            reasoning_output_tokens=30,
        ),
        reservation_usd="0.1",
    )
    # Invoice components: uncached80 + read20*.1 + write10*2 + inclusive output50*3.
    assert value.computed_cost_usd == "0.001252"
    assert value.usage.input_tokens == 110


@pytest.mark.parametrize("changes", [{"input_tokens": None}, {"output_tokens": None}])
def test_missing_billed_component_preserves_unknown_and_entire_liability(changes):
    usage = NormalizedUsage.model_validate(
        {**dict(input_tokens=1000, output_tokens=100), **changes}
    )
    value = policy(output_usd_per_million="0.5").price(usage, reservation_usd="0.1")
    assert value.status == "unknown" and value.computed_cost_usd is None
    assert value.unresolved_liability_usd == "0.1"


def test_unknown_fee_context_never_becomes_token_subtotal():
    value = policy(fee_usd=None).price(NormalizedUsage(input_tokens=100), reservation_usd="0.1")
    assert value.computed_cost_usd is None
    with pytest.raises(ValueError):
        policy(fee_usd=None).maximum_cost(1000, None)


def test_real_zero_and_unbilled_null_are_not_fabricated_counts():
    zero = policy().price(NormalizedUsage(input_tokens=0), reservation_usd="0.1")
    assert zero.computed_cost_usd == "0.000" and zero.usage.output_tokens is None
    free = policy(input_usd_per_million="0", output_usd_per_million="0").price(
        NormalizedUsage(), reservation_usd="0"
    )
    assert free.computed_cost_usd == "0" and free.usage.input_tokens is None
    assert policy().price(NormalizedUsage(), reservation_usd="0.1").status == "unknown"


@pytest.mark.parametrize("rate", ["-1", "NaN", "Infinity", 0.5, True])
def test_invalid_nondecimal_or_nonfinite_rate_rejected(rate):
    with pytest.raises(ValidationError):
        policy(input_usd_per_million=rate)


def test_worst_partition_bound_is_conservative_and_output_needs_proof():
    price = policy(
        cache_mode="partitioned",
        input_usd_per_million="1",
        cache_read_usd_per_million="0.1",
        cache_write_usd_per_million="2",
        output_usd_per_million="3",
    )
    assert price.maximum_cost(1000, 100) == "0.0023"
    with pytest.raises(ValueError):
        price.maximum_cost(1000, None)
    with pytest.raises(ValueError):
        price.maximum_cost(True, 100)
    with pytest.raises(ValueError):
        price.maximum_cost(10**41, 100)


def snapshot_path():
    return Path(__file__).resolve().parents[2] / "prices/synthetic-unit-v1.json"


def test_exact_snapshot_selection_and_hash_tampering_rejected():
    snapshot = load_snapshot(snapshot_path())
    assert snapshot.provenance.origin == "synthetic"
    assert snapshot.provenance.source_commit is None
    assert snapshot.select(
        provider="synthetic", model="fixture-model", context_sha256=digest("price-context")
    )
    with pytest.raises(ValueError, match="price_unknown"):
        snapshot.select(
            provider="synthetic", model="unknown-alias", context_sha256=digest("price-context")
        )
    data = snapshot.model_dump(mode="json")
    data["policies"][0]["fee_usd"] = "99"
    with pytest.raises(ValidationError):
        PriceSnapshot.model_validate(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_commit", "a" * 40),
        ("source_url", "https://example.test/prices"),
        ("official_verified_at", "2026-10-14T00:00:00Z"),
    ],
)
def test_synthetic_fixture_cannot_fabricate_official_provenance(field, value):
    data = load_snapshot(snapshot_path()).model_dump(mode="json")
    data["provenance"][field] = value
    with pytest.raises(ValidationError):
        PriceSnapshot.model_validate(data)


def test_update_utility_is_pure_new_snapshot_and_refuses_overwrite(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts/update_prices.py"
    destination = tmp_path / "snapshot.json"
    command = [sys.executable, str(script), str(snapshot_path()), str(destination)]
    (tmp_path / "sitecustomize.py").write_text(
        "import socket\ndef blocked(*a,**k):raise RuntimeError('no price update network')\n"
        "socket.socket=blocked\nsocket.create_connection=blocked\n"
    )
    environment = {
        **os.environ,
        "PYTHONPATH": str(tmp_path),
        "OPENAI_API_KEY": "",
        "TYPESAFE_API_KEY": "",
    }
    control = subprocess.run(
        [sys.executable, "-c", "import socket;socket.socket()"],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert control.returncode != 0 and "no price update network" in control.stderr
    first = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
    assert first.returncode == 0, first.stderr
    assert "synthetic" in first.stdout
    original = destination.read_bytes()
    assert load_snapshot(destination) == load_snapshot(snapshot_path())
    duplicate = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
    assert duplicate.returncode != 0 and destination.read_bytes() == original
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"schema_version":1,"schema_version":1}')
    failure = subprocess.run(
        [sys.executable, str(script), str(malformed), str(tmp_path / "never.json")],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert failure.returncode != 0 and not (tmp_path / "never.json").exists()
