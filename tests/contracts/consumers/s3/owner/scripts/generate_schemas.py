"""Generate/check JSON Schemas from the normative shared Pydantic models."""

import argparse
import json
from pathlib import Path

from issue_triage.shared.callledger import models as ledger
from issue_triage.shared.providers import models as providers

MODEL_TYPES = {
    "budget-authority": ledger.BudgetAuthority,
    "call-context": ledger.CallContext,
    "limits": ledger.Limits,
    "operation-plan": ledger.OperationPlan,
    "allocation": ledger.Allocation,
    "funding-declaration": ledger.FundingDeclaration,
    "normalized-usage": ledger.NormalizedUsage,
    "billing-policy": ledger.BillingPolicy,
    "cost-observation": ledger.CostObservation,
    "metadata-record": ledger.MetadataRecord,
    "non-model-span": ledger.NonModelSpan,
    "generate-request": providers.GenerateRequest,
    "typed-request": providers.TypedJudgmentRequest,
    "typed-result": providers.TypedJudgmentResult,
    "execution-envelope": providers.ExecutionEnvelope,
    "result": providers.Result,
    "image-part": providers.ImagePart,
    "capabilities": providers.Capabilities,
}


def schema_bytes(model) -> bytes:
    return (
        json.dumps(
            model.model_json_schema(by_alias=True), indent=2, sort_keys=True, ensure_ascii=False
        )
        + "\n"
    ).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[1] / "docs" / "schemas"
    expected = {f"{name}.schema.json": schema_bytes(model) for name, model in MODEL_TYPES.items()}
    if args.check:
        actual = {path.name: path.read_bytes() for path in target.glob("*.schema.json")}
        if actual != expected:
            raise SystemExit(
                "Generated schemas differ; regenerate from normative model definitions"
            )
        print(f"Checked {len(expected)} generated schemas; exact byte parity")
    else:
        target.mkdir(parents=True, exist_ok=True)
        obsolete = {path.name for path in target.glob("*.schema.json")} - expected.keys()
        if obsolete:
            raise SystemExit("Unexpected old schema files require explicit migration")
        for name, content in expected.items():
            (target / name).write_bytes(content)
        print(f"Generated {len(expected)} schemas from normative models")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
