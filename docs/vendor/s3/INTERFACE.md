# Portable wire models and accounting foundation (wire schema version 1)

The Python models under `llm_router_eval.shared.callledger.models` and `llm_router_eval.shared.providers.models` define the normative wire declarations. `scripts/generate_schemas.py` generates the 18 JSON Schemas in `docs/schemas`; `--check` verifies exact byte parity. JSON Schema describes structural constraints. Python validators also enforce distribution sums, weighted Score consistency, cross-field bindings and declared accounting completeness.

## Typed judgments

`TypedJudgmentRequest` accepts native Choice, Noul and Score questions. Choice keeps ordered option criteria; Noul optionally accepts a true/false description map and omits absent descriptions. Score accepts 2–10 ordered criteria, including structured instructions. Answers are a distinct closed union: Noul has a probability and no invented confidence; Score preserves a fractional weighted position with a string-valued response legend and zero-based keys.

`validate_typed_wire(json_text, request)` rejects duplicate keys, nonfinite JSON, extra fields, missing/extra answer IDs, mismatched primitives, criteria hashes and option coverage. Both Choice and Score distributions must sum to one within 1e-6; Score consistency tolerance is 1e-3. Invalid distributions are rejected without normalization. The actual reported model is required. `validate_for` rechecks serialized nested data because frozen Pydantic models do not make nested dictionaries immutable.

## Requests, results and identity

`GenerateRequest` keeps text/image parts separate from typed JSON state. Its wire key `schema` maps to the Python attribute `output_schema`. `Result` preserves raw usage transiently, normalized numeric usage, attempt references, error codes and origin. Failed results cannot expose validated parsed or typed outputs. Successful replay/mock requires matching capture provenance and zero current external cost; source cost may remain unknown. A no-dispatch failure such as a strict miss may have no capture only with empty attempt IDs and current cost zero. The actual controller must establish the offline allocation; these structural fields alone grant nothing. An unavailable first-output time is null.

`ExecutionEnvelope` requires explicit purpose, ledger reference, budget, context, limits and allocation. It checks declared authority/operation/deadline/quota/shape consistency. Semantic request identity excludes machine image paths and ephemeral execution IDs, while retaining ordered criteria, public configuration, source generation and consumer context. The dispatched request digest includes the actual execution reference. Image declarations carry content/rendition hashes and geometry; these declarations do not inspect files, verify image magic, resolve symlinks or prevent a later file change. A future driver must validate and send the same immutable bytes.

## Accounting declarations

`NormalizedUsage`, `BillingPolicy` and `CostObservation` distinguish unknown usage from unbilled null output. A known cost declaration requires all declared billed components. These declaration models do not calculate prices. `OperationPlan`, `Allocation` and `FundingDeclaration` check whole declared fan-out exposure, attempt quota and allocation digest.

The separate `callledger.ledger.Ledger` now provides SQLite-authoritative atomic whole-operation funding, conserved attempt transfers, cumulative counters and persistent known/unknown liabilities. `callledger.pricing.PricePolicy` performs Decimal indicative billing from an explicit snapshot. Both require trusted caller evidence; the committed snapshots/counts are synthetic and cannot establish live funding proof. See the [accounting contract](../src/llm_router_eval/shared/callledger/README.md) for methods, deadline/hold semantics, durability, above-bound halt behavior and remaining controller obligations.

`MetadataRecord` permits only closed codes and numeric usage fields. Raw prompt/response/error bodies and arbitrary provider usage strings are forbidden in this projection. Validation exception text hides input values, but callers must also avoid printing the structured `errors()` data, which can include inputs. No capture store or global cache exists in this edition.

## Copy closure and current boundary

Copy the complete `shared` directory (including its empty root initializer and both sibling subpackages) into a consumer-owned package. Provider models import `..callledger.models`; the copy requires Python 3.12 and Pydantic >=2.11,<3. The repository lock pins the tested version. There are no SDK, HTTP, owner-app, router or scorer imports in this closure. A detached-copy test blocks owner-app imports and network construction.

This edition includes an actual offline `Provider.run`/`complete` controller over strict immutable fixtures or injected synthetic transports, described in [provider-contracts.md](provider-contracts.md). The adapter executes a deliberately supported strict-schema subset and validates the same in-memory PNG bytes used in a payload. Unsupported features refuse before dispatch. There is no SDK/HTTP client, credential access, routing policy, scorer, corpus or real provider result. Accounting methods themselves do not send requests or perform capture lookup. Consumers must pin exact committed Git blob bytes, licence and their own moved checks under an actual source-adoption grant; local model/ledger/controller tests do not establish live integration.
