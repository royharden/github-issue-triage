# Portable untrusted-text screen, schema 1

The reusable closure is `src/issue_triage/shared/screen/*.py`. Copy that directory as one package;
rules/preparation use only the Python standard library and do not import the owner app, S3, SDKs,
images or an environment loader. `screen_typed` is a lazy package attribute or explicit submodule
import. Rules remain standalone standard-library code. The optional native adapter requires the
unchanged sibling S3 providers/callledger closure and Pydantic2; the screen installs no persistence.

`UntrustedText(source_id, source_generation, text)` is the complete caller-assembled model-bound
source. IDs are caller-owned opaque metadata, never raw user text. `ScreenPolicy` is trusted caller
configuration: explicit method, version, cap (1..32768), supported transform/rule versions and,
for typed mode, all three finite hazard thresholds and named provenance. Synthetic-smoke seeds
are exploratory. A `dev_calibrated` declaration is not evidence of calibration; the caller must
pin actual calibration and operating authority before using that profile. Text screening does
not screen image pixels or turn failed OCR into an empty successful input.

`prepare_text` returns `PreparedText` or a partial `HeldInput`; it never authorizes a truncated
prefix. Both original and normalized UTF-8 byte lengths must fit. Original SHA256 always covers
the exact original assembled source. Normalization surfaces HTML comment/details contents,
removes format/control characters (preserving tabs/newlines) and applies NFKC to base+combining
clusters. Segments map normalized half-open UTF-8 byte intervals to original half-open byte
intervals, including zero-width removal segments. An expansion maps to its entire original
cluster, not invented individual character offsets. Unsupported cross-cluster composition is
held as ambiguous. There is no universal Unicode/homoglyph or prompt-injection detection claim.

`screen_rules(source, policy)` returns neutral safety holds for bot overrides, imperative
run/fetch/install requests, credential requests, mixed-script tokens or bidi controls. A legitimate
reproduction imperative can need review without implying maliciousness. Diagnostic notices such
as a descriptive quoted `run` cannot clear actual hazards. Rules results have null probabilities
and model fields. A rules pass does not satisfy a typed-required policy.

`screen_typed(prepared, *, model, typed_gateway, ledger, budget, purpose, context, limits,
allocation, policy, captured_wrapped=None, request_binding=None)` revalidates source/preparation/policy, then forwards
one packed three-Noul request to `typed_gateway.run`. Every accounting keyword is required and
forwarded by object identity. Purpose, policy hash and source generation must match context;
authority ID is required. These checks do not prove paid admission: S3 must validate the actual
complete operation, bounded envelope, allocation, cumulative funds/quota and deadlines. S6 does
not admit/reserve/settle/refund or retry. A conservative serialized request cap can reject early;
a byte cap is not token/price evidence or proof that S3's full envelope fits.

Every fresh request uses a cryptographic 128-bit nonce absent from original/normalized source.
Literal angle brackets are escaped inside two exact named DATA wrappers, preserving complete
source; wrapper SHA differs from source SHA. The question map has only
`addresses_automated_agent`, `asks_to_run_fetch_or_install`, `asks_for_credentials`, each a Noul
with explicit true/false criteria. Results require exact question IDs/tags, finite probabilities,
requested/reported model binding, question digest and typed-only channels. Equal-to-threshold
holds. Invalid/refused/budget/deadline/provider failures hold and preserve returned accounting
references/attempt IDs; arbitrary error bodies are not returned or logged.

The legacy injected-protocol path keeps its original question-map hash and behavior. Without a
native binding, `captured_wrapped` still holds with `capture_allocation_unavailable`; a wrapper
and zero limit alone cannot prove admission. Fresh legacy responses claiming replay hold.

For actual offline S3 integration, call `s3_adapter.bind_native_request(prepared, model=...)`
once before external preparation/admission. It creates one fresh wrapper and native request.
An exact captured request instead supplies its original `captured_wrapped` to that factory;
pass the same wrapper object to `screen_typed`. The caller prepares the binding's native
`request`, supplies trusted RequestEvidence and an actual complete OperationPlan, and obtains
its allocation from the canonical Provider/Ledger. The screen creates no allocation or budget.
Pass `request_binding=binding` plus the same six caller objects to the screen. Fresh bindings
require mock mode; captured bindings require strict_replay. Both require explicit outbound0 and
an actual pending offline zero-attempt child. S3 read-only allocation observation precedes the
one packed `run`; S3 atomically rechecks reuse, cumulative limits, context and deadlines.

Every use checks source ID/generation/content/policy, exact original wrapper and native request
contents, full request hash and native ordered question digest. It does not reconstruct a capture
nonce/request. Reorder, stale content, changed model/context/budget, truncated wrapper, full
wrapped-request caps, a miss or completed allocation cannot become a pass or live fallback.
Authored synthetic captures return `typed_mock`, including under strict_replay. This is no genuine
Jev capture, paid call, calibration or operational-quality evidence.

`ScreenResult` exposes decision/reasons, separate safety flags and diagnostics, method/origin
classification, nullable probabilities/models, digests and opaque accounting/source-capture refs.
Legacy unobserved S3 identity/envelope hashes remain null. Native results retain actual S3
PreparedRequest hashes; `actual_dispatched_envelope_sha256` identifies prepared envelope bytes,
and does not claim dispatch occurred. `safe_metadata()` omits payload, offsets, nonce, arbitrary
error/model strings and reference objects. Payload-bearing values have no payload repr or save
API. Caller-owned storage/caching/deletion is outside this package; no implicit capture occurs.

`result.permits_model_input(current_source, current_policy)` requires a pass plus exact text,
generation, policy, transform and method binding. It is an input-composition guard, never human
approval or an action/disclosure grant. Consumers must keep held items counted and preserve their
own local fallback/review behavior. Actual S7 deletion, S5 unknown-review effects and S10 aggregate
privacy/funding checks require their consumer implementations; screen tests do not prove them.

Native consumers use `native_binding_permits_model_input(binding, result, current_source,
current_policy)` immediately before use. It additionally binds source ID, original native pair,
wrapper/model/ordered-question digests and observed S3 identity. Deletion, a same-generation text
edit, changed source ID or post-result request mutation rejects reuse. Callers must check their
current generation atomically when persisting; this pure guard is no durable cache or race lock.

Offline contract tests in `tests/screen` include detached imports, UTF-8 maps, normalization/cap
negatives, collision/nonce checks, same-object gateway spies, closed typed answer failures,
reference preservation, non-persistence and replay-unavailable checks. Authored gateway results
are synthetic; they do not measure Jev/OpenAI quality or real billing. Moved S3 conformance tests
execute real local admission/reuse with owner imports and network blocked. Exact source/license
and test mapping are in `shared/S3-VENDORED.md` and `docs/vendor/s3/SOURCE.001.json`.
