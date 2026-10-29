# Retained captured-work consumer

`CapturedWorkflow` consumes an existing explicit `JobLease` from the host's open
`JobStore`. The host supplies the configured `RepositoryIdentity`, current
`LabelInventory`, `LabelMap`, an explicit trusted local deterministic judge callable
with signature `(JudgmentContext, JudgmentPolicy)`, and a UTC start timestamp.
For local synthetic use the callable can be the existing `judge_rules`. There is
no default provider, environment discovery, credential access, HTTP transport,
subprocess, queue claim, listener or apply operation in this consumer.

The original retained capture is loaded through `CaptureIntake.load_in` within an
owned transaction. Current issue state, canonical payload and the exact unexpired
lease capability are checked before dispatch and again at completion. Full original
issue text passes the existing deterministic screen before judgment. Reference
analysis reuses `check_capture`, its original index and `JudgmentContext` admission.
The injected output must validate against current context and equal the existing
deterministic rules result. The host is responsible for supplying a trusted local
callable: injection is not a process sandbox or proof of provider isolation.

The completion transaction reloads capture integrity and bindings, checks dependency
identity and lease currency, and atomically completes the job and inserts its tagged
`retained_capture_worker/1` result into existing `local_results`. No second queue or
result ledger is introduced. An exact completed retry returns the same canonical
result without invoking the judge, including after the old lease deadline. A changed
lease capability, source/revision, label observation, label map or policy refuses the
retry. Refusals do not transition jobs; the host retains existing lease expiry/retry
responsibility. Judge errors persist a closed held result with no judgment/proposals.

The result preserves the 64-character capture record ID, original 40-character Git
SHA, inventory digest, capture time, transport provenance and `retained_capture`
source kind separately. `authenticated_github_origin` remains false. The existing
fixture workflow rejects this result's schema and cannot treat it as fixture input.

Comments are always explicitly held with `source_citation_contract_unavailable`.
The canonical S5 `SnapshotLocator` supports Git/fixture locators and cannot truthfully
represent this retained capture record. There is no fabricated locator, comment text
or evidence. Validated existing label/type/priority fields may be present in a
`SuggestionSet`, while its comment field has `needs_human` status and a null value.
The overall result remains `needs_human`. This partial consumer is not a review/apply
entrypoint, and cited-proposal completion remains open pending an owner-approved
shared citation contract. Production separate-process judge integration is also
unverified; this port is explicitly local deterministic execution.

`tests/worker/test_captured.py` contains original synthetic controls for completion,
exact replay, screen holds, lease/revision refusal, changing inputs during judgment,
dependency changes on retry, malformed/fixture input refusal and provenance. These
controls require a separately authorized execution slot; static construction alone
does not establish passing tests, runtime readiness or whole-app acceptance.
