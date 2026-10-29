# App-local judgment contracts

Judgments are draft proposals for human disposition. No function in this package admits a budget,
dispatches a provider, reads credentials, writes labels or records human approval. The default
deterministic rules baseline produces point decisions without invented probabilities or provider
provenance. Unclear input abstains. Its keyword heuristics are transparent and uncalibrated.

Every entrypoint first binds the exact current IssueInput, original model-bound text, source ID and
issue-generation digest to a complete passed ScreenResult and actual codeindex report. Deterministic
screening is checked again; replaced pass fields cannot override a known hold. Actual references are
re-extracted so a consistent empty report cannot silently omit identifiers from the current issue.
Every report item is checked against the retained current index and explicit prior/mapping authority.
Incomplete/ambiguous/tentative source evidence holds before any request binding or classification.

The six type options are bug, feature, question, needs_repro, likely_invalid and unclear. Priority has
four ordered levels: zero critical, one high, two normal, three low. `make_typed_binding` packs one
Choice, one four-level Score and two explicit Nouls into a single native S3 TypedJudgmentRequest.
Its full original and normalized issue text are nonce-wrapped data; code-owned facts are a compact
count summary, with exact issue/report/policy identities. The factory creates one wrapper/request
before external preparation/admission. Callers reuse that exact binding; no retry or capture path
reconstructs a nonce. Native mutable state/questions/model and wrapper drift reject normalization.

`normalize_typed` accepts the canonical S3 Result object, revalidates it against the originating
native request/questions and records its real mock/replay/live origin, accounting reference, cost
availability and full-result digest. It does not parse arbitrary model dictionaries or call an SDK.
Choice/Score distribution concentration and margins are distinct from supplied confidence fields.
Discrete priority uses the unique distribution mode; the probability-weighted Score is retained
separately. Noul uncertainty, internal reproduction disagreement and disagreement with deterministic
source facts suppress every prediction field and route human. Source existence is never decided by
a model. Source lookup cannot establish semantic issue validity.

Current thresholds are exploratory decimal-string seeds, without a measured calibration claim.
This package has not read the sealed author corpus, tuned against labels, executed live calls or
measured model quality. Rules/mock observations cannot promote Jev or claim paid/live performance.
No repository-label mapping, generative/Luna adapter, durable cache, subprocess isolation or complete
triage/apply workflow is implied by these contracts. Label/approval context and canonical provider
funding, retry and unknown-usage controls remain mandatory at their owning workflow boundaries.
