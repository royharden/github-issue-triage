# Implemented boundaries and pending integrations

Product status and execution limits live in [DEVELOPMENT-STATUS.md](../DEVELOPMENT-STATUS.md).
This map names canonical paths rather than duplicating historical test counts or outcomes.

| Boundary | Implemented responsibility | Remaining authority/integration gap |
|---|---|---|
| `contracts`, `shared/ghapp`, `ingest` | Strict issue wires, original-byte HMAC before parse, ignored metadata, delivery conflict audit, causal head ordering and atomic jobs/captured local inputs. | No listening webhook, real GitHub token/HTTP transport, trusted event-time capture or account permission. Synthetic signing is not real RSA proof. |
| `store.JobStore` | Checksummed migrations, WAL/FULL transactions, unique jobs and expiring leases. | Not S3 accounting or S2 human-rulings truth; hostile same-user filesystem and power-loss behavior unproved. |
| `shared/codeindex` | Labelled inventories, Python/JS/TS/TSX definitions and literal routes/flags/configuration, four-status resolution, current digests, bounded reports and explicit verified mappings. | Dynamic/generated/incomplete coverage cannot establish absence. Fixture bytes or plausible Git IDs do not establish real capture or inferred rename lineage. |
| `shared/screen`, `judges`, `suggest` | Whole-input/policy binding, rules and typed offline/mock normalization, current cited fields, active-label allowlists and fixed comments. | Mock/rules are not live provider quality. Blocked/incomplete/unavailable input cannot authorize a usable draft. |
| `worker` | Actual isolated `-I -B` rules child, explicit environment projection, checked bundle/bytecode handshake and lease/currentness gates. | Not a same-user OS sandbox; no provider SDK, account execution or secret-file access implied. |
| `review/local`, canonical S2 rulings | Provisional per-field revision/CAS/value checks, append/fsync/replay and damaged-journal refusal. | Actor strings or synthetic operator sessions cannot establish real Human identity. |
| `review/security`, `review/service` | Dependency-free session/origin/CSRF rules joined to real current proposals and provisional journal writes. | Signing/component rules alone do not prove browser behavior or real Human identity. See [review boundary](REVIEW-BOUNDARY.md). |
| `review/http`, `review/web_auth` | Actual bounded ASGI header/cookie/form parser, escaped Jinja pages, exact configured origin/Host, session-bound sealed forms, persistent local logout and throttling. | Public demo keys are synthetic; independent browser/security acceptance and real identity/HTTPS lifecycle remain separate. No external apply route. |
| `apply/dry_run` | Current provisional label/comment previews, stable separate receipts and zero-write implementation. | No live transport, refreshed context, unknown-effect reconciliation or partial recovery; `live_apply` hard-refuses. |

S6 owns `ghapp`, `codeindex` and `screen`. Adopted S2 rulings/evalkit, S3 providers/ledger and S5
citation source is under `src/issue_triage/shared/`; provenance/license maps live in `docs/vendor/`
and shared `*-VENDORED.md` files. Canonical copies are not reformatted or replaced by app libraries.
Moved/pin controls prove their declared scopes, not live integration.

`runtime.child_environment` projects explicitly selected allowlisted fields from a supplied map;
it does not read credential files. The rules child selects no model/signing/writer credentials.
Future broker/serve/apply roles retain separate scopes and exact effect grants.

Real GitHub capture/apply, authenticated Human workflow, heldout/application evaluation, Linux
or hosted/Bolt deployment are not established by component checks. The S6 sealed corpus/generator/
author material remains sealed. Source availability, runtime installation, independent review and
release acceptance are separate.
