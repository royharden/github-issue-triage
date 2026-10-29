# Bolt handoff — local fixture workflow; inspection only

Target/baseline: **local Python 3.12 + SQLite/JSONL; no hosted database selected**.
No remote database, auth, bucket, edge function, GitHub App or provider account is provisioned.
This is an inspection/preparation inventory, not a provisioning or publication instruction.
See [development status](DEVELOPMENT-STATUS.md) for implemented behavior and remaining work.

## Implemented resources

- Python/uv package, Pydantic contracts and pinned native tree-sitter grammars.
- SQLite WAL/FULL job store; three ordered checksummed migrations embedded in
  `src/issue_triage/store/database.py`. Version1/2 upgrades preserve history; opening a new local
  state directory applies pending migrations. There is no cloud SQL migration or Supabase client.
- Canonical append-only S2 JSONL decisions with an app-specific provisional field adapter.
  Jobs and captured fixture input commit atomically; decisions and dry-run receipts survive reopening.
- SHA-pinned original public fixture CLI/demo, full-input screening, real isolated rules subprocess,
  deterministic index/report/citations, local review and idempotent zero-write previews.
- `pyproject.toml` and `uv.lock`; producer source/license maps live in `docs/vendor/` and
  `src/issue_triage/shared/*-VENDORED.md`.
  Runtime modules do not import another workspace repository. Native grammar ABI checks ran on
  Windows; Linux deployment remains unverified.

## Local commands

```sh
uv sync --frozen
uv run python -m issue_triage --offline
uv run python scripts/demo.py --offline --state-dir .triage-state/demo
```

The demo has exercised the original fixture through proposal, provisional review, dry-run,
reopen/replay and bad-SHA/injection refusal. Focused tests additionally cover bad signatures,
stored hashes, capture rollback, stale/CAS decisions, damaged journals and expired leases.
The demo retains state and can be rerun for exact retries. It does not measure model quality,
prove real human approval, perform Git capture or send GitHub writes. The current rules timeout
holds with no proposals; a timeout is not permission to silently use another provider.

## Deployment gaps and owner steps

A FastAPI/Jinja local review frontend/backend is present. `serve-demo` binds only an exact
configured loopback HTTP origin with intentionally public synthetic credentials. Protected pages,
current per-field decisions and dry-run receipts use real app stores. Persistent local session
admission/revocation and login attempt limits live in the separate `web-auth.sqlite3` version1
schema. No real Human identity, HTTPS account lifecycle or deployed backend is established.
See `docs/REVIEW-BOUNDARY.md` and `docs/HTTP-DEPENDENCIES.md`.
Trusted-clock faults use the guarded generic failure response with the local security headers;
this does not establish production identity, HTTPS readiness or independent browser acceptance.

Actual GitHub transport/token acquisition and trusted capture, refreshed-context remote apply/
reconciliation, protected HTTPS webhook hosting and application evaluation remain unfinished.
Snapshot source text is parsed, never installed/executed.

A deployment must supply a Python/native-grammar process, durable filesystem/SQLite/JSONL and
appropriate protected worker/review/webhook operation, or an explicitly approved port of the backend.
Importing this repo alone has not been shown to run any of those resources. Current Bolt deployment
capabilities are not verified by this local slice. No forced JavaScript/database rewrite is assumed.

No environment variables or secrets are needed for the demonstrated rules-only workflow.
Future GitHub signing/webhook/operator/provider credentials belong only in authorized server
configuration; name/permission/account/deployment decisions remain owner steps. The local rehearsal has intentionally public demo keys; it is unsuitable for private data or
real Human authority. No active provider call exists. Do not read local credential files
or invent bindings while inspecting this repository.

## Inspection prompt for a future Bolt session

Inspect this exact repository revision and the inventory above. Report the concrete runtime,
frontend, native-grammar, durable-storage, auth and worker gaps for the intended target. Preserve
Python/SQLite/JSONL source, migration history, canonical licenses, explicit fixture provenance and
provisional review boundaries. Do not provision, migrate a remote database, import private state,
read credentials, install a GitHub App, enable writes or publish. Present a scoped preparation plan;
any later provisioning/deployment needs separate authorization and real target verification.
