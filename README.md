# GitHub Issue Triage

A local GitHub issue review tool under development, grounded in deterministic source evidence.
An offline fixture workflow joins signed synthetic intake, bounded source indexing, screening,
an isolated rules process, cited proposals, provisional field review and repeatable dry-run receipts.
There is no finished-app acceptance result, real GitHub capture, authenticated human review or live apply.

See [development status](DEVELOPMENT-STATUS.md) for completed work, the exact draft state,
outstanding functionality and verification limits, and [lessons](LESSONS.md) before continuing.

## Quickstart

Python 3.12 and uv are required. From this repository:

```sh
uv sync --frozen
uv run python -m issue_triage --offline
uv run python scripts/demo.py --offline --state-dir .triage-state/demo
```

The demo uses only `examples/local-bundle.json`, an original public synthetic example whose raw
bytes are SHA-pinned in the script. It runs triage, provisional label acceptance and comment editing,
dry-run, reopened-state replay, bad-SHA refusal and injected-input hold. It retains its SQLite,
JSONL and synthetic inputs under the supplied state directory; rerunning the same command checks
exact retries. These decisions are agent-provisional rehearsals, never authenticated human approval.

To submit the same example directly, from the repository root:

```sh
uv run python -m issue_triage triage --input examples/local-bundle.json --input-sha256 334a9d1edbbcfa5941c9c2ad004626fbcaa677549777b3120f033a54c46d5423 --state-dir .triage-state --delivery-id local-example
uv run python -m issue_triage queue --state-dir .triage-state
uv run python -m issue_triage show --state-dir .triage-state --issue 601:602:1
```

`review --decision FILE --state-dir DIR --provisional` records an exact per-field decision bound
to the displayed proposal revision and prior event. `dry-run --issue ID --state-dir DIR --provisional`
returns only current accepted/edited label/comment previews. Unknown labels, stale revisions,
CAS conflicts and damaged journals refuse; no command repairs a journal or sends a remote write.
Bad file SHA refuses before creating state. Signed intake and captured bundle storage are atomic.

## Implemented local workflow and planned live workflow

The local path is signed synthetic issue replay → immutable fixture inventory digest → deterministic
path/symbol report → full-input screening → isolated rules judgment → current proposals → provisional
field disposition → zero-write dry-run. Fixture inventories are labelled explicitly and cannot claim
trusted Git capture. The reusable Python modules include `ghapp`, `codeindex` and `screen`.

Focused component controls cover signed intake, atomic jobs and edit ordering, safe archive/read
ports, Python/JavaScript/TypeScript/TSX code indexing, literal routes/flags/configuration, bounded
existence reports, canonical citation resolution, screening, judgments and per-field proposals.
Canonical S2 rulings, S2 evaluation utilities and S3 provider/ledger modules are vendored with
source maps and licenses. Mock/replay provider results remain mock/replay. A 36-case independent
synthetic corpus is frozen; it has not been used for application evaluation.

Real GitHub capture, authenticated review, remote apply/reconciliation and application evaluation
remain unfinished. A plausible Git object ID alone does not establish capture authority.
An app-local [review authorization port](docs/REVIEW-BOUNDARY.md) joins session/origin/CSRF rules to
provisional decisions. Its FastAPI/Jinja HTTP adapter provides a local review queue, escaped
proposal/evidence pages, guarded forms, durable logout and current zero-write previews.
See [local HTTP review](docs/REVIEW-BOUNDARY.md) for setup, public demo credentials and limits.
Synthetic sessions and typed transport tests cannot establish real Human identity.

## Results and limits

No evaluation or live provider results exist yet. The future fixture evaluation is a synthetic smoke
test with provisional labels, not a population benchmark. See [limitations](docs/LIMITATIONS.md).

Snapshot contents are never installed or executed. There are no actual GitHub writes, paid provider
runs or hosted resources. The rules child uses an isolated interpreter, an environment allowlist
and disabled socket connections; this is not a hostile same-user OS sandbox. Timeout or unavailable
judgment stays `needs_human` with no usable proposals. Importing into Bolt does not provision this Python service; see
[the handoff inventory](BOLT-HANDOFF.md).

Coding agents wrote this version. Component test counts describe their specific candidates and
scopes. They do not establish a working full application, human approval, model quality or remote
effects. Independent finished-app review and the remaining live/security/evaluation scope are pending.
