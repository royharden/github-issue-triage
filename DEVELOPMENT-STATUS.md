# Development status — local fixture workflow, 2026-10-15

The local workflow extends the component baseline `5e75adff97057cda4fbfa6c483eb08b61c216a8c`.
No finished application, authenticated human review, model-quality result or remote effect is claimed.

## Finished component work

- Strict domain serialization, migration checksums, SQLite WAL/FULL jobs, expiring leases,
  atomic signed webhook intake, duplicate delivery handling and causal edit ordering.
- Bounded memory-only archive validation and fixed-host reader/auth ports. Actual GitHub
  transport, signing/token acquisition and capture authority are not implemented.
- Fixture-inventory code indexing for Python/JavaScript/TypeScript/TSX, named definitions and
  supported literal routes, flags and configuration/environment keys. Coverage limitations,
  reference offsets, ambiguity, explicit trusted move mappings and historical absence remain visible.
- Canonical bounded existence reports and an installed S5 citation adapter with current
  namespace/access/generation checks. Fixture snapshots cannot masquerade as Git captures.
- Complete-input text screening, deterministic rule judgments, typed mock/replay normalization,
  exact active-label allowlists, fixed neutral comments and immutable per-field proposal revisions.
- Canonical portable S2 evaluation utilities, S3 provider/ledger, S5 citations and S2 rulings,
  with source/license maps and relocated synthetic controls. No competing journal was added.
- A frozen independent 36-case synthetic corpus exists. Application scoring, tuning and heldout
  evaluation have not run. Labels are provisional rather than actual human ground truth.

Recent component verification includes 94 focused suggestion/judgment/label checks and 67
rulings-adoption checks. The latter comprise 49 relocated runtime controls, 16 object checks,
schema/license verification and a detached-suite wrapper. The detached 49 repeat the same controls
and are not 49 additional independent cases. Actual Windows process/fsync/CAS/replay controls
do not establish POSIX execution, power-loss recovery or hostile multi-user filesystem safety.

## Local fixture workflow

`worker/`, `review/`, `apply/`, `cli.py`, the example local bundle, entrypoint,
third SQLite migration and offline demo join the path:
signed synthetic issue → durable job → explicitly labelled fixture snapshot/report/screen →
scrubbed rules subprocess → current proposals → provisional field disposition → zero-write dry run.
It contains no actual human authentication or live apply permission. The journal is canonical
S2 source; this app supplies its field/generation adapter and provisional provenance.

The four SQL lint findings are fixed. `scripts/demo.py --offline --state-dir DIR` has run the
original public example through real rules subprocess execution, provisional review, two stable
dry-run previews, reopened-state duplicate replay, bad-SHA refusal and injected-input hold.
CLI triage requires the caller's raw-file SHA256 before parsing or creating state. Intake,
issue head, job and immutable bundle now commit atomically; an injected capture-storage failure
rolls them all back. The first captured bundle cannot be overwritten by a same-issue retry.

Source controls cover actual separate CLI processes; signatures and stored bundle digests;
current revision/CAS/allowlisted values; torn journal refusal; lease expiry; and migration upgrades.
The lease-clock control uses an explicit deterministic rules fake; normal API/CLI/demo controls
require the real isolated child. Historical failed setup/lint/status checks remain failures.
An initial local run observed an unavailable rules child and a demo refusal under load; a fresh
demo passed. Timeout now has an explicit `rules_subprocess_timeout` hold, without a fallback pass.
No execution count here implies application quality or independent acceptance.

The Windows offline combined suite collected and passed 1,127 cases with no failures, errors or
skips, including 18 workflow/CLI cases. It also includes canonical producer controls and wrapper
tests that rerun selected moved controls; these are not independent observations to add together.
Scoped Ruff check passed and 99 files passed format verification. The suite excludes the sealed
S6 corpus/generator. These local results do not establish Linux deployment or live provider behavior.

A subsequent review found that isolated Python ignores the environment's bytecode suppression.
Owned isolated launches now pass `-B`; the rules worker reports and requires the actual
`sys.dont_write_bytecode` flag. Follow-up validation is focused on this change and the normal/refusal
journey; the earlier 1,127-case full suite is evidence for its previous candidate, not a new full run.

## Review authorization foundation

`review/security.py` and `review/service.py` add a dependency-free authorization port with expiring
operator sessions and session/issue/revision/field/prior-bound CSRF challenges. It joins current
proposals and canonical provisional rulings without changing producer source or persistent schemas.
Tests use a typed transport double and synthetic keys; they do not establish an HTTP parser,
browser protection, real Human identity or a complete UI. See [review boundary](docs/REVIEW-BOUNDARY.md).

The FastAPI/Jinja HTTP adapter is now implemented separately from the original typed transport
double. It protects reads, parses bounded actual header/cookie/form bytes, binds signed form
metadata to sessions, escapes issue text, and records current provisional review/dry-run receipts.
Persistent admission, global login throttling and cross-instance logout use a separate local
`web-auth.sqlite3` version1 schema; canonical rulings and the job migrations are unchanged.
Unknown auth schema versions and static linked database/sidecars refuse without reset.

Public PyPI setup added 14 SHA-verified compatible wheels while retaining every existing lock
version. Installation ran offline from the verified wheelhouse into this app environment;
`uv pip check` passed. The portable lock retains public registry URLs, not machine-local paths.
See [dependency notes](docs/HTTP-DEPENDENCIES.md). The earlier cached ABI mismatch is resolved.

The initial real-ASGI suite passed 41 request-level cases after correcting test-only escaped-HTML,
fixture-title and oversized pytest-ID assumptions. Failed diagnostics are retained separately.
One upstream Starlette HTTPX deprecation warning remains. This is builder-run Windows ASGI
evidence, not an independent security verdict, real Human identity, deployment or model quality.
Real-browser and final combined candidate results must be reported with their exact execution refs.

## Outstanding

1. Finish trusted real repository capture and a production bounded read broker; preserve capture
   on retries. Complete semantic evaluation reservation/cache identity before any paid request.
2. Independently review and verify the local HTTP/browser boundary; complete real operator
   identity/account lifecycle and deployment configuration before any Human-authority claim.
   Public demo credentials and provisional actor strings never prove human approval.
3. Complete separate apply orchestration with refreshed context, prepared/sent/confirmed/failed/
   unknown states, stable comment-marker reconciliation and partial-effect recovery. Dry-run
   receipts must remain distinct from actual effects. Real writes are unavailable.
4. Complete application scoring and fixed-denominator synthetic evaluation under the corpus
   release rules. Keep errors, abstentions, unavailable observations and mock/live origins visible.
   Real provider tests require bounded pricing/budget/capability preflight. No paid run has occurred.
5. Obtain independent nonauthor review on an exact candidate. Finish the remaining native,
   security/data-loss/evaluation checks before any app acceptance. Component counts do not
   waive these requirements.

A local-only synthetic review server is available through `serve-demo`; it does not capture
GitHub data or enable remote writes. No Docker stack, Git worktree, model acquisition, hosted
database, cloud resource or remote repository has been created. No push/provisioning has occurred.

## Lessons

See [LESSONS.md](LESSONS.md). Preserve current WIP/candidates and actual failed diagnostics;
status output alone does not verify a journey.

A builder-run Chrome148 loopback walkthrough exercised native login, protected issue review,
canonical label acceptance, refreshed dry-run and logout. A zeroed CSRF form and post-logout
read refused; the journal retained one provisional event and one zero-write preview. The initial
native login failed because no-referrer produced Origin:null; same-origin response policy fixed
that without accepting null origins. Browser evidence and ASGI/component evidence are separate.
The owned listener and browser were closed after verification; independent acceptance remains.

Independent review accepted the local HTTP/ASGI construction scope with a nonblocking trusted-clock
fault: invoking the clock before the handler guard allowed a framework500 without four security
headers. The clock call now uses the existing guarded error path; focused real-framework controls
check generic503, explicit headers and unchanged auth/ruling state. The earlier combined1,205-case
run remains evidence for its own candidate, not a rerun of this repair. Independent browser
verification remains incomplete: its resource-bounded attempt stopped before login/review/logout.
The prior builder browser walkthrough is separate and does not replace that missing evidence.
