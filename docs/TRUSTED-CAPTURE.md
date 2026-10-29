# Repository capture boundary

`shared.ghapp.capture.capture_repository` accepts a configured `RepositoryIdentity`, an explicit
reader token, injected GET transport, monotonic clock and explicit `synthetic_transport` or
`configured_transport` provenance. It constructs no HTTP client, acquires no token and discovers
no key, file or environment credential. A configured transport label alone is not GitHub origin
or account authentication proof.

`shared.ghapp.http.HttpsTransport` is an explicit synchronous adapter for these fixed-host
GETs and the narrowed reader-token POST. Construction opens no connection; GET redirects stay
under `bounded_read`, and token POSTs never follow redirects. It discovers no proxy and performs
no retry. Socket timeouts and elapsed checks are cooperative: stdlib DNS, header parsing and
chunk framing are not subject to a hard OS-preempted deadline.

`shared.ghapp.tokens.acquire_reader_token` takes an explicit signer, transport, UTC epoch and
monotonic clock. It requests one repository with exactly the reader permissions, validates strict
JSON and returned scope, and requires expiry more than 30 seconds after acquisition completion
and at most one hour after that completion. Signing, POST and parsing share a maximum 30-second
elapsed budget. It discovers no key, persists or caches no token, and grants no capture admission.
Invented signer and connection controls establish no actual account authentication. Callers must
explicitly compose these APIs with capture; no worker or CLI wiring follows from their presence.

The port checks the repository API ID/name, resolves its default branch once to a lowercase
40-character commit SHA, then reads that exact archive. Metadata endpoints cannot redirect;
archives can redirect only to the same repository/SHA's exact codeload legacy tar path.
Authorization is stripped on the host change. Issue-provided URLs never select a destination.
Metadata uses strict bounded JSON. Archive validation reuses the existing memory-only validator
and its 20 MiB compressed, 100 MiB expanded and 5,000-file ceilings. No snapshot file is installed,
extracted to disk, parsed as executable code or executed.

One 30-second deadline covers the metadata/ref/archive read sequence and checks elapsed time
after archive parsing and cache access. Each GET transport must enforce its supplied streaming
byte/time bounds. Size-bounded parsing is checked after it returns; there is no OS preemption or
universal network/sandbox guarantee. Errors omit response bodies and token values.

`ingest.capture.CaptureIntake(jobs, identity).receive(...)` extends the existing `JobStore` and
`IntakeStore`. Supply the already locally verified typed delivery plus `token`, `transport`,
`clock`, `captured_at` (UTC string) and `provenance`. Receipt, causal head, queued job and first
capture binding commit in one transaction. A failed fetch, validation or persistence rolls the
whole transaction back. Duplicate work reuses its original capture and timestamp without GETs.
New work resolving to a cached repository/SHA/provenance reuses the retained snapshot after the
two metadata/ref reads, without another archive read. The write transaction stays held during
the bounded read; another writer can encounter the existing five-second SQLite busy timeout
and must retry rather than bypass capture admission.

Migration 4 appends capture/cache and work-binding tables; prior migration statements remain
unchanged. Migration 5 adds a nullable `work_captures.binding_sha256` without backfill. Initial
capture atomically records a versioned canonical checksum of the work key, issue identity/revision
and retained snapshot ID. Reload and duplicate intake verify that original checksum before using
the mapping, so substituting another valid same-repository capture fails closed. Each issue
revision has its own checksum even when it legitimately shares one cached capture. Legacy rows
without an original checksum refuse; migration and duplicate intake never bless their current
mapping by manufacturing an anchor. Retained file bytes are stored as canonical base64 JSON in
SQLite. Reload revalidates the canonical manifest, snapshot digest, timestamp, repository identity,
file bytes and the
existing codeindex inventory digest. Archive hashes bind the bytes observed during capture;
the original compressed stream is not retained or reconstructed on reload. This detects the
tested inconsistent stored-data changes, not a same-user attacker rewriting the entire database.

`CaptureIntake.load(work_key)` reads a previously bound capture after restart without a delivery,
token, transport or clock. One existing database transaction joins the job to its retained capture;
the loader validates the original canonical issue payload/digest, deterministic intake work key,
installation/repository identity, original work-to-capture checksum and retained manifest/inventory
checks. Missing captures, fixture inputs and inconsistent bindings refuse. It changes no job,
lease, receipt or capture row and
performs no fetch. The immutable `RetainedCapture` carries the original issue, capture-record
`snapshot_id`, `captured_at` and inventory digest; `commit_sha` and `provenance` come from the
retained capture. These identities remain distinct. This also permits historical inspection of
superseded jobs: loading alone does not validate a current worker lease or current issue revision.
It is an integrity check of stored input, not a signature protecting against coherent database
rewrites by the same user or a new GitHub/account authentication grant.

`worker.capture_checks.check_capture(jobs, identity, work_key)` consumes the accepted loader in
a read-only reference-check journey. It reuses the existing inventory, parser, index and canonical
existence report on the original stored issue text. It opens no database, fetches nothing, and
changes no job, lease or result. Its frozen result keeps the original capture record ID/time,
commit SHA, inventory digest and transport provenance separate. Historical captures remain
inspectable; this does not authorize current job processing.

The app-local `SnapshotRef`, `CodePointer` and `ReportItemRef` support exactly `retained_capture`
in addition to existing fixtures. The retained snapshot ID is the 64-character capture-record
digest, not its 40-character Git commit or inventory digest. Fixture identity rules stay unchanged.
Schema labels alone attest no origin or access; the consumer derives its input exclusively from
the stored binding validated by `CaptureIntake.load`. `configured_transport` is still configuration,
and `synthetic_transport` stays synthetic. Neither claims authenticated GitHub capture.

The existing canonical S5 bridge does not support `retained_capture` and refuses its conversion;
it never relabels it as `fixture_inventory` or `git_commit`. These native code-reference reports
do not claim S5-cited proposals. Full worker classification, cited proposals and CLI reconciliation
remain unfinished. No existing fixture job is upgraded to captured input. No real GitHub transport/account,
token exchange, model call, apply effect, application-quality result or whole-app acceptance
follows from the synthetic controls. Capture values are trusted-process structures, not signed
authentication grants against arbitrary code in the same process.
