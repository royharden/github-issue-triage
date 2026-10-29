# rulings: bounded journal, replay and recorded decisions

Implemented: strict scalar/pair subjects and payloads; opaque two-field record identity; canonical
pair key and separately aligned raw-generation preimages; complete client-intent serialization;
store-sequence exclusion and historical exact-retry receipt shape. Scalar null/false values retain
their types. Reopen/retraction payloads do not implicitly assert current approval.

Copy closure: this directory's Python files, schema.json and README with root MIT LICENSE;
Python3.12/Pydantic2. It imports no docio, matching, receipt, provider or UI code. Raw-record fingerprints
and current-source validation use the consumer-injected producer profile (including product-raw-fields-v1
where applicable); there is no invented generic row hash or matching reducer here.

`JournalStore` now appends canonical UTF-8 JSONL under an exclusive process lock, with a lock deadline,
stable-subject head CAS, an injected current-generation validator, assigned sequence and fsync before
success receipt. Complete client-intent idempotence runs before stale head/source checks; an exact
retry returns its historical sequence without present-generation authority. The maximum encoded event
is 64KiB including LF. Caller policy additionally bounds journal bytes/events; default64MiB/10000events.
There is no implicit payload/error logging or current-source discovery.

The trusted root must be an existing owner-private directory, with a validated single leaf filename.
Ancestor/directory/file reparse points and symlinks, hard links and device/traversal names reject.
Windows UNC/device roots and mapped remote drives reject before filesystem probes.
This does not provide a service for hostile multi-user directory replacement. Locks are local files;
native Windows subprocess concurrency/deadline and process-exit-after-fsync controls are tested.
The POSIX lock branch is implemented but not yet executed on a POSIX host. Power-loss/filesystem
failure recovery is not established by process-exit tests.

Replay validates complete canonical lines, versions, sequences, client IDs, predecessor chains and
pair retraction targets. Damaged/torn bytes remain unchanged; replay exposes prefix count/offset/tail
digest and blocks writes/authoritative projection until a separate explicit repair policy. No repair,
truncation or reseal is automatic. Sync failure is uncertain even if a complete line exists; retrying
the exact intent syncs that historical event before acknowledging it. Reentrant access fails promptly.

Private scalar projection/export preserves null/false, generation/evidence changes, reopen barriers
and orphan/tombstone review. Pair transport and effective-target retraction barriers are supported;
there is no matching, pair graph/component/blocking reducer or source/tombstone service. Recorded
decision state is journal semantics, not action permission. Actor/ref strings are attribution, not
authentication: exports stay agent_provisional or unverified_human until the consumer's actual human
evidence validator succeeds. Synthetic test validators do not supply real human/gold evidence.

Run the installed-environment command `python -m pytest tests/rulings -q` for failure-capable journal,
projection, actual OS-process and moved-runtime tests. Real receipt/UI review, downstream domain
adapter/vendoring, actual human validation and independent app acceptance remain pending.
