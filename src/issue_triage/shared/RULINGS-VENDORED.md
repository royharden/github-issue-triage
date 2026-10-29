# Canonical S2 rulings

The eight files under `rulings/` are byte-identical to the published S2 source at
commit `455d73c6efe283fdf3919267532de7ad5d39924b`. The adjacent
`LICENSE.S2-RULINGS` retains its MIT notice. The complete 16-object source and
test relocation map is `docs/vendor/s2-rulings/SOURCE.001.json`.

S6 uses this journal rather than maintaining a second implementation. Runtime
relative imports are unchanged. Seven public synthetic test files were relocated
with explicit import/helper/root substitutions and additional detached import
denial canaries. Their original assertions remain. The detached closure test runs
all 49 moved controls against an independent module name with owner, S6, provider
and network access denied, including actual local process contention, CAS,
complete-intent retries, fsync uncertainty, replay damage and tombstone behavior.
The nested 49 are repeated controls, not additional independent coverage nodes.

These controls execute on the actual local Windows filesystem. They do not prove
POSIX execution, power-loss recovery, a hostile multi-user filesystem or an actual
mapped network drive. The mapped-drive refusal control is injected.

Recorded actor strings and source hashes do not authenticate a human. Without a
consumer-owned actual human-evidence validator, labels remain agent provisional
or unverified human. A historical exact retry is not current-generation authority.
This vendoring step does not add the S6 workflow, permissions, apply effects,
repair policy, S4 graph, lifecycle/privacy adapter or app acceptance.
