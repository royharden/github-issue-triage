# Code evidence foundations, version 1

Current implementation covers raw inventory, explicit reference extraction, bounded parser-backed
named definitions, JSON/TOML/env config declarations and Python literal framework registrations.
JS framework literals, four-status resolution and trusted moves,
immutable reports, real Git capture and S5 generic citation adapters remain upcoming. An inventory
digest or forty-character string does not establish a captured Git commit.

`inventory_from_files(mapping)` consumes caller-supplied immutable bytes. For real repository
input, the caller must first validate the complete bounded archive and retain only regular files.
For authored fixtures, `fixture_snapshot_id` equals the actual raw inventory SHA256 and remains
labelled construction. Binary, empty, excluded and parser-oversize files remain in raw identity.
No parser/query policy, model, label, timing or coverage field enters that identity.

RawInventory canonical bytes are exactly UTF-8, no BOM or newline, sorted object keys, compact
separators and unescaped Unicode. Its sole keys are `files` and `inventory_schema_version: 1`.
Each file has exactly `byte_length`, `path`, `source_sha256`. Entries sort by exact path UTF-8
bytes; source hashes cover original bytes including CRLF. Bounds are 5,000 files, 100 MiB total
retained bytes, 2 MiB inventory bytes, 4,096 UTF-8 path bytes and 64 path components. Unsafe,
case/NFC-colliding or file/directory-colliding paths reject the entire inventory. Floats, duplicate
JSON keys, extra fields, surrogates and noncanonical serialized bytes reject explicitly.

`InventoryReader(inventory, files)` verifies the whole exact mapping and copies it into immutable
in-memory storage. `read(path)` accepts only exact-case inventory-listed paths. It opens no files,
follows no links and cannot download or execute a source. Missing/changed/extra retained bytes
reject. Physical line counting splits original LF bytes, preserves CR, counts a final nonempty
unterminated line and creates no line after a final LF. A byte line count alone is no text-pointer
validation; empty/binary/unreadable sources cannot acquire an invented line-one citation.

`extract_references(original_text, ExtractionPolicy(...))` finds seven explicit kinds: path,
module, function, class, cli_flag, http_route and config_key. It recognizes bounded file suffixes,
function-call syntax, explicit class/module context, CLI flags, HTTP method/path and named config
or environment keys. Ordinary unquoted prose words are not guessed symbols. This is a deterministic
literal extractor, not complete natural-language understanding. Whole-input/candidate overflow
raises a closed error rather than returning an authorized partial prefix.

References preserve verbatim text and half-open original UTF-8 byte intervals, without Unicode or
case normalization. Query normalization removes function parentheses or normalizes HTTP method
spelling. Unquoted route terminal prose punctuation is excluded; quoted route literals preserve
it. Paths retain exact spelling/case. A Query preimage has `kind`, `normalized_query` and explicit
nullable `language_hint`, `path_hint`, `qualifier_hint`. Its digest excludes itself. Reference ID
hashes input SHA256, original start/end byte positions and query SHA256; repeated query mentions
have separate IDs. `validates_original` checks the exact occurrence and full input identity.

The package currently uses only Python's standard library and can be moved without the S6 app,
providers, credentials or filesystem readers for inventory/reference operations. The lazy parser
API uses pinned tree-sitter 0.26.0, Python grammar0.25.0, JavaScript0.25.0 and TypeScript0.23.2.
Low-level authored controls are separate from the
sealed independent issue corpus; these tests provide no benchmark or model-quality result.

`build_index(snapshot, reader, policy)` indexes Python/JS/JSX/TS/TSX named classes/functions,
nested definitions, class methods and simple callable/class bindings. Imports, call uses and TS
interfaces are not runtime function/class declarations. Pointer source hashes always bind original
file bytes; lines are inclusive physical original lines. `resolve_pointer` validates exact captured
identity/inventory/repository, case-sensitive path, byte digest and a real readable text line range.
An empty, binary or invalid-UTF8 source supplies no line-one pointer. An empty supported source
does prove no named function/class in that file, without obstructing other valid function evidence.

SnapshotRef currently accepts only `fixture_inventory` with actual inventory digest and explicit
UTC construction time. `git_commit` always fails with `capture_authority_unavailable`; real broker
support will require actual capture authority. It does not infer provenance from SHA-shaped text.

IndexPolicy separately pins parser/extractor limits and exclusions. Per-file source parsing is at
most1MiB; default total parsed bytes10MiB, traversal50,000 nodes/file and20,000 definitions/index.
Text validation scans bounded UTF-8 chunks, including oversized retained files, without materializing
an unbounded decoded string. Every retained file has coverage, including malformed/unsupported,
generated, excluded, binary and budget-limited sources. Dynamic definitions, unsupported identifier
escapes/compatibility spellings and object methods record incomplete supported scope. No repository
code, import hook, install script or environment is executed. Static profile completeness is not
runtime reachability or semantic correctness.

`index.exists(name, kind)` returns one exact unambiguous current pointer only when all relevant
inventory coverage for that kind is complete. None does not establish absence. A known extra
definition or incomplete source cannot be ignored to establish uniqueness. `index.resolve(reference,
prior, trusted_mappings)` returns found, ambiguous, renamed_or_moved or not_found with explicit
evidence kinds. RelevantCoverage hashes every relevant retained path and extraction state, exact
query, parser/extractor/policy identities, limits and counts. Explicit path/language hints narrow
the scope; unknown-language files remain relevant. Skipped/failed/unsupported scope cannot prove
absence or uniqueness. Present empty/binary paths remain inventory facts without imaginary lines.

Lexical trigram candidates use an explicit versioned integer threshold and decimal-string scores;
the default 0.650 is an exploratory seed, without a measured quality claim. At most five candidates
are returned as tentative near_match_candidate evidence. Similar names, paths or identical bodies
never establish lineage. Prior-only pointers remain historical and cannot satisfy current exists.
Pointer/history overflow is explicit, with at most ten of each pointer type in a result.

TrustedMapping requires separate trusted-host MappingAuthority configuration containing admitted
source ID, exact canonical mapping artifact hash and an approval receipt hash. It verifies both
actual retained snapshots/source digests/line pointers and unique qualified definitions in complete
relevant scope. The application must load authority from its approval store; reporter text and model
answers cannot populate this channel. The library checks these joins and does not independently
establish that a human approved an arbitrary receipt hash. Synthetic controls use explicitly synthetic
approval fixtures. Invalid mapping context fails before any verified_move result. Actual Git capture
authority and S5 generic envelope installation remain separate next steps.

`extract_config_literals` finds named declarations without returning values. JSON is validated
whole with duplicate-key/nonfinite-literal rejection, then a bounded source lexer records nested
object/array key paths and original physical lines, including escaped Unicode keys. TOML supports
validated bare/dotted keys and ordinary table headers; implicit parent keys receive their first
actual declaration line. Quoted/array table keys, inline table interiors and multiline TOML are
explicitly incomplete. Env files support named assignments, comments and optional export syntax;
values are data and are never executed or returned. Unsupported/multiline env syntax cannot make
the following value line into a fake key. Duplicate env declarations remain separate occurrences.

Config parsing shares file/total-byte/node/definition limits. Malformed/unsupported/limited config
files cannot establish key uniqueness or absence. All retained bytes remain in raw inventory,
regardless of extraction. Physical lines split only at LF, so a Unicode line separator in a value
does not fabricate another source line. Empty env/TOML has no key declarations or line pointers.
These profiles establish retained declarations, not actual environment values or runtime behavior.

Python literal profiles parse captured text with Python3.12's AST; they import no captured module
or framework. Known FastAPI/APIRouter and Flask/Blueprint constructor bindings support literal HTTP
shortcuts or explicit method lists. Argparse constructor/group bindings and Click option decorators
support literal option strings. Explicit os.environ assignments declare keys; environment reads
do not prove a configured key/value. This is supported static syntax, not proof that a third-party
module loaded, a server is reachable, a flag is effective at runtime or arbitrary opaque effects
are absent. Implicit generated flags and runtime/plugin registrations are outside this profile.

Aliases, parameters, function locals, ordinary branch merges, with/exception bindings, deletion,
framework mutation and unsupported dynamic/annotation constructs are checked conservatively.
An unresolved getter cannot become a route declaration. Source-owned modules shadowing framework
names remove trust in the import pattern. Unknown values or registration composition remove
completeness for the affected kind. Unsupported framework profiles cannot silently
inherit complete coverage from another language. TRACE and short alphabetic flags are explicit reference
syntax; negative prose numbers are not guessed flags.

The named tree-sitter parser and Python literal parser share node/definition and total parser-input
byte limits. `parsed_bytes` counts bytes admitted to parser/literal entrypoints, so a source file
analyzed by both engines contributes twice its original byte length; raw inventory is unchanged.
An exhausted second-entrypoint budget records incomplete literal coverage and retains earlier facts.

The syntax profiles follow the official [FastAPI path operation guide](https://fastapi.tiangolo.com/tutorial/first-steps/),
[Flask routing guide](https://flask.palletsprojects.com/en/stable/quickstart/#routing),
[Python3.12 argparse API](https://docs.python.org/3.12/library/argparse.html) and
[Click option declarations](https://click.palletsprojects.com/en/stable/options/).
Framework packages are not installed or executed by the indexer.

JS/TS/TSX literal profiles use the pinned grammar to recognize module-level Express factory/Router
bindings, ESM aliases and the simple CommonJS Express factory. Direct literal HTTP method calls
with handlers record registration occurrences. Commander ESM Command/program bindings support
literal option/requiredOption flags. Explicit Node process.env dot or literal bracket writes
record key declarations, without returning values or treating reads as declarations. These syntax
profiles follow the official [Express routing guide](https://expressjs.com/en/guide/routing/),
[Commander option declarations](https://github.com/tj/commander.js#options) and
[Node process.env API](https://nodejs.org/api/process.html#processenv).

The JS binding profile rejects shadowed/reassigned or mutated object families, including aliases
and destructuring, and never resolves a constructor declared after its use. Computed methods,
method aliases, dynamic code/imports/paths, mounting/chained routes, unsupported framework imports,
escaped literals and unrecognized bindings remove relevant completeness. Branch/local constructor
bindings are conservative. An unresolved getter or helper is never a route declaration. This is
retained static syntax, not installed-module provenance, runtime route reachability or option
effectiveness. Node/framework packages and captured code are never loaded or executed.

`build_existence_report(index, original_text, ...)` creates bounded canonical report bytes containing
the raw input hash, occurrence identities, separately typed current/prior snapshots, exact query and
relevant-coverage tables, configurations/policies, explicit limits/counts and sorted unique items.
The report contains no own digest or ReportItemRef. Its SHA256 is computed after serialization;
`report.item_ref(item_id)` then creates an external reference to the item/query/coverage/current-source
joins. Duplicate/orphan rows, absent explicit nulls, noncanonical JSON, bad preimages and inconsistent
status/evidence combinations reject the whole artifact. Reports are at most4MiB with at most128
items and query/coverage rows. A running encoded-value bound stops oversized table construction;
overflow returns no misleading prefix report. Caller extraction limits can be tighter.

`resolve_report_item(ref, artifact_bytes, current_index, prior=..., trusted_mappings=...)` verifies
bounded retained bytes and all structural joins, then recomputes the requested item's scope and
resolution against the actual supplied retained index/configuration. A valid hash alone does not
verify a false coverage count, altered definition line, changed policy or source generation. Prior
source is required for reports using prior context. Mapping provenance inside a report cannot admit
its own authority: verified moves additionally require the host's separately admitted mapping input.
Missing, stale, invalid and unsupported results are explicit, without a fallback citation.

Successful verification is scoped to the requested recorded search and static semantics. A verified
incomplete report still records an ambiguous result; it cannot prove absence. Input/source identity
hashes are bindings, not authentication or independent proof of real Git capture, reporter truth or
human approval. Reports currently retain explicit fixture_inventory identity. No generic S5 Pointer
dispatch is installed by these domain functions; the adopted report triple requires a separate S5
adapter installation and exact consumer proof.

The optional `cited_adapter` supplies that explicit installation against the unchanged canonical
S5 Registry/Pointer/Resolution classes. `to_cited_file` maps original file-byte digest to both raw
source and direct artifact digest, with the exact retained physical line locator.
`to_cited_report` maps raw inventory/source revision separately from the derived report artifact
and exact item/query/coverage joins. `install_codeindex` installs only the adopted repository and
report triples; a fresh registry supports neither, and no supplied-text fallback is attempted.
Duplicate installation rejects before changing either tuple during single-threaded configuration.

`CodeIndexCitedResolver` requires a trusted host namespace, access policy and current-generation
policy. Their actual ArtifactRef values must match ResolutionContext; access and current admitted
SnapshotRef are checked again before disclosure. Unknown/revoked access, source generation changes,
stale/corrupt bytes, bad ranges, missing report/prior/mapping authority or bounded excerpt overflow
return no excerpt. File text views are at most1MiB, with constant-memory LF traversal and at most
32,768 excerpt characters; larger raw files remain inventory facts but this view is unsupported.
Callers can tighten bounds, which are hashed into the returned profile reference. The generation
policy reads the host's admitted snapshot state; this adapter
never acquires source or follows a mutable repository branch. Policies and reference hashes do not
create authority by themselves.

Report citations return the actual canonical recorded item text, with complete/partial scope
provenance. Coverage counts mean relevant inventory rows accounted for, not a measured quality
score or an assertion that all source was parseable. An incomplete item still records ambiguous
evidence and partial coverage. Generic Finding remains partial or unsupported; resolving a file
excerpt/report cannot upgrade a semantic claim, prove absence outside complete deterministic scope,
or turn synthetic approvals/fixture identities into real human approval/Git capture. Raw codeindex
imports stay independent of Pydantic/cited until the optional adapter is explicitly imported.
