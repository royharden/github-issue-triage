# Current proposal envelope

The app emits four separate proposed or held fields: existing labels, type, priority,
and a fixed neutral comment. Each field has a stable ID derived from installation,
repository, issue number and field name. The complete immutable revision binds the
current issue, retained raw snapshot, code-existence report, judgment and screen
policies, label set, label map and each field's evidence digest. Editing any of those
inputs requires a fresh revision. This is proposal metadata, without human authority,
a journal entry or a GitHub effect.

Source-bearing comment templates cite actual canonical S5 report-item pointers and,
for positive current facts, actual file pointers. The caller supplies the installed
code-index resolver, namespace and current access/generation policies. Every required
pointer must resolve under those policies. A stale, unsupported or revoked pointer
holds the entire source-bearing comment. Complete absence is described only within
the retained search scope and leaves version/context uncertainty explicit. An issue
without explicit references receives a separately marked source-free request for
details. Templates never interpolate issue text, identifiers, URLs or source excerpts.
S5's `partial` finding accounts for evidence availability; it is not a semantic
endorsement or an application acceptance result.

The 4,096-byte comment canonicalizer runs before the preview and later human
disposition. It removes links, neutralizes mentions, issue-reference closing syntax,
HTML and line-leading slash commands, rejects controls/invalid Unicode/overflow,
and is idempotent. Applying a decision must preserve the exact approved value;
it must not silently sanitize or regenerate it after approval. A trusted action
marker belongs to the later apply layer.

Held judgments suppress all four fields. A missing label or unresolved comment
holds only that field when the judgment remains usable. Current component joins
are checked again before constructing a revision. Label values use immutable
tuples and only exact active labels from the current repository inventory.

Original synthetic controls in `tests/pipeline/test_suggestions.py` exercise real
S5 dispatch through the S6 adapter, denial/revocation/current-generation failures,
found/absent/mixed references, hostile input, output bounds, immutable round trips,
stale joins and stable field identities across changed revisions. They do not read
the sealed S6 corpus or demonstrate human approval, live repository capture,
model quality, a persisted decision, an apply action or a remote effect.
