# evalkit: private experiment wires and public boundaries

Implemented: separate scorer-only GoldRecord and PublicMethodInput; present/absent/unlabelled labels;
raw machine versus human-effective prediction wires; fixed manifest order/count/group bindings;
explicit stale/error/eligible/answered populations and undefined metric shape; whole-group resampling
policy shape; closed aggregate-projection admission with approved string values and finite numbers.

Copy closure: this directory's Python files, schema.json and README with root MIT LICENSE;
Python3.12/Pydantic2. No receipt, image/OCR, provider, domain-normalizer or workspace runtime imports.
Domain adapters supply all actual label meanings, eligible populations and safe public source payloads.
PublicMethodInput rejects scorer records/extra top-level fields; trusted adapter assembly must also
prevent semantic label leakage inside arbitrary JSON source content. Gold/source references are
private opaque handles, not required URLs or a runtime Pointer dependency.

Human-corrected reference gold can be valid with actual provenance; human-effective predictions stay
separate from machine scoring. Provisional/synthetic fixture references do not create actual human
gold. Never-run rows cannot invent outputs, calls or measured scores; unknown metrics use reasons.

Runtime: `corpus.load_corpus` checks actual bounded retained JSONL bytes against the frozen digest,
ordered IDs, count, groups and injected domain gold validator. Local path lookup rejects traversal,
symlinks and Windows reparse points; it assumes an owner-controlled directory, not a hostile concurrent
filesystem service. `s1_minimal_to_evalkit` requires explicit full owner enrichment, preserves seed,
freeze, file and actual order, and leaves incomplete input as `needs_owner_metadata`. It does not
acquire data, verify source rights, authenticate labels or silently reseal a corpus.

`runner.compare` dispatches injected methods on separately assembled PublicMethodInput and scores
against private GoldRecord. Fixed requested IDs retain unavailable/stale/error cases. Never-run or
default-disabled live methods produce metadata without fictitious predictions or measured scores.
Provider errors are closed reason codes; source lookup and adapters remain trusted caller code.
Recursive private-key controls catch structural scorer metadata, not every semantic disclosure in
arbitrary JSON source text. There is no provider, SDK, retry, cost collector or live authority here.

Held-out comparison requires explicit matching manifest/seal/dev-config/method-config/history refs
and an injected exposure-history authority before dispatch. The manifest digest is the canonical
typed manifest view, including declared defaults; it is not a hash of an arbitrary original file.
The caller must retain actual provenance, validate the independent seal and maintain durable,
authorized exposure history. A matching SHA/string or a synthetic history spy proves none of those.
This module authors no held-out gold, seals, tuning configuration or persistent history store.

`statistics` provides typed exact equality, confusion/rates, declared micro/macro/weighted summaries,
exact-set accuracy, agreement/kappa and Wilson intervals. Undefined supported metrics remain NA;
human-effective predictions never replace machine output. Domain formulas/normalizers are adapters.
`resampling.paired_group_resample` executes 2,000 paired whole-group draws with the pinned Python3.12
RNG, seed, order, optional whole-group strata, support policy and draw digest. Undefined draws stay
undefined rather than being retried; fewer than two independent groups or insufficient support/valid
draws yields no interval. These tiny synthetic controls are implementation evidence, not a campaign.

`reporting` builds explicit fixed-population rows and an allowlisted aggregate projection. Counts for
corpus, eligible, answered, comparable, stale, errors and abstentions are separate. Unknown/not-run
values stay null with reasons. Public projection is not general de-identification: private per-case
records are excluded, while named synthetic examples need separately approved retained references.
No split generator, human labelling workflow, domain scorer or file report writer is implemented.
