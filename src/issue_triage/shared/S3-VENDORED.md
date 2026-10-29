# Canonical S3 offline Provider/Ledger

Source project: llm-router-eval, commit 2671816d4f4fc46b9a650fc4c05ae4389dada326,
tree 2887e018acff384fc1a872080f399c2aeb44c5e0. The complete fourteen-file shared
closure was copied unchanged from committed Git blobs under the MIT license retained in
`LICENSE.S3`. These modules belong together: providers, callledger and their shared root.
The screen adapter is separate S6 code; it does not modify or duplicate canonical accounting.

`docs/vendor/s3/SOURCE.002.json` pins current source/license bytes and explicit relocated
test mappings. Tests preserve original assertions and synthetic assets; only public import
namespace is adapted from llm_router_eval to issue_triage. Owner-namespace denial guards remain
unchanged. Supplemental offline schema/price scripts use the same import mapping. No prices
were fetched; the supplied snapshot remains synthetic. Test scripts are not runtime entrypoints.

This successor changes only the Ledger from the original c7a03a8 source. Child reuse checks
the declared child purpose even when optional caller limits are omitted; the operation root
may have a different purpose. Public APIs, database schema and eighteen JSON schemas are
unchanged. The original schemas, assets and conformance suite remain attributed to c7a03a8;
four additional purpose-control assets are attributed to 2671816. SOURCE.001.json retains
the original historical pins. No generation-repair implementation is included.

The source supports mock/strict_replay and injected simulation with a marked test transport.
S6's native screen factory supports only mock fresh bindings and strict_replay captured bindings,
using real zero-attempt Ledger allocations. No SDK, HTTP client, real secret/token authority,
live billing, genuine model capture or quality evidence follows from this copy.
