# Observed repository labels and bounded proposals

The broker supplies a verified repository identity, one-repository reader token, clock and bounded
read transport. `read_label_inventory` constructs only the fixed GitHub repository-label GET path;
response URLs are data. Pagination uses numeric pages with 100 results, at most 11 pages/1,000 labels,
256 KiB/page, 1 MiB total and 30 seconds across the complete walk. A full final page requires a terminal
page. Next-link metadata may request another numeric page but never supplies a fetch URL. Label
redirects are rejected before another transport call. Rate/refusal/malformed/ambiguous/limited reads
return no partial inventory. Byte/time bounds are passed into the injected reader before each read.

IDs and exact Unicode names are retained. Duplicate IDs or case/NFC-colliding names hold the whole
observation. Archival state is active only when the response explicitly supplies null archived_at;
missing state is unknown, not permission to apply. Archived and unknown labels remain visible data.
The observation says injected_read_port: shape validation and a fixed URL are not authentication or
an attested atomic remote snapshot. The actual broker owns access/repository provenance; apply must
refresh current context after human disposition. This component constructs no HTTP client or token.

The full inventory SHA binds capture time and page-body hashes. `label_set_sha256` separately binds
the sorted repository ID/label IDs/exact names/archival states. Different fetch times, pagination,
JSON encoding or irrelevant descriptions/colors do not silently change the semantic allowed set.

`LabelMap` is an immutable operator-injected mapping from type/priority to exact names plus optional
common labels. No sealed author configuration is loaded here. `propose_labels` revalidates the
current issue, JudgmentRecord and inventory, then binds their digests and mapping/set identity.
It returns at most five deduplicated active current labels. Missing mappings, unknown/case-mismatched
names, inactive/unknown status, stale issue/repository or a held judgment route human without partial
labels. An explicit empty mapping means no labels. No mapping creates labels or supplies approval.

The read profile follows the official [GitHub repository labels API](https://docs.github.com/en/rest/issues/labels#list-labels-for-a-repository).
It retains the existing 2022-11-28 header, which GitHub currently supports through March 10, 2028;
see [GitHub API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions).
These contracts do not implement a real GitHub transport, human rulings, comment generation, writer
permission, action reconciliation or a complete application workflow.
