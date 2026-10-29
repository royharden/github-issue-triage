# Bounded snapshot preparation

`archive.validate_archive(raw, *, limits)` validates tar.gz bytes entirely in memory, retaining every
validated regular file's original bytes (including CRLF/empty/binary files). It never extracts to a
filesystem, installs dependencies or runs repository code. Caps may tighten defaults20MiB compressed,
100MiB expanded including tar metadata/padding,5000files. Parser source-size policy1MiB belongs to
codeindex and must later record oversized-source coverage; archive validation does not truncate it.

Before tarfile processes extension records, a header preflight bounds per-record/total metadata,
entry counts/sizes/padding/end markers and rejects links/devices/FIFO/sparse/unknown types. Only
bounded ordinary PAX metadata/path and GNU long names are supported; size/link/sparse/unknown PAX
extensions hold. Single root, UTF8 path/depth bounds, no traversal/absolute/drive/UNC/backslash/control
or Windows-reserved names, and no duplicate/case/NFC or file-directory collisions are allowed.
Additional metadata/entry restrictions are conservative rejection profiles, not claims that every
valid tar is supported. Compressed/tar SHA values are archive identities, never Git capture proof or
the adopted codeindex raw inventory hash. Invalid/unsupported input has no usable prefix result.

`reader.archive_request(owner, repo, commit_sha, token=...)` constructs a fixed-api-host GET for a
40hex SHA1-format ref. Syntax is not actual ingestion-resolved provenance; fixture64 is rejected.
`redirected` accepts only HTTPS api.github.com/codeload.github.com, strips authorization on host
change and never restores it on a return hop. Headers and URLs are hidden from default request repr.
`bounded_read` forwards each remaining total deadline/byte limit to an explicit injected transport,
rejects overflow/late/backward-clock/rate/refusal/hostile redirects, follows at most5 redirects and
never sleeps/retries/constructs a transport. The actual HTTP reader must enforce bounds while reading;
post-read spies do not prove socket streaming, credentials or source authenticity.

Focused tests use original tiny archives/read-port responses and never read sealed author fixtures.
Actual GitHub auth/HTTP/ingestion SHA capture, retry scheduling/pagination/label context and snapshot
inventory/coverage integration remain required subsequent work. No mock response becomes real Git
provenance; no model/billing/consumer workflow or finished-app acceptance follows from these checks.

Primary API references: [Python tarfile](https://docs.python.org/3.12/library/tarfile.html),
[Python gzip](https://docs.python.org/3.12/library/gzip.html),
[GitHub archive endpoint](https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-tar).
