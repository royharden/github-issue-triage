# GitHub boundary helpers

`auth.py`, `signatures.py` and lazy `__init__.py` form a standalone stdlib closure. Copying the
whole directory to a detached `ghapp` package can import auth/signature helpers without the S6 app,
Pydantic, provider SDKs or a key loader; the focused detached test exercises this. Preserve the root
MIT LICENSE with any export. No absolute workspace imports or automatic transport are used.

`verify_signature(raw_body, signature_header, secret)` accepts original bytes up to1MiB and a
supplied secret of at least16bytes. It requires the SHA256 header form and constant-time comparison
before JSON decoding. The public test vector comes from
[GitHub's webhook validation documentation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).

`app_jwt(issuer, *, now_seconds, signer)` constructs RS256 claims with issued-at60seconds in the past
and expiry540seconds in the future, calling the explicit signer's `sign(bytes, algorithm='RS256')`.
No default signer/private-key file reader exists. Tests verify local RS256 signing with ephemeral
RSA keys; real installed GitHub App/account verification remains pending. `AppJwt` hides the token in repr.
See [GitHub's JWT requirements](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app).

`installation_token_request(installation_id, repository_id, *, role, registered_permissions)`
returns an immutable one-repo request descriptor; each `payload()` is a fresh map. Reader requests
Contents/Issues/Metadata read; apply requests Issues write/Metadata read. Every requested permission
must fit supplied registered capabilities. This constructs a request, not a minted credential or
account grant. Explicit HTTP/token acquisition and expiry checks are available through
`http.HttpsTransport` and `tokens.acquire_reader_token`; neither is automatically selected. See
[GitHub's token scope documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).

`webhook.py` is lazy and additionally requires the declared S6 `contracts` package/Pydantic2 under
the same parent package layout. It authenticates raw bytes, rejects duplicate/nonfinite JSON, matches
trusted installation/repository IDs and projects supported issues opened/edited. Null body becomes
an empty description; non-null text is preserved whole. Unsupported events/actions, pull requests
and configured app-self events remain visible ignored metadata; other bots can continue.

`Delivery` is a structurally bound trusted-process value, not a serializable authentication grant.
An external handler must always call `parse_delivery`; it must never construct Delivery from HTTP
JSON or treat a dataclass instance as proof against arbitrary same-user Python code.

The separate app-local `ingest.IntakeStore` and `store.JobStore` enforce atomic delivery/job state.
Intake coalescing is not a paid-evaluation cache or S3 reservation; it does not yet bind captured SHA,
allowed-label/policy/threshold/schema dependencies. Those later stages remain required.

## Explicit local RS256 signing

`signing.RS256Signer(pem_bytes)` implements the existing `app_jwt(..., signer=...)` port
with pinned `cryptography==50.0.2` (Apache-2.0 OR BSD-3-Clause). Supply one unencrypted
PKCS#1/PKCS#8 RSA private key as in-memory bytes; accepted RSA sizes are 2048–8192 bits.
The adapter fixes RSA PKCS#1 v1.5/SHA-256 (`RS256`) and bounds PEM/signing inputs to
65,536/4,096 bytes. It rejects encrypted, public, malformed, concatenated and non-RSA keys.
It discovers no environment key or file path, constructs no transport and exchanges no token.
Representations omit the key and errors use fixed codes. The parsed private key remains in
process memory; this is not key erasure or isolation from another same-user process.

The caller still supplies the issuer and current UTC Unix time to `app_jwt`; the existing
60-second clock-skew allowance and nine-minute expiry remain. Local synthetic-key verification
does not establish an installed GitHub App, account authentication or permission to use a key.

Sources: [GitHub App JWT requirements](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app),
[cryptography RSA](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/rsa/),
[key serialization](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/serialization/).

## Signed capture composition and retained checks

`worker.signed_capture.receive_signed_capture` composes the existing verifier, reader-token
acquisition and atomic `CaptureIntake` with caller-supplied repository identity, webhook secret,
signer, transport and clocks. It discovers no credentials or transport. Signature and issue
identity checks precede signing; replay, coalesced revisions, ignored/stale/conflicting deliveries
do not acquire another token. A token/capture failure rolls back the receipt, job and capture
transaction. The token exchange itself cannot be rolled back and is not retried automatically.
Token acquisition and capture retain separate cooperative 30-second budgets. No token or key is
stored in the capture database. This queues retained input; it does not complete a job or classify it.

`python -m issue_triage --offline capture-check --database EXISTING_DB --work-key WORK_SHA256
--installation-id INSTALLATION --repository-id REPOSITORY_ID --owner OWNER --repository NAME`
exposes `worker.capture_checks.check_capture` for a retained work item. This command uses the
normal `JobStore` opening/schema checks (including migrations when needed), then performs the
read-only reference consumer without job/lease transitions. It opens no listener, acquires no
token and fetches nothing. Missing databases refuse instead of being created. Historical captures
remain inspectable; the result explicitly grants no current processing authority. Output keeps
capture-record ID, Git SHA, inventory digest and synthetic/configured provenance distinct and
claims no authenticated origin, S5-cited proposal, human review or apply permission. The fixture
`triage` command remains a separate workflow.
