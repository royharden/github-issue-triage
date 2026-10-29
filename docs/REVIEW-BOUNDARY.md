# Local HTTP review

The FastAPI/Jinja adapter joins real fixture jobs, current proposals, canonical S2 provisional
rulings and zero-write dry-run receipts. It opens no listener on import and reads no environment
or credential files. `create_app(state_root=..., boundary=..., clock=...)` accepts injected trusted
configuration. An operator session never promotes a ruling beyond `agent_provisional`.

## Run the public rehearsal

Install with `uv sync --frozen`, then import a SHA-pinned fixture using the README commands.
Choose an available loopback port; agents first claim/check the project instance with agent-ports.
PORT below is a placeholder, not a reservation. The state directory parent must exist.

```sh
uv run python -m issue_triage serve-demo --state-dir .triage-state --origin http://127.0.0.1:PORT
```

Open that exact origin. The intentionally public rehearsal credential is
`public-local-demo-operator-control-01`. The session key is also public in source. This mode uses
public synthetic fixtures only and proves no real operator identity. Serving imports no fixture.
`--offline serve-demo` refuses before listening.

Sign in, open an issue, inspect captured content/proposal/evidence, then accept, edit, reject or
reopen a field. Edit values use JSON and existing current-field validation. Refresh before a
preview after a decision. An exact retry returns a historical receipt, without reactivating an
old decision. Stale forms/proposals/preview heads refuse. Held issues show reasons without actions.
Sign out revokes the session across app instances and restarts.

Bare Uvicorn binds the configured loopback HTTP host/port with one worker, proxy-header trust and
access logs disabled. No HTTPS certificate, external account or webhook is supplied. Stop the
process to close it; agents release their owned port claim after verifying actual closure.

## Request and persistence boundary

- Actual ASGI headers have byte/count bounds; duplicates refuse. Host/scheme must match trusted
  configuration. Forwarded authority, query strings, cross/same-site fetches, ambiguous cookies
  and unsupported methods refuse. Request fields never configure authority.
- POST requires exact Origin and URL-encoded forms. Content-Length and actual streamed bytes are
  limited to 64 KiB with a five-second read deadline. Missing/lying length, chunked encoding,
  duplicate keys, malformed percent/UTF-8, extra fields and duplicate JSON edit keys refuse.
  This narrow interface supports local browser forms, not a general HTTP API.
- Proposal/challenge reads require signed, admitted, unexpired sessions. Cookies are HttpOnly,
  SameSite Strict and Secure for a configured HTTPS origin; the loopback HTTP demo omits Secure.
  Signed forms bind session/action and server-issued event IDs/timestamps/target metadata. Review
  additionally checks issue/revision/field/prior-bound CSRF and canonical currentness/CAS.
- Dry-run POST binds the displayed proposal revision and journal digest. The job transaction
  verifies both before writing local receipts. There is no live-apply route or external client.
- Separate `web-auth.sqlite3` version1 stores session hashes/expiry and global attempts (five per
  minute). Active admissions cap at64; expired admissions are pruned. A SQLite write gate
  serializes session validation/logout and guarded HTTP work across app instances. Unknown
  versions/nonempty unversioned databases and static linked database/sidecars refuse without
  reset. Startup and every guarded request check the version and the app's own table definitions,
  including the singleton constraint used by login throttling. Existing instances also refuse
  unsupported schema changes without modifying the store. Custom schemas require explicit repair.
  Back it up with local state;
  deletion invalidates admissions. Key rotation invalidates
  signatures. It is not canonical ruling truth or proof of Human identity.
- Trusted templates use explicit HTML autoescaping and StrictUndefined. Issue/template syntax is
  data. Responses set no-store/same-origin-referrer/nosniff and CSP disabling scripts/external resources,
  frames and base overrides. Public errors omit request secrets. Injected clock failures use the
  same generic secured503 response path and create no session, attempt or ruling records.

The state root/ancestors remain owner-controlled. Concurrent hostile same-user filesystem swaps,
power-loss recovery and compromised hosts are outside this local contract. The separate CLI
continues explicit provisional rehearsal and cannot establish Human authority.

## Verification limits

The boundary suite uses a typed transport double. The HTTP suite separately runs actual FastAPI,
Jinja and HTTPX in-process ASGI requests with synthetic keys, real stores/canonical rulings and
the real rules child. Controls cover parsing/refusals, retries/currentness, escaping, persistent
logout/concurrency, auth-store preservation and zero-write previews. ASGI tests open no listener
or browser. Actual browser results must name their origin/candidate/execution separately.

Neither suite proves real Human identity, independent security acceptance, live model quality,
trusted Git capture or deployment. Dependencies and the upstream HTTPX deprecation warning are
in [HTTP dependency notes](HTTP-DEPENDENCIES.md). Independent review of the combined candidate,
account lifecycle, real credential/Human provenance, HTTPS deployment and GitHub apply remain.
