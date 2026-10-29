# Current limitations

The repository contains a keyless package, wire models/schemas, a SQLite/Decimal ledger and an offline controller using strict fixtures or injected synthetic transports.

- Router policies, scoring, live SDK/HTTP transport and evaluation are not implemented.
- No licensed 300-prompt corpus or human judge labels have been acquired.
- No cost, quality, savings or latency result is measured.
- The offline foundation is available as a source snapshot; actual consumer adoption requires its own grant, exact Git blob hashes, licences and moved tests.
- No provider authentication, resource provisioning or public release is established.

Future implementations must generate named failures from actual evaluation output and preserve incomplete evidence honestly.

See [INTERFACE.md](INTERFACE.md) and the [ledger contract](../src/llm_router_eval/shared/callledger/README.md). Wire declarations alone do not reserve money; the ledger performs atomic accounting with trusted registered evidence. No live price/token bounds, filesystem/general image decoder or arbitrary full JSON Schema validation are established. A charge above its bound is recorded and halts further funding; an incorrect bound can cause actual spend above the cap.

The [provider contract](provider-contracts.md) describes the deliberately bounded strict-schema subset and in-memory RGB/RGBA PNG checks. There is no filesystem image loader/general decoder or paid image-bound proof. Genuine SDK retries/timeouts/cancellation and broader schema support remain separate gates. Authored synthetic fixtures cannot become live observations by changing an origin/nonce flag.
