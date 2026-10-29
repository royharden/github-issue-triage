# HTTP dependency provenance

`uv.lock` pins public PyPI metadata and all declared distribution hashes for Python 3.12.
Existing dependency versions were retained. Minimal runtime additions are FastAPI, Jinja2 and
bare Uvicorn; HTTPX is a development-only ASGI test dependency. No standard/all extras, provider
SDK, OTel exporter/SDK, source build or package install script is used by this local path.
FastAPI declares the generic OpenTelemetry API; this app configures no telemetry exporter.

The Windows CPython 3.12 wheel closure was checked against exact-version PyPI metadata and the
lock: wheel SHA/size, ABI tags, bounded ZIP members, RECORD hashes and retained license files.
These are integrity/provenance checks, not publisher-attestation or vulnerability certification.
Native Linux execution and clean-machine installation are separate checks.

| Package | Version | License | Windows artifact SHA256 |
|---|---|---|---|
| annotated-doc | 0.0.5 | MIT | `117bac03a25ede5df5440e855b32d556049ca169ead221505badf432fed4b101` |
| anyio | 4.15.1 | MIT | `6152fdbbf9a77fdec97731721bebf7c4c44f7c29b424b0065826173efc7ed101` |
| certifi | 2026.7.22 | MPL-2.0 | `62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775` |
| click | 8.5.0 | BSD-3-Clause | `255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360` |
| fastapi | 0.143.2 | MIT | `da2fe9893b7392ebce76d8c8511e3fa43e5a25f5852103aa2eee7cff3ab80b75` |
| h11 | 0.16.0 | MIT | `63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86` |
| httpcore | 1.0.9 | BSD-3-Clause | `2d400746a40668fc9dec9810239072b40b4484b640a8c38fd654a024c7a1bf55` |
| httpx | 0.28.1 | BSD-3-Clause | `d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad` |
| idna | 3.20 | BSD-3-Clause | `ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c` |
| jinja2 | 3.1.6 | BSD-3-Clause | `85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67` |
| markupsafe | 3.0.4 | BSD-3-Clause | `11935df9bf455ed0c04eb87bcd720f02b1fe5e02128a9430f23aed6f93336fc7` |
| opentelemetry-api | 1.45.1 | Apache-2.0 | `b31553efa588ae44bc306f863c785c5333a9ecc091248c6ee68b4b6c87fdedfb` |
| starlette | 1.8.0 | BSD-3-Clause | `dfdd6b29c26483288088d990eee59631dedadd66ce20d203402a7ca8e3c4656f` |
| uvicorn | 0.54.0 | BSD-3-Clause | `505bdb0f318731d45f1f712071fc781a8981f6847a31c902c9f5e652d4f67faf` |

Upstream packages retain their own license files in their installed `.dist-info` directories.
No downloaded wheel or environment is committed. Use `uv sync --frozen` from the repository for
portable setup; a cache-only rerun requires the matching locally available artifacts.
Starlette currently warns that its HTTPX TestClient integration is deprecated in favor of
HTTPX2. The tested HTTPX integration remains working; that warning is retained.
