# Sealr identity verifier

This workspace tool independently verifies the committed ZIP32 `sealr.identity-conformance.v1`, ZIP64 `sealr.zip64-identity-conformance.v1`, gzip-wrapped ustar `sealr.tar-gzip-identity-conformance.v1`, restricted PAX `sealr.tar-pax-identity-conformance.v1`, restricted GNU long-name `sealr.tar-gnu-longname-identity-conformance.v1`, gzip-wrapped restricted PAX `sealr.tar-gzip-pax-identity-conformance.v1`, gzip-wrapped restricted GNU long-name `sealr.tar-gzip-gnu-longname-identity-conformance.v1`, zstd-wrapped ustar `sealr.tar-zstd-identity-conformance.v1`, and xz-wrapped ustar `sealr.tar-xz-identity-conformance.v1` bundles. It does not depend on the Sealr crate, invoke a decompressor, or perform filesystem effects.

- For ZIP32 it validates the committed canonical profile bytes, source-bound covering geometry, and the axis lattice, and reproduces the `sealrTreeV1` layout and content roots.
- For ZIP64 it reconstructs the strict profile digest, checks source-bound covering geometry, semantic ZIP64 evidence, and structural-signature denials, reproduces the committed layout preimage and root, and reproduces the format-neutral content root.
- For gzip-wrapped ustar it independently reconstructs the interpretation and transform identities, verifies the exact RFC 1952 wrapper evidence, binds committed derived TAR bytes through CRC32, ISIZE, length, and SHA-256, verifies inner ustar evidence, and reproduces the wrapped `sealrTreeV4`, raw-TAR `sealrTreeV2`, and shared `sealrTreeV1` roots.
- For restricted PAX it verifies the exact source covering, canonical `path` and `size` records, global and local state transitions, underlying and effective member values, exact provenance, the `sealrTreeV5` layout root, and the shared `sealrTreeV1` content root.
- For restricted GNU long-name it verifies the exact old-GNU covering, `L` carrier payloads and their single-NUL grammar, carrier-to-member consumption state, header and carrier provenance, the `sealrTreeV6` layout root, and the shared `sealrTreeV1` content root.
- For gzip-wrapped restricted PAX it reconstructs the composed `sealr.profile.tar-gzip.pax-portable.v1` digest (including the independently reproduced inner PAX profile digest), verifies the wrapper evidence against each case's source bytes, re-parses the committed derived TAR under the restricted PAX language, and reproduces the wrapped `sealrTreeV7`, raw `sealrTreeV5`, and shared `sealrTreeV1` roots.
- For gzip-wrapped restricted GNU long-name it reconstructs the composed `sealr.profile.tar-gzip.gnu-longname-portable.v1` digest (including the independently reproduced inner GNU long-name profile digest), verifies the wrapper evidence against each case's source bytes, re-parses the committed derived TAR under the GNU `L`-only language, and reproduces the wrapped `sealrTreeV8`, raw `sealrTreeV6`, and shared `sealrTreeV1` roots.
- For zstd-wrapped ustar it reconstructs the composed `sealr.profile.tar-zstd.ustar-portable.v1` digest and the `sealr.transform.zstd.rfc8878-single-frame.v1` transform and decoder-parameter digests, replays the restricted RFC 8878 frame grammar over each case's source bytes (exactly one standard frame, denied skippable/reserved/unused/dictionary signals, bounded effective window), binds the committed derived TAR bytes through the frame content size, an independently implemented XXH64 content checksum, length, and SHA-256, re-parses the derived TAR under the portable-ustar language, and reproduces the wrapped `sealrTreeV9`, raw `sealrTreeV2`, and shared `sealrTreeV1` roots.
- For xz-wrapped ustar it reconstructs the composed `sealr.profile.tar-xz.ustar-portable.v1` digest and the `sealr.transform.xz.xzfmt-single-stream.v1` transform and decoder-parameter digests, replays the restricted XZ container grammar over each case's source bytes (exactly one stream, one-to-4096 single-LZMA2-filter blocks with an at-most-8 MiB dictionary, verified header/index/footer CRC32s and backward size, denied check-none, reserved bits, stream padding, and concatenation), binds the committed derived TAR bytes through per-block CRC32/CRC64/SHA-256 checks (CRC64 independently implemented), length, and SHA-256, re-parses the derived TAR under the portable-ustar language, and reproduces the wrapped `sealrTreeV10`, raw `sealrTreeV2`, and shared `sealrTreeV1` roots.

Run it from the repository root:

```powershell
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/zip64-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-gzip-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-pax-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-gnu-longname-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-gzip-pax-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-gzip-gnu-longname-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-zstd-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-xz-identity-v1.json
```

Its exact checks and nonclaims are documented in [identity conformance](../../docs/identity-conformance.md).
