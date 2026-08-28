# Sealr identity verifier

This workspace tool independently verifies the committed ZIP32 `sealr.identity-conformance.v1`, ZIP64 `sealr.zip64-identity-conformance.v1`, and gzip-wrapped ustar `sealr.tar-gzip-identity-conformance.v1` bundles. It does not depend on the Sealr crate, invoke a decompressor, or perform filesystem effects. For ZIP64 it reconstructs the strict profile digest, checks source-bound covering geometry, semantic ZIP64 evidence, and structural-signature denials, reproduces the committed layout preimage and root, and reproduces the format-neutral content root. For gzip-wrapped ustar it independently reconstructs the interpretation and transform identities, verifies the exact RFC 1952 wrapper evidence, binds committed derived TAR bytes through CRC32, ISIZE, length, and SHA-256, verifies inner ustar evidence, and reproduces the wrapped `sealrTreeV4`, raw-TAR `sealrTreeV2`, and shared `sealrTreeV1` roots.

Run it from the repository root:

```powershell
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/zip64-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-gzip-identity-v1.json
```

Its exact checks and nonclaims are documented in [identity conformance](../../docs/identity-conformance.md).
