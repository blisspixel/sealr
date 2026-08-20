# ZipDiff gate

This gate regenerates all 5,927 construction archives from the pinned upstream revision and classifies them with the production `sealr` API. Binary fixtures are generated in CI rather than committed.

The [expectation manifest](expectations.txt) binds:

- the upstream construction count;
- platform-specific aggregate SHA-256 values that bind every relative path, file length, and fixture SHA-256 in sorted order;
- every class and emitted finding-code count;
- the exact allowlist of valid controls and portable character cases.

Every archive absent from the allowlist must be rejected. A new acceptance, a rejected control, a changed finding, a missing fixture, or an upstream construction change fails the gate.

The upstream generator writes some host-dependent ZIP metadata, so Windows and Linux have separate expected aggregate values. The verifier requires an expectation for its current operating system. It does not accept a digest merely because it is valid on another platform.

The aggregate hash record for each fixture is `u64_le(path_length) || path || u64_le(file_length) || sha256(file)`. Records are ordered by normalized relative path and hashed together with SHA-256.

Local reproduction, after generating the upstream `constructions` directory:

```console
cargo run --locked --release -p sealr --example classify_zipdiff -- /path/to/constructions --expect tests/corpus/zipdiff/expectations.txt
```

Source provenance:

- Repository: <https://github.com/ouuan/ZipDiff>
- Revision: `7c427ed254bb3a5985d54870c12f97db78118e67`
- License: Apache-2.0
