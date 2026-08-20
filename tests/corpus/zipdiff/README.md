# ZipDiff gate

This gate regenerates all 5,927 construction archives from the pinned upstream revision and classifies them with the production `sealr` API. Binary fixtures are generated in CI rather than committed.

The [expectation manifest](expectations.txt) binds:

- the upstream construction count;
- an aggregate SHA-256 that binds every relative path, file length, and fixture SHA-256 in sorted order;
- every class and emitted finding-code count;
- the exact allowlist of valid controls and portable character cases.

Every archive absent from the allowlist must be rejected. A new acceptance, a rejected control, a changed finding, a missing fixture, or an upstream construction change fails the gate.

The aggregate hash record for each fixture is `u64_le(path_length) || path || u64_le(file_length) || sha256(file)`. Records are ordered by normalized relative path and hashed together with SHA-256.

Local reproduction, after generating the upstream `constructions` directory:

```console
cargo run --locked --release -p sealr --example classify_zipdiff -- /path/to/constructions --expect tests/corpus/zipdiff/expectations.txt
```

Source provenance:

- Repository: <https://github.com/ouuan/ZipDiff>
- Revision: `7c427ed254bb3a5985d54870c12f97db78118e67`
- License: Apache-2.0
