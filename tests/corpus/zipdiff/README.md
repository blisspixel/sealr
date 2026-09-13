# ZipDiff gate

This gate regenerates all 5,927 construction archives from the pinned upstream revision and classifies them with the production `sealr` API. Binary fixtures are generated in CI rather than committed.

The [expectation manifest](expectations.txt) binds:

- the upstream construction count;
- an aggregate SHA-256 that binds every relative path, file length, and fixture SHA-256 in sorted order;
- every class and emitted finding-code count;
- the exact allowlist of valid controls and portable character cases.

Every archive absent from the allowlist must be rejected. A new acceptance, a rejected control, a changed finding, a missing fixture, or an upstream construction change fails the gate.

The upstream generator defaults each DOS timestamp to the current UTC time. CI applies the committed [deterministic timestamp patch](deterministic-timestamps.patch) after verifying the exact upstream revision and before generation. This removes only that clock input and makes the byte corpus reproducible across runs and operating systems.

The aggregate hash record for each fixture is `u64_le(path_length) || path || u64_le(file_length) || sha256(file)`. Records are ordered by normalized relative path and hashed together with SHA-256.

Local reproduction, after generating the upstream `constructions` directory:

```console
git -C /path/to/ZipDiff apply /path/to/sealr/tests/corpus/zipdiff/deterministic-timestamps.patch
cd /path/to/ZipDiff/zip-diff
cargo run --locked --release --bin construction
cd /path/to/sealr
cargo run --locked --release -p sealr --example classify_zipdiff -- /path/to/constructions --expect tests/corpus/zipdiff/expectations.txt
```

Classification is embarrassingly parallel: each construction is an independent `apply()`. The example uses `std::thread` and `std::thread::available_parallelism`. Set `SEALR_JOBS=1` to force a single worker. Aggregate counts, the allowlist, and the corpus digest are still combined in sorted path order, so the gate does not depend on thread schedule.

Source provenance:

- Repository: <https://github.com/ouuan/ZipDiff>
- Revision: `7c427ed254bb3a5985d54870c12f97db78118e67`
- License: Apache-2.0
