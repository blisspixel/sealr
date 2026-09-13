# Packaged consumer fixture

This isolated Cargo project verifies Sealr as a downstream dependency after `cargo package` has produced and extracted the crate. It is deliberately not a member of the repository workspace and does not point at `crates/sealr`.

Run it from the repository root on x86_64 Linux after building and packaging
the production helper:

```powershell
cargo package --locked -p sealr --allow-dirty
cargo run --locked --manifest-path tests/packaged-consumer/Cargo.toml -- `
  --worker-manifest /absolute/path/to/sealr-worker.manifest
```

CI omits `--allow-dirty` because it runs from a clean checkout. The native
package-contract gate runs the fixture against the exact helper and manifest
it extracted from the release archive. The fixture exercises fail-closed
supervised execution, explicit strict-v2 profile selection, the opaque verified
capability, bounded member reads, stable error categories, and capability
ownership. Its static ZIP is field-grouped so the exact container structure
remains reviewable without a ZIP-building dependency.

The [outcome migration matrix](src/outcome_migration.rs) exercises
`sealr.verdict-consumer-migration.v1` through real public outcomes: inspection,
committed materialization, malformed structure, CRC failure, destination setup
failure, and an unavailable source. Capability reads and requested-effect
checks are independent. Legacy verdict and CLI checks are compatibility
assertions only. Linux main runs the matrix through the authenticated worker.
After extracting the current crate, its in-process variant also runs on Windows:

```powershell
cargo test --locked --manifest-path tests/packaged-consumer/Cargo.toml `
  outcome_migration::tests::public_outcome_migration_matrix
```

The deterministic core test `mutated_staged_content_never_publishes` separately
proves that a late publication failure preserves a readable capability while
the requested effect remains failed. This consumer fixture does not expose a
fault-injection API or manufacture an outcome to simulate that condition.

When the Sealr package version changes, update the dependency version, extracted-package path, and fixture lockfile together. Replacing the package path with a workspace source path defeats this fixture's purpose.
