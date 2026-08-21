# Repository tooling and dependency discipline

> Current status: the shipped `sealr` library and CLI are Rust. PowerShell and Bash are repository and release orchestration tools only. They are not runtime dependencies of the native archives.

## Why PowerShell exists today

The first release pipeline was developed from Windows, and PowerShell 7 is available on the standard Ubuntu, macOS, and Windows GitHub-hosted runners. It therefore provided one implementation for walkthrough generation, documentation checks, license bundles, and the local release operator while the product boundary was still changing.

That choice helped the first two alpha releases ship consistently, but it is not the desired long-term ownership boundary. Deterministic repository logic is easier to test, reuse, and run everywhere when it is implemented in Rust.

## Target tooling shape

Shared tasks move into a small workspace `xtask` binary:

```text
cargo run -p xtask -- docs verify
cargo run -p xtask -- walkthrough verify
cargo run -p xtask -- licenses verify
cargo run -p xtask -- release verify
```

The commands above are target notation, not current commands. Migration order and safety requirements are in the [roadmap](../ROADMAP.md#repository-tooling-and-dependency-rule).

Host wrappers remain thin:

- Bash may prepare a Linux-hosted GitHub Actions environment.
- PowerShell may integrate with a Windows operator session.
- Neither may own archive interpretation, evidence schemas, asset classification, or other shared security logic after its Rust replacement lands.

Release promotion moves last because the current PowerShell implementation contains deliberate numeric release-ID binding, tag and protected-main verification, checksum checks, provenance verification, immutable-release readback, and fail-closed recovery rules. A replacement must preserve every gate before the old path is removed.

## Cross-platform rule

Every shared tool must run from a clean checkout on Ubuntu, macOS, and Windows using repository-pinned Rust. Platform-specific tests may add native coverage, but no release platform may depend on another platform to generate or validate its artifact.

The release matrix remains:

- native Linux tests and archive;
- native macOS tests and archive;
- native 64-bit Windows tests and archive;
- 32-bit Windows ABI compile check today; native 32-bit execution is a future gate when an explicitly supported runner is available.

## Runtime dependency rule

A new dependency in the shipped library or CLI needs:

1. a concrete capability that the standard library or existing graph cannot reasonably provide;
2. maintained-source and advisory review;
3. license compatibility with Apache-2.0 distribution;
4. transitive dependency and binary-size review;
5. deterministic and offline behavior for the security path;
6. cross-platform tests on every supported release target.

Rust dependencies are locked and covered by repository license and advisory checks, and GitHub Actions are pinned by commit SHA. Runner-provided host tools are part of the documented CI environment but are not shipped runtime dependencies. Convenience alone does not justify adding an async runtime, terminal UI framework, network client, telemetry library, or second serialization stack to the release binary.

## CLI rule

The CLI is a thin presentation layer over typed library outcomes. Human formatting can improve, but machine JSON, rule identities, and exit classes remain versioned contracts. No UI dependency may become a second policy engine or parser.

The Rust task-runner shape follows the small-workspace pattern described by [`cargo-xtask`](https://github.com/matklad/cargo-xtask); Sealr does not need to depend on that repository or a task-runner framework.
