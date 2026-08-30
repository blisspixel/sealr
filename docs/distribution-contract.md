# Distribution contract

> Status: executable pre-1.0 contract. This page defines what the repository is prepared to publish and how native archives are tested. It does not announce a stable release or widen the security claims in the README.

Sealr has two separate distribution promises:

1. a source crate that downstream Rust projects compile for their own target;
2. native command archives built and tested by the release workflow.

Evidence for one promise does not imply the other. A successful `cargo package` does not prove a native binary's operating-system floor, and a native smoke test does not freeze the Rust API.

## Source crate

Only the `sealr` library crate is allowlisted for publication to `crates-io`. The CLI, worker protocol, helper, wheel laboratory, conformance tools, lifecycle tools, and license-closure tool remain repository or native-release components and have `publish = false`.

The package contract at `tests/package-contract/sealr.json` pins:

- the complete `cargo package --list` result;
- the crates.io registry allowlist;
- Rust 1.98 as the current minimum supported Rust version;
- the Apache-2.0 SPDX expression;
- a package-root `README.md` and `LICENSE` whose bytes match the repository sources.

Required CI packages and verifies the crate, extracts the exact `.crate`, and builds two separately locked downstream consumers plus the packaged [copyable PyPA handoff](../crates/sealr/examples/pypa_installer_handoff/README.md) against that extraction. The general consumer exercises supervised ZIP, every current in-process format selection through Copy-only 7z, retained and later member reads after source removal, and the public wheel evaluator. The Linux POSIX PyPA consumer independently verifies canonical evidence, removes the source, stages bounded member bytes only through `VerifiedArchive`, and completes real installer 1.0.1 filesystem effects for a controlled fixture and the exact hash-pinned upstream wheel. The handoff is built once as an example inside the extracted package, then copied into an isolated project whose manifest still resolves `sealr` only to that extraction. CI rejects any internal Sealr feature in the copied graph. The package contract pins the handoff's `main.rs`, `stage.rs`, `wheel_source.py`, `README.md`, exact Python requirements, and standalone Cargo manifest template. The check fails if another workspace crate becomes publishable or any packaged path changes without a reviewed contract update.

### Public API review

The supported source surface is the documented public `sealr` API exercised by:

- `crates/sealr/tests/public_api.rs`;
- the extracted `tests/packaged-consumer` project;
- the copied `examples/pypa_installer_handoff` project;
- Rustdoc with warnings denied.

That surface includes the one-operation compatibility API, explicit interpretation-profile selection, outcome and evidence types, the opaque `VerifiedArchive`, bounded retention and member reads, immutable member container facts, and explicit fail-closed Linux supervision types.

The three features whose names begin with `__internal-` exist only to compile repository fuzzing, worker-lab, and lifecycle seams. They are not supported activation surfaces, and no stable compatibility promise applies to them. Other workspace crates and private semantic-record types are not part of the published library API.

The current `0.1.0-alpha.*` line is prerelease software. Every breaking prerelease change must be called out in the changelog and reflected in compatibility fixtures. At stable 1.0:

- incompatible public API or behavior changes require a new major version;
- additive compatible changes use a minor version;
- compatible fixes use a patch version;
- the MSRV is pinned in package metadata and required CI;
- patch releases never raise the MSRV;
- a later 1.x minor release may raise the MSRV only with an explicit changelog entry, metadata update, and compatibility-test update.

The current Rust 1.98 declaration is executable now. The stable 1.0 API and profile freeze remains gated by the trust, usefulness, assurance-history, and independent-review requirements in the roadmap.

## Native archives

The machine-readable floor is `tests/package-contract/native.json`. Workflows use explicit runner labels and reject host or target drift before tests or packaging.

| Archive target | Required build and smoke-test floor | Runtime boundary |
|---|---|---|
| `x86_64-unknown-linux-gnu` | Ubuntu 24.04 x86_64, glibc 2.39, Linux 6.8 or later | The ordinary library and CLI path is in process. Explicit supervised execution additionally runtime-probes Landlock ABI 3 and installs the documented x86_64 seccomp filter. It fails closed without fallback when those capabilities are unavailable. |
| `aarch64-apple-darwin` | macOS 15 on arm64, Darwin 24, `MACOSX_DEPLOYMENT_TARGET=15.0` | In-process inspection and materialization only. Linux supervision fails closed as unavailable. |
| `x86_64-pc-windows-msvc` | Windows Server 2022 x64, NT build 20348, MSVC ABI | In-process inspection and materialization only. Linux supervision fails closed as unavailable. |

These are the supported native archive floors, not claims that the artifacts fail on every older or different system. Generic Linux distributions with compatible glibc may work, but only the named Ubuntu floor is promised. Windows desktop versions may work, but the required release evidence is Windows Server 2022. No x86_64 macOS archive is produced.

The exact runners are `ubuntu-24.04`, `macos-15`, and `windows-2022`. The release matrix:

1. verifies the runner, architecture, ABI, and deployment contract;
2. runs the optimized workspace tests on that host;
3. builds the release CLI and independent canonical-evidence verifier;
4. packages the exact target archive;
5. extracts and smoke-tests both packaged executables;
6. verifies the target-specific license closure and exact archive contents;
7. stages only the three expected archives for checksums and provenance.

Every extracted native CLI is exercised through portable ustar inspect and materialization against the same independently produced fixture, with exact source, layout, content, and output bytes. The extracted CLI also emits admitted and rejected canonical evidence that the extracted `sealr-identity-verifier` checks against the observed source. View, receipt, source, and pair-substitution mutations must all fail closed. Linux additionally proves that selecting portable ustar with the packaged authenticated worker returns typed isolation unavailability, creates no destination or stage, and does not fall back to in-process execution.

All three archives contain `sealr-identity-verifier` or its `.exe` form beside `sealr`. It remains a separate executable with no dependency on the Sealr crate. The Linux archive also contains the authenticated static helper and its fixed manifest. The helper is absent from macOS and Windows archives. Required Linux CI extracts that native package and runs the copied `WheelSource` handoff twice against its helper manifest and verifier: once from supervised inspect and once from supervised materialization. The source wheel is removed before Python begins in both cases. A separate pinned-kernel QEMU gate proves that explicit Linux supervision fails before source transfer on Landlock ABI 2, while required Linux tests exercise successful ABI 3 setup on the declared release host.

## Release evidence

Protected `main` exposes one required check named `Required CI`. That aggregator succeeds only after the exact quality, native-platform, ZipDiff, supply-chain, and real-kernel jobs succeed. Tag validation then requires successful exact-commit main CI and fuzz evidence before the release workflow can build, attest, and stage artifacts.

Publication is a separate trust-boundary operation. The publisher rechecks the protected-main commit, annotated tag, release notes, workflow identities, immutable-release setting, asset set, checksums, and provenance immediately before publication and verifies the immutable result afterward.

Until stable 1.0, this contract can become stricter through reviewed prerelease changes. It cannot be weakened silently, inferred from a mutable `*-latest` label, or broadened from a source-package result to a native-platform claim.
