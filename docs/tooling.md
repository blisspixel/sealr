# Repository tooling and dependency discipline

> Current status: the shipped `sealr` library and CLI are Rust. PowerShell and Bash are repository and release orchestration tools only. They are not runtime dependencies of the native archives.

## Why PowerShell exists today

The first release pipeline was developed from Windows, and PowerShell 7 is available on the standard Ubuntu, macOS, and Windows GitHub-hosted runners. It therefore provided one implementation for walkthrough generation, documentation checks, license bundles, and the local release operator while the product boundary was still changing.

That choice helped the first three alpha releases ship consistently, but it is not the desired long-term ownership boundary. Deterministic repository logic is easier to test, reuse, and run everywhere when it is implemented in Rust.

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

## Rust version policy

The current minimum supported Rust version is 1.98. Package metadata declares `rust-version = "1.98"`, `rust-toolchain.toml` pins 1.98.0 for contributors, and required CI installs exactly 1.98.0 rather than relying on a moving stable channel.

During the preview series, raising the MSRV requires an explicit changelog entry, package-metadata update, and green packaged-consumer build on the new minimum. After a stable 1.x release, patch releases do not raise the MSRV. A minor release may raise it only as a documented compatibility decision.

## Runtime dependency rule

A new dependency in the shipped library or CLI needs:

1. a concrete capability that the standard library or existing graph cannot reasonably provide;
2. maintained-source and advisory review;
3. license compatibility with Apache-2.0 distribution;
4. transitive dependency and binary-size review;
5. deterministic and offline behavior for the security path;
6. cross-platform tests on every supported release target.

Rust dependencies are locked and covered by repository license and advisory checks, and GitHub Actions are pinned by commit SHA. Runner-provided host tools are part of the documented CI environment but are not shipped runtime dependencies. Convenience alone does not justify adding an async runtime, terminal UI framework, network client, telemetry library, or second serialization stack to the release binary. Codec coverage does not justify libarchive, a vendor unarchiver, or a subprocess. Each new decompression crate is a trusted-computing-base change and is reviewed as such.

The single required `CI` workflow verifies the library package with `cargo package --locked -p sealr` after tests, optimized builds, the README walkthrough, and rustdoc. It then runs `tests/packaged-consumer` against Cargo's extracted package directory. This catches missing packaged files, package-only compilation failures, accidental workspace-only APIs, and capability regressions while the crate remains intentionally unpublished. An external integration test also compiles against the public crate boundary from outside the library module.

`sealr-identity-verifier` is a separate non-published workspace tool, not the future general `xtask`. It intentionally has no dependency on `sealr`, uses only the existing Serde, serde_json, and SHA-256 dependency families, and independently checks the committed [identity-conformance bundle](identity-conformance.md). Required CI names that check explicitly in addition to running its tamper tests through the workspace suite. It is not included in native release archives.

`sealr-wheel-lab` is also a non-published workspace tool. It uses the public Sealr API and explicitly selects [strict ASCII v2](profiles/zip-strict-ascii-v2.md) to analyze a bounded, digest-pinned corpus without another ZIP parser. Raw wheels remain outside Git. Required CI performs an offline verification of the committed [pilot report](wheel-compatibility-pilot.md): analyzer revision, manifest, interpretation-profile and default-policy bindings, artifact metadata, rollups, canonical JSON, and rendered Markdown must agree. Re-executing the measurement is a deliberate research operation because it requires the ignored local artifact cache.

`sealr-materialization-lifecycle` is a non-published, cross-platform executable oracle over the public `sealr` outcome. Required Linux, macOS, and Windows CI runs 500 release-mode iterations divided equally among successful publication, preexisting-destination setup collision, CRC verification abort, and a destination race. A repository-only feature plants the racing destination after staged-tree audit and immediately before the native no-replace publication call. This exact interleaving is deterministic and does not depend on thread scheduling. The tool independently states the expected public axes, receipt materialization and cleanup states, findings, capability presence, bounded member reads, destination preservation, and absence of leaked stage or fixture objects. It does not claim exhaustive schedules, test the isolated Linux worker, or prove a general filesystem race property.

`sealr-worker-bootstrap-lab` is a Linux-only executable conformance tool with a trivial non-Linux build path and cross-platform fixed-frame unit tests. It is not a release asset and does not depend on `sealr-cli` or `sealr-worker-protocol`. On Linux only, it selects `sealr`'s hidden `__internal-worker-lab` feature to create, validate, execute, and decode the dormant canonical semantic records without adding a default or supported API. `rustix` and `landlock` exercise sequenced-packet descriptor transfer, two-layer authority closure, a direct Landlock floor query plus fixed ABI 3 enforcement, exact truncation flags, parent observation, point-specific abrupt exit, absolute monotonic authority-round deadlines, pidfd termination and reap, checked cleanup ordering, and one backpressured member-output pipe. Its raw receive path follows Linux `CMSG_ALIGN` layout on GNU and musl, validates every returned control header, accepts one rights record with up to two descriptors, and proves installed descriptors close on rejected short, truncated, unknown, malformed, and multiple-rights packets. Bounded kernel-sealed plan, completion, retained-content, and member-read request memfds independently validate required seals, length, role, digest, and handoff correlation. The restricted inspect worker binds the full plan to an exact file-backed Store-and-Deflate snapshot, executes only planned payload ranges without structural reparse, and captures both selected fixture members during that pass. After worker reap, the supervisor replays that accepted plan against its retained exact source descriptor and requires byte-for-byte canonical agreement with both worker proposals. Each later non-retained read spawns a fresh worker that receives no stage or destination, validates the exact plan, completion, and read request, and writes only one selected range to a write-only pipe. The supervisor pre-reserves the exact authorized output and returns it only after exact EOF, correlated result, integrity, clean exit, and reap. The materialize route passes only a supervisor-created stage root, source, and sealed plan, captures retained files through the same verifier calls that write the stage, waits for clean exit and exact reap before decoding either output, then performs completion and retention replay, exact stage audit, and supervisor-only no-replace publication. Conformance covers retained-bundle mutation, post-reap stage mutation, destination appearance, cleanup failure, four writer crashes, two writer stalls, and 500 alternating writer lifecycles in addition to the original 500-case campaign. A dependency-free x86_64 seccomp-BPF module uses `TSYNC`, audit-architecture and x32 checks, a measured deny set, direct `EPERM` probes, and procfs observation to close process creation, stage permission mutation, rename, link, unlink, symlink, device creation, mount, truncate, and new socket authority before source transfer.

The semantic helper path now uses one self-bound generic adapter for inspect, materialize, and member-read execution. It validates the actual sealed-plan profile, policy identity, budget, target, consumer, effect, member-sync, target identity, and retention instead of reconstructing the fixed conformance request. Supervisor replay reconstructs owned private outcome and retention state only after exact source-derived completion and retained-content agreement, including canonically stopped verification outcomes. Evidence-only retained-content validation remains borrow-only in the helper.

Normal conformance uses the separate `sealr-worker` artifact built without the `lab` feature. It accepts no commands or fault selector. Both the lab and supported `LinuxWorker` require its explicit absolute path, exact byte length, and SHA-256, then authenticate a no-symlink opened object, sealed executable copy, helper hello, running executable identity, and exact reap without fallback before sending archive authority. Only deliberate fault modes execute the lab binary. The frame codec, raw descriptor transport, sealed-blob envelope, and helper-artifact authenticator are implemented once in `sealr`. The [fixed Linux package contract](helper-packaging.md) places that static artifact under `libexec`, binds its exact manifest and dependency notices, and reuses one package verifier in Required CI and the tag workflow. Package smoke now exercises public supervised inspect, retained borrow, capability clone and drop, one-shot read, and exact reap. Supervised materialization, CLI activation, and real-kernel failure evidence remain open.

The first [private semantic-record experiment](semantic-record.md) is a dormant crate-private module, not another workspace executable or dependency. It reuses the shipped crate's existing SHA-256 implementation, adds no runtime dependency, and remains absent from `apply`, CLI, and shipped runtime paths. The nondefault `__internal-fuzzing` feature exposes only an unsupported hidden byte-slice driver so the separate fuzz workspace can exercise the private codec; ordinary and default-feature builds expose no semantic-record type or supported API. Its custom bounded codec exists to exercise pre-growth encoded-size and pre-reservation count checks, supervisor-bound depth allocation, exact correlation, hostile range validation, source binding, and semantic state coherence without adding a second general serialization stack. Protocol and semantic targets use separate seed manifests, dictionaries, corpora, and bounded jobs. Required verification binds the complete Cargo manifest, parsed target and dependency graph, lock checksum, registry-rooted crates.io fuzz engine in a Cargo-config-free environment, and complete scheduled workflow. Executable negative fixtures reject inert TOML remapping, local, patched, or vendored fuzz-engine substitution, manual-only drift, weakening, inactive or appended commands, inert artifact evidence, and duplicate last-wins arguments, so evidence for one decoder cannot be mistaken for evidence for the other.

## CLI rule

The CLI is a thin presentation layer over typed library outcomes. Human formatting can improve, but machine JSON, rule identities, and exit classes remain versioned contracts. No UI dependency may become a second policy engine or parser.

Repository tools may use `std::thread` and `std::thread::available_parallelism` for independent jobs such as ZipDiff classification. `SEALR_JOBS` caps that parallelism. It is not a `Policy` field and must not change trees, findings, or roots. A thread pool crate is not justified for that.

The Rust task-runner shape follows the small-workspace pattern described by [`cargo-xtask`](https://github.com/matklad/cargo-xtask); Sealr does not need to depend on that repository or a task-runner framework.
