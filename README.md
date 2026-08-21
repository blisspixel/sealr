# sealr

[![CI](https://github.com/blisspixel/sealr/actions/workflows/ci.yml/badge.svg)](https://github.com/blisspixel/sealr/actions/workflows/ci.yml)

> **One archive. One tree. Evidence.**

sealr is becoming the canonical archive-to-tree compiler and admission authority for its supported profiles. Today, it is a high-assurance ZIP32 boundary that gives accepted bytes one versioned Sealr interpretation, verifies every member, and either publishes that interpreted tree without replacement or publishes no destination.

```text
Untrusted archive x policy
  -> (Allowed { wrote } | Rejected) x receipt x inspectable view
```

It is not a safer unzip. The product is the decision, evidence, and constrained view around extraction.

> Status: `v0.1.0-alpha.2` is the second development preview of the ZIP boundary. It is useful for evaluation, development, and adversarial testing. It is not ready to protect a production host from arbitrary hostile archives. The limitations below are security boundaries, not fine print.

## Why this exists

Agents, package systems, upload handlers, and data pipelines routinely receive archives from outside their trust boundary. Archive formats encode filesystem topology as well as content, and different parsers can assign different meanings to the same bytes.

The 2025 ZipDiff study compared 50 ZIP parsers across 19 languages, found that almost every parser pair disagreed somewhere, and classified 14 ambiguity types. Its public artifact includes constructors for those cases. A 2025 `uv` advisory then documented that one wheel digest could expand differently across installers, and PyPI added upload-time rejection for several ambiguous ZIP structures. These results make parser agreement a testable security property instead of an assumption.

sealr therefore has one operation:

```rust
pub fn apply(request: Request<'_>) -> Outcome
```

Every outcome contains:

- an allow or reject verdict;
- a structured view of the interpretation;
- a receipt binding the available source digest, policy, view, tool, and environment;
- publication of the requested destination only after every member and the complete archive pass.

## What works today

The current Rust implementation supports classic ZIP32 archives with stored or Deflate members.

- CD-first parsing with exact EOCD, central-directory, local-header, and data-descriptor agreement.
- Rejection of hidden stream records, unreferenced layout bytes, overlapping records, spanned archives, ZIP64, encryption, unsupported methods, and mismatched flags or metadata.
- Pure lexical path jailing for absolute paths, parent traversal, ADS colons, reserved Windows names, trailing dots and spaces, control characters, empty components, depth, duplicates, case-fold collisions, and file/directory topology conflicts.
- Strict filename handling. Invalid UTF-8 and non-ASCII CP437 names are rejected until the canonical Unicode path design is complete.
- Bounded source reads, metadata, file count, declared and actual member size, total expanded size, and declared and actual compression ratio.
- Streaming Deflate, exact compressed-input consumption, CRC32, and SHA-256 calculation without buffering an expanded member in memory. Trailing bytes and concatenated raw DEFLATE streams inside one declared member payload are rejected.
- Component-bound, same-volume staging with 128-bit random names. Every member component is opened no-follow from a retained directory handle, files use create-new handles, and the requested destination is published with native no-replace semantics only after every member passes.
- Deterministic JSON view and versioned unsigned receipt on allow and reject paths. Receipts record the materializer backend, stage mode, stage-creation primitive, component-resolution guarantee, durability, publication primitive, outcome, and cleanup state.
- A pinned 5,927-file, 14-class ZipDiff construction gate with a deterministically generated aggregate corpus digest, exact finding-count expectations, and an explicit 73-file control allowlist.
- An adversarial unit suite, strict Clippy, rustfmt, documentation checks, cross-platform tests, and cargo-deny policy in CI.

## Security limitations

The following work must land before a production-readiness claim:

- The ZipDiff gate covers its pinned known constructions. It does not prove that future or previously unknown parser ambiguities cannot exist.
- The archive itself is currently buffered in memory, with a default 512 MiB input cap. Expanded members stream.
- Unicode normalization and CP437 decoding are not implemented, so non-ASCII member paths fail closed.
- Materialization is supported only on Linux, macOS, and Windows; other targets fail closed. On Linux and macOS, sealr accepts only an existing parent owned by the effective user or root that is not externally writable unless sticky semantics protect entries. macOS also requires extended ACLs to be absent. Filesystems that do not enforce these namespace rules are outside this preview's support boundary.
- Windows materialization is limited to a non-remote, writable NTFS parent that reports persistent ACL support. ReFS, FAT-family filesystems, remote shares, read-only volumes, and ambiguous volume queries fail closed.
- Windows atomically creates and retains the stage with `NtCreateFile`, installing a protected DACL whose owner and sole allow principal are the effective token user. The inheritable ACE is verified through the returned handle before any member write. Publication uses `NtSetInformationFile` with the retained stage and parent handles. The native adapters are isolated, tested on 64-bit Windows, and compile-checked for the 32-bit Windows ABI.
- Repeated hostile concurrent mutation stress remains unfinished. Static Unix symlink refusal, Windows generic reparse-point refusal, private-DACL inheritance, and deterministic stage-substitution resistance are covered. A reduced-authority worker will limit a compromised parser's ambient authority, but other processes running as the same user remain outside the containment claim.
- Normal rejection attempts stage cleanup and retries once after failure, then records `removed` or `failed` in the receipt. Setup failure after stage creation uses the retained stage handle first and a parent-relative retry. A killed process or two cleanup failures can leave a hidden staging directory.
- The default durability mode is `flush-only`. Setting the Rust policy field `atomic: true` syncs completed member files, but directory syncing, crash recovery, and power-loss durability are not implemented.
- Landlock, seccomp, AppContainer, and other process sandboxes are not implemented. Receipts report `kernel_jail: unavailable`.
- After a source is read, its receipt digest is the archive SHA-256. A failure before the bytes are available currently uses an all-zero SHA-256 sentinel; explicit digest availability is still a receipt-schema gate.
- Receipts are unsigned, and their JSON digest is deterministic for the current Rust structs but is not yet RFC 8785 JCS.
- The current `View` is invocation evidence, not an effect-independent tree artifact. Its digest covers verdict, write state, findings, and members, so it is not a semantic tree identity. Materialization failures also currently map into the end-to-end `Rejected` verdict. A versioned admitted-tree schema, separate admission and effect outcomes, layout and content roots, and explicit view completeness are the next semantic gate.
- ZIP64, TAR, compressed TAR, gzip, zstd, and 7z are not implemented.
- There is no external security audit or stable production-supported release.

See [SECURITY.md](SECURITY.md), [the threat model](docs/threat-model.md), and [the invariants](docs/invariants.md) before integrating the crate.

## Try it

The repository pins Rust 1.98.0 in `rust-toolchain.toml`; rustup selects it automatically.

Download the native preview archives, `SHA256SUMS`, and provenance from the [`v0.1.0-alpha.2` release](https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.2), or build from source:

```powershell
git clone https://github.com/blisspixel/sealr.git
cd sealr
cargo test --locked --workspace

# Inspect only. View goes to stdout; receipt goes to stderr.
cargo run --locked -p sealr-cli -- path/to/archive.zip

# Materialize into a new destination below an existing parent.
cargo run --locked -p sealr-cli -- path/to/archive.zip --dest ./out
```

The CLI exits `0` when policy allows the archive and `2` when it rejects it. Operational command-line errors use the normal Clap exit behavior.

## Walkthrough

The walkthrough uses two byte-stable fixtures and the direct release binary. The committed terminal captures show Windows PowerShell, so they include the `.exe` suffix; the script selects the native suffix on Linux and macOS. Run the complete scenario from a clean checkout with:

```powershell
pwsh -NoLogo -NoProfile -File scripts/walkthrough.ps1
```

The script builds the locked release binary, verifies both fixture digests, separates stdout view JSON from stderr receipt JSON, asserts the filesystem state, and produces the exact transcripts shown below.

### 1. Inspect without writing

```powershell
target/release/sealr.exe target/readme-walkthrough/fixtures/allowed.zip
```

Expected result: exit `0`, verdict `allowed`, `wrote: false`, and two sorted members with their measured sizes and SHA-256 digests.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme-walkthrough/sealr-inspect-allowed-terminal-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/readme-walkthrough/sealr-inspect-allowed-terminal-light.png">
  <img alt="Screenshot of sealr allowing a two-member ZIP inspection while reporting that no files were written." src="docs/assets/readme-walkthrough/sealr-inspect-allowed-terminal-light.png" width="1000">
</picture>

### 2. Reject a parent path

```powershell
target/release/sealr.exe target/readme-walkthrough/fixtures/rejected-parent-path.zip `
  --dest target/readme-walkthrough/blocked
```

Expected result: exit `2`, verdict `rejected`, finding `path.dotdot` for `../outside.txt`, and neither the destination nor the outside file exists.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme-walkthrough/sealr-reject-parent-path-terminal-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/readme-walkthrough/sealr-reject-parent-path-terminal-light.png">
  <img alt="Screenshot of sealr rejecting a parent-path member and confirming that no destination was created." src="docs/assets/readme-walkthrough/sealr-reject-parent-path-terminal-light.png" width="1000">
</picture>

### 3. Materialize the approved tree

```powershell
target/release/sealr.exe target/readme-walkthrough/fixtures/allowed.zip `
  --dest target/readme-walkthrough/materialized
```

Expected result: exit `0`, verdict `allowed`, `wrote: true`, and exactly the two inspected members exist in the new destination.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme-walkthrough/sealr-materialize-allowed-terminal-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/readme-walkthrough/sealr-materialize-allowed-terminal-light.png">
  <img alt="Screenshot of sealr materializing two approved members into a new destination after inspection." src="docs/assets/readme-walkthrough/sealr-materialize-allowed-terminal-light.png" width="1000">
</picture>

The semantic walkthrough is enforced by CLI integration tests. The PNGs are committed documentation assets generated from those verified transcripts. CI regenerates the transcript HTML and validates each PNG's dimensions, format, size, and metadata; it does not perform a flaky pixel comparison.

## Design rules

- One interpretation serves inspect and materialize. There is no recovery parser.
- Policy is data and its digest is part of the receipt. There is no `--insecure` mode.
- Unknown or unsupported structure fails closed.
- Declared sizes never authorize allocation or output. Actual bytes are counted as they arrive.
- Rejection is evidence-bearing. It still returns a view and receipt.
- Format breadth and acceleration come after the boundary is measurable.

## What comes next

The next milestone remains the Phase 0.1 trust gate, not another archive format. The immediate priority is semantic identity: a versioned, effect-independent admitted-tree representation; separate interpretation, verification, admission, and effect outcomes; distinct source, interpretation, layout, content-tree, and invocation identities; and one object consumed by every Sealr destination without reparsing the archive.

The supervised Linux worker follows that contract because its bounded protocol and the supervisor's final staged-tree audit need the same canonical tree and manifest. The supervisor will own the destination parent, private stage, publication, and cleanup; the worker will receive only the archive snapshot and stage capabilities and install Landlock before reading the first archive byte. Linux is the first enforced worker platform, while macOS and Windows must remain natively green and report isolation honestly until their worker boundaries are implemented.

Authenticated abandoned-stage recovery follows the worker because recovery must be owned by the final supervisor lifecycle. Landlock limits the worker's ambient authority; it does not contain another process running as the same user. A distinct service identity or equivalent mandatory-access-control boundary would be required to bring that actor into scope.

Canonical CP437 and Unicode collision semantics, snapshot-backed bounded random access, fuzz and property suites, small-core proofs, compatibility measurement, an independent evidence verifier, and performance gates based on avoided parsing, decompression, and writes complete Phase 0.1 before TAR begins. Python wheel admission is the preferred first consumer profile after the semantic core, not a claim of current support.

The order and exit criteria are in [ROADMAP.md](ROADMAP.md).

## Research basis

- [My ZIP isn't your ZIP, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [ZipDiff artifact and construction generator](https://github.com/ouuan/ZipDiff)
- [`uv` ZIP archive confusion advisory](https://github.com/advisories/GHSA-8qf3-x8v5-2pj8)
- [PyPI response to wheel archive confusion attacks](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [cap-std capability-oriented filesystem API](https://github.com/bytecodealliance/cap-std)
- [Kani Rust Verifier](https://model-checking.github.io/kani/)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)

## Documentation

| Document | Purpose |
|---|---|
| [ROADMAP.md](ROADMAP.md) | Ordered work, gates, and rationale |
| [docs/vision.md](docs/vision.md) | Product direction and priorities |
| [docs/semantic-model.md](docs/semantic-model.md) | Current semantics and target admitted-tree model |
| [docs/api.md](docs/api.md) | Current alpha.2 contract and target outcome axes |
| [docs/policy.md](docs/policy.md) | Policy schema and defaults |
| [docs/findings.md](docs/findings.md) | Stable finding-code registry |
| [docs/threat-model.md](docs/threat-model.md) | Adversary and ZipDiff classes |
| [docs/invariants.md](docs/invariants.md) | Non-negotiable safety properties |
| [docs/differentials.md](docs/differentials.md) | Single-interpretation rules and corpus |
| [docs/sandbox.md](docs/sandbox.md) | Reduced-authority process design |
| [docs/attestations.md](docs/attestations.md) | Unsigned evidence and future authenticated claims |
| [docs/assurance.md](docs/assurance.md) | Hostile and benign corpora, cross-platform determinism, fuzzing, proofs, and audit |
| [docs/architecture.md](docs/architecture.md) | Current trust boundaries and target semantic pipeline |
| [docs/usage.md](docs/usage.md) | Intended CLI surface |
| [CHANGELOG.md](CHANGELOG.md) | Preview release history |
| [docs/releasing.md](docs/releasing.md) | Reproducible release process and verification |

## License

[Apache-2.0](LICENSE). Native release archives also include a target-specific `THIRD_PARTY_LICENSES.txt` generated and verified from the locked dependency graph.
