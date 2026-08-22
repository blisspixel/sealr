# sealr

[![CI](https://github.com/blisspixel/sealr/actions/workflows/ci.yml/badge.svg)](https://github.com/blisspixel/sealr/actions/workflows/ci.yml)

> **Goal: one archive, one tree, and evidence for the decision.**

sealr is an early attempt to make archive ingestion easier to reason about. Alpha.3 implements a deliberately narrow ZIP32 path: it builds one versioned interpretation from an immutable source snapshot, verifies accepted members, and either publishes the requested tree without replacement or publishes no destination. Receipts record separate outcome axes and unsigned layout and content identities. It does not yet provide a process sandbox or production security claim.

```text
Untrusted archive x policy
  -> (Allowed { wrote } | Rejected) x receipt x inspectable view
```

The longer-term aim is an archive-to-tree admission boundary whose decision and evidence can be reused by other systems. The current release is a small step toward that aim, not proof that the category or design is finished. Usefulness is not “more unzip.” It is: same bytes and policy produce one tree or no tree on Linux, macOS, and Windows, and the next tool consumes that tree instead of opening the ZIP again. Until a dependent does that, a receipt is just a receipt. The [usefulness test](docs/usefulness.md) is the quality bar.

> Status: `v0.1.0-alpha.3` is the third development preview of the ZIP boundary. It is useful for evaluation, development, and adversarial testing. It is not ready to protect a production host from arbitrary hostile archives. The limitations below are security boundaries, not fine print.

## Why this exists

Agents, package systems, upload handlers, and data pipelines routinely receive archives from outside their trust boundary. Archive formats encode filesystem topology as well as content, and different parsers can assign different meanings to the same bytes.

The 2025 ZipDiff study compared 50 ZIP parsers across 19 languages, found that almost every parser pair disagreed somewhere, and classified 14 ambiguity types. Its public artifact includes constructors for those cases. A 2025 `uv` advisory then documented that one wheel digest could expand differently across installers, and PyPI added upload-time rejection for several ambiguous ZIP structures. These results motivate testing parser agreement instead of assuming it.

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
- Streaming Deflate, exact compressed-input consumption, CRC32, and SHA-256 calculation without buffering an expanded member in memory. The staged-tree audit also hashes through a fixed 64 KiB buffer. Trailing bytes and concatenated raw DEFLATE streams inside one declared member payload are rejected.
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
- Windows atomically creates and retains the stage with `NtCreateFile`, installing a security descriptor whose object owner is the effective token user and whose protected DACL contains one inheritable allow ACE for that SID. The descriptor is verified through the returned handle before any member write. Descendants inherit that sole-principal DACL but receive the creating token's default owner; a principal matching that owner SID can change a descendant DACL and is outside the in-process containment promise. Publication uses `NtSetInformationFile` with the retained stage and parent handles. The native adapters are isolated, tested on 64-bit Windows, and compile-checked for the 32-bit Windows ABI.
- Repeated hostile concurrent mutation stress remains unfinished. Static Unix symlink refusal, Windows generic reparse-point refusal, private-DACL inheritance, and deterministic stage-substitution resistance are covered. A reduced-authority worker will limit a compromised parser's ambient authority, but other processes running as the same user remain outside the containment claim.
- Normal rejection attempts stage cleanup and retries once after failure, then records `removed` or `failed` in the receipt. Setup failure after stage creation uses the retained stage handle first and a parent-relative retry. A killed process or two cleanup failures can leave a hidden staging directory.
- The default durability mode is `flush-only`. Setting the Rust policy field `atomic: true` syncs completed member files, but directory syncing, crash recovery, and power-loss durability are not implemented.
- Landlock, seccomp, AppContainer, and other process sandboxes are not implemented. Receipts report `kernel_jail: unavailable`.
- When the complete source bytes are held, the receipt records their SHA-256. A failure before a complete snapshot is available records `{ "status": "unavailable" }` instead of a digest. Receipts also carry separate interpretation, admission, verification, effect, and view-completeness axes; the alpha.2 `Allowed`/`Rejected` shape remains a compatibility adapter and still maps an admitted archive with a failed destination to `Rejected`.
- Receipts are unsigned, and their JSON digest is deterministic for the current Rust structs but is not yet RFC 8785 JCS.
- The inspectable `View` remains invocation evidence. Its digest covers verdict, write state, findings, and members. Receipts now also carry separate `sealrTreeV1` layout and content-tree identities derived from `ArchiveIR`. Those roots are unsigned, preview-line encodings; they are not yet a lock, an authenticated subject, or a claim that every extra-field payload is semantic. Materialization failures still map into the end-to-end `Rejected` verdict.
- ZIP64, TAR, compressed TAR, gzip, zstd, and 7z are not implemented.
- There is no external security audit or stable production-supported release.

See [SECURITY.md](SECURITY.md), [the threat model](docs/threat-model.md), and [the invariants](docs/invariants.md) before integrating the crate.

## Try it

The repository pins Rust 1.98.0 in `rust-toolchain.toml`; rustup selects it automatically.

Download the native preview archives, `SHA256SUMS`, and provenance from the [`v0.1.0-alpha.3` release](https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.3). Runnable checksum and provenance commands are in [release verification](docs/release-verification.md). To build from source:

```text
git clone https://github.com/blisspixel/sealr.git
cd sealr
cargo test --locked --workspace

# Inspect only. View goes to stdout; receipt goes to stderr.
cargo run --locked -p sealr-cli -- path/to/archive.zip

# Materialize into a new destination below an existing parent.
cargo run --locked -p sealr-cli -- path/to/archive.zip --dest ./out
```

The library and shipped CLI are Rust. CI runs native tests and release builds on Ubuntu, macOS, and Windows; the platform-specific materializers are release gates, not secondary ports. Some repository maintenance and release scripts are currently PowerShell because the same scripts run on all three GitHub-hosted runner families and the local release operator uses Windows. PowerShell is not a runtime dependency of `sealr`, but this is more scripting surface than the project should keep. Shared deterministic repository tasks are scheduled to move into a small Rust `xtask`, leaving only thin host-specific wrappers where an operating-system or operator boundary requires one.

The CLI exits `0` when the archive is admitted, `2` when it is not admitted, and `3` when it is admitted but a requested destination effect fails. The inspectable view now includes the same interpretation, admission, verification, effect, and completeness axes as the receipt. The compatibility `verdict` still maps an admitted archive with a failed destination to `rejected`. Operational command-line errors use the normal Clap exit behavior.

## Walkthrough

The walkthrough uses two byte-stable fixtures and a locally built release-profile binary from the checked-out source. The committed rendered terminal-style summaries use Windows PowerShell notation, so they include the `.exe` suffix; the script selects the native suffix on Linux and macOS. Run the complete scenario from a clean checkout with:

```powershell
pwsh -NoLogo -NoProfile -File scripts/walkthrough.ps1
```

The script builds the locked release-profile binary, verifies both fixture digests, separates stdout view JSON from stderr receipt JSON, asserts the filesystem state, and produces the transcripts used by the captures below.

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

The semantic walkthrough is enforced by CLI integration tests on the native platform jobs. The PNGs are rendered terminal-style summaries derived from alpha.3's separate JSON view and receipt streams; they are not literal captures of raw CLI output or the planned human interface. The visible summary intentionally uses the stable decision, finding, and member subset. CI regenerates the fixtures, native transcript variant, and HTML, checks fixture and platform-specific transcript SHA-256 values against the committed asset manifest, then verifies every PNG's SHA-256, dimensions, format, size, density, and metadata policy. CI does not claim a pixel comparison.

## Design rules

- One interpretation serves inspect and materialize. There is no recovery parser.
- Policy is data and its digest is part of the receipt. There is no `--insecure` mode.
- Unknown or unsupported structure fails closed.
- Declared sizes never authorize allocation or output. Actual bytes are counted as they arrive.
- Rejection is evidence-bearing. It still returns a view and receipt.
- Format breadth and acceleration come after the boundary is measurable. Common ZIP/TAR codecs are in scope as adapters on that boundary, not as a second extractor or a large codec framework.
- Do not add TAR, 7z, or a richer CLI as a substitute for a dependent that imports the crate and stops unzipping. Wheel admission is the first consumer that would prove the category.
- Unique covering is sequential. Independent member verification may use many cores after one IR exists. A second parse is not a use of extra cores.
- The shipped library keeps a small trusted computing base. New runtime dependencies need a written capability need; unknown methods fail closed.

## What comes next

The next milestone remains the Phase 0.1 trust gate, not another archive format. Step 3 semantic identity now has a preview-line contract:

1. Outcome axes and explicit digest availability have landed in the library and `sealr.receipt.v2`. The inspectable `View` still serializes the compatibility verdict.
2. `SourceSnapshot` names the current owned and caller-borrowed in-memory bytes. Parse, payload reads, and digest recording use that one object.
3. A versioned `sealr.archive-ir.v1` is built once from that snapshot after path admission. Inspect and materialize consume the same IR; they do not reparse the archive.
4. Constructor `Policy` compiles into typed supported controls before source ingestion. Ratio checks use integer arithmetic. Security counters use checked addition. Reserved policy fields fail closed instead of appearing enforced.
5. Distinct source, interpretation, layout, and content-tree identities are recorded on the receipt. `sealrTreeV1` is a domain-separated binary encoding over the IR. `view_digest` remains invocation evidence.

Cross-platform golden ZIP fixtures now pin the preview encodings. The remaining Step 3 work is to replace ignored extra fields with an explicit allowlist under a new profile identifier. The compatibility verdict remains for the preview line; the independent axes and CLI exit `3` are authoritative when a destination effect fails. That identity is what a wheel consumer would reuse.

In parallel, the materializer now refuses intra-call directory-component replacement and staged-content mutation, and audits the staged tree against the admitted IR before publication. Repeated hostile races and the independent supervisor audit remain Step 2/4 work. Those tests strengthen the shipped capability boundary without creating a competing semantic representation.

The supervised Linux worker follows that contract because its bounded protocol and the supervisor's final staged-tree audit need the same canonical tree and manifest. The supervisor will own the destination parent, private stage, publication, and cleanup; the worker will receive only the archive snapshot and stage capabilities and install Landlock before reading the first archive byte. Linux is the first enforced worker platform, while macOS and Windows must remain natively green and report isolation honestly until their worker boundaries are implemented.

Authenticated abandoned-stage recovery follows the worker because recovery must be owned by the final supervisor lifecycle. Landlock limits the worker's ambient authority; it does not contain another process running as the same user. A distinct service identity or equivalent mandatory-access-control boundary would be required to bring that actor into scope.

Canonical CP437 and Unicode collision semantics, snapshot-backed bounded random access, fuzz and property suites, small-core proofs, compatibility measurement, an independent evidence verifier, and performance gates based on avoided parsing, decompression, and writes complete Phase 0.1. After that gate, common ZIP codec adapters (Zstd, XZ/LZMA, BZip2, Deflate64) land on the same boundary with exact input consumption and no extra extractor. Python wheel admission can proceed on Store and Deflate. TAR begins only when it can reuse those adapters. None of this is a claim of current support.

The exact active queue, implementation order, and exit criteria are in [ROADMAP.md](ROADMAP.md#active-execution-queue).

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
| [docs/usefulness.md](docs/usefulness.md) | Admission-boundary test: one tree, one consumer that does not reparse |
| [docs/semantic-model.md](docs/semantic-model.md) | Current semantics and target admitted-tree model |
| [docs/theory.md](docs/theory.md) | Research notes: unique covering, partial interpretation, named conjectures |
| [docs/api.md](docs/api.md) | Current alpha.3 contract and target API direction |
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
| [docs/release-verification.md](docs/release-verification.md) | Runnable checks for the current immutable prerelease |
| [docs/tooling.md](docs/tooling.md) | Cross-platform repository tooling and runtime dependency discipline |

## License

[Apache-2.0](LICENSE). Native release archives also include a target-specific `THIRD_PARTY_LICENSES.txt` generated and verified from the locked dependency graph.
