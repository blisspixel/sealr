# sealr

[![CI](https://github.com/blisspixel/sealr/actions/workflows/ci.yml/badge.svg)](https://github.com/blisspixel/sealr/actions/workflows/ci.yml)

> **Goal: one archive, one tree, and evidence for the decision.**

sealr is an early attempt to make archive ingestion easier to reason about. The released Alpha.5 boundary implements a deliberately narrow ZIP32 path: it builds one versioned interpretation from an immutable source snapshot, verifies accepted members, and either publishes the requested tree without replacement or publishes no destination. Checked random access serves interpretation and verification, path inputs are copied once into a Sealr-owned private file, native source-change and resource gates exercise that boundary, and a bounded capability-oriented worker protocol prepares the next process boundary. Sealr does not yet provide a process sandbox or production security claim.

```text
Untrusted archive x policy
  -> (Allowed { wrote } | Rejected) x receipt x inspectable view
```

The longer-term aim is an archive-to-tree admission boundary whose decision and evidence can be reused by other systems. The current release is a small step toward that aim, not proof that the category or design is finished. Usefulness is not “more unzip.” It is: same bytes and policy produce one tree or no tree on Linux, macOS, and Windows, and the next tool consumes that tree instead of opening the ZIP again. Until a dependent does that, a receipt is just a receipt. The [usefulness test](docs/usefulness.md) is the quality bar.

> Status: `v0.1.0-alpha.5` is the fifth development preview of the ZIP boundary. It is useful for evaluation, development, and adversarial testing. It is not ready to protect a production host from arbitrary hostile archives. The limitations below are security boundaries, not fine print.

> Release contents: Alpha.5 adds checked random access, a private file-backed path snapshot, native mutation controls, bounded-memory evidence, a three-platform 3 GiB sparse gate, and the bounded worker-protocol codec with pinned fuzz evidence. The [Alpha.5 release notes](docs/releases/v0.1.0-alpha.5.md) define the shipped delta and remaining limitations.

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

## Released Alpha.5 boundary

The released Alpha.5 Rust implementation supports classic ZIP32 archives with stored or Deflate members.

- CD-first parsing with exact EOCD, central-directory, local-header, and data-descriptor agreement.
- Rejection of hidden stream records, unreferenced layout bytes, overlapping records, spanned archives, ZIP64, traditional or strong encryption indicators, masked headers, unsupported methods, and mismatched flags or metadata.
- Pure lexical path jailing for absolute paths, parent traversal, ADS colons, reserved Windows names, trailing dots and spaces, control characters, empty components, depth, duplicates, case-fold collisions, and file/directory topology conflicts.
- Strict filename handling. Invalid UTF-8 and non-ASCII CP437 names are rejected until the canonical Unicode path design is complete.
- An opt-in [strict ASCII ZIP32 v2 profile](docs/profiles/zip-strict-ascii-v2.md) with an exhaustive 16-bit flag table and an all-extra-fields-denied rule. `apply()` preserves v1 compatibility; `apply_with_options` records the selected profile in IR and receipt identity.
- Bounded source reads, metadata, file count, declared and actual member size, total expanded size, and declared and actual compression ratio.
- Checked `u64` snapshot access for magic detection, ZIP discovery, local and central metadata, covering audit, and payload verification. Path inputs are opened once, copied and hashed through a fixed 64 KiB buffer into a random private directory, reopened read-only, unlinked before ingest returns, and then served with positional reads. Caller byte slices remain memory-backed. Structural scratch reads are fixed-size or metadata-capped, and compressed member ranges stream through fixed 64 KiB buffers.
- Streaming Deflate, exact compressed-input consumption, CRC32, and SHA-256 calculation without buffering an expanded member in memory. The staged-tree audit also hashes through a fixed 64 KiB buffer. Trailing bytes and concatenated raw DEFLATE streams inside one declared member payload are rejected.
- Component-bound, same-volume staging with 128-bit random names. Every member component is opened no-follow from a retained directory handle, files use create-new handles, and the requested destination is published with native no-replace semantics only after every member passes.
- Deterministic JSON view and versioned unsigned receipt on allow and reject paths. Receipts record the materializer backend, stage mode, stage-creation primitive, component-resolution guarantee, durability, publication primitive, outcome, and cleanup state.
- Fully verified admitted outcomes expose an opaque `VerifiedArchive`. Callers may use `apply_with_options` to select a small exact-path set for independently capped retention during the original verification pass. Retained bytes can be borrowed without another parse, inflation, allocation, or hash; unretained reads remain caller-bounded and revalidate size, CRC32, and SHA-256 from the recorded payload range. See the [API contract](docs/api.md#bounded-one-pass-retention).
- A pinned 5,927-file, 14-class ZipDiff construction gate with a deterministically generated aggregate corpus digest, exact finding-count expectations, and an explicit 73-file control allowlist.
- An adversarial unit suite, an external-crate API fixture, a separate consumer that runs against the extracted packaged crate, strict Clippy, rustfmt, documentation checks, cross-platform tests, and cargo-deny policy in CI.
- A versioned four-case identity-conformance bundle with two exact profile vectors, checked by both the production API and a standalone workspace verifier that has no dependency on the Sealr crate. It hashes exact source and profile bytes, checks the claimed covering without searching or inflating, and independently reproduces three layout and three content roots.
- A non-shipping, byte-addressed [20-wheel compatibility pilot](docs/wheel-compatibility-pilot.md) analyzed only through Sealr's public API under strict ASCII v2. The profile admits 19 artifacts; one SciPy wheel is denied by three per-member `quota.ratio` findings. The sample is judgmental evidence, not a PyPI-wide compatibility claim or supported wheel admission.
- A non-published, zero-dependency [bounded worker protocol v1](docs/worker-protocol.md). Its 4 MiB control-frame limit, fixed start frame, out-of-band capability slots, correlated result state, canonical manifest, fallible decoder, request-bound profile and resource validation, adversarial regressions, and pinned libFuzzer target prepare later worker transport without embedding archive bytes in IPC.

## Repository-only evidence on current main

The following Alpha.6 work is implemented and tested in the repository, but it is dormant, non-shipping, and absent from the Alpha.5 release surface.

- A repository-only [Linux authority-bootstrap conformance lab](docs/sandbox.md#current-bootstrap-evidence). It proves descriptor closure, raw validation of every returned ancillary header, runtime-probed Landlock and architecture-checked seccomp setup before source transfer, direct no-descendant and stage-permission-mutation denial, bounded failure handling, reap, and checked cleanup. The lab interprets no archive and is not included in native release archives.
- A dormant crate-private [split-phase semantic-record experiment](docs/semantic-record.md). Its bounded records bind the complete invocation and represented ZIP evidence back to the supervisor-owned snapshot and reconstruct accepted completion IR exactly once. The immutable 12-case v1 baseline and 12 additive v2 cases pin 24 named observations; every v2 case declares its apply, backend, or supervisor-reproduction oracle. Ordinary `apply` and the in-crate conformance harness consume one production-compiled owning plan result, while `apply` never encodes, decodes, or executes a semantic record. The repository-only Linux bridge consumes validated plans without structural ZIP parsing, transfers immutable original-pass retained bytes, and now performs caller-bounded non-retained Store and Deflate reads through a fresh restricted worker per call. The supervisor reserves the exact verified size before spawn and returns no bytes until it has observed exact EOF, a correlated result, matching size, CRC32, and SHA-256, clean exit, and reap. Required 64-bit Linux, macOS, and Windows CI measures completion reconstruction near the private 64 MiB record limit. The record and worker paths remain absent from the default library, CLI, public protocol, and every shipped invocation. See the detailed [shadow evidence](docs/semantic-record.md#differential-shadow-artifacts), [isolated-read evidence](docs/semantic-record.md#one-shot-isolated-member-read), and [heap limits](docs/semantic-record.md#near-limit-completion-heap-evidence).

## Security limitations

The following work must land before a production-readiness claim:

- The ZipDiff gate covers its pinned known constructions. It does not prove that future or previously unknown parser ambiguities cannot exist.
- Path inputs no longer allocate a whole-archive byte buffer. The required resource probe applies physically sparse valid 1 MiB and 128 MiB ZIPs in isolated child processes, caps tracked heap allocation at 8 MiB and its size-related delta at 1 MiB, and caps peak resident memory at 256 MiB and its delta at 64 MiB. The latest Windows run measured 210,367 tracked heap bytes for both inputs and about 7.3 MiB peak resident memory for each. A separate 3 GiB sparse gate passed locally with 131,072 allocated source bytes and 210,427 tracked heap bytes and runs through the [monthly native resource workflow](.github/workflows/resource-evidence.yml) on Linux, macOS, and Windows. These are bounded regression measurements, not universal memory proofs. `Source::Bytes` necessarily remains backed by caller memory and is copied once if a returned `VerifiedArchive` must outlive the borrow. The default source cap remains 512 MiB.
- A path snapshot uses a random `.sealr-source-*` directory in the system temporary directory. Linux and macOS require a safe sticky or non-writable parent and verify a mode-`0700`, effective-user-owned directory; macOS also rejects an extended ACL. Windows requires local writable NTFS with persistent ACLs and verifies a protected effective-TokenUser-only DACL. Windows denies write sharing while the caller source is copied. Unix compares the opened file's device, inode, mode, length, mtime, and ctime before and after copying; a change fails closed. Sealr removes the spool filename after opening its read-only handle, so successful ingest exposes no persistent pathname to the bytes. Normal drop removes the now-empty directory. Abrupt termination during construction can leave a protected directory and partial spool; termination after successful ingest or a later cleanup failure can leave an empty random directory. Privileged actors and same-principal access to private construction artifacts remain outside this in-process privacy boundary.
- Unicode normalization and CP437 decoding are not implemented, so non-ASCII member paths fail closed.
- Materialization is supported only on Linux, macOS, and Windows; other targets fail closed. On Linux and macOS, sealr accepts only an existing parent owned by the effective user or root that is not externally writable unless sticky semantics protect entries. macOS also requires extended ACLs to be absent. Filesystems that do not enforce these namespace rules are outside this preview's support boundary.
- Windows materialization is limited to a non-remote, writable NTFS parent that reports persistent ACL support. ReFS, FAT-family filesystems, remote shares, read-only volumes, and ambiguous volume queries fail closed.
- Windows atomically creates and retains the stage with `NtCreateFile`, installing a security descriptor whose object owner is the effective token user and whose protected DACL contains one inheritable allow ACE for that SID. The descriptor is verified through the returned handle before any member write. Descendants inherit that sole-principal DACL but receive the creating token's default owner; a principal matching that owner SID can change a descendant DACL and is outside the in-process containment promise. Publication uses `NtSetInformationFile` with the retained stage and parent handles. The native adapters are isolated, tested on 64-bit Windows, and compile-checked for the 32-bit Windows ABI.
- Repeated hostile concurrent mutation stress remains unfinished. Static Unix symlink refusal, Windows generic reparse-point refusal, private-DACL inheritance, and deterministic stage-substitution resistance are covered. A reduced-authority worker will limit a compromised parser's ambient authority, but other processes running as the same user remain outside the containment claim.
- Normal rejection attempts stage cleanup and retries once after failure, then records `removed` or `failed` in the receipt. Setup failure after stage creation uses the retained stage handle first and a parent-relative retry. A killed process or two cleanup failures can leave a hidden staging directory.
- The default durability mode is `flush-only`. Setting the Rust policy field `atomic: true` syncs completed member files, but directory syncing, crash recovery, and power-loss durability are not implemented.
- The shipped library and CLI do not use Landlock, seccomp, AppContainer, or another process sandbox. Receipts report `kernel_jail: unavailable`. The repository-only Linux lab tests a narrow Landlock, seccomp, descriptor, semantic execution, reaped-writer, and exact stage-audit boundary. It still does not isolate the structural parser, provide a general network or IPC confinement claim, or establish production containment.
- Worker protocol v1 is a codec and authority contract, not a worker. It cannot synthesize the public `Outcome`, complete `ArchiveIR`, or `VerifiedArchive`, and its result does not echo the source or policy digest. The request-bound validator checks every returned constraint the v1 result can represent, but does not create complete invocation binding. The current parser still runs in process. Alpha.5's clean AddressSanitizer campaign is bounded heuristic evidence and does not prove decoder safety or process containment.
- The private semantic-record experiment has an immutable 12-case v1 baseline, 12 additive v2 cases with explicit oracle ownership, and a near-limit requested-heap measurement for completion reconstruction. The shadow and heap evidence remains a bounded fixture projection and excludes planning memory, RSS, allocator internals, the near-ceiling retained-transfer and isolated-read resource envelopes, and public runtime-worker behavior. It does not establish broad profile or policy parity, decoder safety, or a production containment claim. Record binding and canonical decode alone do not prove that payload verification ran: a correlated completion can carry an arbitrary non-directory content digest. The Linux repository lab therefore treats the decoded completion as an untrusted proposal, replays the accepted plan against the supervisor's retained exact source descriptor after worker reap, and requires byte-for-byte canonical agreement before accepting content evidence. A forged canonical digest regression proves the distinction. A separate canonical sealed bundle transfers supervisor-selected Store and Deflate bytes captured during the worker's original verification pass. Later non-retained reads use a different one-shot capability: the worker receives no stage or destination, and the supervisor releases no partial bytes on cancellation, crash, protocol failure, integrity failure, or unclean exit. The private materialize route gives the worker only a supervisor-created stage root, requires clean exit and reap before replay and exact stage audit, and leaves publication to the supervisor. None of this shapes public `Outcome` or `VerifiedArchive` state. The experiment does not construct `VerifiedArchive`, launch a public worker mode, change `kernel_jail`, isolate structural parsing, prove every cancellation epoch, or prove that the worker record is the source's unique structural meaning.
- When the complete source bytes are held, the receipt records their SHA-256. A failure before a complete snapshot is available records `{ "status": "unavailable" }` instead of a digest. Receipts also carry separate interpretation, admission, verification, effect, and view-completeness axes; the alpha.2 `Allowed`/`Rejected` shape remains a compatibility adapter and still maps an admitted archive with a failed destination to `Rejected`.
- Receipts are unsigned, and their JSON digest is deterministic for the current Rust structs but is not yet RFC 8785 JCS.
- The inspectable `View` remains invocation evidence. Its digest covers verdict, write state, findings, and members. Receipts now also carry separate `sealrTreeV1` layout and content-tree identities derived from `ArchiveIR`. Those roots are unsigned, preview-line encodings; they are not yet a lock, an authenticated subject, or a claim that every extra-field payload is semantic. Materialization failures still map into the end-to-end `Rejected` verdict.
- The independent identity verifier establishes internal consistency for the finite committed vectors. It does not run a second ZIP interpretation, execute codecs, recompute member hashes from compressed payloads, prove SHA-256, authenticate evidence, or establish correctness outside those cases.
- ZIP64, TAR, compressed TAR, gzip, zstd, and 7z are not implemented.
- There is no external security audit or stable production-supported release.

See [SECURITY.md](SECURITY.md), [the threat model](docs/threat-model.md), and [the invariants](docs/invariants.md) before integrating the crate.

## Try it

The repository pins Rust 1.98.0 in `rust-toolchain.toml`; rustup selects it automatically.

The crate's current minimum supported Rust version is 1.98, declared through `rust-version`. CI selects exactly 1.98.0. Preview releases may raise this minimum only as a documented compatibility change; patch releases within a stable 1.x line will not.

Download the native preview archives, `SHA256SUMS`, and provenance from the [`v0.1.0-alpha.5` release](https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.5). Runnable checksum and provenance commands are in [release verification](docs/release-verification.md). To build from source:

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

The CLI exits `0` only when the archive is admitted and completely verified without an effect failure, `2` when admission or verification does not complete successfully, and `3` when admission succeeds but a requested destination effect fails. The inspectable view now includes the same interpretation, admission, verification, effect, and completeness axes as the receipt. The compatibility `verdict` maps incomplete verification and an admitted archive with a failed destination to `rejected`. Operational command-line errors use the normal Clap exit behavior.

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

The semantic walkthrough is enforced by CLI integration tests on the native platform jobs. The PNGs are rendered terminal-style summaries derived from Alpha.5's separate JSON view and receipt streams; they are not literal captures of raw CLI output or the planned human interface. The visible summary intentionally uses the stable decision, finding, and member subset. CI regenerates the fixtures, native transcript variant, and HTML, checks fixture and platform-specific transcript SHA-256 values against the committed asset manifest, then verifies every PNG's SHA-256, dimensions, format, size, density, and metadata policy. CI does not claim a pixel comparison.

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

The next milestone remains the Phase 0.1 ZIP trust gate, not another archive format. Alpha.4 closed the measured semantic and adopter-facing contract, and Alpha.5 closed bounded immutable input. The Alpha.6 repository-only Linux lab removes unrelated inherited authority, validates an optional synthetic stage, installs `no_new_privs`, fixed Landlock ABI 3 handling, and an x86_64 seccomp deny set, then reports readiness before receiving the deterministic ZIP snapshot. Direct probes prove process creation, execution, namespace, permission, ownership, xattr, and `ioctl` denial. This establishes a narrow pre-parser confinement order without forcing the reduced protocol v1 manifest into the public API or changing shipped execution.

The landed [private semantic-record assurance](docs/semantic-record.md) now includes an immutable 12-case v1 baseline, 12 additive v2 cases with explicit apply, backend, and supervisor-reproduction oracles, an in-process plan-native inspect executor, a shared owning plan seam, and a required near-limit completion heap probe. The Linux bootstrap has closed no-descendant and permission-mutation authority before source transfer, parses every raw ancillary header while closing all installed descriptors on rejection, and enforces supervisor-owned absolute monotonic deadlines across every authority round. Eleven deterministic stalls prove pidfd kill, reap, and cleanup ordering from pre-bootstrap receive through post-ack exit, including sealed-plan receipt and acceptance. A required 500-iteration Linux campaign repeats the complete non-stall case matrix while checking child reap, supervisor descriptor stability, retained source and outside-sentinel integrity, and checked cleanup after every iteration. Bounded `SLRBLOB1` memfds carry the canonical semantic plan, completion, and retained-content bundle for a deterministic Store-and-Deflate inspect fixture. The restricted worker binds the plan to the exact file-backed snapshot, invokes no structural parser during execution, reads only planned payload ranges, and captures both selected members during that verification pass. After worker exit and reap, the supervisor treats both sealed outputs as untrusted plan-bound proposals, independently replays the accepted plan against its retained exact source descriptor, and requires byte-for-byte canonical agreement. A separate private one-shot read boundary gives each caller-bounded non-retained read a fresh operation and restricted worker, transfers no stage or destination authority, and withholds bytes until exact output, correlated success, integrity, clean exit, and reap all agree. Tests cover clone serialization, pre-spawn, queued, and active cancellation, post-result crash isolation, next-call recovery, 64 alternating Store and Deflate reads, and last-owner cleanup. A private materializing path now gives the restricted worker only the supervisor-created stage root and sealed plan, closes writer authority on exit, requires exact reap before result validation, replays the retained source, audits the exact stage, and leaves no-replace publication solely to the supervisor. Targeted writer faults and 500 repeated writer lifecycles cover post-reap mutation, destination races, cleanup failure, crash, reap, and descriptor stability. The next dependency is an authenticated child-only Linux helper artifact with explicit verified discovery and package placement. Public outcome and capability integration, materialization retention parity, and real-kernel setup-failure evidence follow on that stable process boundary. No public worker mode or protocol v2 exists yet.

Assurance now advances with each increment rather than waiting for a late phase. The non-shipping wheel laboratory has published its first small compatibility measurement and now expands toward wheel-aware semantic evaluation, while supported `python-wheel.v1` admission remains gated on its exact UTF-8 ZIP profile, canonical paths, use of the bounded retention capability, consumer budgets, and identities.

See the [near-term execution plan](docs/near-term.md) for release-sized work and acceptance gates, the [identity-conformance contract](docs/identity-conformance.md) for the independent root checks, the [wheel pilot report](docs/wheel-compatibility-pilot.md) for the bounded measurement, the [roadmap](ROADMAP.md) for the full trust gate, and the [wheel profile draft](docs/profiles/python-wheel-v1.md) for the first-consumer design. No wheel evaluator or supported consumer profile exists yet.

## Research basis

- [My ZIP isn't your ZIP, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [ZipDiff artifact and construction generator](https://github.com/ouuan/ZipDiff)
- [`uv` ZIP archive confusion advisory](https://github.com/advisories/GHSA-8qf3-x8v5-2pj8)
- [PyPI response to wheel archive confusion attacks](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [2026 Python wheel parser differential advisory](https://github.com/google/security-research/security/advisories/GHSA-w97x-xxj5-gpjx)
- [Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [cap-std capability-oriented filesystem API](https://github.com/bytecodealliance/cap-std)
- [Kani Rust Verifier](https://model-checking.github.io/kani/)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)

## Documentation

| Document | Purpose |
|---|---|
| [Documentation index](docs/index.md) | Guided map of current contracts, security material, plans, and operations |
| [Near-term execution plan](docs/near-term.md) | Alpha.4 through Alpha.6 work packages and measurable gates |
| [Identity conformance](docs/identity-conformance.md) | Independent profile, covering, and tree-root vectors with exact nonclaims |
| [Private semantic record](docs/semantic-record.md) | Dormant Alpha.6 planning/completion codec, inspect executor, validation rules, evidence, and remaining gates |
| [Roadmap](ROADMAP.md) | Full capability order, release gate, and non-goals |
| [Safety specification](docs/safety.md) | Normative safety rules and supported boundary |
| [API contract](docs/api.md) | Current Alpha.5 Rust and JSON surface |
| [Release verification](docs/release-verification.md) | Checksums, provenance, tag, and immutable release verification |

## License

[Apache-2.0](LICENSE). Native release archives also include a target-specific `THIRD_PARTY_LICENSES.txt` generated and verified from the locked dependency graph.
