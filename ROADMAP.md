# Roadmap

Updated 2026-08-20.

sealr's product is the boundary:

```text
UntrustedArchive x Policy
  -> (Materialization | Rejection) x Receipt x InspectableView
```

## Executive decision

The next milestone is **Phase 0.1: the ZIP trust gate**.

Do not add TAR, 7z, MCP, Python, GPU, or signing first. The current implementation has the right contract, a credible ZIP32 parser, an executable ZipDiff gate, and component-bound output. The strongest claims still depend on reduced-authority filesystem isolation, canonical Unicode paths, bounded random-access input, and layered adversarial assurance.

This order matters because format breadth multiplies every unresolved parser, path, resource, and materialization mistake. Closing one format exceptionally well gives later formats a real boundary to reuse.

## Current baseline

The repository now has:

- a Rust workspace with `sealr` and `sealr-cli`;
- one `apply()` operation returning verdict, view, and receipt;
- classic ZIP32 Store and Deflate support;
- CD-first structure agreement across EOCD, CDH, LFH, and data descriptors;
- exact local-record layout with hidden bytes, gaps, prefixes, and overlap rejected;
- bounded archive reads and streaming expanded-byte enforcement;
- staged materialization that publishes only after all members pass;
- component-bound no-follow member writes, random same-volume staging, create-new files, and native no-replace publication on Linux, macOS, and Windows;
- versioned materialization receipts that report the backend, stage mode, stage-creation primitive, component resolution, durability, platform publication primitive, outcome, and cleanup state;
- fail-closed ASCII path handling and topology-collision checks;
- a pinned, aggregate-digested gate over all 5,927 upstream ZipDiff constructions, with exact finding counts and an explicit valid-control allowlist;
- adversarial tests for traversal, ADS, ambiguity, layout, CRC rollback, destination preservation, and quota behavior;
- a pinned current Rust toolchain plus strict format, Clippy, debug test, optimized build, cross-platform release test, docs, and supply-chain CI gates;
- dependency update automation and an explicit permissive-license policy;
- protected `main` requiring pull requests, linear history, resolved conversations, and every CI job.

This is a strong pre-alpha baseline. It is not a production security boundary yet.

## Phase 0.1: ZIP trust gate

Target: a single-format boundary whose claims are backed by fixtures, properties, fuzzing, capability-based output, reduced process authority, and measurable performance.

### 1. Make the ZipDiff corpus executable: complete locally

Completed 2026-08-20:

1. The CI job fetches revision `7c427ed254bb3a5985d54870c12f97db78118e67` and generates all 5,927 construction files. Generated binaries are not committed.
2. The manifest records origin, revision, license, an aggregate SHA-256 binding every fixture path and digest, exact class and finding counts, and the exact valid-control allowlist. A committed patch replaces the upstream generator's current-time DOS header defaults with zero only after its exact revision is verified, making the byte corpus reproducible across runs and operating systems.
3. The production API classifies the corpus. Any new acceptance, rejected control, finding-count drift, missing file, byte change, or upstream construction change fails the gate.
4. All A3, A5, B1, B3, B4, C1, C2, C3, C4, and C5 constructions reject. A4 retains only its valid empty-directory control. A2 retains ten internally consistent controls. B2 retains 62 portable punctuation controls.
5. Local deterministic tests cover valid directories and descriptors plus the ambiguity gaps found during corpus evaluation.

Why it was first: the USENIX study found 14 ambiguity types across 50 parsers, and its artifact provides constructors. Running those bytes exposed real gaps in Unicode Path extras, directory attributes, hidden ZIP64 structures, stored-descriptor record positioning, backslashes, and ASCII DEL handling.

Evidence:

- [expectation manifest](tests/corpus/zipdiff/expectations.txt);
- [gate documentation](tests/corpus/zipdiff/README.md);
- `classify_zipdiff` production-API classifier;
- dedicated `ZipDiff 14-class gate` CI job;
- no external parser is part of the library or extraction runtime.

### 2. Put every destination operation behind a directory capability: in progress

Completed 2026-08-20:

- The private materializer is factored out of `apply` behind one narrow component-based boundary.
- All archive-derived member paths are passed as canonical relative components to a `cap-std` stage handle. Each component is created or opened separately with no-follow semantics from a retained directory capability.
- Stage names use 128 bits from the operating-system random source. Unix stages are created with mode `0700`.
- The destination parent must already exist. Linux accepts only trusted-owner parents protected by mode or sticky rename semantics. Apple platforms additionally reject extended ACLs through a retained descriptor query.
- Windows atomically creates and retains the stage with parent-relative `NtCreateFile`, preventing a discovered name from being replaced between creation and handle acquisition.
- Member files use no-follow, create-new handles. Windows validates the generic reparse-point attribute on opened directory and file handles rather than recognizing only ordinary symbolic links.
- Normal rejection attempts explicit stage cleanup twice before constructing the receipt. Receipts distinguish not-started, setup-failed, staged, aborted, publication-failed, and committed outcomes, including final cleanup success or failure.
- Final publication uses `RENAME_NOREPLACE` on Linux, `RENAME_EXCL` on Apple platforms, and `NtSetInformationFile` with the retained source and parent handles on Windows. All three are no-replace operations.
- Unsupported publication platforms fail closed instead of using a check-then-rename fallback.
- Deterministic tests preserve a destination that appears after staging, refuse parent and leaf symlinks, reject non-component input and non-directory parents, preserve outside bytes, verify explicit cleanup, and require inspect and materialize member equality.

Remaining deliverables:

1. Install an explicit owner-private Windows stage ACL and define the exact local-filesystem support matrix for NTFS, ReFS, and remote shares.
2. Add repeated Linux symlink-swap and Windows junction or reparse-point mutation tests, plus deterministic injected-race seams where scheduler timing would otherwise make failures flaky.
3. Move parsing and materialization into a reduced-authority worker so same-principal processes do not inherit the caller's full ambient filesystem authority.
4. Detect abandoned stage directories safely using an authenticated ownership marker and age policy, without deleting unrelated or attacker-created lookalike paths.
5. Expand deterministic commit fault injection and golden receipt fixtures across Linux, Apple, and Windows. Cleanup retry-success and terminal-failure injection are already covered.
6. Define directory syncing and power-loss durability separately from normal transactional rollback.

Why this remains next: archive-controlled names now cross a component-bound no-follow materializer, and Windows stage creation and publication retain object identity. The remaining filesystem risk is authority, not ordinary path traversal: any principal granted child-mutation rights by the inherited parent DACL can modify staged content, same-principal processes share the caller's authority, and an interrupted process can leave a stage behind. Private stage authority, a constrained worker, repeated race evidence, and safe recovery close that narrower claim before the project expands accepted names or formats.

Exit proof:

- archive-controlled strings never reach ambient filesystem open functions;
- each archive-derived component is opened no-follow from a retained directory handle;
- reject returns without a published destination;
- existing destinations are preserved byte-for-byte;
- symlink and reparse-point race tests cannot redirect a write;
- Windows stage creation and publication remain bound to the retained objects under deterministic substitution attempts;
- receipts report the actual platform publication primitive and every post-stage cleanup outcome;
- crash-recovery behavior is documented and tested separately from normal rollback.

### 3. Define one canonical member-name representation

Deliverables:

1. Preserve raw ZIP filename bytes through structure comparison.
2. Decode general-purpose bit 11 names as strict UTF-8 and legacy names as CP437.
3. Produce one `CanonicalPath` containing display text, normalized components, and a destination comparison key.
4. Decide and document Unicode normalization with test vectors. Do not choose compatibility normalization casually.
5. Model Windows reserved names, trailing-dot behavior, ADS, separators, case folding, and reparse-sensitive names explicitly.
6. Reject collisions before decompression or output.
7. Put path byte length, component length, and depth in policy.

Why third: rejecting all non-ASCII paths is safe but not useful enough to ship. Lossy decoding is unacceptable because distinct hostile byte strings can collapse to one path. The canonical representation must be shared by inspect, materialize, fixtures, fuzzing, and future format adapters.

Exit proof:

- no lossy filename decoding exists in the decision path;
- inspect and materialize use the same canonical object;
- a platform matrix covers ASCII, CP437, UTF-8, normalization, case, and reserved-name collisions;
- each rejected collision has one stable finding code.

### 4. Remove whole-archive buffering

Deliverables:

1. Replace `Vec<u8>` parser ownership with a bounded seekable source abstraction.
2. Parse EOCD and the central directory through checked random-access reads.
3. Stream the source digest once without trusting file size or allowing unbounded allocation.
4. Keep all offset arithmetic in checked `u64`, with explicit conversion at I/O boundaries.
5. Add mutation tests for truncation and growth while the source handle is open.
6. Consider mmap only behind a size and file-stability gate after the ordinary file path is correct.

Why fourth: expanded members already stream, but the archive blob is buffered up to 512 MiB. A security boundary must bound both compressed and expanded memory. CD-first parsing needs seekability, not whole-file ownership.

Exit proof:

- resident memory is bounded independently of archive size;
- a multi-gigabyte sparse valid fixture can be inspected without a multi-gigabyte allocation;
- truncation and growth produce structured rejection, never panic or stale reads.

### 5. Add layered adversarial assurance

Current foothold: the deterministic unit suite now drives the public `apply()` boundary over every truncation of a valid ZIP, three mutations at every byte position, and deterministic noise inputs from 0 through 1,024 bytes, asserting that none panic. This is a fast regression gate, not a substitute for coverage-guided fuzzing or semantic property tests.

Deliverables:

1. Add property tests for canonical path containment, topology conflicts, and monotonic quota counters.
2. Add `cargo-fuzz` targets for ZIP parsing, canonical names, and inspect-only `apply()`.
3. Seed fuzz targets with the ZipDiff and local adversarial corpus.
4. Assert no panic, bounded output, deterministic verdict, and receipt presence.
5. Add Kani harnesses for the pure path and quota core only.
6. Run fast deterministic gates on every change. Add longer scheduled fuzzing only after runtime and cost are measured.
7. Keep unsafe code out of the parser, jail, and quota core. Isolate unavoidable operating-system calls in small platform modules with explicit reviewed invariants.

Why fifth: unit tests lock known attacks, fuzzing searches byte-level state space, property tests cover semantic classes, and Kani proves bounded properties. None replaces the others. Kani's own guidance makes small proof harnesses the right unit, while the Rust Fuzz Book makes byte-slice parser targets straightforward.

Exit proof:

- every invariant has at least one deterministic test;
- the three fuzz targets run locally from a documented seed corpus;
- Kani proves bounded path and counter properties without verifying codecs;
- zero unsafe blocks exist in the trusted core, or each exception has a reviewed invariant.

### 6. Start the parser in reduced authority

Deliverables:

1. Create a process-owned worker path. A library call must not unexpectedly sandbox its caller.
2. Open or receive only the archive and destination capabilities needed for the request.
3. Apply Landlock before reading the first archive header on Linux.
4. Add seccomp only after the syscall surface is measured.
5. Record the detected Landlock ABI and actual enforced rights in the receipt.
6. Treat unavailable isolation as explicit degraded mode.
7. Design the AppContainer worker boundary for Windows without blocking the Linux gate.

Why sixth: the Linux kernel describes Landlock as an unprivileged, stackable restriction on ambient rights. It reduces the impact of parser or materializer defects, but it cannot replace userspace correctness. Process ownership also avoids mutating the authority of arbitrary library callers.

Exit proof:

- the Linux worker cannot read or write outside its granted archive and destination set;
- the restriction is active before any format byte is interpreted;
- the receipt accurately distinguishes enforced and unavailable isolation;
- userspace invariant tests still pass with isolation disabled in the test harness.

### 7. Stabilize receipts and measure the boundary

Deliverables:

1. Canonicalize policy and view JSON with RFC 8785 JCS before hashing.
2. Version the policy, view, receipt, and finding registry with compatibility tests.
3. Add receipt fields for isolation and degraded conditions. Materializer backend and stage-cleanup evidence are already versioned in the current receipt.
4. Benchmark inspect and materialize against representative valid ZIPs.
5. Compare tree and content results with established parsers only for well-formed inputs.
6. Publish CPU time, peak memory, allocations, and output throughput, not one headline number.
7. Define the performance budget before optimization.

Why seventh: cryptographic receipts need canonical bytes, and performance work needs a correct workload. Measuring earlier would optimize an implementation whose I/O and name model are still changing.

Exit proof:

- equivalent policy objects hash identically;
- golden receipts are stable across Linux, macOS, and Windows except documented environment fields;
- well-formed fixtures produce identical inspect and materialize trees;
- the baseline and accepted regression budget are checked into the repository.

## Phase 0.1 release gate

Phase 0.1 is complete only when every row is green.

| Gate | Required evidence |
|---|---|
| One ZIP interpretation | Complete: 14-class ZipDiff manifest and passing 5,927-file fixture suite in public CI. |
| Path containment | Canonical-path properties plus capability-writer race tests |
| Resource bounds | Source, metadata, member, total, ratio, and counter tests |
| Reject rollback | No published destination on content, I/O, or policy failure |
| Inspect equals materialize | Golden tree and digest comparisons |
| Reduced authority | Landlock worker test and receipt field |
| Assurance | Unit, property, fuzz smoke, Kani, Clippy, rustfmt, docs, cargo-deny |
| Portability | Current baseline complete: Linux, macOS, and Windows CI green |
| Performance | Reproducible baseline with memory and throughput budgets |
| Honesty | README limitations match executable behavior |

## Phase 0.2: TAR without weakening the gate

Only after Phase 0.1:

- TAR, PAX, and GNU long-name parsing through the same canonical path and quota core;
- gzip and zstd wrappers with bounded window and metadata policy;
- default denial of symlinks, hardlinks, devices, sparse surprises, and unsafe modes;
- TAR checksum, duplicate path, extension-header, and truncation fixtures;
- the same capability materializer, receipt schema, isolation worker, and fuzz expectations.

Done when ZIP and TAR are format adapters around one tested boundary rather than separate extractors.

## Phase 1: consumer surfaces

- PyO3 bindings over `apply()`;
- C ABI with ownership and error-lifetime tests;
- JSONL CLI mode for streaming consumers;
- an agent-facing tool or MCP surface that returns view and receipt, with destination optional;
- Sigstore keyless signing after the unsigned receipt is stable;
- native 7z only if it can use the same jail and materializer. No shelling out to `7z x`.

Done when one external consumer receives the same findings and view as the Rust API.

## Phase 2: ecosystem and audit

- CycloneDX member inventory;
- WASM or napi-rs only for a real consumer;
- continuous public fuzzing;
- external security audit after the core surface freezes;
- one package-manager or agent-runtime integration;
- signed release artifacts and reproducible release metadata.

## Phase 3: research differentiation

- safe normalize and repack using sealr's interpretation;
- deeper formal arguments for path and quota properties;
- selective and content-addressed access for very large datasets;
- ZipDiff-style TAR and 7z differential research;
- a possible unambiguous next-generation container and converters.

## Deferred performance track

Mojo, nvCOMP, QAT, CubeCL, io_uring, IOCP, and intra-stream parallel gzip remain experiments until the Phase 0.1 performance baseline proves a bottleneck.

Any backend must:

- preserve the same canonical view and findings;
- stay outside path, policy, and receipt decisions;
- beat the CPU path after transfer and startup costs;
- report why it was selected;
- remain optional.

## Not planned

- RAR in the default binary
- recursive nested extraction
- a format-conversion GUI
- cloud-hosted extraction
- disabling antivirus
- silent overwrite
- an insecure mode
- GPU as the default
- a 7-Zip replacement

## Primary research behind the order

- [USENIX Security 2025 ZipDiff paper](https://www.usenix.org/conference/usenixsecurity25/presentation/you): 50 parsers, 19 languages, and 14 ambiguity types.
- [ZipDiff artifact](https://github.com/ouuan/ZipDiff): public constructors and a reproducible classification workflow.
- [Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html): unprivileged, stackable filesystem and network restriction with runtime ABI detection.
- [cap-std](https://github.com/bytecodealliance/cap-std): portable capability-oriented filesystem APIs and beneath-style path resolution.
- [Kani](https://model-checking.github.io/kani/): proof harnesses for Rust safety and correctness properties.
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/): libFuzzer targets over arbitrary byte slices.
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use): least privilege and immutable action references for CI.

## Decision rule

When choosing the next task, prefer the work that most increases justified trust in the boundary per unit of trusted code. Breadth, bindings, signing, and acceleration follow that rule.
