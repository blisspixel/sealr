# Roadmap

Updated 2026-08-21.

sealr's product is the boundary:

```text
Archive bytes -> versioned interpretation -> verified admitted tree
                                           -> requested effect outcome
All stages                                  -> evidence
```

The current `apply()` API is a sound one-entry-point preview, but its `Verdict`, `View`, and `view_digest` still combine admission, effect, and diagnostic facts. Phase 0.1 must separate those axes before external consumers depend on them.

## Executive decision

The next milestone is **Phase 0.1: the ZIP trust gate**.

Sealr is an archive-ingress boundary. It is not a general agent-execution proxy, model verifier, credential broker, or enterprise control plane.

Do not add TAR, 7z, MCP, language bindings, accelerators, or archive-decision signing first. The current implementation has a strict but incomplete ZIP32 parser, an executable ZipDiff gate, and component-bound output. The next work is a versioned admitted-tree identity and separate outcome axes, followed by reduced-authority filesystem isolation, canonical Unicode paths, snapshot-backed bounded input, and layered adversarial assurance.

This order matters because format breadth multiplies every unresolved parser, path, resource, and materialization mistake. Testing one narrow format thoroughly gives later formats a clearer boundary to reuse.

## Current baseline

The repository now has:

- a Rust workspace with `sealr` and `sealr-cli`;
- one `apply()` operation returning verdict, view, and receipt;
- classic ZIP32 Store and Deflate support;
- CD-first structure agreement across EOCD, CDH, LFH, and data descriptors;
- exact local-record layout with hidden bytes, gaps, prefixes, and overlap rejected;
- exact consumption of one declared raw DEFLATE stream, with trailing bytes and concatenated streams rejected;
- bounded archive reads and streaming expanded-byte enforcement;
- staged materialization that publishes only after all members pass;
- component-bound no-follow member writes, random same-volume staging, create-new files, and native no-replace publication on Linux, macOS, and Windows;
- versioned materialization receipts that report the backend, stage mode, stage-creation primitive, component resolution, durability, platform publication primitive, outcome, and cleanup state;
- fail-closed ASCII path handling and topology-collision checks;
- a pinned, aggregate-digested gate over all 5,927 upstream ZipDiff constructions, with exact finding counts and an explicit valid-control allowlist;
- adversarial tests for traversal, ADS, ambiguity, layout, CRC rollback, destination preservation, and quota behavior;
- pinned Rust 1.98.0 plus strict format, Clippy, debug test, optimized build, cross-platform release test, Rustdoc build, documentation, and supply-chain CI gates;
- dependency update automation and an explicit permissive-license policy;
- protected `main` requiring pull requests, linear history, resolved conversations, and all five current required CI checks;
- the `v0.1.0-alpha.2` hardened-materialization preview line, built from protected `main` through all five required main CI checks and the release workflow, with immutable releases enabled.

This is the current second-alpha baseline. It is incomplete and is not a production security boundary.

## Active execution queue

There is one primary implementation stream and one parallel assurance stream:

1. **Primary: Step 3, semantic identity.** First separate outcome and completeness axes, then introduce `SourceSnapshot` and the versioned `ArchiveIR`, then make inspect and materialize consume that one object, and finally specify layout and content-tree identities with cross-platform golden bytes.
2. **Parallel: finish the Step 2 adversarial matrix.** Add deterministic namespace and staged-content mutation seams on Linux, macOS, and Windows. These tests may strengthen the existing materializer, but they must not invent a second tree or manifest representation.
3. **Next after the semantic contract: Step 4, the supervised Linux worker.** The worker protocol and supervisor audit consume the Step 3 tree and manifest. macOS and Windows stay native release gates and report process isolation unavailable until credible platform-specific worker boundaries exist.

Steps 5 through 10 then proceed in order: authenticated recovery and durability, canonical Unicode paths, snapshot-backed bounded random access, layered assurance, stable evidence plus avoided-work performance, and the stable CLI experience. After Phase 0.1, the Python wheel consumer and reusable-tree gate come before TAR or any other format expansion.

## Repository tooling and dependency rule

The shipped library and CLI remain Rust and have no PowerShell or Bash runtime dependency. Native Ubuntu, macOS, and Windows jobs are equal release gates.

The repository currently uses PowerShell for several cross-runner documentation, walkthrough, licensing, and promotion tasks because `pwsh` is available on all three hosted runner families and the release operator uses Windows. Bash is also used for Linux-hosted GitHub API and release checks. This works, but it duplicates logic across scripting environments and makes the repository look more platform-specific than the product is.

Shared deterministic tasks will move into a small Rust `xtask` surface in this order:

1. documentation and metadata verification;
2. walkthrough fixture, transcript, and asset-manifest generation;
3. third-party license generation and verification;
4. release-candidate classification and archive inspection;
5. release promotion after the Rust implementation reproduces every numeric-ID, provenance, and fail-closed gate in the current operator script.

Thin host-specific wrappers may remain only where an operating-system or operator boundary requires them. New runtime dependencies require a written capability need, license and advisory review, transitive-size review, and evidence that the standard library or an existing dependency is insufficient. UI work must not add an async runtime, TUI framework, telemetry client, or network stack to the release binary without a measured requirement.

## Phase 0.1: ZIP trust gate

Target: a single-format boundary whose claims are backed by fixtures, properties, fuzzing, capability-based output, reduced process authority, and measurable performance.

### 1. Make the ZipDiff corpus executable: complete in public CI

Completed 2026-08-20:

1. The CI job fetches revision `7c427ed254bb3a5985d54870c12f97db78118e67` and generates all 5,927 construction files. Generated binaries are not committed.
2. The manifest records origin, revision, license, an aggregate SHA-256 binding every fixture path and digest, exact class and finding counts, and the exact valid-control allowlist. A committed patch replaces the upstream generator's current-time DOS header defaults with zero only after its exact revision is verified, making the byte corpus reproducible across runs and operating systems.
3. The production API classifies the corpus. Any new acceptance, rejected control, finding-count drift, missing file, byte change, or upstream construction change fails the gate.
4. All A1, A3, A5, B1, B3, B4, C1, C2, C3, C4, and C5 constructions reject. A4 retains only its valid empty-directory control. A2 retains ten internally consistent controls. B2 retains 62 portable punctuation controls.
5. Local deterministic tests cover valid directories and descriptors plus the ambiguity gaps found during corpus evaluation.

Why it was first: the USENIX study found 14 ambiguity types across 50 parsers, and its artifact provides constructors. Running those bytes exposed real gaps in Unicode Path extras, directory attributes, hidden ZIP64 structures, stored-descriptor record positioning, backslashes, and ASCII DEL handling.

Evidence:

- [expectation manifest](tests/corpus/zipdiff/expectations.txt);
- [gate documentation](tests/corpus/zipdiff/README.md);
- `classify_zipdiff` production-API classifier;
- dedicated `ZipDiff 14-class gate` CI job;
- no external parser is part of the library or extraction runtime.

### 2. Put every destination operation behind a directory capability: foundation shipped, adversarial closure active

Completed through 2026-08-21:

- The private materializer is factored out of `apply` behind one narrow component-based boundary.
- All archive-derived member paths are passed as validated ASCII relative components to a `cap-std` stage handle. Each component is created or opened separately with no-follow semantics from a retained directory capability.
- Stage names use 128 bits from the operating-system random source. Linux and macOS stages are created with mode `0700`.
- The destination parent must already exist. Linux accepts only trusted-owner parents protected by mode or sticky rename semantics. macOS additionally rejects extended ACLs through a retained descriptor query.
- Windows admits only non-remote, writable NTFS parents with persistent ACLs, then atomically creates and retains the stage with parent-relative `NtCreateFile` and a protected effective-TokenUser-only inheritable DACL.
- Windows verifies the stage owner and exact DACL through the retained handle before any member write, removing inherited DACL grants to other principals and preventing a discovered name from being replaced between creation and handle acquisition. Descendants inherit the sole TokenUser ACE but receive the creating token's default owner; a principal matching that owner SID remains outside the in-process containment promise.
- Member files use no-follow, create-new handles. Windows validates the generic reparse-point attribute on opened directory and file handles rather than recognizing only ordinary symbolic links.
- Normal rejection attempts explicit stage cleanup and retries once after failure before constructing the receipt. Setup failure after stage creation uses retained-handle cleanup first and a parent-relative retry. Receipts distinguish not-started, setup-failed, staged, aborted, publication-failed, and committed outcomes, including final cleanup success or failure.
- Final publication uses `RENAME_NOREPLACE` on Linux, `RENAME_EXCL` on macOS, and `NtSetInformationFile` with the retained source and parent handles on Windows. All three are no-replace operations.
- Materialization receipt v2 reports non-sensitive Windows storage observations and stage-ACL verification in addition to the common lifecycle primitives.
- Unsupported publication platforms fail closed instead of using a check-then-rename fallback.
- Deterministic tests preserve a destination that appears after staging, refuse parent and leaf symlinks, reject non-component input and non-directory parents, preserve outside bytes, verify explicit cleanup, and require inspect and materialize member equality.

Remaining deliverables:

1. Add deterministic race seams and repeated Linux symlink swaps, macOS link swaps, Windows junction or reparse-point mutation, leaf replacement, destination appearance, and staged-content mutation tests.
2. Require every successful publication to match an independently audited staged-tree manifest exactly.

These materializer tests remain active release gates while Step 3 defines semantic identity. The final staged-tree manifest audit depends on that admitted-tree contract and completes with the worker boundary in Step 4.

Why this remains active: archive-controlled names now cross a component-bound no-follow materializer, and all three release platforms have native no-replace publication. Windows stage creation additionally installs and verifies a private DACL. The remaining risks are parser authority, adversarial mutation evidence, and crash lifecycle, not ordinary lexical traversal.

Exit proof:

- archive-controlled strings never reach ambient filesystem open functions;
- each archive-derived component is opened no-follow from a retained directory handle;
- reject returns without a published destination;
- existing destinations are preserved byte-for-byte;
- symlink and reparse-point race tests cannot redirect a write;
- Windows stage creation and publication remain bound to the retained objects under deterministic substitution attempts;
- receipts report the actual platform publication primitive and every post-stage cleanup outcome;
- crash-recovery behavior is documented and tested separately from normal rollback.

### 3. Establish semantic identity and separate outcomes: immediate implementation milestone

Implementation order inside this step:

1. Replace the unavailable all-zero source digest with explicit digest availability, add separate outcome and completeness types, and preserve a compatibility adapter for the alpha.2 public shape. **Landed:** `SourceDigest` omits SHA-256 when bytes were never held; `Outcome` and receipt v2 expose interpretation, admission, verification, effect, and view-completeness; `Verdict` remains the alpha.2 adapter. The inspectable `View` still serializes `allowed`/`rejected`.
2. Introduce `SourceSnapshot` over the current owned and caller-borrowed in-memory bytes, then build the versioned `ArchiveIR` once from that snapshot. **Snapshot landed:** path inputs become `memory-owned` and caller byte inputs stay `memory-borrowed`; payload reads are checked ranges over that object. Receipts record `source_snapshot`. `ArchiveIR` is the next item.
3. Make inspect serialization, materialization, tests, and future worker messages consume the same immutable IR without reparsing source bytes.
4. Compile interpretation, budget, target, consumer, and effect inputs into typed supported controls. Replace floating-point ratios and saturating security counters before their external formats stabilize.
5. Specify canonical layout and content-tree bytes with domain separation and golden vectors, then require byte-identical results on every supported release platform.

Deliverables:

1. Define a versioned, effect-independent `ArchiveIR` for the accepted ZIP profile. Preserve raw name bytes, decoded and canonical paths, kinds, source header and payload ranges, flags, classified extra fields, declared and measured sizes, content hashes, verification state, and normalization actions.
2. Make the immutable admitted tree the only representation consumed by inspect serialization, materialization, tests, worker messages, and future destinations. No downstream Sealr path may reparse the archive bytes.
3. Define a `SourceSnapshot` abstraction and make the current owned and caller-borrowed in-memory byte sources its first implementations. Every later source must preserve that invocation immutability.
4. Separate interpretation status (`interpreted`, `malformed`, `unsupported`, or `indeterminate`), admission status (`admitted`, `denied`, or `not-evaluated`), verification status (`structure-only`, `partial`, or `complete`), and effect status (`not-requested`, `committed`, or `failed`). Mark every view as complete or partial with a stopping phase and cause.
5. Define distinct identities for source bytes, the interpretation profile, canonical layout, fully verified content tree, and invocation or effect evidence. Keep `view_digest` as diagnostic evidence and add a tree-only digest only after its canonical bytes are specified.
6. Split future configuration into a versioned interpretation profile, deterministic resource budget, target filesystem model, consumer profile, and effect policy. Compile external policy into typed supported controls before reading an archive. Make ZIP flags and extra fields exact profile allowlists. Replace floating-point ratio semantics with checked rational arithmetic and replace saturating security counters with checked operations and an explicit overflow finding before the policy format stabilizes.
7. Specify `sealr.lock.v1` only after the interpretation and tree-root algorithms are stable. It will bind byte identity to semantic identity so consumers can verify meaning without selecting another parser.
8. Add golden cross-platform fixtures proving that the same source bytes and profile produce the same IR and layout identity on Linux, macOS, x86_64 Windows, and 32-bit Windows where runtime tests are supported.

Why this is the immediate next implementation step: a worker protocol, cache, projection, language binding, package profile, or attestation built around the current invocation-shaped `View` would freeze the wrong abstraction. The admitted tree and independent outcome axes are the contract every later component needs.

Exit proof:

- the same bytes and interpretation profile produce byte-identical canonical tree evidence on every supported platform;
- inspection and materialization consume the same immutable tree object and never invoke a second parser;
- an admitted archive with a failed destination effect remains distinguishable from an unsafe or indeterminate archive;
- a partial view cannot be mistaken for a complete member inventory;
- `view_digest` and tree identity are documented and tested as different claims.

### 4. Start parsing and writing in reduced authority

Deliverables:

1. Split a trusted supervisor from a same-binary worker. A library call must not unexpectedly sandbox its caller.
2. Let the supervisor open the archive and destination parent, create and retain the private stage, and remain the only component with publication authority.
3. Give the worker only the archive and stage capabilities through a bounded, versioned protocol. Never give it the destination parent or final name.
4. Apply `no_new_privs` and runtime-probed Landlock before the worker reads the first archive byte on Linux. Add seccomp only after the real syscall surface is measured.
5. Treat the worker result as untrusted. Audit the exact staged tree, identities, sizes, and SHA-256 digests before publication.
6. Record process mode, protocol, Landlock ABI, handled and granted rights, inherited archive authority, publication ownership, and degraded or failed setup in the receipt.
7. Add deterministic barriers and bounded repeated hostile namespace and content-mutation tests. Require zero outside writes, zero destination replacement, and exact manifest equality on success.
8. Keep macOS and Windows behavior green and report isolation unavailable there until their credible worker packaging boundaries are implemented.

Why fourth: the Windows DACL removes inherited DACL grants to other principals but does not reduce a compromised parser's ambient authority. Windows descendants still receive the creating token's default owner, and a principal matching that SID remains outside this milestone. The worker protocol should carry the canonical IR and staged-tree manifest from Step 3 rather than invent another representation. A supervisor-owned lifecycle also defines the correct owner for recovery. Landlock confines the worker itself; it does not constrain another process running as the same user. Same-principal containment requires a distinct service identity or equivalent mandatory-access-control boundary and remains outside this milestone.

Exit proof:

- isolation is installed before the first archive byte is interpreted on the required Linux release runner;
- the worker cannot open an unrelated sentinel, create a sibling beside the stage, or publish;
- the supervisor rejects malformed, oversized, crashed, or inconsistent worker results;
- the staged-tree audit rejects every extra, missing, linked, reparse, identity-duplicate, size-mismatched, or digest-mismatched object;
- deterministic race seams and the release stress gate produce no escape, replacement, or incorrect successful publication;
- receipts distinguish enforced, unavailable, setup-failed, worker-crashed, audit-failed, aborted, publication-failed, and committed states.

### 5. Make crash lifecycle and durability explicit

Deliverables:

1. Create a durable authenticated intent before stage creation and bind the later record to stable parent and stage identities.
2. Store recovery records in a private per-user state directory and authenticate them with HMAC-SHA-256. Protect the Windows key with DPAPI and a private DACL.
3. Keep an operation lease for liveness. Recover only an old, inactive, authenticated record whose retained parent and stage identities still match.
4. Quarantine a verified abandoned stage with a no-replace retained-handle rename, revalidate it, then remove it through component handles. Never scan and delete by `.sealr-stage-*` name alone.
5. Fault-inject process death at every lifecycle transition and prove idempotent recovery without touching the final destination or lookalikes.
6. Define member sync, directory sync, publication durability, and power-loss guarantees as separate receipt evidence and policy choices.
7. Expand golden lifecycle receipts across Linux, macOS, and Windows. Cleanup retry-success and terminal-failure injection are already covered.

Why fifth: recovery must follow the supervisor lifecycle so a later process split does not invalidate ownership records or locks. Normal rollback is not crash durability, and file sync alone is not directory or power-loss durability.

Exit proof:

- an unauthenticated, malformed, young, active, moved, or identity-mismatched record never authorizes deletion;
- crash injection before and after each state transition leaves either no stage or one safely recoverable stage;
- repeated recovery is idempotent and preserves every final destination and unrelated lookalike;
- the receipt describes the actual file, directory, publication, and recovery durability achieved.

### 6. Define one canonical member-name representation

Deliverables:

1. Preserve raw ZIP filename bytes through structure comparison.
2. Decode general-purpose bit 11 names as strict UTF-8 and legacy names as CP437.
3. Produce one `CanonicalPath` containing display text, normalized components, and a destination comparison key.
4. Decide and document Unicode normalization with test vectors. Do not choose compatibility normalization casually.
5. Model Windows reserved names, trailing-dot behavior, ADS, separators, case folding, and reparse-sensitive names explicitly.
6. Reject collisions before decompression or output.
7. Put path byte length, component length, and depth in policy.

Why sixth: rejecting all non-ASCII paths is safe but not useful enough to ship. Lossy decoding is unacceptable because distinct hostile byte strings can collapse to one path. The canonical representation must be shared by the `ArchiveIR`, inspect, materialize, fixtures, fuzzing, and future format adapters.

Exit proof:

- no lossy filename decoding exists in the decision path;
- inspect and materialize use the same canonical object;
- a platform matrix covers ASCII, CP437, UTF-8, normalization, case, and reserved-name collisions;
- each rejected collision has one stable finding code.

### 7. Replace whole-archive buffering with immutable snapshots

Deliverables:

1. Extend the `SourceSnapshot` abstraction beyond in-memory bytes with a private spool or content-addressed object, or a filesystem object whose immutability is actually verified.
2. Replace `Vec<u8>` parser ownership with bounded random access over that snapshot, not arbitrary mutable `ReadAt`.
3. Parse EOCD and the central directory through checked random-access reads.
4. Stream the source digest once without trusting file size or allowing unbounded allocation.
5. Keep all offset arithmetic in checked `u64`, with explicit conversion at I/O boundaries.
6. Add mutation tests proving that header interpretation and later payload reads can never observe different byte versions.
7. Consider mmap only behind a size and snapshot-stability gate after the ordinary file path is correct.

Why seventh: expanded members already stream, but the archive blob is buffered up to 512 MiB. A security boundary must bound both compressed and expanded memory without reintroducing a source-mutation differential. CD-first parsing needs a stable snapshot and seekability, not whole-file ownership.

Exit proof:

- resident memory is bounded independently of archive size;
- a multi-gigabyte sparse valid fixture can be inspected without a multi-gigabyte allocation;
- truncation and growth produce structured rejection, never panic or stale reads.

### 8. Add layered adversarial and compatibility assurance

Current foothold: the deterministic unit suite now drives the public `apply()` boundary over every truncation of a valid ZIP, three mutations at every byte position, and deterministic noise inputs from 0 through 1,024 bytes, asserting that none panic. This is a fast regression gate, not a substitute for coverage-guided fuzzing or semantic property tests.

Deliverables:

1. Add property tests for canonical path containment, topology conflicts, and monotonic quota counters.
2. Add `cargo-fuzz` targets for ZIP parsing, canonical names, and inspect-only `apply()`.
3. Seed fuzz targets with the ZipDiff and local adversarial corpus.
4. Assert no panic, bounded output, deterministic verdict, and receipt presence.
5. Add Kani harnesses for the pure path and quota core only.
6. Run fast deterministic gates on every change. Add longer scheduled fuzzing only after runtime and cost are measured.
7. Keep unsafe code out of the parser, jail, and quota core. Isolate unavoidable operating-system calls in small platform modules with explicit reviewed invariants.
8. Maintain a hostile conformance corpus with expected findings, source spans, and tree identities, plus a benign ecosystem corpus that measures acceptance and top rejection causes for each named profile.

Why eighth: unit tests lock known attacks, fuzzing searches byte-level state space, property tests cover semantic classes, compatibility data keeps strict profiles usable, and Kani proves bounded properties. None replaces the others. Kani's own guidance makes small proof harnesses the right unit, while the Rust Fuzz Book makes byte-slice parser targets straightforward.

Exit proof:

- every invariant has at least one deterministic test;
- the three fuzz targets run locally from a documented seed corpus;
- Kani proves bounded path and counter properties without verifying codecs;
- each profile publishes acceptance rates and investigated rejection classes over a reproducible benign corpus;
- zero unsafe blocks exist in the trusted core, or each exception has a reviewed invariant.

### 9. Stabilize evidence and measure avoided work

Deliverables:

1. Canonicalize policy and view JSON with RFC 8785 JCS before hashing.
2. Version the policy, view, receipt, tree, and finding registry with compatibility tests.
3. Add receipt fields for isolation and degraded conditions. Materializer backend and stage-cleanup evidence are already versioned in the current receipt.
4. Build a small independent verifier for canonical evidence bytes, tree-root computation, structural coverage claims, policy identity, signatures when present, and effect-record consistency. It must not extract archives.
5. Benchmark structure, full verification, realization, and reuse separately against representative valid ZIPs.
6. Compare tree and content results with established parsers only for well-formed inputs.
7. Publish CPU time, peak memory, allocations, open-handle peak, cancellation latency, and avoided decompression or writes, not one headline number.
8. Define the performance budget before optimization.

Why ninth: authenticated attestations need canonical claim bytes, and performance work needs a correct workload. Measuring earlier would optimize an implementation whose I/O and name model are still changing. The valuable performance claim is reuse of the exact verified tree without reparsing or reinflating, not merely faster unzip throughput.

Exit proof:

- equivalent policy objects hash identically;
- source, interpretation, layout, content-tree, and invocation identities remain distinct;
- golden receipts are stable across Linux, macOS, and Windows except documented environment fields;
- well-formed fixtures produce identical inspect and materialize trees;
- the baseline and accepted regression budget are checked into the repository.

### 10. Stabilize a quiet, honest CLI experience

Deliverables:

1. Keep the library as the semantic authority. The CLI translates typed outcomes into presentation and never reparses an archive or reimplements policy.
2. Make the default output a concise human summary that names the decision, verification completeness, effect status, source and tree identities when available, important findings, and evidence location.
3. Provide one stable machine envelope through `--json`; keep progress and diagnostics off machine stdout. Add `--evidence-out` and related output controls only after their schemas are versioned.
4. Introduce job-oriented verbs such as `gate`, `verify`, `materialize`, and `explain` only after the Step 3 outcome axes exist. Preserve a documented compatibility path for the alpha CLI.
5. Support terminal-aware color with `auto`, `always`, and `never`, honor `NO_COLOR`, avoid animation in noninteractive output, and make every command useful without color or Unicode decoration.
6. Define stable exit classes for admitted, denied, indeterminate, effect-failed, and command-line misuse. Human wording may improve without changing machine fields or rule identities.
7. Add cross-platform golden tests for help, human summaries, JSON, narrow terminals, redirected streams, paths with spaces, and failure remediation on Ubuntu, macOS, and Windows.
8. Keep the release binary local and quiet by default: no telemetry, update checks, implicit network calls, or hidden writes.
9. Enforce the runtime dependency rule above. Prefer standard formatting and the existing argument parser over a TUI or rendering framework.
10. Regenerate README walkthrough transcripts and light and dark screenshots from a release-profile binary built from the exact release candidate whenever visible output changes. Keep copyable commands and expected text beside every image, and bind committed screenshots to a checked transcript and asset manifest.

Why tenth: polishing the alpha.2 combined verdict first would make a pleasant interface around the wrong semantic model. The CLI should expose the independent facts established in Step 3 and the evidence stabilized in Step 9. It is still a Phase 0.1 gate because users must be able to understand a security decision without reading raw internal JSON.

Exit proof:

- the same command communicates the same semantic facts on Linux, macOS, and Windows;
- redirected machine output is byte-stable and free of progress or color sequences;
- human output remains readable at narrow widths and with color disabled;
- every denial and indeterminate result names a stable rule or phase and a useful next action;
- README screenshots match the checked transcripts from the exact release-candidate source;
- the CLI adds no unreviewed runtime dependency or network behavior.

## Phase 0.1 release gate

Phase 0.1 is complete only when every row is green.

| Gate | Required evidence |
|---|---|
| Interpretation | Complete known-class gate: 14-class ZipDiff manifest and passing 5,927-file fixture suite in public CI. Exact single-stream DEFLATE consumption is enforced. |
| Semantic identity | Versioned effect-independent tree, canonical tree bytes, separate layout and content identities, and no reparsing by consumers |
| Outcome honesty | Separate interpretation, admission, verification, and effect states plus explicit complete or partial views |
| Path containment | Canonical-path properties plus capability-writer race tests |
| Resource bounds | Source, metadata, member, total, ratio, and counter tests |
| Reject rollback | No published destination on content, I/O, or policy failure |
| Inspect equals materialize | Both consume one immutable admitted tree; golden tree and digest comparisons |
| Reduced authority | Landlock worker test and receipt field |
| Assurance | Unit, property, fuzz smoke, Kani, Clippy, rustfmt, docs, cargo-deny |
| Portability | Current baseline green; every new gate must keep native Linux, macOS, and Windows CI green |
| Performance | Reproducible baseline with memory and throughput budgets |
| CLI experience | Stable human and machine output, cross-platform goldens, quiet defaults, screenshot provenance, and reviewed dependency budget |
| Honesty | README limitations match executable behavior |

## Phase 0.2: one canonical consumer

Only after Phase 0.1:

- a `python-wheel.v1` consumer profile that validates wheel metadata, `RECORD`, normalized topology, relocation destinations, and actual verified content;
- `sealr lock` binding source, interpretation, consumer, policy, layout, and content identities;
- a GitHub Action that gates wheels and emits the same evidence as the Rust API;
- one public same-digest, different-tree wheel demonstration and a reproducible compatibility report;
- one external package publisher, registry, build backend, or installer that consumes Sealr's admitted representation rather than reparsing the ZIP;
- Sigstore keyless signing of Sealr semantic admission records only after their unsigned claim bytes and independent verifier are stable. Release archives already carry GitHub build-provenance attestations.

Done when one external consumer treats Sealr's admitted tree and semantic lock as its canonical decision.

## Phase 0.3: reusable admitted trees

- a local content-addressed store keyed by the verified content-tree identity;
- materialization from verified blobs without reparsing or reinflating the source;
- a read-only projection with an explicit verification frontier and no implicit promotion;
- cache admission bound to source, interpretation, policy, target, consumer, and verification identities;
- separate structure, verification, realization, and reuse benchmarks.

Done when repeated consumers can reuse one admitted tree without a second parser and every partial verification state remains explicit.

## Phase 1: TAR without weakening the gate

- TAR, PAX, and GNU long-name parsing through the same canonical path and quota core;
- gzip and zstd wrappers with bounded window and metadata policy;
- default denial of symlinks, hardlinks, devices, sparse surprises, and unsafe modes;
- TAR checksum, duplicate path, extension-header, and truncation fixtures;
- the same capability materializer, receipt schema, isolation worker, and fuzz expectations.

Done when ZIP and TAR are format adapters around one tested boundary rather than separate extractors.

## Phase 2: ecosystem and audit

- CycloneDX member inventory;
- WASM or napi-rs only for a real consumer;
- continuous public fuzzing;
- external security audit after the core surface freezes;
- one package-manager or agent-runtime integration;
- an `agent-workspace.v1` consumer profile after the wheel profile, with read-only admitted-tree access and explicit promotion;
- any detached release signatures required beyond the existing build-provenance attestations, plus reproducible release metadata.

## Phase 3: research differentiation

- safe normalize and repack using sealr's interpretation;
- deeper formal arguments for path and quota properties;
- selective and content-addressed access for very large datasets;
- ZipDiff-style TAR and 7z differential research;
- a possible unambiguous next-generation container and converters.

## Deferred performance track

Optional codec, I/O, and hardware backends remain experiments until the Phase 0.1 workload taxonomy proves a bottleneck. Avoided parsing, decompression, and writes take priority over faster extraction.

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
- [`uv` archive confusion advisory](https://github.com/advisories/GHSA-8qf3-x8v5-2pj8): one archive digest could expand to different package contents across installers.
- [PyPI response](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/): upload-time rejection for ambiguous wheel ZIP structures.
- [in-toto digest sets](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md): useful prior art for artifact and directory identities, while Sealr still requires its own normative tree semantics.
- [Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html): unprivileged, stackable filesystem and network restriction with runtime ABI detection.
- [cap-std](https://github.com/bytecodealliance/cap-std): portable capability-oriented filesystem APIs and beneath-style path resolution.
- [Kani](https://model-checking.github.io/kani/): proof harnesses for Rust safety and correctness properties.
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/): libFuzzer targets over arbitrary byte slices.
- [GitHub secure use reference](https://docs.github.com/en/actions/reference/security/secure-use): least privilege and immutable action references for CI.

## Decision rule

When choosing the next task, prefer the work that most increases justified trust in the boundary per unit of trusted code. Breadth, bindings, signing, and acceleration follow that rule.
