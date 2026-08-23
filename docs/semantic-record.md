# Private semantic-record experiment

Status: implemented as dormant crate-private Alpha.6 code. No production `apply`, CLI, worker, receipt, default-feature, supported API, or release path invokes it. Outside crate tests, only the unsupported hidden driver enabled explicitly by the fuzz workspace reaches it.

This experiment makes the split-phase handoff in the [semantic-ownership decision](decisions/0001-alpha6-semantic-ownership.md) executable without defining operation protocol v2 or changing public behavior. It establishes a bounded representation and hostile decoder for semantic proposals. It does not establish process isolation or a public verified capability.

## Record boundary

The experimental format has independent `SEALRSEM` magic, version `1`, planning and completion kinds, a zero reserved byte, little-endian fixed integers, an exact body length, and a 64 MiB encoded-length limit. The encoder checks each required length before requesting buffer growth or copying field bytes, uses bounded fallible reserve requests, and stops appending after the first error. An allocator may retain capacity beyond the logical encoded length, so the limit is not an allocator-capacity claim. The decoder checks counts against semantic maxima and the minimum bytes remaining before fallible vector reservation. After exact equality with the supervisor-supplied expected binding succeeds, it also applies the bound `max_path_depth` before allocating owned component strings and bounds normalization reservation by actions representable by the encoded member name. Input-sized validation scratch is either allocation-free or reserved fallibly: path topology sorts one borrowed-path vector with allocation-free ASCII folding, detects adjacent equality, and binary-searches every slash-delimited ancestor so an interleaving sibling cannot hide a file conflict; extra-field duplicate detection uses a fixed ID bitset; and covering reproduction reserves its two range vectors before population. Strings are length-bounded and validated as UTF-8 before typed conversion. Unknown tags, nonzero reserved state, truncation, trailing bytes, range overflow, allocation failure, and cross-phase decoding fail closed with a typed static-detail error.

Successful decode must re-encode to the exact same bytes. The format is private and experimental, so these bytes are pinned as repository evidence rather than promised as a public compatibility surface.

### Planning record

The supervisor-owned invocation binding carries:

- one nonzero 128-bit operation ID;
- exact source length and binary SHA-256;
- the selected interpretation profile and its recomputed digest;
- the bounded caller policy ID and opaque policy digest;
- every compiled resource-budget field, target model, consumer profile, requested effect, and member-sync control;
- an optional opaque target identity for materialization;
- retention as distinct absent or present state, including an empty present plan, exact ceilings, and strictly byte-sorted canonical paths under the public retention limits.

The current code encodes compiled controls exactly but marks their separate identity unavailable. Sealr has not specified a canonical compiled-controls preimage, so the experiment does not invent a digest claim.

A planning record is either:

- `ReadyForVerification`, with a complete pending `ArchiveIR` and no error finding; or
- terminal structure or admission evidence, with `StructureOnly` verification, a partial view cause bound to the first error finding, and no IR except the current `covering.inconsistent` state.

The IR omits redundant top-level identity fields and derives them from the validated invocation. It carries the full covering and every structural member field in central-directory order. Components are derived from the validated canonical path. Every member is pending and has no actual size, CRC32, content digest, or failed state.

The request ID hashes a domain-separated canonical invocation binding. The plan ID hashes a separate domain plus the exact planning-record bytes. Neither digest is self-referential.

### Completion record

A completion echoes the exact operation, request ID, and plan ID before any variable allocation. It does not duplicate or mutate structural IR on wire. Instead, it carries one verification state for every member in planning order:

- `Verified` with actual size, CRC32, and binary SHA-256;
- one optional `Failed` frontier with a closed finding-code cause; or
- `Pending` after that frontier.

A complete record requires every member verified and no error finding. A stopped record requires the exact `Verified*`, `Failed`, `Pending*` sequence. Its public `pending_members` count remains the total minus the verified prefix, so it includes the failed frontier member, matching current behavior. Interpretation, admission, verification, and view completeness are derived from the first error and the validated member vector instead of trusting duplicated worker-authored axes. Failure validation is member-aware: directories cannot fail during inspect execution, Store members cannot report Deflate failures, and declared member, total, ratio, or arithmetic-overflow quotas that already passed Ready-plan admission cannot be replayed as execution failures. Semantic validation borrows the accepted planning IR. Canonical re-encoding uses that proof without validating or cloning the IR again. Accepted decode drops the canonical byte buffer before one fallible IR reconstruction, applies the validated member states, and moves decoded findings into the result. Direct encode and rejected decode materialize no IR.

Effect, cleanup, audit, publication, compatibility verdict, `wrote`, CLI exit, view and receipt schemas, environment evidence, tree-root claims, retained bytes, and later member-read authority are absent. Those remain supervisor-owned.

### Plan-native inspect executor

The dormant executor consumes a `ValidatedPlanningRecord` by value and binds it to the exact `SourceSnapshot` by ownership after rechecking source length and SHA-256. This produces a non-cloneable Ready inspect capability whose individual validated value cannot be recovered after execution. Terminal plans, materialization requests, and any present retention plan, including present-empty retention, fail with a typed phase error before a payload read. A different snapshot, including one with equal length but different bytes, fails binding before execution. The private decoder can intentionally accept the same canonical planning frame again, so global operation-ID replay control remains a later supervisor lifecycle gate.

Execution walks pending IR in source order and opens only each recorded compressed-payload range. It does not call the structural ZIP parser, rebuild a `ZipMember`, clone names or extra-field collections, create a destination, or construct `VerifiedArchive`. `apply`, later `VerifiedArchive` reads, and this executor share one bounded Store and Deflate payload verifier with fixed 64 KiB streaming buffers, exact Deflate input consumption, declared-size enforcement, CRC32, and binary SHA-256. One fallible exact reservation for the completion-state vector occurs before payload reads. Allocation or other infrastructure failure returns a record error and cannot become archive evidence.

The executor emits canonical completion bytes directly. Reachable inspect stops are source I/O, a declared-size lie, or CRC mismatch for Store and Deflate, plus invalid or trailing input for Deflate. Member, total, and ratio limits are planning-terminal for every accepted Ready plan under the current check order. The public path remains unchanged; this executor is a private in-process precursor to a later sealed worker bridge, not process-isolation evidence.

## Structural validation

Before reconstructing crate-private IR, the adapter checks:

- exact invocation, source, profile, policy, budget, target, consumer, effect-request, and retention binding;
- checked half-open ranges without using saturating range helpers on hostile values;
- an exact structural partition for every IR, followed during hostile ready-plan decode by source length and digest agreement; EOCD zero-disk enforcement plus member-count, central-directory, and comment-geometry agreement; header signatures; LFH and CDH fixed-field and variable-length agreement; encoded names; extra-field headers, ranges, and counts; local-offset reproduction; zero disk-start enforcement; and member-kind agreement with source external attributes;
- local-header, payload, optional data-descriptor, and central-header containment and adjacency, including descriptor signature, length, CRC32, and sizes;
- extra-field site order, per-site ID uniqueness, header/data adjacency, ZIP16 lengths, owner containment, profile disposition, and exact source-backed coverage of the encoded local and central extra-field regions;
- raw-name and decoded-name equality for the current strict ASCII profiles;
- canonical path, components, normalization actions, case-fold uniqueness, and file/directory topology;
- Store or Deflate only, encryption-bit denial, strict-v2 flag closure, directory empty-content rules, structural-signature exclusion in comments and stored data-descriptor payloads, and all declared resource budgets, including a parser-equivalent metadata aggregate derived from comment, central-directory, and source-checked local-header geometry rather than worker-reported extra-field records;
- pending-only planning state, exact completion-vector length, verified-prefix ordering, one failed frontier, absent measurements for failed or pending members, exact declared size and CRC32 for verified members, aggregate actual-size bounds, and failure-cause reachability for the planned member kind and method;
- rejection of completion findings that claim supervisor-owned audit, cleanup, commit, publication, or unsupported-stage outcomes.

`Finding.member` remains a bounded diagnostic label, not an authority-bearing canonical path. Hostile original labels such as `../outside.txt` and `safe.txt:hidden` round-trip without being mistaken for IR paths.

## Current evidence

Focused deterministic tests cover:

- ready planning with reversed path order, proving IR source order is preserved;
- complete v2 reconstruction with a directory and files;
- partial verification where the failed member is included in `pending_members`;
- hostile finding labels and finding order;
- supervisor-owned destination-setup failure merged into the existing admitted, structure-only, failed-effect axes;
- terminal admission without IR and terminal covering evidence with IR;
- every truncation of canonical planning and completion vectors, trailing bytes, header confusion, and cross-phase decode;
- structured operation, source, profile, policy, budget, requested-effect, target, member-sync, and retention mutations;
- stale request or plan correlation, impossible completion frontiers, member reorder, and hostile range overflow;
- exact metadata-budget acceptance and one-byte-under rejection through both trusted encode and hostile decode, checked against the shipped parser on a nonempty ignored-extra fixture, with omitted records, correlated geometry shrinkage, and source extra-ID relabeling rejected;
- source-byte mutation that rejects a ready plan and admits IR-bearing `covering.inconsistent` evidence only when the supervisor reproduces the exact finding;
- fixed EOCD, LFH, and CDH field forgery, descriptor drift, central-comment signatures, and nonzero per-member disk-start rejection;
- per-member ZIP64 sentinels and the ambiguous 12-byte descriptor whose first word is the optional signature;
- planning and completion phase-finding allowlists, including wrong-phase archive and execution findings;
- materialization-only setup merging with setup-owned error causes;
- parity with the public parser for 257 path components and 257 normalization actions, plus rejection of the same deep plan before component allocation when its authenticated depth is reduced;
- rejection at a deliberately small encoder limit before the attempted field can grow the output;
- zero completion IR materializations for direct encode, stale correlation, and a late-invalid frontier; exactly one for accepted Complete and Stopped decode;
- a deterministic failpoint walk across every completion-reconstruction reservation, with typed `AllocationFailed` results and the accepted plan left pending and unchanged;
- a record above 64 KiB that measures the exact logical reconstruction budget, rejects one byte under that budget, and succeeds with one materialization at the exact budget;
- distinct absent and present-empty retention bindings;
- pinned plan and completion vector digests;
- executor rejection of wrong snapshots, terminal plans, materialization, present-empty retention, and injected allocation failure before any parser or payload-verifier call;
- zero parser calls during execution, successful execution while EOCD reads are poisoned, and one verifier call per planned file rather than per directory;
- exact executor parity for the 12 manifest cases, plus an overstated end-of-stream size lie and source I/O after a verified prefix;
- strict-v2 directory and file reconstruction, and byte-identical memory versus private-file completion after the caller source path is removed;
- a middle-member CRC failure with a real trailing Pending member, an unread later payload, and the exact verified and pending counts;
- exact-cap execution plus one-under planning-terminal controls for member, total, and ratio budgets;
- ignored-extra payload geometry and destination-setup precedence over an independently CRC-bad payload;
- rejection of forged member, total, ratio, and overflow quota stops, failed directories, and Deflate-specific failures on Store members.

The committed [`semantic-shadow-v1` manifest](../crates/sealr/tests/conformance/semantic-shadow-v1.json) pins 12 ordered `StrictAsciiV1`, memory-backed cases. Each entry exposes the profile, policy identity and digest, requested effect, and retention state instead of relying only on transitive request correlation. The harness captures the production pending IR after covering and before setup or verification. For executable plans, the source-owning executor now generates the completion frame; terminal and setup cases remain supervisor-owned. The harness compares decoded planning and completion evidence with exact pending and final IR where present, semantic axes, phase and cause, verification counts and frontier, ordered record-owned findings, and source, request, plan, and frame identities. The cases cover Store and Deflate completion, a matching descriptor, unsupported magic, LFH/CDH name disagreement, member quota denial, CRC after a verified prefix, declared-size lie, invalid and trailing Deflate streams, post-planning source I/O, and an existing destination. The setup case pins its deterministic finding signature rather than its path-bearing detail. Unknown manifest fields fail closed. Executor activation did not change the canonical evidence; the manifest SHA-256 remains `b064c6945ca31603914d45a3d18775750bf30ddb667c356eb6d331673a9feb59`.

A separate `semantic_records` libFuzzer target uses a hidden, nondefault fuzz-only feature to reach this private boundary. It decodes arbitrary planning and completion bytes, applies up to 128 input-directed mutations per canonical Ready, terminal-admission, Complete, and Stopped frame, requires stable success or error class and error offset on repeated decode, checks exact Ready-plan IR equality with the production pending IR, rejects stale completion correlation, and exercises every valid record kind. A committed dictionary and four seed cases have their paths, lengths, and SHA-256 digests checked by required CI. The verifier binds the complete Cargo manifest, parsed exact bin, hidden driver source, lock checksum, and registry-rooted crates.io libFuzzer package while refusing Cargo configuration, then compares the complete scheduled workflow with a manifest-derived contract covering its weekly trigger, permissions, concurrency, setup, shell programs, resource bounds, dictionaries, and failure artifacts. Executable negative fixtures reject inert TOML remapping, local, patched, or vendored fuzz-engine substitution, manual-only drift, direct weakening, inactive or appended commands, inert artifact evidence, and raw or quoted duplicate last-wins arguments. The target compiles under the pinned fuzz workspace. Clean exact-main on-demand evidence is recorded in the [assurance report](assurance.md#current-evidence); the first scheduled-event run and accumulated scheduled history remain pending.

The manifest establishes zero-difference executor parity only for its executable memory-backed strict-v1 cases. Focused regressions add one strict-v2 mixed directory and file case plus private-file backend parity, but do not establish corpus-wide semantic equivalence, broad strict-v2 or backend parity, an independent implementation, full `VerifiedArchive` equivalence, transport safety, isolation, or runtime-worker parity.

### Near-limit completion heap evidence

A required, explicitly invoked regression measures completion decode and reconstruction in four isolated child processes. Its deterministic strict-v2 Store fixture has 349 one-byte files with unique 64,000-byte single-component names. The source is 44,698,895 bytes. Its canonical planning frame is 67,041,104 bytes with SHA-256 `e697bec9023d83f1983c90ee35d9e09f8edf94f6053404d517755d9351773c72`, leaving 67,760 bytes below the private 64 MiB frame limit.

The accepted Complete control first warms the decoder and uses the existing allocation budget to derive an 89,486,520-byte logical reconstruction size. After the source, encoded plan, completed reference IR, and warm result are dropped, a test-only system-allocator wrapper samples requested live Rust heap while retaining the decoded result. The local Windows sample added 89,503,272 peak bytes, only 16,752 bytes above the logical reconstruction, and retained exactly 89,486,520 bytes at the sample point. It materialized IR once.

An accepted Stopped control fails the final member with `crc.mismatch`, fills the 65,535-byte diagnostic-member limit, and fills the 1,024-byte finding-detail limit. Its logical reconstruction was 89,486,480 bytes. The local Windows sample peaked at 89,569,847 bytes and retained 89,553,095 bytes, including the moved record-owned finding. It also materialized IR exactly once. Required CI repeats all four controls in release mode on 64-bit Ubuntu, macOS, and Windows and enforces these relational limits:

- each accepted peak delta is at least the logical reconstruction and no more than 1 MiB above it;
- each accepted final live delta retains at least the logical reconstruction and no more than 256 KiB above it;
- peak delta is less than two logical reconstructions;
- stale correlation performs no IR materialization and peaks at no more than 64 KiB;
- a full-member-vector completion with a late invalid frontier performs no IR materialization and peaks at no more than 1 MiB.

The local stale-correlation control allocated no bytes. The full-member-vector late-invalid control peaked at 16,752 bytes, returned to its baseline, and did not materialize IR. These controls distinguish early correlation rejection from a record that decodes its complete member vector before semantic rejection.

This is a requested Rust-heap measurement of `decode_completion` against accepted Complete and Stopped records plus two hostile controls. It excludes fixture planning, source parsing, the already retained validated plan, allocator metadata and fragmentation, native codec storage, stacks, mappings, RSS, handles, executor memory, transport, isolation, materialization, cancellation, and retained-content behavior. It closes the completion-reconstruction peak-live prerequisite, not the worker resource envelope.

## Remaining gates

Before any runtime or public activation, Alpha.6 still requires:

1. expansion of the pinned matrix across strict-v2, memory and private-file backends, ignored extras, IR-bearing covering terminals, path and topology stops, and size, ratio, and total-budget stops, preserving every discrepancy as a deterministic regression;
2. closure of the pre-parser authority gate: no process or thread creation, no descendant or stage-permission mutation, per-epoch stalls, raw unknown-ancillary rejection, and repeated native stress;
3. one real crate-private plan-only seam shared by in-process `apply` and a repository lab, rather than using the test-only planning capture and repeating completed verification;
4. sealed immutable plan and completion blobs with exact seals, length, digest, expected invocation binding, clean exit, and reap, followed by isolated consumption of the validated plan without structural reparse;
5. independent content authority that verifies exact file bytes and their source relationship before any worker proposal shapes public semantic state, plus immutable retained-content transfer and original-pass retention semantics;
6. isolated, caller-bounded non-retained reads with clone, cancellation, crash, and last-owner behavior;
7. writer quiescence, stage audit, and supervisor-owned publication;
8. a helper packaging and discovery model that works for both library and CLI consumers;
9. the first scheduled-event campaign and accumulated clean scheduled history, with every reproducible failure promoted to a deterministic regression.

The first honest isolated bridge is Linux-only, repository-only, inspect-only, and without retention or a destination. The supervisor retains the snapshot, expected invocation, accepted plan, replay state, deadlines, lifecycle, and all public semantic merging. After restriction readiness, the worker receives the read-only snapshot and a sealed plan blob. Record validation may read represented structural ranges without invoking the ZIP parser; after plan acceptance, the executor reads only recorded Store or Deflate payload ranges. The worker returns a sealed completion blob, exits cleanly, and is reaped. The supervisor then checks blob seals and length, independently recomputes the digest from the exact kernel-sealed bytes, and treats any worker-reported digest as untrusted metadata before decoding the record against its retained plan. Only after clean exit, reap, and binding-validated, bounded semantic decode may the supervisor retain the result as an untrusted, plan-bound proposal. Correlation, seals, and canonical decoding do not prove that payload processing ran: a file proposal can echo declared size and CRC while supplying an arbitrary content SHA-256. The lab must not translate that proposal into public interpretation, admission, verification, `ArchiveIR`, or `VerifiedArchive` state. This lab may prove isolated plan consumption, but it cannot activate a public worker, construct `VerifiedArchive`, claim complete parser confinement, or close content-authority, retained-content, later-read, materialization, stage-audit, publication, helper-packaging, receipt, macOS, or Windows gates.

Invalid records, bad transport state, worker crash, and timeout are infrastructure failures. They must never be translated into archive denial, malformed interpretation, failed effect, or another worker-authored semantic claim.
