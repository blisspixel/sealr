# Private semantic-record experiment

Status: implemented as crate-private Alpha.6 code used by the explicit supported Linux supervisor and the repository-only worker lab. A self-bound generic worker adapter consumes the actual sealed-plan semantics for inspect, materialize, and one-shot reads. `apply_supervised` invokes inspect or materialize and later-read records through default Linux library code, while `inspect_supervised` remains the inspect-only convenience. Ordinary `apply` and `apply_with_options` remain in-process; the CLI, wheel analyzer, and extracted-package consumer can select the manifest-backed boundary and fail closed without fallback. Non-Linux activation reports isolation unavailable. The wire format stays private and experimental rather than becoming public protocol v2.

This experiment makes the split-phase handoff in the [semantic-ownership decision](decisions/0001-alpha6-semantic-ownership.md) executable without defining operation protocol v2. It establishes bounded representations and hostile decoders for semantic proposals, one-shot read authority, and materialization requests. The supported Linux supervisor uses those private records behind the public `Outcome` and `VerifiedArchive` contract, and the repository lab supplies broader process-isolated lifecycle evidence. That activation does not establish structural-parser confinement or a general production-containment claim.

The record experiment is now fed by a production-compiled, crate-private owning planner shared with ordinary in-process `apply`. This planner is representation-neutral and is not a record codec or worker path. Public `apply` never encodes, decodes, reconstructs, or executes a `SEALRSEM` record.

## Record boundary

The experimental format has independent `SEALRSEM` magic, version `1`, planning, completion, and member-read-request kinds, a zero reserved byte, little-endian fixed integers, an exact body length, and a 64 MiB encoded-length limit. The encoder checks each required length before requesting buffer growth or copying field bytes, uses bounded fallible reserve requests, and stops appending after the first error. An allocator may retain capacity beyond the logical encoded length, so the limit is not an allocator-capacity claim. The decoder checks counts against semantic maxima and the minimum bytes remaining before fallible vector reservation. After exact equality with the supervisor-supplied expected binding succeeds, it also applies the bound `max_path_depth` before allocating owned component strings and bounds normalization reservation by actions representable by the encoded member name. Input-sized validation scratch is either allocation-free or reserved fallibly: path topology sorts one borrowed-path vector with allocation-free ASCII folding, detects adjacent equality, and binary-searches every slash-delimited ancestor so an interleaving sibling cannot hide a file conflict; extra-field duplicate detection uses a fixed ID bitset; and covering reproduction reserves its two range vectors before population. Strings are length-bounded and validated as UTF-8 before typed conversion. Unknown tags, nonzero reserved state, truncation, trailing bytes, range overflow, allocation failure, and cross-phase decoding fail closed with a typed static-detail error.

Successful decode must re-encode to the exact same bytes. The format is private and experimental, so these bytes are pinned as repository evidence rather than promised as a public compatibility surface.

### Shared owning planning seam

After successful policy compilation, `plan_source` acquires the exact immutable source snapshot, detects and parses the selected ZIP profile, applies structure and admission controls, constructs pending source-ordered IR, and completes the covering audit. It returns either a terminal planning result or one non-cloneable Ready value. Ready owns the original `SourceSnapshot`, pending `ArchiveIR`, planning findings, selected profile, opaque policy identity and digest, and full compiled controls. Terminal owns the same context plus magic, phase-local axes, findings, and optional covering IR. Source-acquisition failure remains outside semantic records.

Ordinary `apply` consumes Ready directly into retention planning, destination setup, payload verification, materialization, and outcome construction. It does not reopen or recopy the source, clone or reconstruct IR, reparse ZIP, or traverse the semantic encoder, decoder, or executor. The in-crate conformance harness invokes the same planner separately and derives its record binding from the owned snapshot and planning context. Its full public `apply` call is an intentional differential oracle, so named parity cases still repeat completed verification in test code. The direct plan-native path performs one structural parse, zero payload-verifier calls before Ready, and no additional structural parse during semantic execution.

Focused evidence covers a private-file Ready value after removal of the caller path, a direct one-over archive-cap ingest failure before parsing, exact plan-owned context, zero payload reads during planning, and plan-native completion without a structural parse. The fuzz context also consumes actual pending IR from this seam; it no longer clones completed IR and resets verification fields to synthesize planning state. The same executor runs through the supported sealed Linux supervisor and through a feature-gated lab with additional deterministic faults. A supervisor-authored retention plan captures selected bytes during that execution pass and returns a separately sealed canonical bundle. After worker reap, the supervisor replays the accepted plan against its retained exact descriptor and requires byte-for-byte completion and retention-bundle equality. This is isolated plan consumption, source-derived content authority, original-pass retained-content transfer, and drift-control evidence. It is not structural-parser confinement or a full resource-envelope measurement.

### Self-bound generic worker adapter

The authenticated helper no longer reconstructs `Policy::default_v1`, strict ASCII v2, or the lab fixture's fixed two-path retention request before semantic execution. One private adapter decodes the bounded invocation binding from the sealed plan, creates an exact file-backed snapshot under that plan's archive budget, and requires the process operation and selected inspect or materialize effect to match. Canonical validation then covers the plan's actual profile, policy identity, complete budget, target, consumer, member-sync control, target identity, and absent or present retention plan before any payload execution.

The same adapter executes inspect and materialize plans, validates retained-content evidence without copying retained member bytes, and lets the supervisor reconstruct owned retention state only after its exact source replay matches both worker outputs. It preserves canonically stopped completions, including CRC and codec failures, as source-authorized semantic outcomes instead of converting them into helper protocol failures. The one-shot read path derives its request and result checks from the exact accepted plan and completion rather than lab-owned source bytes or a separately reconstructed retention request.

Focused tests use a custom policy identity, strict ASCII v1, exact custom resource ceilings, and a one-path retention plan, then prove effect and operation drift rejection, complete retention reconstruction, and a bound one-shot read. A separate bad-CRC source proves that worker execution and supervisor replay agree on the stopped frontier and finding. This removes fixture-specific semantic reconstruction from the helper boundary. The public Linux supervisor now maps infrastructure failures separately, constructs the hidden worker-backed `VerifiedArchive` backend for inspect and materialize, and retains stage audit and publication authority. Manifest-backed CLI and consumer integration use this same API.

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

Effect, cleanup, audit, publication, compatibility verdict, `wrote`, CLI exit, view and receipt schemas, environment evidence, tree-root claims, public retained-capability construction, and later member-read authority are absent. Those remain supervisor-owned.

### Plan-native inspect executor

The executor consumes a `ValidatedPlanningRecord` by value and binds it to the exact `SourceSnapshot` by ownership after rechecking source length and SHA-256. This produces a non-cloneable Ready capability whose individual validated value cannot be recovered after execution. Inspect and materialize plans cannot cross into the other executor, and terminal plans fail with a typed phase error before a payload read. A bounded present retention plan selects capture sinks for that same pass. A different snapshot, including one with equal length but different bytes, fails binding before execution. The private decoder can intentionally accept the same canonical planning frame again, so global operation-ID replay control remains a supervisor lifecycle property rather than a record-codec property.

Execution walks pending IR in source order and opens only each recorded compressed-payload range. It does not call the structural ZIP parser, rebuild a `ZipMember`, clone names or extra-field collections, create a destination, or construct `VerifiedArchive`. `apply`, later `VerifiedArchive` reads, and this executor share one bounded Store and Deflate payload verifier with fixed 64 KiB streaming buffers, exact Deflate input consumption, declared-size enforcement, CRC32, and binary SHA-256. One fallible exact reservation for the completion-state vector occurs before payload reads. Allocation or other infrastructure failure returns a record error and cannot become archive evidence.

The executor emits canonical completion bytes directly. When a retention plan is present, it also captures selected bytes through the same verifier call and emits one canonical entry for every requested path and status. The retained-content frame binds operation, request, plan, and completion SHA-256; enforces canonical path order, size, CRC32, SHA-256, per-path status, 64-path, and 63 MiB content bounds; and validates member bytes by borrowing the decoded frame rather than copying them. Reachable inspect stops are source I/O, a declared-size lie, or CRC mismatch for Store and Deflate, plus invalid or trailing input for Deflate. Member, total, and ratio limits are planning-terminal for every accepted Ready plan under the current check order. Public `apply_supervised` invokes the selected executor only in the restricted child. Default `apply`, `apply_with_options`, and the CLI without `--worker-manifest` remain in-process.

### Plan-native materialize executor

The private materialize binding is distinct from inspect. It requires `RequestedEffect::Materialize`, an opaque target digest, and the bound member-sync control. It may carry the same absent or bounded retention plan used by inspect. Inspect plans cannot enter this executor, and materialize plans cannot enter inspect execution. The target digest is a named repository-fixture identity, not a public destination contract.

The supervisor creates the real `CapabilityMaterializer` stage before spawn and duplicates only its retained root descriptor. The worker validates that exact directory identity, installs Landlock and seccomp before source transfer, validates the sealed plan against the exact source, and consumes the stage descriptor into a `StageWriteRoot`. `StageWriteRoot` carries no destination parent, stage name, final name, cleanup, or publication authority. Its directory and create-new nofollow file operations are the same production-compiled implementation used by in-process materialization. File payloads use the shared planned-range reader, Store or Deflate verifier, 64 KiB buffer, flush behavior, and bound member-sync decision. No structural ZIP parse occurs during execution.

The worker completion and retained-content bundle remain untrusted proposals. When retention is present, selected bytes are captured by the same verifier calls that write the corresponding stage files. The supervisor receives both sealed descriptors while the child is alive but does not decode or validate them. It sends the exit acknowledgement, requires a successful exit and exact pidfd-backed reap, then replays the accepted plan against the retained source into a sink and requires byte-for-byte canonical equality for both outputs. Only a complete replay yields an opaque authorized stage manifest and retained-content evidence. The supervisor audits the retained root for private root security, stable stage-name identity, exact expected paths and kinds, no reparse points, single-link regular files on Linux, exact sizes, and streamed SHA-256. An audited stage alone can reach the supervisor's existing no-replace publication primitive.

If termination and reap cannot be proved, the active writer wrapper deliberately abandons the stage owner instead of running recursive cleanup through `Drop`. Once reap is proved, failure may abort the stage. Targeted Linux evidence covers two-file Store and Deflate retention, retained-bundle mutation, stage mutation after reap, destination appearance after audit, cleanup failure, crash after writes, crash after completion sealing, crash after result observation, crash after exit acknowledgement, and stalls before execution and during exit. A separate 500-iteration campaign alternates publication and hostile writer cases with child and descriptor baseline checks after every iteration. The supported supervisor reuses the proven lifecycle, maps infrastructure failures outside archive axes, and constructs `VerifiedArchive` only from source-authorized completion.

### One-shot isolated member read

The member-read request is distinct from original-pass retention. It binds one fresh nonzero read operation ID to the original operation ID, request ID, plan ID, SHA-256 of the exact accepted completion, source-order member index, canonical path, and caller maximum. Creation and decode require the selected member to exist, be a completely verified non-directory, fit the caller maximum and the 63 MiB isolated-read ceiling, and carry canonical size, CRC32, and SHA-256 evidence. The member index must identify that exact path. Every truncation, trailing byte, nonzero reserved field, binding mutation, noncanonical path, absent member, directory, incomplete verification, and oversized limit fails closed.

The Linux supervisor validates this authority before taking the shared one-slot permit, then fallibly reserves the exact verified output size before spawning. Capability clones share immutable plan, completion, source, and replay authority plus the coordinator. A cancelled request fails before spawn when it is already cancelled or cancelled while queued. Each active call creates a fresh restricted worker with a new process operation ID. The worker receives no stage, destination parent, final name, publication capability, or retained-content sink. It receives the read-only source plus separately sealed plan, completion, and request records, validates all four against the exact process boundary, accepts one write-only FIFO, and runs the shared verifier over only the selected planned Store or Deflate payload range.

The supervisor drains that pipe under the same absolute read deadline while polling the control socket, pidfd, and sticky cancellation event. It buffers at most the exact authorized size and treats an extra byte, early EOF, duplicate or malformed result, cancellation, timeout, crash, or transport failure as an infrastructure error. No buffered bytes cross the capability boundary until the worker has closed the pipe at exact EOF, returned one correlated result, matched the authorized length and CRC32, exited cleanly, been reaped, and passed a final size, CRC32, and SHA-256 validation against the completion. Error paths terminate and reap the child before releasing the permit. A post-result injected crash therefore returns no bytes, and a later read starts a new worker from the same immutable authority.

Deterministic Linux conformance covers Store and Deflate success, exact caller caps, one-under rejection without spawn, pre-cancel without spawn, active cancellation at a probe-execution stall, queued clone cancellation without spawn, post-result crash isolation, success immediately after that crash, 64 alternating one-shot reads with no surviving child after each call, and last-owner restoration of the supervisor descriptor baseline. The public backend adds retained borrow, clone-after-original-drop, one-shot Deflate read, exact reap, and typed read failure integration. It does not yet expose cancellation, exercise a near-ceiling pipe, prove cancellation at every protocol epoch, permit concurrent active reads, or keep an idle worker.

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
- exact executor parity for the 12 v1 manifest cases, plus an overstated end-of-stream size lie and source I/O after a verified prefix;
- a mixed strict-v2 directory, Store file, and Deflate file with the only allowed nonzero flag on a matching data descriptor;
- byte-identical memory versus private-file planning and completion frames after the caller source path is removed;
- same-byte strict-v1 admission and strict-v2 extra-field rejection, including cross-profile planning and completion rejection;
- a middle-member CRC failure with a real trailing Pending member, an unread later payload, and the exact verified and pending counts;
- exact-cap execution plus one-under planning-terminal controls for member, total, and ratio budgets;
- ignored-extra payload geometry and destination-setup precedence over an independently CRC-bad payload;
- rejection of forged member, total, ratio, and overflow quota stops, failed directories, and Deflate-specific failures on Store members.

### Differential shadow artifacts

The committed [`semantic-shadow-v1` manifest](../crates/sealr/tests/conformance/semantic-shadow-v1.json) pins 12 ordered `StrictAsciiV1`, memory-backed cases. Each entry exposes the profile, policy identity and digest, requested effect, and retention state instead of relying only on transitive request correlation. The harness consumes the same owning planner as ordinary `apply`, directly obtaining pending IR after covering and before setup or verification. For executable plans, the source-owning executor generates the completion frame; terminal planning records come from the shared terminal decision, while setup merging remains supervisor-owned. A separate complete public operation remains the differential oracle. The harness compares decoded planning and completion evidence with exact pending and final IR where present, semantic axes, phase and cause, verification counts and frontier, ordered record-owned findings, and source, request, plan, and frame identities. The cases cover Store and Deflate completion, a matching descriptor, unsupported magic, LFH/CDH name disagreement, member quota denial, CRC after a verified prefix, declared-size lie, invalid and trailing Deflate streams, post-planning source I/O, and an existing destination. The setup case pins its deterministic finding signature rather than its path-bearing detail. The file is frozen at 17,119 bytes with SHA-256 `b064c6945ca31603914d45a3d18775750bf30ddb667c356eb6d331673a9feb59`.

The additive [`semantic-shadow-v2` manifest](../crates/sealr/tests/conformance/semantic-shadow-v2.json) names v1 as its predecessor and embeds that exact path, byte length, and digest. The v2 file is 19,769 bytes with SHA-256 `9243570b35667aaf9142483d823cb676391e8ba4a90b3594928533a0139b1967`. Its operation registry contains only the inspect ID exercised by the additions; the predecessor retains its separate materialize setup case. Both files require UTF-8 without a byte-order mark, LF line endings, deterministic two-space JSON, one trailing newline, closed object shapes, exact case order, and raw-byte identity. The v2 name versions only this evidence manifest. Private `SEALRSEM` planning and completion frames remain wire version 1.

V2 contributes these 12 ordered additions:

1. `strict-v2-mixed-memory-complete`
2. `strict-v2-mixed-private-file-complete`
3. `same-extra-strict-v1-complete`
4. `same-extra-strict-v2-terminal`
5. `dotdot-terminal`
6. `interleaved-exact-topology-terminal`
7. `interleaved-folded-topology-terminal`
8. `total-quota-exact-complete`
9. `total-quota-one-under-terminal`
10. `ratio-quota-exact-complete`
11. `ratio-quota-one-under-terminal`
12. `covering-inconsistent-terminal`

Every addition declares one or more closed oracle labels. `apply-outcome-parity` compares record-owned fields with the ordinary public `apply()` result. Ready cases obtain pending IR and plan-owned binding fields from the shared production planner and, when executable, compare plan-native completion. Terminal cases encode the corresponding private terminal record from the shared terminal decision, then compare it with the separate public outcome. The strict-v2 backend pair also declares `backend-semantic-parity`: production byte and path requests confirm their actual memory-borrowed and private-file receipt backends; the plan-owned private snapshot outlives removal of the caller path; all evidence fields except the case name match; and the canonical planning and completion frame bytes are identical. Public receipt bytes are not claimed identical because source path, snapshot kind, and dependent view data may differ. This shared seam removes the former test-only TLS IR clone, but the public oracle and plan-native executor remain intentionally separate differential executions.

The same extra-field bytes are admitted and executed under strict-v1, where both local and central records remain explicitly Ignored, and rejected under strict-v2 with `zip.extra`. Their profile, request, and plan identities differ. A v1 plan is rejected against the v2 binding, and the v1 completion is rejected against the v2 terminal plan. The topology cases separately pin exact `path.conflict` and ASCII-folded `path.case_fold` when an unrelated sibling separates a file ancestor from its descendant. Total and ratio pairs pin successful exact boundaries as well as planning-terminal one-under denials, without implying runtime quota stops after an accepted Ready plan.

`supervisor-reproduced-terminal` is deliberately separate. The covering case starts from valid strict-v2 IR, changes the supervisor snapshot, proves the same IR cannot decode as Ready, independently reproduces the first `covering.inconsistent` audit finding, and only then accepts an IR-bearing terminal plan. It is not an ordinary reachable `apply()` parity claim. The `pending_ir_sha256` and `final_ir_sha256` fields in both manifests hash the test's Rust JSON serialization for exact differential comparison. They are not the preview layout or content roots and are not public lock identities.

A separate `semantic_records` libFuzzer target uses a hidden, nondefault fuzz-only feature to reach the planning and completion boundary. It decodes arbitrary planning and completion bytes, applies up to 128 input-directed mutations per canonical Ready, terminal-admission, Complete, and Stopped frame, requires stable success or error class and error offset on repeated decode, checks exact Ready-plan IR equality with the production pending IR, rejects stale completion correlation, and exercises every fuzzed record kind. The one-shot member-read request currently has deterministic hostile tests rather than a fuzz entry. A committed dictionary and four seed cases have their paths, lengths, and SHA-256 digests checked by required CI. The verifier binds the complete Cargo manifest, parsed exact bin, hidden driver source, lock checksum, and registry-rooted crates.io libFuzzer package while refusing Cargo configuration, then compares the complete scheduled workflow with a manifest-derived contract covering its weekly trigger, permissions, concurrency, setup, shell programs, resource bounds, dictionaries, and failure artifacts. Executable negative fixtures reject inert TOML remapping, local, patched, or vendored fuzz-engine substitution, manual-only drift, direct weakening, inactive or appended commands, inert evidence, and raw or quoted duplicate last-wins arguments. The target compiles under the pinned fuzz workspace. Clean exact-main on-demand and first scheduled-event evidence are recorded in the [assurance report](assurance.md#current-evidence); accumulated scheduled history remains pending.

Together the manifests establish exact equality only for their named fixtures and owned oracle fields. They do not establish corpus-wide semantic equivalence, broad strict-v2 or backend parity, an independent archive interpretation, full `VerifiedArchive` equivalence, worker-computed content authority, transport safety, isolation, or runtime-worker parity.

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

The first bounded matrix expansion, shared owning planning seam, public worker-backed capability, supervised materialization, and manifest-backed CLI, wheel-laboratory, and extracted-package-consumer activation are complete. Continued parity growth beyond these named fixtures remains assurance work. Alpha.6 release readiness still requires accumulated clean scheduled fuzz and main-branch history, with every reproducible failure promoted to a deterministic regression.

The isolated bridge has landed as Linux-only, repository-only inspect, read, and materialize evidence. Normal cases execute a distinct child-only helper only after exact-byte authentication, a private hello, running executable identity proof, and pidfd binding; deliberate fault cases retain the lab executable. Shared authenticated worker protocol primitives now place the frame codec, raw descriptor transport, sealed-blob envelope, and helper-artifact authenticator in the library, with the helper tool using a hidden bridge to the same implementation. The [fixed helper package](helper-packaging.md) separately binds release placement, artifact identity, production-only license closure, and extracted-helper conformance.

The supervisor retains the expected invocation, accepted plan, deadlines, lifecycle, source descriptor, and all public semantic merging. After restriction readiness, the worker receives the read-only snapshot and sealed canonical plan. Record validation binds the plan to the exact file-backed snapshot and may read represented structural ranges without invoking the ZIP parser; after plan acceptance, the executor reads only recorded Store or Deflate payload ranges. The sealed plan itself carries the retention request and all other semantic controls. Selected fixture members are captured as output sinks of their original inspect or materialize verifier calls. The worker returns separately sealed canonical completion and retained-content bundles while retaining its source and handoff descriptors through supervisor observation, then exits cleanly and is reaped. The supervisor checks blob seals and length, independently recomputes each digest from the exact kernel-sealed bytes, and decodes both records against its retained plan first as untrusted proposals. Correlation, seals, canonical decoding, and successful worker execution do not themselves prove the proposed file-content SHA-256 values. The supervisor therefore replays the accepted plan against its retained exact source descriptor after reap and requires both canonical outputs to match the proposals byte for byte. A regression supplies a fully canonical completion with forged file SHA-256: proposal validation accepts it, while the source-derived authority step rejects it. Retention regressions reject every truncation, content mutation, and a request above the transfer ceiling. Materialization additionally rejects a changed retained bundle before the stage can be authorized. This replay is independent of worker output but deliberately uses the same bounded verifier implementation.

One-shot non-retained reads bind fresh process authority to the exact accepted completion and use only one write-only output pipe. The public supervisor translates source-authorized completion and retained content into the existing outcome and capability state, while keeping worker lifecycle failure outside archive findings. For materialization, it alone creates the stage and retains the destination parent and final name; the worker receives only the stage root, exact source, and sealed plan. After clean exit and reap, the supervisor requires source-derived completion and retention equality, audits every staged object, and alone performs no-replace publication. A required pinned-kernel QEMU gate proves fail-closed inspect and materialize setup on actual Landlock ABI 2. Structural-parser confinement and macOS or Windows isolation remain open.

Invalid records, bad transport state, worker crash, and timeout are infrastructure failures. They must never be translated into archive denial, malformed interpretation, failed effect, or another worker-authored semantic claim.
