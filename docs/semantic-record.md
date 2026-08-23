# Private semantic-record experiment

Status: implemented as dormant crate-private Alpha.6 code. No `apply`, CLI, worker, receipt, default-feature, supported API, or release path invokes it. Only the unsupported hidden driver enabled explicitly by the fuzz workspace reaches it.

This experiment makes the split-phase handoff in the [semantic-ownership decision](decisions/0001-alpha6-semantic-ownership.md) executable without defining operation protocol v2 or changing public behavior. It establishes a bounded representation and hostile decoder for semantic proposals. It does not establish process isolation or a public verified capability.

## Record boundary

The experimental format has independent `SEALRSEM` magic, version `1`, planning and completion kinds, a zero reserved byte, little-endian fixed integers, an exact body length, and a 64 MiB encoded-length limit. The encoder checks each required length before requesting buffer growth or copying field bytes, uses bounded fallible reserve requests, and stops appending after the first error. An allocator may retain capacity beyond the logical encoded length, so the limit is not an allocator-capacity claim. The decoder checks counts against semantic maxima and the minimum bytes remaining before fallible vector reservation. After exact equality with the supervisor-supplied expected binding succeeds, it also applies the bound `max_path_depth` before allocating owned component strings and bounds normalization reservation by actions representable by the encoded member name. Strings are length-bounded and validated as UTF-8 before typed conversion. Unknown tags, nonzero reserved state, truncation, trailing bytes, range overflow, and cross-phase decoding fail closed with a typed static-detail error.

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

A completion echoes the exact operation, request ID, and plan ID before any variable allocation. It does not duplicate or mutate structural IR. Instead, it carries one verification state for every member in planning order:

- `Verified` with actual size, CRC32, and binary SHA-256;
- one optional `Failed` frontier with a closed finding-code cause; or
- `Pending` after that frontier.

A complete record requires every member verified and no error finding. A stopped record requires the exact `Verified*`, `Failed`, `Pending*` sequence. Its public `pending_members` count remains the total minus the verified prefix, so it includes the failed frontier member, matching current behavior. Interpretation, admission, verification, and view completeness are derived from the first error and the validated member vector instead of trusting duplicated worker-authored axes.

Effect, cleanup, audit, publication, compatibility verdict, `wrote`, CLI exit, view and receipt schemas, environment evidence, tree-root claims, retained bytes, and later member-read authority are absent. Those remain supervisor-owned.

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
- pending-only planning state, exact completion-vector length, verified-prefix ordering, one failed frontier, absent measurements for failed or pending members, exact declared size and CRC32 for verified members, and aggregate actual-size bounds;
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
- distinct absent and present-empty retention bindings;
- pinned plan and completion vector digests.

A separate `semantic_records` libFuzzer target uses a hidden, nondefault fuzz-only feature to reach this private boundary. It decodes arbitrary planning and completion bytes, applies up to 128 input-directed mutations per canonical Ready, terminal-admission, Complete, and Stopped frame, requires stable success or error class and error offset on repeated decode, checks exact Ready-plan IR equality with the production pending IR, rejects stale completion correlation, and exercises every valid record kind. A committed dictionary and four seed cases have their paths, lengths, and SHA-256 digests checked by required CI. The verifier binds the complete Cargo manifest, parsed exact bin, hidden driver source, lock checksum, and registry-rooted crates.io libFuzzer package while refusing Cargo configuration, then compares the complete scheduled workflow with a manifest-derived contract covering its weekly trigger, permissions, concurrency, setup, shell programs, resource bounds, dictionaries, and failure artifacts. Executable negative fixtures reject inert TOML remapping, local, patched, or vendored fuzz-engine substitution, manual-only drift, direct weakening, inactive or appended commands, inert artifact evidence, and raw or quoted duplicate last-wins arguments. The target compiles under the pinned fuzz workspace. The first clean exact-commit Linux AddressSanitizer campaign passed in [on-demand run 32634689922](https://github.com/blisspixel/sealr/actions/runs/32634689922) at `384781fcba15409dd4a30a3202dc2844a06e7dce`: 194,476 units in 601 seconds at 512 MiB peak RSS, with no crash or reproducer. Because the event was `workflow_dispatch`, the first scheduled-event run and accumulated scheduled history remain pending.

These tests establish parity for the named deterministic record, source-binding, and codec cases. They do not establish broader shadow parity or full `VerifiedArchive` equivalence.

## Remaining gates

Before any runtime or public activation, Alpha.6 still requires:

1. broader semantic shadow parity against the current `apply()` corpus, including malformed structure, quota stops, and codec stops; data descriptors and v1 ignored extras now have focused source-binding coverage;
2. execution that consumes the validated plan without structurally reparsing the source;
3. immutable retained-content transfer and original-pass retention semantics;
4. isolated, caller-bounded non-retained reads with clone, cancellation, crash, and last-owner behavior;
5. sealed immutable blob transport with exact seals, length, digest, clean exit, and reap;
6. no-descendant and stage-permission-mutation controls, writer quiescence, stage audit, and supervisor-owned publication;
7. a helper packaging and discovery model that works for both library and CLI consumers;
8. the first scheduled-event campaign and accumulated clean scheduled history, with every reproducible failure promoted to a deterministic regression.

Invalid records, bad transport state, worker crash, and timeout are infrastructure failures. They must never be translated into archive denial, malformed interpretation, failed effect, or another worker-authored semantic claim.
