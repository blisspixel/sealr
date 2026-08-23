# Private semantic-record experiment

Status: implemented as dormant crate-private Alpha.6 code. No library, CLI, worker, receipt, or release path invokes it.

This experiment makes the split-phase handoff in the [semantic-ownership decision](decisions/0001-alpha6-semantic-ownership.md) executable without defining operation protocol v2 or changing public behavior. It establishes a bounded representation and hostile decoder for semantic proposals. It does not establish process isolation or a public verified capability.

## Record boundary

The experimental format has independent `SEALRSEM` magic, version `1`, planning and completion kinds, a zero reserved byte, little-endian fixed integers, an exact body length, and a 64 MiB hard record limit. Counts are checked against semantic maxima and the minimum bytes remaining before fallible vector reservation. Strings are length-bounded and validated as UTF-8 before typed conversion. Unknown tags, nonzero reserved state, truncation, trailing bytes, range overflow, and cross-phase decoding fail closed with a typed static-detail error.

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
- an exact structural partition for every IR, followed during hostile ready-plan decode by source length, digest, EOCD, header signature, LFH and CDH variable-length geometry, encoded name, extra-field header, range, and count reproduction against the supervisor-owned `SourceSnapshot`;
- local-header, payload, optional data-descriptor, and central-header containment and adjacency;
- extra-field site order, per-site ID uniqueness, header/data adjacency, ZIP16 lengths, owner containment, profile disposition, and exact source-backed coverage of the encoded local and central extra-field regions;
- raw-name and decoded-name equality for the current strict ASCII profiles;
- canonical path, components, normalization actions, case-fold uniqueness, and file/directory topology;
- Store or Deflate only, encryption-bit denial, strict-v2 flag closure, directory empty-content rules, and all declared resource budgets, including a parser-equivalent metadata aggregate derived from comment, central-directory, and source-checked local-header geometry rather than worker-reported extra-field records;
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
- distinct absent and present-empty retention bindings;
- pinned plan and completion vector digests.

These tests establish record and semantic-evidence parity for the covered states. They do not establish full `VerifiedArchive` equivalence.

## Remaining gates

Before any runtime or public activation, Alpha.6 still requires:

1. shadow parity against a broader current `apply()` corpus, including data descriptors, v1 ignored extras, malformed structure, quota stops, codec stops, audit failure, and publication failure;
2. a dedicated plan/completion fuzz target and committed seed vectors;
3. immutable retained-content transfer and original-pass retention semantics;
4. isolated, caller-bounded non-retained reads with clone, cancellation, crash, and last-owner behavior;
5. sealed immutable blob transport with exact seals, length, digest, clean exit, and reap;
6. no-descendant and stage-permission-mutation controls, writer quiescence, stage audit, and supervisor-owned publication;
7. a helper packaging and discovery model that works for both library and CLI consumers.

Invalid records, bad transport state, worker crash, and timeout are infrastructure failures. They must never be translated into archive denial, malformed interpretation, failed effect, or another worker-authored semantic claim.
