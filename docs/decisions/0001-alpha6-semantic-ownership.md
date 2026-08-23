# Alpha.6 semantic ownership

Status: accepted; first dormant record and hostile-decoder slice implemented.

Date: 2026-08-22.

## Decision

Alpha.6 will prototype private, bounded semantic-handoff records before it defines operation protocol v2 or exposes worker execution. The records are common infrastructure, not a public wire contract and not permission to construct public evidence from arbitrary bytes.

The eventual public capability is likely hybrid:

1. the supervisor owns a complete local semantic record and any retained member bytes;
2. a separately selected isolated backend performs non-retained member reads that require codec execution;
3. a materializing writer worker terminates and is reaped before stage audit;
4. the supervisor alone owns effect, cleanup, publication, and final receipt facts.

This decision does not activate worker execution. It preserves operation protocol v1, public Rust symbols, CLI behavior, receipt schemas, and release assets.

## Implementation checkpoint

The first [private semantic-record experiment](../semantic-record.md) is now compiled and tested inside the library crate but is unreachable from shipped call paths. It uses independent magic and a canonical bounded binary format. Planning carries exact invocation binding plus complete pending IR in central-directory order. Completion carries exact operation, request, and plan correlation plus one verification state for every planned member. The supervisor adapter derives non-effect completion axes from the first error and verified-prefix state rather than trusting duplicated axes. A dormant source-owning inspect executor now consumes an accepted Ready plan by value, rejects effects and retention, reads only planned payload ranges through the shared bounded verifier, and emits canonical completion bytes without structural reparse.

The checkpoint pins canonical vector digests and covers hostile truncation, trailing data, kind confusion, structured binding mutation, stale correlation, path and topology state, range overflow, partial-frontier coherence, member-specific failure reachability, hostile diagnostic labels, and destination-setup merge semantics. Executor evidence adds zero structural parser calls, exact complete and stopped parity for reachable Store and Deflate outcomes, strict-v2 directory handling, private-file snapshot ownership, and rejection of ineligible work before payload verification. Broader parity, retained bytes, later reads, `VerifiedArchive`, process transport and isolation, lifecycle, and public activation remain open gates.

## Why the previous binary choice was incomplete

A complete IR and a long-lived worker session solve different parts of the current contract.

- `Outcome::archive_ir()` can expose borrowed local evidence after planning, including an admitted operation whose destination setup failed before complete verification.
- `VerifiedArchive::archive_ir()`, `members()`, and `member()` return borrowed local evidence.
- `VerifiedArchive::retained_member()` returns a borrowed slice captured during the original verification stream.
- `VerifiedArchive` is cheap to clone, and `into_verified_archive()` lets it outlive the outcome, the caller's byte borrow, and the original path.
- A non-retained `read_member()` currently reopens no caller path, but it does execute Store or Deflate processing against the retained immutable snapshot and rechecks size, CRC32, and SHA-256.

A pure session cannot provide those borrowed local values without mirroring them. A complete local IR alone would put later codec work back in the caller process. A materializing session cannot stay alive through stage audit because its writable authority would make the audit unstable.

## Ownership and validation ledger

| Fact | Proposed producer | Required validator | Final owner |
|---|---|---|---|
| Source descriptor, length, digest, and snapshot lifetime | Supervisor | Supervisor | Supervisor |
| Request, profile, policy, limits, target, consumer, effect request, and retention plan | Supervisor | Supervisor | Supervisor |
| Interpretation, admission, verification, findings, and complete IR proposal | Worker | Supervisor validates canonical form, bounds, coherence, and request binding | Local outcome evidence |
| Retained bytes captured during original verification | Worker | Supervisor checks declared path, length, digest, aggregate limits, and immutable transfer | Local verified capability |
| Non-retained verified read | Isolated read backend | Caller limit plus backend result validation | Returned call value |
| Worker restriction, termination, exit, and reap | Kernel and supervisor | Supervisor | Supervisor |
| Stage contents | Materializing worker | Quiescent supervisor audit | Supervisor |
| Effect, cleanup, publication, and final receipt | Supervisor | Supervisor | Supervisor |

A complete record proves representation completeness and internal coherence. It does not by itself prove that worker interpretation is the only meaning of the source. The worker remains in the semantic trusted computing base for every source-to-record fact the supervisor does not independently recompute. The supervisor must not reparse the archive to manufacture a second meaning.

## Options considered

| Option | Contract fit | Blocking problem |
|---|---|---|
| Complete record plus local snapshot | Preserves local IR and capability lifetime | Non-retained reads execute codecs in the caller |
| Long-lived worker session | Keeps later codec work isolated | Cannot directly provide borrowed IR or retained slices, and conflicts with writer quiescence |
| Complete record plus every expanded member | Makes later reads local | Becomes the separately planned content-store problem and scales with expanded content |
| Hybrid record, retained bundle, and isolated read backend | Best fit with current semantics | Helper packaging, backend lifetime, and public activation remain unresolved |

Only the private semantic-record experiment is accepted now. Retained-content transfer, the content-read backend, and the public packaging model remain explicit gates.

## Experimental handoff records

The current API plans the complete IR before destination-stage setup, then performs content verification. An admitted operation whose destination setup fails can therefore expose an IR with incomplete verification and no `VerifiedArchive`. The experiment must preserve that ordering through explicit planning and completion phases. A candidate shape is a restricted plan-only worker that finalizes and transfers a bounded record, then terminates and is reaped before the supervisor validates that record and attempts stage setup. A fresh restricted execution worker consumes the validated plan without structurally reparsing the source. The supervisor merges a validated plan-ready disposition with its own setup failure to reproduce the current admitted, setup-failed outcome. Any equivalent shape must prove the same public observations and single-interpretation property.

The first prototype should use independent magic and explicitly experimental schema versions. The bounded planning record should bind:

- one nonzero operation ID;
- source length and SHA-256;
- interpretation profile ID and digest;
- the opaque supervisor-supplied policy identity plus a separately specified compiled-controls identity when that preimage exists;
- resource limits, target model, consumer profile, requested effect, and retention plan;
- either a phase-local `ReadyForVerification` disposition or terminal interpretation, admission, `StructureOnly` verification, and view-completeness fields for a planning failure; effect remains supervisor-owned, and a successful plan must not freeze public axes that later verification can change;
- the complete optional IR in every state where the current API exposes one;
- bounded planning findings;
- a digest over the canonical planning record for later phase binding.

The completion record in the accepted experiment proposes the final interpretation, admission, verification, and view-completeness axes, plus bounded verification findings. It must carry either the complete updated IR or canonical deltas for every affected member's actual uncompressed size, actual CRC32, content SHA-256, and verification state, all bound to the planning-record digest; untouched members remain `Pending`. Correlation and canonical validation establish the proposal's shape and invocation binding, not that payload verification ran. A file proposal can echo declared size and CRC while supplying an arbitrary content SHA-256. No proposal may shape public `Outcome`, `ArchiveIR`, or `VerifiedArchive` state until a separate content-authority design verifies the exact bytes and their source relationship. A future content-authority extension may add bounded retained-content references only after that design exists. The first experiment carries the requested retention plan but neither retained bytes nor retained-content references, and it does not claim that content transfer is solved.

It must not contain a worker-authored final effect, publication, cleanup, compatibility verdict, receipt, or release claim.

The record need not fit one `SOCK_SEQPACKET` message. A small control frame may reference a bounded immutable blob. A Linux experiment can evaluate a sealed `memfd`, but the supervisor must verify required seals, declared length, a hard maximum, exact digest, and trailing-byte absence before decoding.

## Decoder and conversion rules

Before any allocation sized from untrusted fields or any typed conversion, the supervisor must check:

1. magic, experimental version, total length, reserved fields, and exact input consumption;
2. every count, string length, member length, aggregate, offset, and range with checked arithmetic;
3. exact request, source, profile, policy, resource, target, consumer, effect, and retention binding;
4. unique canonical paths, valid parent topology, member order, and count agreement;
5. range containment, allocation safety, method constraints, and verification-state coherence in every record; `ReadyForVerification` and completion records additionally require a successful exact source covering, while a terminal `covering.inconsistent` record may retain its IR only when the supervisor independently reproduces the covering failure and matching terminal cause, and it must never transition to execution;
6. the recomputed profile digest; a canonical layout root only when an IR exists; a canonical content root only after complete verification; and explicit `Unavailable` identity states otherwise, all scoped to record consistency rather than independent source interpretation;
7. consistency among record-owned axes, findings, IR presence, member verification metadata, retention metadata, and the supervisor-authored requested effect;
8. exact planning-record digest and operation binding across split phases.

Do not add `Deserialize` or a public constructor to `ArchiveIR`. Conversion from a fully validated planning record into crate-private `ArchiveIR` and outcome evidence remains crate-private and associated with the supervisor-owned snapshot. The experiment must not construct `VerifiedArchive` until retained-content transfer and isolated non-retained read authority pass their gates.

## Content-authority gate

Before public activation, Sealr must decide how non-retained `read_member()` keeps codec execution outside the caller while preserving synchronous bounds, cheap cloning, cancellation, crash behavior, and last-owner shutdown. Retained bytes must remain immutable local slices captured during original verification. A later RPC read cannot masquerade as original-pass retention.

A materializing worker may never survive into stage audit. Inspect-only read helpers and materializing writers can share record definitions, but they have different authority and lifetime rules.

## Packaging gate

A library cannot assume that its caller executable implements a hidden child command. Public activation must select one explicit helper packaging and discovery model. It must reject CLI-only behavior, unsafe fork from an arbitrary multithreaded caller, implicit executable search, and unverified embedded-helper extraction.

## Conformance before activation

The private record tests must cover at least:

- admitted inspect planning with and without a retention request;
- admitted materialization planning followed by supervisor-owned stage setup;
- destination setup failure after `ReadyForVerification` is supervisor-merged into the existing admitted, setup-failed axes with the IR, incomplete verification, no `VerifiedArchive`, and no worker-authored effect;
- coherent covering-audit denial with an IR, admission failure with no IR, and malformed structure with no IR;
- worker crash before and after record finalization;
- every truncation, trailing byte, invalid enum, count drift, range overflow, duplicate path, topology conflict, and request-binding mutation;
- unchanged public symbols, CLI behavior, receipts, release assets, and protocol v1 golden vectors.

End-to-end merge tests, rather than worker-record variants, must separately cover source failure before worker execution, complete verification followed by effect failure, committed publication, writer-quiescence failure, stage-audit failure, cleanup failure, publication failure, capability clone and drop, caller-byte mutation, original-path removal, retained borrow, and bounded non-retained read.

## Versioning and nonclaims

Operation protocol v1 remains byte-compatible. The experimental handoff is not protocol v2 and may be replaced without a public migration path.

This decision does not claim that parsing is confined, that a complete IR is an independently checkable certificate, that a content-read helper is solved, or that Linux worker packaging is suitable for library consumers. Those claims require executable parity, lifecycle, containment, and packaging evidence.
