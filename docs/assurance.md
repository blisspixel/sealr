# Testing, compatibility, and assurance

> This page separates current evidence from the target assurance program. The Alpha.4 baseline has a deterministic Rust suite, strict cross-platform CI, cargo-deny policy, a pinned 5,927-file ZipDiff construction gate, six finite-domain property families, an opaque bounded-read capability with one-pass exact-member retention, a consumer that runs against the extracted packaged crate, an independent verifier for three profile vectors and four identity-conformance cases, and a 20-wheel compatibility measurement. Alpha.5 adds the private file-backed source, native mutation controls, required heap and peak-resident-memory comparison, scheduled multi-gigabyte sparse gate, and a pinned bounded-protocol fuzz target with clean campaign evidence. Alpha.6 adds an immutable 12-case semantic-record shadow baseline and 12 additive cases with explicit oracle ownership, source-owning inspect and materialize executors with no structural reparse, a required near-limit completion heap probe, a separate deterministic-seed target with clean exact-main on-demand and first scheduled-event evidence, immutable original-pass retention, one-shot isolated non-retained reads, a public reaped-writer stage-audit and supervisor-publication lifecycle, packaged public API smoke, a separate public-API native materialization lifecycle oracle required on all three platforms, and a pinned scheduled discovery workflow for three full-domain scalar Kani harnesses plus bounded mutation and source-coverage reports. The post-Alpha.6 repository adds an exact wheel profile, bounded evaluator, hostile fixtures, a predecessor-bound inventory, and an external non-reopening bridge. Accumulated scheduled history remains pending. Broader ecosystem sampling, ZIP and topology fuzz targets, the general authenticated-evidence verifier, and an external audit remain future work.

Trust is the scarce resource. Format breadth and acceleration follow stable semantics and measured compatibility.

## Current evidence

| Layer | Current evidence | Remaining work |
|---|---|---|
| Unit | ZIP path grammar, topology, overlap and layout, quotas, inspect/materialize equality, rollback, destination preservation, platform materializer controls, exhaustive strict-v2 flag-word and extra-field-ID domains, deterministic truncation, mutation, and noise no-panic coverage, plus private-source length, same-length mutation, Windows writer exclusion, replacement, short-read, interruption, cleanup, and backend-parity cases | Add broader independently varied schedules as new race boundaries appear |
| Resource allocation | A required integration probe applies physically sparse valid 1 MiB and 128 MiB ZIPs through isolated child processes, caps tracked heap allocation at 8 MiB with a 1 MiB delta, and caps peak resident memory at 256 MiB with a 64 MiB delta. A monthly native matrix runs the exact 3 GiB sparse gate; the local Windows run used 131,072 allocated source bytes and 210,427 tracked heap bytes. | Record open-handle peak and accumulate scheduled native history across runner generations |
| Public API and package | External-crate fixture exercises evidence types, `VerifiedArchive`, and bounded retention; a separate Cargo consumer runs the same retention path against the extracted packaged crate in required quality CI; Linux package smoke authenticates the extracted helper and exercises public supervised inspect, materialize, retained and one-shot reads, pre-worker setup failure, exact reap, and stage cleanup | Add semantic compatibility checks after publication and a wheel-aware metadata selector |
| Corpus | All 5,927 pinned ZipDiff constructions, local generated adversarial fixtures, and a byte-addressed non-shipping pilot of 20 exact PyPI wheels with an investigated denial cluster | Expand producer and feature diversity; add codec-boundary, source-race, and wheel-semantic fixtures |
| Differential | The ZipDiff expectation gate binds strict rejection and a documented valid-control allowlist. The immutable `semantic-shadow-v1` gate pins 12 strict-v1 cases. Additive `semantic-shadow-v2` pins 12 named observations: mixed strict-v2 with the allowed descriptor flag, exact memory/private-file plan and completion frame equality, a same-byte v1/v2 ignored-extra differential with cross-profile rejection, dot-dot, exact and folded interleaved topology, exact and one-under total and ratio quotas, and an IR-bearing covering terminal. Ordinary cases compare production `apply()` with decoded records on record-owned fields; the backend pair adds exact semantic and frame equality; only the covering case uses supervisor audit reproduction. | Expand beyond these fixtures, compare major consumers on well-formed profile inputs, track disagreement frontiers, and add independent bounded path and quota models |
| Property | Six finite-domain families: compression ratio against quotient and remainder; verified-member limits against `limit >= measured_size`; retention selection over 8,125 size and limit combinations; checked `offset + len` against `u128` over 4,624 boundary pairs; discovery exact partitions against a per-byte bitmap over 1,055,758 lists of zero through three intervals plus the covering audit's ordered predicate over 204,204 cases; atomic quota transitions against `u128` over 159,528 valid states and increments | Add independent bounded models for strict-profile path topology and lifecycle transitions |
| Fuzz | `protocol_decoders` exercises arbitrary start and result frames plus input-directed mutations of valid frames under pinned bounds. `semantic_records` exercises arbitrary planning and completion bytes, mutations of every fuzzed canonical record kind, repeated-decode stability, Ready-plan equality with production pending IR, and stale correlation from four digest-pinned seeds. Exact-main on-demand run [32938266865](https://github.com/blisspixel/sealr/actions/runs/32938266865) passed against executable `main` commit `6b3461793b9cfe5e69537f814f772b79aae21dfd`. `semantic_records` completed 266,452 units in 601 seconds at 443 executions per second, coverage 2,461, feature coverage 5,321, corpus 432/6,196 bytes, and 505 MiB peak RSS. `protocol_decoders` completed 13,846,664 units in 601 seconds at 23,039 executions per second, coverage 860, feature coverage 1,898, corpus 313/4,272 bytes, and 511 MiB peak RSS. Neither job produced a crash or reproducer. First scheduled-event run [32708222003](https://github.com/blisspixel/sealr/actions/runs/32708222003) passed against `main` commit `2bdecc97442e6c5fdc27fb08e7f80db706d74cf6`. `semantic_records` completed 269,202 units in 601 seconds at 447 executions per second, coverage 2,451, feature coverage 5,367, corpus 435/7,003 bytes, and 506 MiB peak RSS. `protocol_decoders` completed 12,636,011 units in 601 seconds at 21,024 executions per second, coverage 851, feature coverage 2,090, corpus 358/about 19 KiB, and 522 MiB peak RSS. Neither scheduled job produced a crash or reproducer. Required verification binds the complete Cargo manifest, parsed targets, lock checksum, and registry-rooted crates.io fuzz engine while refusing Cargo configuration, then compares the complete scheduled workflow, including its weekly trigger, permissions, concurrency, exact shell programs, and failure-artifact fields. Executable negative fixtures reject inert TOML remapping, local, patched, or vendored fuzz-engine substitution, manual-only drift, weakening, inactive or appended commands, inert evidence, and raw or quoted duplicate last-wins arguments. The member-read request has deterministic hostile coverage but is not yet included in `semantic_records`. | Add targets for interpretation, canonical paths, covering, codecs, inspect-only `apply()`, and the member-read request; accumulate scheduled history |
| Executable specification | A no-Sealr-dependency verifier agrees with production evidence on four exact identity cases and independently checks their covering, profile digest, and roots | Add independent bounded models for paths and lifecycle transitions; extend identity cases with each published profile and encoding branch |
| Native materialization lifecycle | A non-published tool runs 500 release-mode cases on required Linux, macOS, and Windows CI. Its independent expected-state oracle covers equal counts of publication, setup collision, CRC verification abort, and a destination collision planted by a repository-only seam after staged-tree audit and immediately before native no-replace publication. This exact boundary is deterministic and independent of scheduler timing. It checks exact public axes, receipt lifecycle, findings, capability behavior, destination preservation, and leaked objects. | Run longer native histories; add new cases when the production lifecycle gains states |
| Linux authority bootstrap | A repository-only lab uses an authenticated child-only helper for normal cases and its own executable only for deliberate faults. It transfers the source only after helper-byte, hello, executable-identity, ABI-floor, fixed Landlock ABI 3, and x86_64 seccomp-BPF proofs. It directly probes no-descendant, execution, namespace, permission, ownership, xattr, `ioctl`, rename, link, unlink, mount, and new-socket denial; observes filter mode and exact paused-child descriptors; parses every raw control header; rejects kernel-generated unknown ancillary, malformed layouts, and multiple rights records; distinguishes short data from `MSG_TRUNC` and `MSG_CTRUNC`; and proves descriptor closure on rejected descriptor-bearing packets. Canonical semantic plan, completion, retained-content, and member-read request records cross through bounded sealed memfds with independent length, SHA-256, role, and binding validation. Store plus Deflate plan execution invokes no structural parser and returns 30 original-pass retained fixture bytes in both inspect and materialize modes. After worker reap, the supervisor replays the accepted plan against its retained exact source and requires byte-for-byte agreement for completion and retained content. One-shot later reads receive no stage or destination, stream only one authorized range through a write-only pipe, and release no bytes before complete validation, clean exit, and reap. Their lifecycle evidence covers exact preflight, clones, cancellation, post-result crash isolation, recovery, 64 alternating calls, and last-owner cleanup. The materialize route receives only a supervisor-created stage root, exact source, and sealed plan. Both result descriptors, retained-source replay, exact stage audit, cleanup, and supervisor-only no-replace publication are accepted only after clean exit and exact reap. Targeted writer evidence covers retained-bundle mutation, post-reap stage mutation, destination race, cleanup failure, four crash barriers, and two stalls. Twenty-two abrupt-exit barriers and eleven changing-authority stalls cover the original bootstrap path. One required 500-iteration campaign repeats all 44 original non-stall cases; a second alternates six real writer success and hostile cases. Both check child and descriptor baselines after every iteration. A separate required QEMU TCG gate boots hash-pinned Debian 6.1.0-15-amd64, independently requires observed Landlock ABI 2, and proves the public inspect and materialize routes return typed restriction failure before source transfer with no fallback, destination, leaked stage, sentinel change, or surviving child. The supported request-level supervisor also exercises inspect, materialize, and later-read success through packaged public API smoke. | Add longer-running independently varied worker schedules and near-ceiling read and retained-transfer resource measurements |
| Authenticated Linux helper | The production-only `sealr-worker` target accepts no command or fault selector. Required Linux conformance supplies an absolute path, byte length, and SHA-256; pins it without symlinks through `openat2`; streams the same object into an executable sealed memfd; independently rehashes the retained image; binds a pidfd; validates a nonce-correlated helper hello; and compares `/proc/<pid>/exe` with the retained object before bootstrap or archive transfer. Normal inspect, read, materialize, mutation, timeout, and repeated cases have no lab or `PATH` fallback. Direct invocation and hostile loader tests are required. The Linux package fixes `libexec/sealr/sealr-worker`, binds an exact manifest and helper-aware license closure, and repeats artifact identity, direct-refusal, authenticated handshake, public inspect, public materialize, later reads, exit, and reap checks after hostile-path extraction. macOS and Windows packages are exactly helper-free. | Add concurrent unrelated-exec inheritance stress and CLI runtime integration |
| Private semantic record | Crate-private planning, completion, retained-content, and member-read request frames use independent magic, exact invocation and plan binding, a 64 MiB encoded-length cap, hostile validation, exact re-encoding, pinned vectors, 24 manifest-pinned bounded shadow observations, source-owning inspect and materialize executors with no additional structural parse, and a dedicated fuzz target. The supported Linux supervisor carries those records through authenticated sealed worker handoffs, retains the exact source through observation and reap, treats worker output as a proposal, and accepts it only after exact source-derived replay. Retention and member-read validation bind canonical order, operation, plan, completion, caller limit, size, CRC32, and SHA-256. The public worker-backed `VerifiedArchive` keeps retained bytes local and uses one fresh restricted worker for each non-retained read, including capabilities returned after supervised materialization. The materialize binding requires an opaque target digest; the worker receives only the source, sealed plan, and stage root, while post-reap audit and no-replace publication remain supervisor-owned. A required isolated-child probe pins a 67,041,104-byte plan and bounds transient requested heap for Complete and Stopped reconstruction. | Expand parity beyond the bounded projection; fuzz the member-read request; add near-ceiling read and retained-transfer measurements; accumulate scheduled fuzz history |
| Generic worker semantics | One self-bound private adapter validates and executes the actual sealed-plan profile, policy identity, budget, target, consumer, effect, member-sync, target identity, and retention for inspect and materialize. The helper preserves complete and stopped verification outcomes, validates retained content without duplicating its bytes, and binds one-shot reads to the exact plan and completion. The supervisor reconstructs owned outcome and retention state only from exact source-derived replay. Public fail-closed inspect, materialize, and worker-backed `VerifiedArchive` reads use this adapter. Focused evidence covers a custom policy, strict ASCII v1, exact custom ceilings, one-path retention, operation and effect drift, a bad-CRC stopped frontier, pre-worker destination setup failure, committed publication, retained reads, and one-shot reads. | Expand end-to-end parity across supported public requests and lifecycle failures |
| Model checking | Kani 0.67.0 checks three production scalar kernels with unwind bound 1: interval construction over every pair of `u64` endpoints, atomic quota consumption over every valid `used <= limit` state and `u64` amount, and ratio comparison over every triple of `u64` inputs. The manifest pins each domain, assumption, solver, property, unsupported construct, and nonclaim. Local reproduction completed all three with zero failures. | Accumulate ten distinct successful scheduled `main` runs before any promotion; add separate bounded path and lifecycle models without widening these claims |
| Mutation and source coverage | A weekly bounded workflow records cargo-mutants 27.1.0 outcomes for the three scalar kernels and cargo-llvm-cov 0.9.0 summary JSON for the `sealr` all-features tests. Reports are retained for 30 days, have no coverage threshold, and are discovery-only. | Review missed mutants and blind branches as leads; never report either result as a correctness or security score |
| Audit | Reporting process and automated dependency checks | Independent review after the semantic core stabilizes |

## Evidence vocabulary

Sealr reports assurance at the granularity actually earned.

| Evidence | What it establishes | What it does not establish |
|---|---|---|
| Finite unit or corpus cases | Behavior on the exact named inputs | Behavior outside that finite set |
| Property testing | Behavior across generated examples from a stated strategy | Exhaustiveness or correctness of the generator or oracle |
| Executable specification | Agreement with a simpler independent model over tested inputs | Correctness of either implementation outside the modeled relation |
| Coverage-guided fuzzing | Heuristic exploration guided by observed execution | Exhaustive reachability or absence of defects |
| Bounded model checking | Exhaustive checking within the harness domain, assumptions, and unwind bounds | Correctness beyond those bounds or of unmodeled dependencies |
| Mathematical or deductive proof | The stated theorem under its definitions and assumptions | End-to-end correctness unless the theorem and model cover the full system |
| Native systems testing | Observed behavior under concrete filesystems, kernels, schedules, and fault seams | Universal race freedom or containment against excluded principals |
| Cryptographic evidence | Integrity or authenticity under named algorithms, identities, and verifier policy | Semantic correctness of the claimed archive interpretation |

No row may be summarized as a formally verified extractor. Reports name the property, implementation revision, tool version, assumptions, bounds, platform, and result.

The exact harness, report, and ten-run promotion rules are in [assurance discovery and promotion](assurance-promotion.md). Its machine-readable manifest and ledger keep scheduled evidence categories separate from the one protected required-CI authority.

## ZipDiff gate

CI regenerates the [ZipDiff](https://github.com/ouuan/ZipDiff) construction output at a pinned revision. After verifying that revision, a committed patch replaces the generator's current-time DOS timestamp defaults with zero. The [expectation manifest](../tests/corpus/zipdiff/expectations.txt) binds fixture bytes through an aggregate digest, exact finding counts, and a valid-control allowlist.

The 50-parser Docker farm is not part of CI or the product runtime. If the pinned construction set, bytes, expected findings, or valid controls change, the gate fails until the change is reviewed deliberately.

## Compatibility is a security property

A strict parser that rejects most ordinary inputs will be bypassed. A permissive recovery mode creates another interpretation. The answer is named profiles plus public compatibility evidence.

### Hostile conformance corpus

Every case should bind:

```text
source digest
interpretation profile and version
expected interpretation and admission outcome
expected finding rule identifiers and source spans
expected layout and content roots when defined
```

Include ZipDiff classes, grammar mutations, overlapping ranges, path attacks, quota arithmetic, exact codec stream termination, filesystem races, source mutation, and platform target collisions.

### Benign ecosystem corpus

Measure real artifacts from the domain of each profile. Candidate sources include PyPI wheels and source distributions, Maven and JAR artifacts, Office documents, APKs, GitHub release ZIPs, vendor SDK bundles, and archives produced by common Linux, macOS, and Windows tools.

Publish, per profile and release:

- acceptance rate;
- top rejection rules;
- producer and tool distribution;
- investigated false positives;
- semantic changes and revocations;
- differences across supported operating systems and architectures.

The objective is not maximum acceptance. It is rejection of known ambiguous constructions with high acceptance inside the profile's explicitly supported domain.

The benign corpus must respect licenses, privacy, and redistribution rules. Store digests and reproducible acquisition metadata when raw artifacts cannot be redistributed.

The first [wheel compatibility pilot](wheel-compatibility-pilot.md) implements that acquisition pattern for 20 exact artifacts totaling 90,417,280 source bytes. It binds the manifest, current interpretation-profile digest, default-policy digest, and analyzer revision; records 19 admissions and one investigated three-member expansion-ratio denial; and uses no second ZIP parser. The committed report verifier checks metadata binding, internal counts, profile and policy identity, and canonical rendering in required CI. It does not reacquire or reanalyze the raw wheels in CI, and the sample does not establish ecosystem prevalence.

## Cross-platform determinism

For a stable interpretation profile:

```text
same immutable source bytes + same profile
    -> same ArchiveIR, layout root, and interpretation findings
on supported Linux, macOS, and Windows targets
```

Environment-dependent filesystem effects may differ and are recorded separately. The host must not silently choose path decoding, Unicode normalization, case folding, or archive semantics. Platform-specific projection rules belong to an explicit target filesystem model.

Golden semantic fixtures should run across x86_64 and aarch64 where release infrastructure permits. Evidence fields that legitimately vary by environment must be documented and excluded from semantic tree identity.

## Immutable-source tests

The bounded random-access implementation must preserve the guarantee that interpretation and verification use the same byte object. The first private spool copies the opened source once before interpretation and serves every later range from the retained Sealr-owned read-only file.

Current deterministic coverage includes opened-handle path replacement, source-length mismatch, growth beyond the cap, deterministic same-length in-place mutation, Windows existing-writer exclusion, repeated short reads, interrupted reads, private-directory cleanup, original-path deletion before verified reads, and file-versus-memory semantic parity. Remaining work includes:

- repeated hostile native mutation stress across supported filesystems;
- remote object mutation or inconsistent range responses;
- cache lookup under mismatched source or profile identity.

An arbitrary `ReadAt`, path, file length, or ETag is not sufficient evidence of immutability.

## Codec assurance

For each approved codec backend and version, fixtures must establish:

- valid stream completion;
- exact declared compressed-input consumption;
- exact uncompressed-output size;
- integrity check success;
- rejection of trailing bytes and concatenated alternate streams where the profile permits only one stream;
- distinct findings for malformed, truncated, trailing-input, size, and integrity failures;
- identical accepted output and semantic findings across approved backends.

An acceleration backend cannot change interpretation, accepted bytes, verification completeness, or tree identity.

## Semantic properties

The highest-value generated and machine-checked properties are small:

| Property | Daily evidence | Bounded proof candidate |
|---|---|---|
| Canonical path containment and collision detection | Unit and property tests | Kani or Verus over the pure path core |
| Range non-overlap and complete referenced layout | Shared checked interval construction, separate discovery and covering partition predicates, grammar mutations, and 1,259,962 bounded bitmap-oracle cases | Kani over checked interval arithmetic |
| Monotone quota accounting with no overflow | Shared atomic transition and 159,528 wide-integer oracle cases | Kani over the pure counter core |
| Fail-closed supported policy compilation | Exhaustive reserved-control tests | Finite-state model checking after controls become typed |
| Monotone policy overlays | Deferred until an overlay type exists | Generated and machine-checked properties only after semantics are defined |

The intended lemmas, and the distinction between combinatorial covering, cryptographic assumptions, and systems obligations, are in [theory.md](theory.md). Do not claim a formally verified extractor. A justified future statement would identify the exact pure properties that have machine-checked proofs while stating that parsers and codecs are tested and fuzzed.

## Verification-state tests

The target outcome axes require explicit state-machine tests:

- source read failure is indeterminate, not denied;
- malformed and unsupported inputs remain distinct;
- a filesystem commit failure does not change admission;
- a structure-only result never carries complete content identity;
- partial results name the verified and pending members and stopping cause;
- materialize and projection consume the same IR without reparsing;
- a content-tree root appears only after required content verification completes.

## Filesystem adversarial tests

Continue deterministic and repeated race testing on native Linux, macOS, and Windows filesystems:

- parent and leaf link substitution;
- Windows junction and generic reparse-point mutation;
- destination appearance during staging;
- stage-name and stage-content substitution;
- missing, extra, linked, reparse, duplicate-identity, size-mismatched, and digest-mismatched staged objects;
- cleanup failure and retry;
- crash points before and after each lifecycle transition;
- preservation of existing destinations and unrelated lookalikes.

Each successful publication should eventually match an independently audited admitted-tree manifest exactly.

## Evidence verifier tests

The [identity-conformance verifier](identity-conformance.md) now covers source and profile bytes, semantic-axis coherence, exact findings and IR, the claimed ZIP32 covering, and layout/content root derivation for four finite cases. Its tamper tests cover source, profile bytes, covering, roots, object shape, root availability, and duplicate case identity.

The future general evidence verifier still needs golden accepted and rejected bundles for:

- canonical serialization;
- profile and rule versioning;
- layout and content-root derivation;
- partial and complete verification states;
- effect-record consistency;
- signature, signer identity, issuer, subject, and timestamp checks;
- tampered manifests, roots, envelopes, and effect fields.

Neither verifier extracts the archive, and neither may imply that it independently executed codecs.

## Near-term execution increments

1. **Executable assurance kernel.** Checked interval construction is shared by ZIP discovery and the covering audit. Their separate partition predicates are tested against independent bitmap oracles, while checked range construction is tested against a wide-integer oracle. Declared, actual, remaining, and member quota accounting shares an atomic transition tested against a wide-integer oracle. Strict-profile path and topology planning and outcome lifecycle transitions remain to be extracted and checked.
2. **Bounded model checking.** Check scalar range, ratio, quota, and outcome properties for full integer domains where feasible, plus explicitly bounded adjacent partitions. Run scheduled until cost and stability justify promotion.
3. **Coverage-guided fuzzing.** Fuzz inspect-only ZIP bytes, raw path and topology processing, and covering plus codec boundaries. Apply explicit input, time, memory, and output bounds. Persist every reproducible failure as a deterministic regression.
4. **Systems stress.** Exercise native namespace races, worker failures, stage mutation, audit, cleanup, and no-replace publication repeatedly. Compare every receipt with the executable lifecycle model.
5. **Test-strength and dependency review.** Use targeted mutation testing, coverage reports, and dependency review as review aids. Coverage percentage is not a release claim, and a time-bounded dependency exemption is not an audit.

The detailed budgets and promotion gates are in the [near-term execution plan](near-term.md#assurance-cadence). The existing `CI` workflow remains the only required promotion authority. Scheduled assurance jobs discover evidence. A scheduled gate moves into required CI only after its runtime is bounded, failures reproduce locally, and ten consecutive main runs are stable.

## Continuous program

- Run fast deterministic tests, formatting, strict lints, documentation checks, dependency policy, release-fixture checks, and native platform jobs on every change.
- Keep the protocol and semantic-record fuzz targets, their separate seed manifests, and the scheduled campaigns reproducible.
- Add inspect-only ZIP, topology, covering, and codec targets after each interface is stable.
- Seed later parser targets with locally authored cases and the reproducibly generated ZipDiff corpus where redistribution permits.
- Publish compatibility changes and profile semantics with each release.
- Add public continuous fuzzing after the crate and fuzz interfaces stabilize.
- Commission an external review after the target semantic surface freezes.

## Unsafe policy

The parser, path grammar, and quota core contain no `unsafe`. The shipped crate's current `unsafe` blocks are isolated in the macOS descriptor-ACL and Windows native storage, stage, security-descriptor, and publication adapters with focused invariants and tests. Test-only allocation probes have small documented `GlobalAlloc` wrappers around the system allocator. Their source is present in the source package, but conditional compilation keeps the instrumentation out of normal library and CLI runtime artifacts.

A future memory-mapped source may require a small I/O exception, but mapping mutable archive storage is not an immutable snapshot. Any such adapter must document source-stability requirements and remain outside output handling.
