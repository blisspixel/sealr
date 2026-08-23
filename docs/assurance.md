# Testing, compatibility, and assurance

> This page separates current evidence from the target assurance program. The published Alpha.3 has a deterministic Rust unit suite, strict cross-platform CI, cargo-deny policy, and a pinned 5,927-file ZipDiff construction gate. Current main adds six finite-domain property families, an opaque bounded-read capability with one-pass exact-member retention, a consumer that runs against the extracted packaged crate, an independent verifier for four identity-conformance cases, and an initial 20-wheel compatibility measurement. Broader ecosystem sampling, property families, coverage-guided fuzzing, model checking, the general authenticated-evidence verifier, and an external audit remain future work.

Trust is the scarce resource. Format breadth and acceleration follow stable semantics and measured compatibility.

## Current evidence

| Layer | Current evidence | Remaining work |
|---|---|---|
| Unit | ZIP path grammar, topology, overlap and layout, quotas, inspect/materialize equality, rollback, destination preservation, platform materializer controls, and deterministic truncation, mutation, and noise no-panic coverage | Expand for every new semantic state and backend |
| Public API and package | External-crate fixture exercises evidence types, `VerifiedArchive`, and bounded retention; a separate Cargo consumer runs the same retention path against the extracted packaged crate in required quality CI | Add semantic compatibility checks after publication and a wheel-aware metadata selector |
| Corpus | All 5,927 pinned ZipDiff constructions, local generated adversarial fixtures, and a byte-addressed non-shipping pilot of 20 exact PyPI wheels with an investigated denial cluster | Expand producer and feature diversity; add codec-boundary, source-race, and wheel-semantic fixtures |
| Differential | ZipDiff expectation gate binds strict rejection and a documented valid-control allowlist | Compare major consumers on well-formed profile inputs and track disagreement frontiers |
| Property | Six finite-domain families: compression ratio against quotient and remainder; verified-member limits against `limit >= measured_size`; retention selection over 8,125 size and limit combinations; checked `offset + len` against `u128` over 4,624 boundary pairs; exact partitions against a per-byte bitmap over 1,055,758 lists of zero through three intervals; atomic quota transitions against `u128` over 159,528 valid states and increments | Add independent bounded models for strict-profile path topology and lifecycle transitions |
| Fuzz | None yet | `cargo fuzz` targets for interpretation, canonical paths, and inspect-only `apply()` |
| Executable specification | A no-Sealr-dependency verifier agrees with production evidence on four exact identity cases and independently checks their covering, profile digest, and roots | Add independent bounded models for ranges, quotas, paths, and lifecycle transitions; extend identity cases with each published profile and encoding branch |
| Model checking | None yet | Add Kani harnesses with explicit domains, assumptions, and unwind bounds |
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

The future bounded random-access implementation must retain the whole-buffer guarantee that interpretation and verification use the same byte object.

Test at least:

- truncation after structural interpretation;
- growth and alternate payload insertion;
- in-place payload mutation through another handle;
- path replacement while a snapshot is active;
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
| Range non-overlap and complete referenced layout | Shared production kernel, grammar mutations, and 1,055,758 bounded bitmap-oracle cases | Kani over checked interval arithmetic |
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

1. **Executable assurance kernel.** Checked interval and partition logic is shared by ZIP discovery and covering audit and tested against independent wide-integer and bitmap oracles. Declared, actual, remaining, and member quota accounting shares an atomic transition tested against a wide-integer oracle. Strict-profile path and topology planning and outcome lifecycle transitions remain to be extracted and checked.
2. **Bounded model checking.** Check scalar range, ratio, quota, and outcome properties for full integer domains where feasible, plus explicitly bounded adjacent partitions. Run scheduled until cost and stability justify promotion.
3. **Coverage-guided fuzzing.** Fuzz inspect-only ZIP bytes, raw path and topology processing, and covering plus codec boundaries. Apply explicit input, time, memory, and output bounds. Persist every reproducible failure as a deterministic regression.
4. **Systems stress.** Exercise native namespace races, worker failures, stage mutation, audit, cleanup, and no-replace publication repeatedly. Compare every receipt with the executable lifecycle model.
5. **Test-strength and dependency review.** Use targeted mutation testing, coverage reports, and dependency review as review aids. Coverage percentage is not a release claim, and a time-bounded dependency exemption is not an audit.

The detailed budgets and promotion gates are in the [near-term execution plan](near-term.md#assurance-cadence). The existing `CI` workflow remains the only required promotion authority. Scheduled assurance jobs discover evidence. A scheduled gate moves into required CI only after its runtime is bounded, failures reproduce locally, and ten consecutive main runs are stable.

## Continuous program

- Run fast deterministic tests, formatting, strict lints, documentation checks, dependency policy, release-fixture checks, and native platform jobs on every change.
- Add property tests and fuzz smoke tests once targets are stable.
- Seed coverage-guided fuzzing with ZipDiff and local adversarial fixtures.
- Add longer scheduled fuzzing only after runtime and cost are measured.
- Publish compatibility changes and profile semantics with each release.
- Add public continuous fuzzing after the crate and fuzz interfaces stabilize.
- Commission an external review after the target semantic surface freezes.

## Unsafe policy

The parser, path grammar, and quota core contain no `unsafe`. The current macOS descriptor-ACL and Windows native storage, stage, security-descriptor, and publication adapters are isolated exceptions with focused invariants and tests.

A future memory-mapped source may require a small I/O exception, but mapping mutable archive storage is not an immutable snapshot. Any such adapter must document source-stability requirements and remain outside output handling.
