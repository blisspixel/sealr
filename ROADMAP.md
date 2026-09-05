# Roadmap

Updated 2026-09-04.

Sealr's product is the boundary:

```text
Archive bytes -> versioned interpretation -> verified admitted tree
                                           -> requested effect outcome
All stages                                 -> evidence
```

The latest release is `v0.1.0-alpha.13`. It proves the boundary inside this repository through a supported wheel evaluator, an authenticated reduced-authority Linux worker, an independently implemented evidence verifier, a copyable PyPA `WheelSource` handoff, and an exact Poetry 2.4.2 fixture. It does not yet prove that another project can depend on this boundary successfully.

That missing external proof now determines the order of work. Parser breadth is frozen until the usefulness, stability, and review gates below are met.

## Current position

| Area | Current state | Remaining product gate |
|---|---|---|
| Interpretation | Twelve explicit container and codec selections, each fail closed and separately identified | Preserve existing profiles while compatibility evidence drives any new profile |
| Capability | Fully verified outcomes expose `VerifiedArchive`; consumers need not reopen the source | Prove that contract in a separately maintained consumer |
| Linux execution | Supported ZIP32 verification, stage writes, and later reads can run in an authenticated Landlock and seccomp worker | Decide the stable supported scope and close remaining lifecycle evidence |
| Evidence | Canonical RFC 8785 view and receipt documents can be checked by the independent packaged verifier | Freeze the stable claim and schema only after adopter feedback |
| Wheel consumer | Public evaluator, copied PyPA handoff, and exact Poetry fixture pass repository CI | Establish external adoption and measure the compatibility gaps it exposes |
| Distribution | The `sealr` crate package and three native package floors are checked in CI with Rust 1.98 | Select and exercise an ordinary prerelease delivery path for the adopter |
| Assurance | Required deterministic gates and scheduled discovery are active | Accumulate the defined history, close material race and lifecycle gaps, and complete independent review |

The [current release notes](docs/releases/v0.1.0-alpha.13.md) define the Alpha.13 delta and limitations. The [milestone history](docs/milestones.md) links every earlier preview to its immutable release notes. Current executable behavior remains in the [README](README.md), [API contract](docs/api.md), and [security policy](SECURITY.md).

## Why external adoption is next

Repository fixtures have answered whether the mechanism can work. They have not answered whether the public API, package split, evidence handoff, failure model, and documentation are usable without repository knowledge.

The next dependency chain is therefore:

```text
external adopter pilot
    -> observed compatibility and API friction
    -> candidate API, identity, and evidence freeze
    -> independent security review
    -> stable-release decision
```

Changing this order would create avoidable risk:

- another format would add trusted code without testing the product claim;
- freezing the API before adoption would preserve assumptions instead of usage;
- commissioning the final review before the surface settles would review code that adopter feedback may change;
- signing evidence before the claim is stable would authenticate an unsettled contract.

The [usefulness test](docs/usefulness.md) defines the product proof. The [near-term execution plan](docs/near-term.md) turns it into bounded work packages and acceptance criteria.

## Active execution queue

### 1. Complete one external adopter pilot

Target one separately maintained publisher, registry, build backend, or installer with a narrow wheel workflow on x86_64 Linux, where Sealr's strongest worker boundary is available.

The exact baseline artifact, semantic, handoff, negative-test, and reporting requirements are now pinned by the [external adopter pilot contract](docs/adopter-pilot.md). Required CI rejects drift between that contract, the package manifests, native floor, profile and policy identities, consumer digest, helper protocol, evidence schemas, and installer bridge. No external adopter has accepted the contract and no publishable pilot release has been assigned. Alpha.13 remains the verified baseline and must not be retroactively uploaded because its immutable packaged README describes it as GitHub-only.

The pilot must:

1. consume only the public `sealr` API and authenticated native release artifacts;
2. independently verify canonical evidence before accepting the result;
3. keep the exact wheel plan in the trusted Rust side of the handoff;
4. make the original wheel unavailable after admission;
5. complete through `VerifiedArchive` member access without another ZIP parser;
6. prove through an open hook or equivalent trace that the source is not reopened;
7. publish its supported scope, failure behavior, compatibility results, and nonclaims.

Done means the integration and its CI are maintained outside Sealr's repository and treat Sealr's admitted capability as authoritative. A copied example, fork maintained as a fixture, or receipt followed by another unzip does not pass.

### 2. Use the pilot to prepare a stable semantic surface

Run this work alongside the pilot, but do not declare a freeze until integration feedback exists.

1. After agreeing the adopter scope, cut a new prerelease whose allowlisted `sealr` crate and authenticated native worker and verifier package come from the same clean tag. Publish and read back that crate through an ordinary registry path. Do not retroactively publish Alpha.13 or make a local path patch the long-term integration contract.
2. Inventory the public Rust API, interpretation profile identifiers, policy identities, tree encodings, canonical evidence schemas, CLI machine output, MSRV, and native package layout.
3. Record every adopter-requested change and classify it as additive, breaking, profile-versioned, schema-versioned, or documentation-only.
4. Extend the benign wheel corpus where present evidence is weak, especially Unicode member paths and data-descriptor-bearing wheels. Preserve byte-addressed acquisition and investigated rejection clusters.
5. Publish a candidate-freeze document that names what is stable, what remains preview, and how future migrations work.

Done means a downstream integration can update deliberately, every semantic change receives a new identity where required, and the candidate surface has no known repository-only assumption.

### 3. Close the production-readiness evidence

The project can prepare these gates in parallel with adoption. Final review waits for the candidate surface.

1. Accumulate the scheduled-assurance history defined by the [promotion contract](docs/assurance-promotion.md), preserving each evidence category's stated bounds and nonclaims.
2. Complete repeated hostile namespace and content-mutation stress on the supported materialization platforms.
3. Decide and implement the stable crash-recovery and durability contract. Current flush-only behavior, possible abandoned stages, and absent directory-sync guarantees cannot be hidden behind a stable claim.
4. Measure and review the trusted computing base, including runtime dependencies, platform `unsafe`, helper packaging, and codec-specific audit boundaries.
5. Freeze the independent-review scope, commission the review, resolve release-blocking findings, and rerun the affected evidence.

Done means the stable claim is narrower than or equal to the behavior covered by required CI, accumulated assurance, and independent review.

## Stable 1.0 gates

All rows must be green before a stable release.

| Gate | Required evidence |
|---|---|
| External usefulness | A separately maintained consumer uses the admitted capability and independently verified evidence without reopening the archive |
| Semantic stability | Advertised profiles, policy identities, tree encodings, and evidence schemas are frozen with compatibility vectors and migration rules |
| API stability | Public Rust API, CLI machine output, MSRV, package layout, and SemVer policy pass downstream compatibility review |
| Cross-platform boundary | Every advertised platform preserves interpretation, identity, path, quota, rollback, and no-replace publication invariants |
| Worker boundary | Every advertised reduced-authority operation has explicit scope, fail-closed setup, authenticated packaging, lifecycle evidence, and no fallback |
| Lifecycle and durability | Crash recovery, cleanup, file sync, directory sync, publication durability, and power-loss nonclaims are explicit and tested |
| Assurance | Required deterministic gates are green, scheduled histories meet their promotion rules, reproducible failures are regressions, and the TCB report is current |
| Independent review | The frozen security surface has been reviewed independently, blocking findings are resolved, and fixes are retested |
| Distribution | Source and native artifacts satisfy the [distribution contract](docs/distribution-contract.md) and can be consumed without repository-only patches |
| Honesty | The README, security policy, API docs, and release notes describe exactly the supported behavior and residual risk |

Preview releases may deliver individual gates before 1.0. A version label is not permission to ship a red gate.

## Work that remains parallel

The first targeted compatibility increment is implemented: a [24-artifact Unicode and streaming producer matrix](docs/wheel-producer-compatibility.md), source-deletion and native materialization regressions, and the copied supervised installer checks. It exposed an incomplete Deflate stream that retained matching plaintext and checksums; the shared decoder now requires explicit stream completion. The next compatibility increment should use real adopter artifacts and an independently maintained downstream CI path.

These tracks may proceed while the adopter pilot runs because they strengthen the existing boundary without adding another interpretation:

- targeted wheel compatibility measurement;
- scheduled fuzzing, model checking, mutation discovery, and native fault stress;
- TCB measurement and dependency review;
- authenticated abandoned-stage recovery and explicit durability levels;
- ZIP64 and TAR worker-record design, provided unsupported selections continue to fail closed;
- documentation, examples, and adopter support;
- structure, verification, realization, and avoided-work benchmarks.

The exact assurance claims and promotion rules live in [docs/assurance.md](docs/assurance.md) and [docs/assurance-promotion.md](docs/assurance-promotion.md). Tooling migration and dependency discipline live in [docs/tooling.md](docs/tooling.md).

## Later roadmap

Later work is ordered by evidence, not by format count.

### Reusable admitted trees

After the external capability contract is proven, add semantic locks, verified content-addressed blobs, read-only projection, and materialization from verified content. Repeated consumers should avoid a second parse, inflation, and write while preserving explicit verification state. See [docs/bigger.md](docs/bigger.md).

### Format and codec breadth

After usefulness and review, resume the parked 7z LZMA/LZMA2 member and packed-header work. ZIP methods 12, 93, and 95, Deflate64, cpio, ar/deb, CAB, RPM, and restricted RAR5 remain separately gated. Each addition needs a versioned language, exact-consumption boundary, dependency review, hostile and benign evidence, independent identity vectors, and a consumer reason. The current matrix and promotion gates are in [docs/format-support.md](docs/format-support.md) and [docs/codec-dependency-gates.md](docs/codec-dependency-gates.md).

### Additional consumers

Agent workspaces and hermetic build inputs are the leading candidates after the wheel boundary is externally proven. OCI, JAR, APK, and language bindings follow only when a real consumer's semantics and authority handoff are explicit. See [docs/vision.md](docs/vision.md).

### Authenticated claims and performance

Signatures, attestations, content-addressed reuse, parallel member verification, and alternate backends follow stable canonical claims and measured bottlenecks. Authentication does not replace interpretation or verification. Performance work must preserve identical trees, findings, evidence, and failure behavior. See [docs/attestations.md](docs/attestations.md) and [docs/backends.md](docs/backends.md).

## Decision rules

Choose the work that most increases justified trust in the boundary per unit of trusted code.

- Keep one interpretation. No recovery parser, fallback extractor, or `--insecure` mode.
- Keep the runtime dependency graph small enough to review. Every addition needs a written capability, license, advisory, transitive-size, native-code, build-script, and `unsafe` review.
- Preserve exact compressed-input consumption, checked resource accounting, canonical paths, and no-replace publication across every adapter.
- Treat corpus, fuzzing, model checking, systems stress, and review as different evidence types. None inherits another's claim.
- Prefer external usefulness, compatibility evidence, and lifecycle closure over more formats, bindings, signing, acceleration, or presentation work.

## Documentation map

| Question | Source |
|---|---|
| What works now? | [README](README.md), [API contract](docs/api.md), and [security policy](SECURITY.md) |
| What changed in each preview? | [Milestone history](docs/milestones.md), [changelog](CHANGELOG.md), and [release notes](docs/releases/v0.1.0-alpha.13.md) |
| What is the next bounded plan? | [Near-term execution plan](docs/near-term.md) |
| What may the first pilot pin? | [Candidate surface inventory](docs/candidate-surface.md) |
| What proves usefulness? | [Usefulness test](docs/usefulness.md) |
| What is the product direction? | [Vision](docs/vision.md) |
| Which formats and codecs are supported or gated? | [Format support architecture](docs/format-support.md) |
| What assurance exists? | [Assurance](docs/assurance.md) and [promotion contract](docs/assurance-promotion.md) |
| What can be distributed? | [Distribution contract](docs/distribution-contract.md) |
| What remains a security limitation? | [README security limitations](README.md#security-limitations) and [threat model](docs/threat-model.md) |
