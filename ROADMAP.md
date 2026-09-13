# Roadmap

Updated 2026-09-13.

Sealr's product is the boundary:

```text
Archive bytes -> versioned interpretation -> verified admitted tree
                                           -> requested effect outcome
All stages                                 -> evidence
```

This source tree targets `v0.1.0-alpha.16`, built with Rust 1.98. The [release page](https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.16) records publication state. Alpha.16 contains typed publisher outcomes, tested evidence and Rust consumer migrations, named durability controls, and reproducible assurance bookkeeping. The owner-maintained [validation project](https://github.com/blisspixel/sealr-validation) consumes real release artifacts. Independent adoption and an independent security audit remain unproven.

Progress and release readiness use executable evidence. Human approval, adopter recruitment, and paid review are not prerequisites. Automation cannot manufacture independent adoption or audit claims. Existing fail-closed CI, artifact authentication, semantic identities, and security limits still apply.

The [optional external pilot](docs/adopter-pilot.md) retains its independent
ownership and attribution requirements without gating technical progress.

## Why this order

The publisher and migration gaps now have executable consumer evidence. A controlled downstream run also shows substantial repeated-read cost for a small known working set, but does not identify which internal phase dominates. Measure that attribution before changing authority or adding runtime complexity. Lifecycle gaps and coordinated dependency maintenance remain explicit work. More formats would increase trusted code before answering those questions.

```text
typed outcomes and tested consumer migrations
    -> bounded attribution of repeated-read costs
    -> justified implementation changes and lifecycle closure
    -> accumulated assurance and complete compatibility scope
    -> scoped stable-release decision
```

The [near-term plan](docs/near-term.md) defines deliverables and exit criteria. The [execution record](docs/autonomous-improvement.md) preserves reasoning, measurements, artifact provenance, and costs.

## Completed increments

| Increment | Executable evidence |
|---|---|
| Typed publisher outcomes | Versioned failure reports, preserved success reports, two accepted Linux variants and ten refusals |
| Ordinary artifact replay | Immutable Alpha.15 Git source, authenticated matching native release, and bounded process-tree source-open observations |
| Evidence migration | Five packaged cases refuse legacy and mixed lineages and keep verified rejection evidence consumer-denied |
| Rust consumer migrations | Six real outcome cases separate `VerifiedArchive` authority from requested effects; named `Durability` selections preserve historical policy and worker bytes |
| Assurance bookkeeping | Bounded read-only collection, deterministic ledger replay, 47 behavioral tests, and a preserved eight-entry September 13 observation |

These close the named increments, not a stable API freeze or lifecycle qualification. All four planned replacements now have tested migration rules in the [candidate inventory](docs/candidate-surface.md). Exact local validation scope remains in the execution record.

## Active execution queue

### 1. Attribute repeated-read costs before changing the boundary

The [controlled downstream observation](docs/capability-reuse-experiment.md#controlled-repeated-read-observation) used released Alpha.15 and eight members totaling 363,559 bytes. Across six measured pairs, median totals for 16 read calls were 3.685663 seconds without retention and 0.000056 seconds with those members retained. Separate returned-byte digest checks and initial admission are excluded. This is a local warm-cache comparison, not a full-installation benchmark or latency promise.

Measure source hashing, plan validation, worker setup, and payload verification separately under fixed input, ordering, repetition, and resource bounds. Record diagnostic-build differences explicitly. Retention bypasses several costs together, so this result cannot attribute the difference to hashing, decompression, or process creation alone.

Done means a bounded reproducible report identifies the work worth changing while preserving semantic identities, complete verification, mutation detection, byte limits, cancellation, and reap. A private validated read authority or process pool remains a proposal until that evidence justifies it.

### 2. Close lifecycle gaps beyond named member syncing

`Durability::FlushOnly` and `Durability::MemberSync` now name the existing behavior precisely. Both retain private staging and native no-replace publication. Neither provides directory syncing, crash recovery, or power-loss durability.

Specify authenticated abandoned-stage ownership and recovery before implementing cleanup. Exercise interruption at creation, writes, audit, publication, and cleanup, plus hostile renames, links, unrelated neighbors, and existing destinations on each advertised platform. Never recover by recursively deleting a filename pattern.

Done means each additional lifecycle guarantee has a versioned contract and reproducible fault evidence. Existing named durability selections must not silently acquire a stronger claim.

### 3. Keep compatibility, assurance, and dependencies current

Accumulate genuine scheduled history using the [promotion contract](docs/assurance-promotion.md) and replay tools. The September 13 snapshot leaves every category ineligible and unpromoted under the unchanged ten-distinct-commit rule. Coverage and mutation remain discovery-only. A saved report cannot itself authorize promotion.

Prepare one coordinated dependency closure update for the flate2, lzma, and CRC changes exposed by partial maintenance PRs 121 and 122. Update root, fuzz, proof, and consumer lockfiles together; regenerate dependency, license, and TCB evidence; then pass locked checks. The split updates fail contract gates and are deferred maintenance, not a reason to merge them blindly or block the unchanged release dependency set.

Keep compatibility vectors and tested migration rules current, then write a scoped freeze proposal when all advertised surfaces have evidence. External feedback may add concrete cases whenever it arrives; a maintainer interview is not an exit condition.

### 4. Replay each new release without rewriting historical evidence

Preserve exact-commit CI, provenance, immutable tags, checksums, matching companions, and release readback. The downstream Alpha.15 observations retain their original source and artifact pins. Adopting Alpha.16 requires a new explicit acquisition and replay record; old reports do not become Alpha.16 results by relabeling them.

GitHub-only distribution remains supported. A future crates.io version requires truthful tagged documentation and registry readback; existing GitHub-only releases must not be uploaded retroactively.

## Stable 1.0 gates

Every applicable technical gate must pass before the corresponding stable claim. No gate requires a person to respond or approve.

| Gate | Required executable evidence |
|---|---|
| Usefulness | An isolated artifact-consuming workflow completes through the capability after source removal, with a no-reopen check and typed outcomes |
| Semantic stability | Versioned profiles, policy identities, tree encodings, and canonical schemas have cross-version vectors and migration rules |
| API stability | Rust API, CLI machine output, MSRV, package layout, and SemVer policy pass pinned downstream compatibility checks |
| Cross-platform boundary | Each advertised platform preserves interpretation, identity, path, quota, rollback, and no-replace publication invariants |
| Worker boundary | Every reduced-authority operation has explicit scope, fail-closed setup, authenticated packaging, lifecycle tests, and no fallback |
| Lifecycle and durability | Recovery, cleanup, sync, publication durability, and power-loss limitations are explicit and tested |
| Assurance | Required CI is green, qualifying scheduled histories are captured, reproducible defects have regressions, and the TCB report is current |
| Distribution | Exact source and native artifacts satisfy the [distribution contract](docs/distribution-contract.md) without repository-only patches |
| Honesty | README, security policy, API docs, and release notes match tested behavior and explicitly state independent adoption and audit status |

Independent review is a separate assurance observation. A stable version must not imply an audit, safety to execute admitted code, or guarantees beyond the tested scope. Current releases remain development previews.

## Later roadmap

After publisher, stability, and lifecycle increments have executable proof, consider semantic locks, verified content-addressed blobs, read-only projection, and materialization from verified content. See [reusable admitted trees](docs/bigger.md).

Format breadth remains lower priority. Each new codec or container needs a consumer reason, versioned language, exact input consumption, dependency analysis, hostile and benign evidence, and identity vectors. Parked 7z and additional ZIP methods retain the [codec gates](docs/codec-dependency-gates.md).

Agent workspaces and hermetic build inputs are the next consumer candidates. Bindings, signatures, parallel verification, alternate backends, and a hosted service follow measured demand and stable claims. See the [vision](docs/vision.md) and [backend strategy](docs/backends.md).

## Decision rules

- Increase justified trust and useful downstream work per unit of trusted code.
- Keep one interpretation, bounded resources, and no-replace publication.
- Preserve historical profile identities and published measurement reports.
- Keep runtime dependencies small and document each capability and audit boundary.
- Treat fuzzing, model checking, mutation, systems stress, and independent review as distinct evidence with distinct limits.
- Select the next bounded increment from observed failures and measurements, implement it, run the relevant checks, update the evidence, and repeat.
- Keep external purchases at $0 by default and never exceed the $5 aggregate cap. See the [cost policy](docs/autonomous-improvement.md#cost-policy).

## Documentation map

| Question | Source |
|---|---|
| What works now? | [README](README.md), [API](docs/api.md), [security policy](SECURITY.md) |
| What changed? | [Milestones](docs/milestones.md), [changelog](CHANGELOG.md), [Alpha.16 notes](docs/releases/v0.1.0-alpha.16.md) |
| What is the next bounded plan? | [Near-term execution](docs/near-term.md) and [iteration record](docs/autonomous-improvement.md) |
| What may a consumer pin? | [Candidate inventory](docs/candidate-surface.md) |
| What proves usefulness? | [Usefulness test](docs/usefulness.md) |
| What assurance exists? | [Assurance](docs/assurance.md) and [promotion contract](docs/assurance-promotion.md) |
| What remains a limitation? | [Implementation](docs/implementation.md#security-limitations) and [threat model](docs/threat-model.md) |
