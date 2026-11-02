# Roadmap

Updated 2026-11-02.

Sealr's product is the boundary:

```text
Archive bytes -> versioned interpretation -> verified admitted tree
                                           -> requested effect outcome
All stages                                 -> evidence
```

This source tree targets `v0.1.0-alpha.19`, built with Rust 1.99. Published native archives are on the [Alpha.19 release page](https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.19). Alpha.19 explains a refusal on the terminal and pins finding-code discriminants. It does not change admission or policy. Alpha.18 admits minimal GNU tar records and keeps `max_ratio` at 100. Alpha.17 contains typed publisher outcomes, tested evidence and Rust consumer migrations, named durability controls, and reproducible assurance bookkeeping. The owner-maintained [validation project](https://github.com/blisspixel/sealr-validation) consumes real release artifacts. Independent adoption and an independent security audit remain unproven. Repeated-read phases are measured. Linux and macOS can return a stage-retention record after failed cleanup and remove that one directory when the record is presented again. A caller-chosen retention file can survive process death after it is written. Windows does not record a file identifier. That remaining lifecycle gap comes before the deferred flate2, lzma, and CRC closure.

Progress and release readiness use executable evidence. Human approval, adopter recruitment, and paid review are not prerequisites. Automation cannot manufacture independent adoption or audit claims. Existing fail-closed CI, artifact authentication, semantic identities, and security limits still apply.

The [optional external pilot](docs/adopter-pilot.md) retains its independent
ownership and evidence requirements without gating technical progress.

Alpha.17 starts a new owner-controlled distribution history. Earlier remote
releases and runs are retired; all six active assurance histories restart at
zero. The observations below remain historical evidence. See
[distribution history](docs/distribution-history.md).

## Why this order

The publisher and migration gaps now have executable consumer evidence. A controlled downstream run showed substantial repeated-read cost but did not identify which phase dominated. The [phase observation](docs/repeated-read-phases.md) separates source hashing, plan validation, worker setup, and payload verification for two archive sizes. Failed cleanup on Linux and macOS can return a stage-retention record, and recovery removes that one presented directory. A caller-chosen retention file can keep that record across process death. Windows does not record a file identifier. The deferred flate2, lzma, and CRC closure follows that remaining lifecycle gap. The zip and Poetry fixture Dependabot closure is current. More formats would increase trusted code before that work is done.

```text
typed outcomes and tested consumer migrations
    -> measured time spent in each repeated-read phase
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

### 1. Repeated-read phases are measured

The [controlled downstream observation](docs/capability-reuse-experiment.md#controlled-repeated-read-observation) used released Alpha.15 and eight members totaling 363,559 bytes. Across six measured pairs, median totals for 16 read calls were 3.685663 seconds without retention and 0.000056 seconds with those members retained. Separate returned-byte digest checks and initial admission are excluded. This is a local warm-cache comparison, not a full-installation benchmark or latency promise. Retention bypasses several costs together, so that result cannot attribute the difference to hashing, decompression, or process creation alone.

The [phase observation](docs/repeated-read-phases.md) is a separate diagnostic. On a 6,152-byte archive, worker setup was most of the unretained time. On an 8,394,850-byte archive with the same eight 45,000-byte members and one unread pad, supervisor hashing and the child snapshot work inside worker setup were most of the time. Payload verification of the requested member stayed near one millisecond. Retained reads recorded no phase samples. Semantic identities, complete verification, mutation detection, byte limits, and reap were preserved. A private validated read authority or process pool remains a proposal. A later change has to account for both repeated full-file hashing and process setup.

### 2. Close lifecycle gaps beyond named member syncing

`Durability::FlushOnly` and `Durability::MemberSync` name the existing behavior. Both retain private staging and native no-replace publication. Neither provides directory syncing, crash recovery, or power-loss durability.

[Abandoned-stage ownership](docs/abandoned-stage.md) (`sealr.abandoned-stage.v1`) specifies the gap. A live operation authenticates the stage by the retained directory capability. Linux and macOS require the stage name to identify that same device and inode before publication. Windows keeps the stage handle without delete sharing. Cleanup removes that retained object, with one exact-name retry only where setup cleanup already does, and never by listing `.sealr-stage-*`. A later materialization leaves an abandoned stage, a same-shaped lookalike, a link, an unrelated file, and a pre-existing directory in place. An existing destination is preserved by the publication tests.

Failed cleanup on Linux and macOS returns `sealr.stage-retention.v1` from `Outcome::stage_retention`. The record holds the exact component and the `sealr.stage-witness.v1` device and inode. It is not written into `sealr.materialization.v2` or `sealr.receipt.v3`. `ApplyOptions::with_stage_retention_path` writes that same record to a caller-chosen file after the stage exists and removes the file when the stage is removed or published. A process killed after that write leaves the file. A process killed before the write still has no record. `recover_abandoned_stage` removes the opened directory only when the caller presents that record and every current namespace check passes. Windows does not record a file identifier, so a requested path fails closed and recovery removes nothing there. Same-user replacement remains outside the in-process boundary. Do not add filename-pattern cleanup.

Done means each additional lifecycle guarantee has a versioned contract and reproducible fault evidence. Existing named durability selections must not silently acquire a stronger claim. This specification and its preservation tests are the current evidence. Directory sync, crash recovery, and power-loss durability are still absent.

### 3. Keep compatibility, assurance, and dependencies current

Accumulate genuine scheduled history using the [promotion contract](docs/assurance-promotion.md) and replay tools. The September 13 snapshot leaves every category ineligible and unpromoted under the unchanged ten-distinct-commit rule. Coverage and mutation remain discovery-only. A saved report cannot itself authorize promotion.

The open Dependabot alerts are closed by one closure: `zip` 9.2.2 in the workspace and both downstream consumer lockfiles, with the cargo-deny ignores for the extract-only advisories removed, and the Poetry 2.4.2 fixture refreshed to certifi 2026.10.23, filelock 4.2.7, msgpack 1.2.4, urllib3 2.8.0, and virtualenv 21.15.2. Poetry itself, Poetry Core, installer, and pip stay pinned. The runtime dependency closure is unchanged.

The flate2, lzma, and CRC changes exposed by partial maintenance PRs 121 and 122 remain one later coordinated update. Update root, fuzz, proof, and consumer lockfiles together; regenerate dependency, license, and TCB evidence; then pass locked checks. The split updates fail contract gates and are deferred maintenance, not a reason to merge them blindly or block the unchanged release dependency set.

Keep compatibility vectors and tested migration rules current, then write a scoped freeze proposal when all advertised surfaces have evidence. External feedback may add concrete cases whenever it arrives; a maintainer interview is not an exit condition.

### 4. Replay each new release without rewriting historical evidence

Preserve exact-commit CI, provenance, immutable tags, checksums, matching companions, and release readback. The downstream Alpha.15 observations retain their original source and artifact pins. Adopting Alpha.17 or Alpha.18 requires a new explicit acquisition and replay record; old reports do not become later results by relabeling them.

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
| What changed? | [Milestones](docs/milestones.md), [changelog](CHANGELOG.md), [Alpha.19 notes](docs/releases/v0.1.0-alpha.19.md) |
| What is the next bounded plan? | [Near-term execution](docs/near-term.md) and [iteration record](docs/autonomous-improvement.md) |
| What may a consumer pin? | [Candidate inventory](docs/candidate-surface.md) |
| What proves usefulness? | [Usefulness test](docs/usefulness.md) |
| What assurance exists? | [Assurance](docs/assurance.md) and [promotion contract](docs/assurance-promotion.md) |
| What remains a limitation? | [Implementation](docs/implementation.md#security-limitations) and [threat model](docs/threat-model.md) |
