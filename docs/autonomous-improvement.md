# Autonomous improvement record

Updated 2026-09-13.

This file preserves the original iteration observations. Alpha.17 starts a new
owner-controlled repository history; earlier remote releases, tags, and run
identities are retired. Their recorded hashes and measurements are historical,
not active acquisition or qualification claims. All six active assurance
histories restart at zero. See [distribution history](distribution-history.md).

## Objective and loop

Make Sealr an exceptional archive boundary by completing bounded, evidence-driven
increments: select an observed gap, define an executable acceptance test,
implement the change, validate it, update the plan, and repeat. The
[roadmap](../ROADMAP.md) orders the work; the [near-term plan](near-term.md)
contains acceptance criteria. Human approvals, adopter recruitment, and paid
reviews are not dependencies.

This record tracks engineering work and evidence. It does not certify independent
adoption, an independent audit, or completion of the stable technical gates.

## Research findings

Three parallel research tracks examined the product plan, implementation, and
automation. Their converging first recommendation was the existing publisher
gate's failure contract. The code admits a wheel and makes a useful business
decision, but Alpha.15 returns success JSON only and collapses every failure into
text and exit `1`. A machine-readable failure report closes a practical consumer
gap without adding a parser, dependency, or runtime authority.

| Priority | Evidence | Decision |
|---|---|---|
| Publisher outcomes | Alpha.15 content gate has no structured failure result; the downstream contract requires failure separation | Add typed stage/code reports and process-level refusal checks |
| Ordinary acquisition | Packaged consumers prove composition through extracted-crate path patches | Replay immutable artifacts in an isolated owner-maintained consumer |
| Candidate stability | Inventory already identifies public surfaces and planned replacements | Require compatibility vectors and migrations rather than an adopter interview |
| Full-install cost | First Deepr observation spends 209.286 of 225.607 seconds staging members | Measure controlled repeated reads before changing source-binding authority |
| Assurance bookkeeping | Successful scheduled runs exist, while the committed ledger has empty histories | Build a read-only collector that preserves domain, attempt, and failure history |
| Dependency maintenance | Two open dependency PRs fail coordinated lockfile and dependency-evidence checks | Refresh related locks and actual measurements together; preserve the gates |

The full-install figures are single observations from the
[retention experiment](capability-reuse-experiment.md). They do not establish a
general speedup or justify dropping source validation.

The external technical sources support the chosen integration scope. Wheel
installation requires RECORD hash checks, so matching member names alone cannot
replace archive and wheel verification. See the
[PyPA wheel specification](https://packaging.python.org/en/latest/specifications/binary-distribution-format/).
Cargo supports exact Git revisions and records Git dependency commits in the
lockfile, providing a source acquisition option while releases remain GitHub-only.
See [Cargo dependency sources](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html).
Native companions still need their own authentication and version checks.

Read-only GitHub observations on 2026-09-13:

- Alpha.15 [CI](https://github.com/blisspixel/sealr/actions/runs/33978431616),
  [release](https://github.com/blisspixel/sealr/actions/runs/33979176995), and
  [exact-commit fuzz](https://github.com/blisspixel/sealr/actions/runs/33978434439)
  succeeded. These results describe the released commit, not the current edits.
- Scheduled assurance succeeded on
  [September 2](https://github.com/blisspixel/sealr/actions/runs/33615049485) and
  [September 9](https://github.com/blisspixel/sealr/actions/runs/34335686928).
  [September 1 resource evidence](https://github.com/blisspixel/sealr/actions/runs/33482339571)
  also succeeded. These observations do not establish ten qualifying runs or
  authenticate an entire consecutive history.
- Dependency [PR 121](https://github.com/blisspixel/sealr/pull/121) and
  [PR 122](https://github.com/blisspixel/sealr/pull/122) were failing locked-build
  or dependency-evidence checks. Their state may change after this observation.
- Branch protection required zero approving reviews and strict `Required CI`
  with enforced administrators. No remote setting was changed.

## Iteration 1: unattended publisher decisions

Status: completed locally on 2026-09-13; changes are unreleased.

The increment preserves the successful `sealr.deepr-content-gate.v1` result and
adds a separate versioned failure schema. It distinguishes stages and codes
without classifying errors by diagnostic text. The Linux smoke checks consume
the machine report, preserve the caller source, and keep zero installation
output. See the [gate contract](wheel-content-gate.md).

The same iteration replaces active human dependencies in the README, roadmap,
near-term plan, contribution policy, usefulness criteria, candidate inventory,
and assurance promotion policy. The historical external-adopter contract remains
an optional attribution contract with its artifact digests intact. Published
release notes and measurement reports retain their original evidence.

Validation passed:

- `cargo test --locked --workspace --all-features` on Windows.
- `cargo test --locked -p sealr --example deepr_content_gate`: 15 tests on Windows.
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
  and `cargo fmt --all -- --check`.
- `verify_docs.ps1`, `verify_adopter_contract.ps1`,
  `verify_candidate_surface.ps1`, `verify_assurance.ps1`, `verify_tcb_report.ps1`,
  and `verify_crate_package.ps1` under `scripts/`.
- Linux WSL execution of `scripts/verify_deepr_content_gate.py` with matching
  source-built companions and a static musl worker: two accepted retention
  variants and ten typed refusals. The observed semantic identities remain
  identical between retention variants. This is local source-build evidence,
  not a newly published or provenance-attested release artifact.
- A separate review identified and resolved verifier-exit misclassification and
  missing post-deletion refusal coverage, then confirmed both fixes and the
  documented stage/code mapping.

The local smoke artifact is `target/deepr-content-gate-failure-smoke.json`, schema
`sealr.deepr-content-gate-smoke.v2`. It is generated evidence under ignored build
output, not a committed historical measurement. The report includes the exact
wheel digest, source/tree/artifact/plan identities, retention outcomes, and all
refusal results. No timing threshold is claimed. The existing required Linux CI
will exercise the updated script when these changes reach CI; no remote workflow
was dispatched in this iteration. macOS was not executed locally.

At the end of this iteration, the implementation was local commit `bc364da` on
`autonomous-publisher-integration`, not yet pushed or released. Later release
preparation is recorded below; this entry preserves the original observation.

## Iteration 2: ordinary downstream publisher replay

Status: completed locally on 2026-09-13 in the separate owner-maintained
`sealr-validation` checkout. Remote CI has not run these changes.

The project resolves released Alpha.15 commit
`8090a6bb6b0a6cc51461d2bce18966eb1a323434` without a path patch and authenticates
the matching native release before extraction. Active pins now use Alpha.15;
historical Alpha.14 retention reports retain their original bytes and claims.

The new typed publisher application is an explicitly adapted downstream consumer
of the released API. `publisher-origin.json` records released baseline hashes,
unpublished adaptation input `bc364da`, and current application, harness, and
trace-analyzer hashes separately. Source checks compare the actual Cargo-resolved
checkout, reject missing or duplicate resolve nodes, require an empty public
feature set, and validate the exact copied handoff before worker source transfer.

Local Linux WSL execution passed both accepted retention variants and ten typed
refusals using the authenticated native artifacts and ordinary released Git
dependency. Acceptance preserves semantic identities, independently verifies
evidence before private-source deletion, preserves the caller source, and creates
no installation output. Windows public-API tests also passed for all 1,576
members across the three pinned project wheels.

Required merged `strace` observations passed for baseline acceptance, metadata
retention, and the late filename refusal. The traces contain 8, 4, and 4 completely
terminated processes respectively, with zero observed wheel pathname or
wheel-FD-annotation opens after private-source deletion. The claim is limited to
the observed process tree and recognizable pathnames or annotations; it does not
cover unseen aliases or processes. Reads through verified snapshot FDs remain
allowed.

The harness enforces a 60-second process deadline, a live one MiB combined output
cap, and an inherited hard four MiB file-write ceiling that bounds trace growth.
Nine Linux analyzer/resource tests passed. Separate review caught and resolved
missing spawned-child records, trailing pathname components, and escaped FD
annotations. Nine source/provenance refusal cases passed on Windows and Linux.

The downstream publisher workflow now requires source validation, the smoke,
and retained report/trace artifacts. Its aggregate gate includes this job without
a human approval step. Local results are preserved in the downstream publisher
`publisher/observations/2026-09-13/` directory. They establish owner-maintained conformance, not an
independently maintained adopter or a production publishing deployment.

At the end of this iteration, the downstream change was local commit `6452714`
on `autonomous-publisher-validation`, not yet pushed or released. Its historical
Alpha.15 dependency and native artifact pins remain unchanged by Alpha.16 release
preparation.

## Iteration 3: read-only assurance history

Status: completed locally on 2026-09-13.

`scripts/collect_assurance_history.py` collects bounded GET-only GitHub evidence
and exact historical source identities. Original attempts and required jobs,
failure and domain resets, duplicate commits, proven pre-contract history, and
incomplete pagination have explicit outcomes. The default 200-request and
300-second bounds include processing cached observations.

`scripts/propose_assurance_ledger.py` replays a complete saved report against the
actual local evidence files, including untracked sources. It writes a separate
proposal, preserves governance and promotion flags, and cannot overwrite the
active ledger or report. Saved reports are unauthenticated inputs for local
bookkeeping; promotion still requires fresh remote verification and required CI.

The [saved live observation](../tests/assurance/observations/2026-09-13.json)
contains eight qualifying category/run entries: Kani 1, mutation 2, coverage 2,
public API compatibility 2, fuzzing 1, and native resource evidence 0. The
proposal was applied locally, reproduces byte-for-byte from that snapshot, and
passes `scripts/verify_assurance.ps1`. Every category remains ineligible and
unpromoted; mutation and coverage remain discovery-only.

All 47 offline behavioral tests passed and now run in required CI. They cover
attempt laundering, missing/failed jobs, duplicate commits, domain changes,
source binding, acquisition bounds, stale or forged summaries, output separation,
and clock exhaustion. Live integration caught coarse Windows clock readings and
the existing PowerShell verifier's whole-second comparison. Collection now waits
for distinct real seconds within its deadline without inventing timestamps.
Explicit LF output and `.gitignore` checkout rules preserve observed bytes on
Windows without ignoring source differences.

## Iteration 4: evidence consumer migration

Status: completed locally on 2026-09-13. Native Linux and macOS execution of this
new matrix remains for the existing required CI jobs.

The next candidate gap is consumer migration from default view v1/receipt v2 to
canonical view v2/receipt v3. Existing `evidence_encoding.rs` tests already cover
semantic parity, exact digests, legacy field stability, and rejection determinism.
Existing native package checks produce and verify canonical allow/reject cases.

The packaged consumer matrix now rejects the legacy pair and both mixed
lineages without sorting, reserialization, or fallback. Verification of coherent
canonical rejection evidence still leaves the consumer decision denied. The
candidate inventory v2 binds these five cases to
`sealr.evidence-lineage-migration.v1` and both evidence-schema replacements.
At this point, `Verdict` and `Policy.atomic` migration remained separate work;
iteration 5 completes their bounded consumer contracts. No
default, runtime schema, or semantic identity changed.

Full native-package verification passed against a freshly packaged local
Alpha.15 Windows CLI/verifier pair, including all five migration cases. The
candidate verifier, PowerShell parsing, documentation checks, and whitespace
checks also passed. The source-built ZIP is
`target/migration-native-alpha15/sealr-0.1.0-alpha.15-x86_64-pc-windows-msvc.zip`,
SHA-256 `d36fc8986dc12db6946a8e8323d2157386aa86af364ea063136076f235c3e279`.
It is a local test artifact, not a newly published release.

## Iteration 5: public outcome and durability migrations

Status: implemented and locally validated on 2026-09-13 for the Alpha.16 source
tree. All four candidate replacement rows now name tested migration rules.

The real Deepr gate, PyPA handoff, and extracted-package consumer now obtain
actual `VerifiedArchive` authority and check requested effects separately.
Inspection cannot satisfy a requested committed write. Destination setup can
fail before verification, while a later publication failure can preserve a
readable capability. The existing real staged-content audit test covers that
late distinction without manufacturing an outcome or exposing fault injection.

Six public consumer cases cover inspected capability, committed materialization,
malformed structure, CRC denial, failed destination setup, and unavailable
source. Nineteen example tests and the Windows extracted-package matrix passed.
Linux then passed the complete consumer using the published Alpha.15 native
artifact authenticated before extraction. An earlier pass used the iteration-1
source-built helper; these are separate artifact observations, not interchangeable
provenance claims. The consumer used a fresh local Alpha.15-versioned source
package before the coordinated Alpha.16 version bump.

Named `Durability::FlushOnly` and `Durability::MemberSync` controls on `Policy`
and `PolicyDocument` now select the historical `atomic` behavior. The four public
migration tests cover all-schema byte and digest parity, validation and memoized
identity, rejection of an alternate JSON durability field, and actual
materialization with existing-destination preservation. Policy and worker
encodings remain unchanged. Directory syncing, abandoned-stage recovery, and
power-loss durability remain unimplemented guarantees.

## Iteration 6: controlled downstream repeated reads

Status: completed locally on 2026-09-13 using immutable released Alpha.15 commit
`8090a6bb6b0a6cc51461d2bce18966eb1a323434` and authenticated matching native
artifacts. The [raw report and observation](https://github.com/blisspixel/sealr-validation/tree/main/experiments/repeated-reads/observed-linux-wsl-2026-09-13)
remain historical downstream evidence. Report SHA-256 is
`3b823bbc6e2a1d60f4fc3f97647b53951ed03a21e91573fb6494380a49a5b70f`.

The run completed 14 cases and 224 member reads in 37.846 seconds within a
300-second bound. Eight selected members totaled 363,559 bytes. Each case read
them twice; one discarded warmup pair preceded six measured pairs with balanced
strategy order. Other project builds and tests were paused for measurement.
Median totals for 16 reads were 3.685663 seconds without retention and 0.000056
seconds with retention, excluding separate digest checks and initial admission.
Whole-case medians were 4.953719 and 0.321272 seconds respectively.

All cases preserved semantic and exact evidence identities, independently
verified evidence before deletion, matched returned sizes and hashes, fulfilled
retention, preserved the caller cache, and left no surviving child process.
There was no installation. The observation is local warm-cache evidence, not a
full-installation, cold-cache, or Alpha.16 performance claim. Nine bounded
experiment and process-contract tests passed before measurement.

The next bounded increment is attribution of source hashing, plan validation,
worker setup, and payload work. Retention avoids several costs together, so
the result does not justify removing a validation step, raising a limit, or
implementing pooling without further evidence.

## Release stopping point

The current implementation loop ends with the Alpha.16 release contents:
typed outcomes, tested consumer migrations, explicit existing durability modes,
and assurance replay. The [release page](https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.16)
records publication; this historical execution log does not replace exact-commit
CI, release staging, checksum/provenance checks, or immutable-release readback.

Partial dependency PRs 121 and 122 were closed with their proposed diffs and
reason preserved. Their flate2, lzma, and CRC changes are deferred to one
coordinated root, fuzz, proof, and consumer closure update with regenerated
dependency, license, and TCB evidence. The unchanged release set does not wait
for those maintenance proposals. The [near-term plan](near-term.md) retains
that work after phase attribution and lifecycle specification.

## Cost policy

The total external spending ceiling for this campaign is **$5**, with **$0**
external purchases authorized by the execution plan. Use local tools and cached
artifacts plus free public documentation and read-only repository APIs.

Do not provision paid compute, larger runners, hosted services, subscriptions,
or commissioned audits. Do not assume a service is free from its name alone.
Unknown-cost operations are excluded; choose a local path and continue with
independent work. The initial local research and measurement iterations did
not dispatch remote workflows. Release completion uses the existing ordinary
public CI, bounded fuzz, and release workflows on standard hosted runners.
It does not authorize paid runners or services.

External purchases to date: **$0**. Model/session usage is billed by the host;
this workspace has no dollar meter or enforceable session spending control.
The $0 record does not claim that model usage is free or included in that total.
Research fan-out is bounded to three agents, reused for follow-up work.
