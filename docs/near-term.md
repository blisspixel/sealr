# Near-term execution plan

Updated 2026-09-13.

This source tree targets Alpha.17. The completed publisher, artifact replay,
migration, and assurance increments are recorded below. The next implementation
question is measuring time spent in each repeated-read phase, followed by lifecycle
closure. Technical acceptance criteria govern progress; external maintainer
participation and independent human review are not dependencies.

Earlier remote tags, releases, and run identities are retired. Historical
reports do not establish current artifact availability or qualification; all
six active assurance histories restart at zero. New downstream acquisition
must use Alpha.17. See [distribution history](distribution-history.md).

## Completed consumer and automation increments

- The [Deepr gate](wheel-content-gate.md) now emits typed, versioned failure
  reports while preserving its success schema and exit codes. Two accepted
  variants and ten Linux process refusals cover the consumer boundary.
- The owner-maintained [validation project](https://github.com/blisspixel/sealr-validation)
  previously acquired immutable Alpha.15 source and authenticated matching native artifacts.
  That replay checked source contracts before transfer and observed wheel pathname opens
  in a bounded process tree after private-source deletion. Its reports establish
  technical conformance, not independent adoption or a deployed publisher gate.
- Five packaged evidence cases refuse legacy and mixed lineages without
  fallback and leave coherent canonical rejection evidence consumer-denied.
- Real examples and six extracted-package outcome cases use `VerifiedArchive`
  and separate requested-effect checks. Named `Durability` controls replace
  direct Rust `atomic` writes while retaining historical policy and worker bytes.
  All four [candidate replacements](candidate-surface.md) have tested migration
  rules; the candidate is still an inventory rather than a freeze.
- Bounded read-only assurance collection and deterministic ledger replay have
  47 behavioral tests and a saved September 13 observation. Its eight historical
  category/run entries cannot qualify the new repository; every active history
  restarts empty, ineligible, and unpromoted.

The [iteration record](autonomous-improvement.md) preserves exact validation
scope, source-built versus released artifacts, and historical Alpha.15 pins.
Neither local tests nor an older release's CI establish Alpha.17 remote results.

## 1. Measure the repeated-read phases

The [controlled repeated-read observation](capability-reuse-experiment.md#controlled-repeated-read-observation)
completed 14 cases and 224 reads with released Alpha.15. Its eight-member,
363,559-byte working set was read twice per case. After one discarded warmup
pair, six measured pairs alternated strategy order. Median totals for 16 calls
were 3.685663 seconds without retention and 0.000056 seconds with retention.
Returned-byte digest checks and initial admission are outside those read totals.

Retention bypasses source binding, plan checks, worker setup, and streaming
work together. The result supports the existing bounded retention API for this
small known working set. It does not identify which unretained phase dominates,
measure cold-cache behavior, or establish full-installation performance.

Deliver a separate diagnostic experiment that measures source hashing, plan
validation, worker setup, and payload verification under a fixed protocol.

Acceptance:

- Pin exact source, native artifacts, consumer code, inputs, and output hashes.
- Record diagnostic changes separately from the released-helper baseline.
- Bound cases, total time, child output, file writes, and cleanup; mark partial
  observations incomplete.
- Control repetitions and strategy order and report raw observations and ranges.
- Preserve source, tree, artifact, plan, and evidence identities, complete member
  verification, byte limits, mutation detection, stream completion, and reap.
- Explain the measured contribution before proposing a private validated read
  authority, process pooling, or another runtime change.

## 2. Define and test the remaining lifecycle contract

`FlushOnly` and `MemberSync` select existing completed-member behavior. Both
retain private staging and native no-replace publication. Neither syncs
directories or promises crash recovery or power-loss durability.

Specify authenticated abandoned-stage ownership and recovery. Exercise
interruption at stage creation, writes, audit, publication, and cleanup. Test
hostile renames, links and substituted directories, unrelated neighbors, and
existing destinations on each advertised platform. No cleanup may rely on a
filename pattern. Any stronger durability guarantee needs a new explicit
contract and fault evidence rather than a renamed flush operation.

## 3. Coordinate dependency maintenance and assurance history

The partial maintenance updates represented by PRs 121 and 122 expose flate2,
lzma, and CRC dependency work. Replace split lockfile changes with one coherent
closure update across root, fuzz, proof, and consumer projects. Regenerate the
actual dependency, third-party-license, and TCB evidence and pass locked builds.
Investigate a budget change against the resolved graph rather than raising the
limit blindly. These deferred updates do not block the unchanged release set.

Use the [assurance collector and replay contract](assurance-promotion.md) for
genuine scheduled history. Preserve exact jobs, attempts, commits, evidence
domains, complete pagination, and observation times. Saved reports cannot grant
promotion. Keep the ten-distinct-commit rule and discovery-only mutation and
coverage status. Never create empty commits or reruns to manufacture history.

## 4. Maintain release and candidate evidence

Replay new releases from authenticated artifacts and record new observations.
Historical Alpha.14 retention and Alpha.15 publisher/repeated-read reports keep
their original bytes and claims. GitHub-only source acquisition may use an exact
Git revision; a future registry release needs truthful new tagged documentation
and registry readback. Do not retroactively upload a GitHub-only release.

Keep the candidate inventory, golden identities, public API checks, native
package cases, and downstream migrations aligned. A scoped freeze requires
complete evidence for the advertised surfaces, not an adopter interview or a
green API comparison alone. The [external pilot](adopter-pilot.md) remains an
optional independent-adoption contract.

## Execution and spending

This release is the stopping point for the current implementation loop. Future
work starts with the first bounded measurement above, with acceptance criteria
before code changes. No additional parser, hosted UI, binding, or backend is
needed to finish Alpha.17.

Use local computation, cached artifacts, free public documentation, and ordinary
public CI. External purchases stay at $0 by default and never exceed the $5
aggregate ceiling. No paid runner, subscription, hosted service, or commissioned
audit is required. See the [cost record](autonomous-improvement.md#cost-policy).
