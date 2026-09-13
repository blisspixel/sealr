# Assurance discovery and promotion

Alpha.17 starts a new owner-controlled repository history. All six active
qualification histories restart at zero; retired repository runs cannot count
toward promotion. Historical observation files remain unchanged. See
[distribution history](distribution-history.md).

This document binds Sealr's scheduled model-checking, mutation, source-coverage, and public-API-compatibility evidence to exact tools, finite claims, retained reports, and a conservative promotion rule. The machine-readable source of truth is [the assurance manifest](../tests/assurance/manifest.json). Promotion history is recorded separately in [the promotion ledger](../tests/assurance/promotion-ledger.json).

## Scheduled discovery workflow

The weekly [assurance workflow](../.github/workflows/assurance.yml) runs at `29 9 * * 3` and may also be dispatched manually. It has read-only repository permission, fixed 20-minute job limits, and retains each report for 30 days.

| Evidence | Exact tool | Bounded work | Result and nonclaim |
|---|---|---|---|
| Scalar model checking | Kani 0.67.0 | Three named harnesses, unwind bound 1 | Exhaustive only within each stated domain and assumptions. It is not an extractor proof. |
| Targeted mutation discovery | cargo-mutants 27.1.0 | Three source files, three production function filters, explicit proof-harness exclusion, two workers, 120-second Cargo invocation timeout | Missed and timed-out mutants are review leads. The caught fraction is not a correctness or security score. |
| Source coverage discovery | cargo-llvm-cov 0.9.0 on Rust 1.98.0 | `sealr` package tests with all features, 20-minute job | The JSON report identifies exercised regions. It has no percentage gate and makes no completeness claim. |
| Public API compatibility discovery | cargo-semver-checks 0.49.0 on Rust 1.98.0 | Exact source-only baseline tag-to-commit binding, a self-contained baseline Cargo package, SHA-256-authenticated x86_64 Linux tool archive, explicit minor release class, an empty expected-warning file, and a 20-minute job | Any warning, deny-level finding, expected-warning drift, summary drift, or infrastructure failure fails the scheduled job. A green job is not a claim of behavior, evidence-format, platform, or security compatibility. |
| ClusterFuzzLite code-change fuzzing | google/clusterfuzzlite actions pinned by commit, `base-builder-rust` pinned by image digest, the campaign's exact nightly-2026-08-01 toolchain installed in the build | 300 seconds per changed fuzz target on pull requests, seeded from the committed corpus and dictionaries | Bounded discovery. The manifest-verified scheduled campaign remains the reproducibility contract, the run is informational rather than required, and it may be promoted only under the ten-clean-runs rule. It is never a coverage or correctness score. |

Mutation exit codes for missed mutants and mutant timeouts preserve the report. Baseline, usage, filter, and internal tool failures fail the job. Coverage is not sent to a scoring service and cannot gate required CI by percentage.

The pre-merge local mutation reproduction evaluated 17 production mutants: 16 were caught, one result-replacement mutant was unviable, and none were missed or timed out. The local coverage command produced a complete summary JSON. These observations validate the workflow and identify no immediate test gap, but neither is a correctness claim and neither is committed to a promotion history.

## Bounded model-checking claims

Kani's released compiler currently uses Rust `1.93.0-nightly (53732d5e0 2025-11-20)`, while the product is compiled and tested with the repository's Rust 1.98 toolchain. The isolated [proof manifest](../verification/kani/Cargo.toml) therefore compiles the exact production `interval.rs`, `quota.rs`, and `ratio.rs` modules and nothing else. Required CI separately compiles the complete product workspace and the proof manifest with Rust 1.98. This split does not establish any property of the parser, codecs, dependency graph, platform adapters, or worker.

| Harness | Domain | Assumptions | Solver | Property | Nonclaim |
|---|---|---|---|---|---|
| `interval_offset_len_matches_wide_oracle` | Every `offset: u64` and `length: u64` | None | CaDiCaL | Checked construction agrees with a widened `u128` sum and preserves both endpoints | No partition, covering, parser, or later-use property |
| `quota_consume_matches_wide_oracle_and_is_atomic` | Every `used: u64`, `limit: u64`, and `amount: u64` | `used <= limit` at entry | CaDiCaL | One transition agrees with widened arithmetic and is unchanged after overflow or limit rejection | No caller sequencing, concurrency, or aggregate-archive proof |
| `ratio_exceeds_matches_checked_product_oracle` | Every uncompressed size, compressed size, and maximum ratio representable by `u64` | None | Kissat | The widened product comparison agrees with a checked 64-bit product oracle, including zero and overflowing products | No codec-size, profile-selection, archive-admission, or policy-appropriateness proof |

Every harness has unwind bound 1 and contains no loop. The ratio harness pins Kissat because the same full-domain multiplication equivalence is impractically slow with the default solver. A local Kani 0.67.0 reproduction completed all three harnesses with zero failures: 101 checks for interval construction, 159 for quota consumption, and 9 for the ratio predicate.

Kani reports one caller-location construct and one foreign function in the three compiled modules. Neither is reachable from the named harnesses. Verification fails if a later source change makes either reachable, and the report does not claim support for those constructs.

Reproduce the scheduled proof on a supported Kani host with:

```text
cargo install kani-verifier --version 0.67.0 --locked
cargo kani setup
cargo kani --manifest-path verification/kani/Cargo.toml --package sealr --default-unwind 1
```

## Promotion governance

Scheduled evidence is not automatically required evidence. Each category remains separate because model checking, fuzzing, native resource testing, mutation discovery, source coverage, and public API compatibility support different claims.

A promotable check may enter the one protected `Required CI` workflow only when all of these conditions hold:

1. Its exact local reproduction is committed and time bounded.
2. Ten distinct, consecutive, successful scheduled runs complete on ten distinct `main` commits.
3. Every run ID, commit, event, conclusion, URL, and observation time is recorded in the ledger.
4. Any unsuccessful scheduled run resets that check's committed consecutive sequence.
5. A CI-validated change records the computed `eligible` and `promoted` values and adds the declared marker to required CI. No human approval is required. The read-only history collector must verify the remote evidence before proposing this change; the offline verifier alone cannot authenticate GitHub history.

Manual runs do not count toward the ten-run sequence. Mutation and coverage reports are permanently discovery-only in the current ledger, so they cannot become required percentage or score gates. Public API compatibility is promotable from the clean source-only baseline, with a fresh history starting at zero. Kani, fuzzing, and native resource evidence are promotable only after their own independent histories qualify.

The historical [2026-09-13 observation](../tests/assurance/observations/2026-09-13.json)
records one qualifying Kani run, two public-API-compatibility runs, one fuzz run,
and zero native-resource runs for the retired repository's evidence inputs.
Mutation and coverage each retain two historical runs. None of these runs counts
toward the new repository: all six active histories are empty and no category is
eligible or promoted. Required CI remains one strict protected authority without
importing an ineligible scheduled job.

The current API baseline is the source-only tag `source-baseline-20260913`, bound
to commit `157d47168ea7bdab1a5d0a1a7c2c8ec896d195d1`. Its source package retains
version `0.1.0-alpha.16`; it has no native release and does not restore a retired
release tag. The workflow verifies the tag's exact commit before packaging it.
The manifest and ledger contain the matching reproduction commands and zero
expected warnings.

The offline verifier, `scripts/verify_assurance.ps1`, rejects tool, workflow, bound, domain, source-symbol, artifact, baseline, history, eligibility, or required-CI drift. This governs what evidence may be claimed. It does not validate the truth of Kani, cargo-mutants, cargo-llvm-cov, cargo-semver-checks, GitHub Actions, or the declared independent oracles.

## Read-only history collection

Run the bounded collector with Python 3 and a GitHub CLI session that can read
public workflow history:

```sh
python3 scripts/collect_assurance_history.py \
  --report target/assurance-history/remote-main.json
```

The default subject is the observed remote `main` commit. `--revision` selects
an exact 40-character revision available through GitHub's API; it cannot read an
unpublished local commit. The collector uses only GET requests. It writes a
versioned `sealr.assurance-history.v1` report and never changes GitHub state,
the committed ledger, or required CI.

Defaults bound collection to 200 GET requests and 300 seconds, including cached
observation processing. Each observation retains a real UTC timestamp. The
collector waits at most 1.25 seconds for a later whole second within a category,
because the existing PowerShell ledger verifier compares dates at whole-second
precision. Clock exhaustion produces incomplete evidence; timestamps are never
spaced by inventing offsets.

Exit `0` means the bounded observation is complete. Each category separately
reports `eligible` or `ineligible`; a complete report with no eligible category
is an ordinary successful observation. Exit `2` and `incomplete` identify missing
or ambiguous evidence, API or response bounds, or pending work. An incomplete
category cannot authorize promotion. Unknown fields or success counts from an
unrelated report are not a substitute for this contract.

For each scheduled `main` run, collection binds repository, workflow, source
commit, original attempt, required jobs, and historical evidence inputs. The
original attempt is inspected even if a later rerun passed. All reruns are
conservatively excluded and reset the sequence. A commit counts at most once
within the current sequence. Failed runs and missing, duplicate, or unsuccessful
required jobs cannot extend it. The resource category requires all three native
matrix jobs.

Domain fingerprints use historical workflow and contract data plus named
supporting source identities. Each report lists its current inputs so a reset
is explainable. README changes and updates to recorded histories, eligibility,
or promotion flags do not themselves reset a category. A change to an included
source file may conservatively reset a category even when behavior is unchanged.
This is a readiness rule, not a semantic-equivalence analysis.

When an exact historical commit tree proves that the promotion contract did not
yet exist, the collector records `contract_not_present` as a nonqualifying
boundary and resets the sequence. It does not invent that old contract from
today's configuration. Failure to retrieve a tree or an expected blob remains
incomplete evidence.

The collector checks complete bounded API pagination and Git blob identities
against the requested commit tree. These checks still trust GitHub's API and Git
identity model. They do not verify retained fuzz or model-checker artifacts,
prove correctness, establish an independent audit, or change discovery-only
categories into promotable scores.

Required CI runs the collector and proposal tool's offline behavioral fixtures:

```sh
python3 -m unittest discover -s tests/assurance -p "test_*.py"
```

Live collection remains a separate read-only operation. A ledger refresh must
preserve the collected observation and verify that its domain matches the local
contract before using any qualifying run. Publication or promotion must
revalidate mutable remote state rather than treating a saved report as permanent
authorization.

## Local ledger proposals

After a complete live collection, generate a bookkeeping proposal:

```sh
python3 scripts/propose_assurance_ledger.py \
  --report target/assurance-history/remote-main.json \
  --output target/assurance-history/proposed-ledger.json
```

The proposal tool makes no network requests. It replays the observed decisions,
checks exact job sets and chronological times, recomputes eligibility, and binds
the report to actual local evidence inputs, including untracked source files.
It refuses incomplete reports, source drift, invented summary counts, and reports
older than the current ledger observation. Its explicit output cannot overwrite
the active ledger or input report.

Local source hashing uses actual checkout bytes, including line endings. The
repository pins source and evidence file endings to LF so Windows checkout
conversion cannot silently change a fingerprint. Do not normalize a saved
report's claimed hashes or ignore an unexplained local difference to force a
proposal through.

Only qualifying history and computed eligibility change in the proposal.
Governance fields and promotion flags are preserved. Existing promotion cannot
survive a newly ineligible history without a separate CI demotion change. A saved
report is an unauthenticated proposal input and cannot grant promotion. Apply a
fresh, validated proposal with its observation artifact in the same change, then
run `scripts/verify_assurance.ps1`. Any promotion additionally requires fresh
remote verification and the declared required-CI change.
