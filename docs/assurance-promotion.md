# Assurance discovery and promotion

This document binds Sealr's scheduled model-checking, mutation, and source-coverage evidence to exact tools, finite claims, retained reports, and a conservative promotion rule. The machine-readable source of truth is [the assurance manifest](../tests/assurance/manifest.json). Promotion history is recorded separately in [the promotion ledger](../tests/assurance/promotion-ledger.json).

## Scheduled discovery workflow

The weekly [assurance workflow](../.github/workflows/assurance.yml) runs at `29 9 * * 3` and may also be dispatched manually. It has read-only repository permission, fixed 20-minute job limits, and retains each report for 30 days.

| Evidence | Exact tool | Bounded work | Result and nonclaim |
|---|---|---|---|
| Scalar model checking | Kani 0.67.0 | Three named harnesses, unwind bound 1 | Exhaustive only within each stated domain and assumptions. It is not an extractor proof. |
| Targeted mutation discovery | cargo-mutants 27.1.0 | Three source files, three production function filters, explicit proof-harness exclusion, two workers, 120-second Cargo invocation timeout | Missed and timed-out mutants are review leads. The caught fraction is not a correctness or security score. |
| Source coverage discovery | cargo-llvm-cov 0.9.0 on Rust 1.98.0 | `sealr` package tests with all features, 20-minute job | The JSON report identifies exercised regions. It has no percentage gate and makes no completeness claim. |
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

Scheduled evidence is not automatically required evidence. Each category remains separate because model checking, fuzzing, native resource testing, mutation discovery, and source coverage support different claims.

A promotable check may enter the one protected `Required CI` workflow only when all of these conditions hold:

1. Its exact local reproduction is committed and time bounded.
2. Ten distinct, consecutive, successful scheduled runs complete on ten distinct `main` commits.
3. Every run ID, commit, event, conclusion, URL, and observation time is recorded in the ledger.
4. Any unsuccessful scheduled run resets that check's committed consecutive sequence.
5. A review explicitly changes both `eligible` and `promoted` and adds the declared marker to required CI.

Manual runs do not count toward the ten-run sequence. Mutation and coverage reports are permanently discovery-only in the current ledger, so they cannot become required percentage or score gates. Kani, fuzzing, and native resource evidence are promotable only after their own independent histories qualify.

As of 2026-08-27, no scheduled category is eligible or promoted. The fuzz campaign expanded to include raw portable ustar and therefore reset its qualifying history to zero rather than inheriting evidence from the smaller protocol-and-semantic domain. Kani and the native 3 GiB resource gate also have zero qualifying scheduled runs. Mutation and coverage have zero runs and remain non-promotable. Required CI therefore remains one strict protected authority without importing any unstable scheduled job.

The offline verifier, `scripts/verify_assurance.ps1`, rejects tool, workflow, bound, domain, source-symbol, artifact, history, eligibility, or required-CI drift. This governs what evidence may be claimed. It does not validate the truth of Kani, cargo-mutants, cargo-llvm-cov, GitHub Actions, or the declared independent oracles.
