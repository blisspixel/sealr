# Milestone history

Updated 2026-09-05.

This page records what each published preview established. It replaces completed milestone logs that previously lived in the roadmap and near-term plan. The per-release notes are the detailed, versioned source for contents, limitations, compatibility changes, and verification instructions. The [changelog](../CHANGELOG.md) is the compact file-level history.

All previews remain non-production releases. A completed milestone means its bounded repository gate shipped, not that the whole security boundary became stable.

## Published previews

| Release | Date | Milestone | Detailed record |
|---|---|---|---|
| Alpha.1 | 2026-08-20 | First strict ZIP32 Store and Deflate boundary, native no-replace materialization, structured evidence, and the 5,927-case ZipDiff gate | [Release notes](releases/v0.1.0-alpha.1.md) |
| Alpha.2 | 2026-08-21 | Exact single-stream Deflate consumption, stronger Windows stage ACL and filesystem rules, materialization receipt v2, and documentation contract checks | [Release notes](releases/v0.1.0-alpha.2.md) |
| Alpha.3 | 2026-08-22 | Immutable `ArchiveIR`, separate outcome axes and semantic identities, checked policy compilation, staged-tree audit, and parallel corpus tooling | [Release notes](releases/v0.1.0-alpha.3.md) |
| Alpha.4 | 2026-08-22 | Opaque `VerifiedArchive`, bounded one-pass retention, strict ASCII v2, independent identity vectors, finite-domain properties, and the first wheel pilot | [Release notes](releases/v0.1.0-alpha.4.md) |
| Alpha.5 | 2026-08-22 | Private file-backed snapshots, checked random access, source-mutation resistance, sparse resource evidence, and bounded worker protocol v1 | [Release notes](releases/v0.1.0-alpha.5.md) |
| Alpha.6 | 2026-08-26 | Explicit reduced-authority x86_64 Linux worker, authenticated helper packaging, supervisor-owned publication, isolated later reads, and assurance promotion rules | [Release notes](releases/v0.1.0-alpha.6.md) |
| Alpha.7 | 2026-08-26 | Repository-only wheel semantics research, distinct consumer identities, a non-reopening installer bridge, and executable source and native distribution contracts | [Release notes](releases/v0.1.0-alpha.7.md) |
| Alpha.8 | 2026-08-27 | Supported portable UTF-8 ZIP profile and public capability-only Python wheel evaluator | [Release notes](releases/v0.1.0-alpha.8.md) |
| Alpha.9 | 2026-08-27 | Explicit zero-new-dependency portable POSIX ustar and the shared multi-format interpretation core | [Release notes](releases/v0.1.0-alpha.9.md) |
| Alpha.10 | 2026-08-28 | Explicit strict ZIP64 and exact single-member gzip-wrapped portable ustar, both with independent two-domain or format-native evidence | [Release notes](releases/v0.1.0-alpha.10.md) |
| Alpha.11 | 2026-08-28 | Restricted raw POSIX PAX with a closed two-key language, exact precedence provenance, independent covering replay, and no new runtime dependency | [Release notes](releases/v0.1.0-alpha.11.md) |
| Alpha.12 | 2026-08-30 | Canonical evidence, packaged independent verification, validated policy files, repository PyPA conformance, six additional TAR and codec selections, and Copy-only 7z | [Release notes](releases/v0.1.0-alpha.12.md) |
| Alpha.13 | 2026-08-31 | Full-integrity supervised prefix reads, a packaged public-API-only PyPA `WheelSource` handoff, and an exact Poetry 2.4.2 repository fixture | [Release notes](releases/v0.1.0-alpha.13.md) |
| Alpha.14 | 2026-09-04 | Explicit Deflate completion, 24 Unicode and streaming wheel producer vectors, twelve complete supervised installer runs, and machine-checked adopter and candidate inventories | [Release notes](releases/v0.1.0-alpha.14.md) |
| Alpha.15 | 2026-09-05 | Capability-only publisher content decision, measured bounded-retention guidance, and a consistent visual identity with current Linux examples | [Release notes](releases/v0.1.0-alpha.15.md) |

## Durable detail by topic

The milestone sequence produced detailed contracts that remain active even though the delivery plans are complete.

| Topic | Maintained documentation |
|---|---|
| Current behavior and limitations | [README](../README.md), [API contract](api.md), and [security policy](../SECURITY.md) |
| Interpretation and identity model | [Semantic model](semantic-model.md), [identity conformance](identity-conformance.md), and [evidence encoding](evidence-encoding.md) |
| ZIP and parser-differential evidence | [Differentials](differentials.md) and [ZipDiff gate](../tests/corpus/zipdiff/README.md) |
| Filesystem safety and publication | [Safety specification](safety.md), [threat model](threat-model.md), and [invariants](invariants.md) |
| Reduced-authority Linux execution | [Sandbox boundary](sandbox.md), [private semantic record](semantic-record.md), and [helper packaging](helper-packaging.md) |
| Assurance program | [Assurance](assurance.md) and [assurance promotion](assurance-promotion.md) |
| Formats, codecs, and dependency decisions | [Format support](format-support.md), [codec dependency gates](codec-dependency-gates.md), and the [profile directory](profiles/) |
| Wheel compatibility and consumer semantics | [Wheel profile](profiles/python-wheel-v1.md), [current v5 inventory](wheel-compatibility-v5.md), and [usefulness test](usefulness.md) |
| PyPA and Poetry repository proofs | [Copyable handoff](../crates/sealr/examples/pypa_installer_handoff/README.md), [PyPA conformance kit](../tests/pypa-installer-consumer/README.md), and [Poetry fixture](../tests/poetry-consumer/README.md) |
| Packaging and release mechanics | [Distribution contract](distribution-contract.md), [release verification](release-verification.md), and [release process](releasing.md) |

## Why the completed plans were retired

The former roadmap and near-term plan accumulated implementation diaries for Alpha.4 through Alpha.13 beside still-open work. That made completed detail look active, duplicated release notes and topic contracts, and obscured the actual next decision.

Historical facts now live in immutable release notes and the maintained topic documents above. The root [roadmap](../ROADMAP.md) contains only current sequencing and stable gates. The [near-term plan](near-term.md) contains only the remaining adopter and readiness work.
