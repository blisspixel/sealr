# Changelog

All notable changes to sealr are documented in this file.

The project is in initial development. Compatibility may change between preview releases, and every such change must be documented here.

## [Unreleased]

## [0.1.0-alpha.2] - 2026-08-21

### Added

- DEFLATE verification now requires exactly one valid raw stream to consume every declared compressed byte. Trailing data and concatenated streams receive stable codec findings.
- Windows stages now receive a protected effective-TokenUser-only inheritable DACL during the existing atomic `NtCreateFile` operation and are verified through the returned handle before member writes.
- Materialization receipt v2 records the Windows storage policy, filesystem and device-scope observations, persistent-ACL and read-only flags, and stage-ACL verification without exposing a SID or volume identity.
- New `materialize.unsupported_filesystem` and `materialize.unsafe_stage` findings distinguish fail-closed Windows storage admission from stage-security verification.

### Changed

- Relicense the project from MIT to Apache-2.0.
- Windows materialization now supports only non-remote, writable NTFS parents that report persistent ACLs. ReFS, FAT-family filesystems, remote shares, read-only volumes, and ambiguous volume queries reject before staging.
- Current-contract documentation now distinguishes unsigned receipts from future attestations, documents source-digest unavailability, and aligns platform, cleanup, durability, and walkthrough claims with executable behavior.
- Native archives now include target-specific third-party license bundles generated and verified from the locked release dependency graphs.

## [0.1.0-alpha.1] - 2026-08-20

First public development preview of the ZIP boundary.

### Added

- Classic ZIP32 inspection for Store and Deflate members.
- Structured allow and reject views with unsigned evidence receipts.
- Bounded archive, metadata, member, total-expanded-size, and compression-ratio policy enforcement.
- Strict fail-closed path, topology, layout, and parser-differential checks.
- Per-component no-follow staged materialization with atomic retained-handle Windows stage creation, retained-handle native no-replace publication, fail-closed Unix parent checks, and explicit receipt evidence.
- A deterministic gate over all 5,927 pinned ZipDiff constructions and 14 ambiguity classes.
- Cross-platform format, lint, test, documentation, optimized-build, and supply-chain checks.
- Native preview archives, SHA-256 checksums, and build provenance attestations.
- A protected draft-then-promote release path with exact-main CI revalidation and immutable-release verification.

### Security status

This preview is not a production-ready security boundary and has not received an external security audit. See the security limitations in the README and the reporting policy in `SECURITY.md` before evaluating it.

[Unreleased]: https://github.com/blisspixel/sealr/compare/v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/blisspixel/sealr/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.1
