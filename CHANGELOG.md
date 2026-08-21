# Changelog

All notable changes to sealr are documented in this file.

The project is in initial development. Compatibility may change between preview releases, and every such change must be documented here.

## [Unreleased]

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

[Unreleased]: https://github.com/blisspixel/sealr/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.1
