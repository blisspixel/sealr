# Changelog

All notable changes to sealr are documented in this file.

The project is in initial development. Compatibility may change between preview releases, and every such change must be documented here.

## [Unreleased]

### Changed

- Reorganized the near-term roadmap into release-sized Alpha.4, Alpha.5, and Alpha.6 increments, started the assurance and wheel-consumer research lanes earlier, and added task-oriented planning documents and a documentation index.

## [0.1.0-alpha.3] - 2026-08-22

### Added

- `sealr.archive-ir.v1` is the versioned ZIP interpretation. Inspect and materialize consume the same IR under `sealr.profile.zip.strict-ascii.v1` instead of reparsing archive bytes. The IR now records source ranges, extra-field dispositions, and path-normalization actions.
- `SourceSnapshot` is the named immutable in-memory source. Path inputs are process-owned; caller byte slices stay borrowed. ZIP payload reads go through checked snapshot ranges, and receipts record `source_snapshot` as `memory-owned`, `memory-borrowed`, or `unavailable`.
- Receipts now use `sealr.receipt.v2` and record separate interpretation, admission, verification, effect, and view-completeness axes. The alpha.2 `Allowed`/`Rejected` verdict remains a derived compatibility adapter, so an admitted archive whose destination fails is still `Rejected` at the CLI.
- Receipts record distinct source, interpretation-profile, `sealrTreeV1` layout, and `sealrTreeV1` content-tree identities. `view_digest` remains invocation evidence and is not a tree root.
- `Policy::compile()` produces typed supported controls before source ingestion. Unknown formats and reserved-field mutations fail closed with `policy.unsupported`.
- The interpretation profile has a digest covering its method, flag, extra-field, and name rules, stored on `ArchiveIR` and the receipt.

### Changed

- `Policy.max_ratio` is now `Option<u64>`. The default remains 100:1 using integer comparison. `null` disables the check; `0` is not off. A member with uncompressed size greater than zero and compressed size zero is an infinite ratio.
- Quota, metadata, and remaining-total counters use checked arithmetic. Overflow is `quota.overflow` rather than a saturating admit.
- Source digest unavailability is explicit. When archive bytes were never held, `receipt.source` and `view.source.digest` are `{ "status": "unavailable" }` instead of a 64-zero SHA-256 sentinel. Held bytes, including over-cap `Source::Bytes` inputs, are hashed.
- Clarified the post-alpha.2 execution queue and reconciled supporting research documentation with the semantic-identity-first roadmap.
- Recorded the reliability bar, minimal trusted-computing-base rule, and common ZIP/TAR codec-adapter destination in the roadmap without changing current Store/Deflate support.
- Added research notes on unique covering, partial interpretation, and named conjectures in `docs/theory.md`. They are not proofs.
- Documented sequential unique covering versus parallel independent-member verification. The ZipDiff classifier now uses `std::thread` and optional `SEALR_JOBS` without adding a runtime dependency.
- Recorded the usefulness test: Sealr is an admission boundary other software calls, not an unzip. A receipt does not prove the category until a consumer (wheels first) stops reparsing.
- Pinned cross-platform `sealrTreeV1` golden roots for the empty tree and the walkthrough allowed fixture. Inspect, materialize, and a failed destination share the same layout root; a denied parent-path archive has none. Layout identity now includes the ZIP32 source covering (local prefix, central directory, EOCD, comment).
- The inspectable view serializes the same interpretation, admission, verification, effect, and completeness axes as the receipt. The CLI exits `3` when an admitted archive cannot publish a destination. The compatibility `verdict` remains `rejected` on that path.
- Added deterministic materializer tests for destination-as-file, destination-as-link, and replacing a created directory component with a symlink or junction before the next member.
- Added runnable checksum, provenance, and immutable-release verification commands for the current published prerelease without changing its historical release notes.
- Added a versioned walkthrough manifest that binds regenerated fixture and platform-specific transcript hashes to the six committed PNG hashes, and clarified that the images are rendered summaries rather than literal raw CLI captures.
- Added a codec-free covering checker: after IR construction, Sealr verifies that the claimed local, central, EOCD, and comment ranges partition the snapshot and that LFH/CDH/EOCD signatures sit at the recorded offsets. The checker does not search for an EOCD or inflate. Mutated covering claims fail with `covering.inconsistent`.
- Materialization now audits the staged tree against the admitted IR before no-replace publication: member sizes, content digests, implicit parent directories, and the exact path set. Divergence is `materialize.audit`, aborts the stage, and does not publish. Test-only hooks cover intra-call directory-component replacement and staged-content mutation.

### Fixed

- The staged-tree audit now hashes files with a fixed 64 KiB buffer instead of loading each expanded file into memory.
- Layout roots now bind every member's complete local-header, payload, optional descriptor, and central-header ranges. Public content-root calculation returns unavailable for unverified members or malformed digests.
- Directory entries now require Store, zero sizes, and the CRC32 of empty content. LFH and CDH CRC fields must agree when no data descriptor is present.
- Malformed and unsupported inputs report a partial structure view instead of claiming a complete member inventory.
- Over-cap caller byte slices retain an honest `memory-borrowed` snapshot classification. A path that grows beyond the cap no longer reports a digest of only the bounded prefix as if it covered the complete archive.

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

[Unreleased]: https://github.com/blisspixel/sealr/compare/v0.1.0-alpha.3...HEAD
[0.1.0-alpha.3]: https://github.com/blisspixel/sealr/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/blisspixel/sealr/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.1
