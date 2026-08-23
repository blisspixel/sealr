# Changelog

All notable changes to sealr are documented in this file.

The project is in initial development. Compatibility may change between preview releases, and every such change must be documented here.

## [Unreleased]

## [0.1.0-alpha.5] - 2026-08-22

### Added

- Added checked `u64` exact reads, bounded owned reads, and range-limited streaming readers to the internal `SourceSnapshot` boundary. Regression coverage now exercises maximum-distance EOCD discovery, repeated short reads, stream signatures split across 64 KiB boundaries, invalid ranges before allocation, and semantic parity between owned and borrowed memory backends.
- Added the first private file-backed snapshot for path inputs. Sealr opens the caller path once, copies and hashes through a fixed 64 KiB buffer under the archive cap, verifies the opened source length and modification state, reopens only the Sealr-owned file read-only, removes its filename, and retains the unnamed capability for parsing, verification, materialization, and later `VerifiedArchive` reads.
- Added path-replacement, truncation, growth, short-read, interrupted-read, private-directory cleanup, file-versus-memory parity, and post-source-deletion verified-read regressions.
- Added deterministic same-length mutation coverage. Windows source opens now deny concurrent write sharing for the duration of the copy; Unix source admission compares device, inode, mode, length, modification time, and change time before and after the copy.
- Added a physically sparse ZIP32 fixture generator, a required 1 MiB versus 128 MiB child-process peak-resident-memory and heap-allocation gate, and a monthly three-platform 3 GiB sparse gate. The local Windows 3 GiB run used 131,072 allocated source bytes and 210,427 tracked heap bytes.
- Added the non-published, zero-dependency `sealr-worker-protocol` crate. Protocol v1 has a fixed 212-byte start frame, a 4 MiB whole-frame cap, out-of-band source and stage capability slots, operation correlation, bounded canonical manifests and findings, fallible allocation, and typed non-allocating errors.
- Added deterministic protocol regressions for valid state round trips, every truncation point, header and capability confusion, count inconsistency, malformed strings, invalid result states, canonical ordering, and three mutations at every byte position.
- Added a separate pinned libFuzzer workspace and weekly AddressSanitizer workflow for both protocol decoders. Required CI checks the source-controlled seed and dictionary digests, toolchain, tool versions, and explicit input, time, timeout, RSS, job, and reproducer-retention bounds.

### Changed

- Routed magic detection, EOCD discovery, central-directory and local-header parsing, data-descriptor checks, the codec-free covering audit, initial content verification, and later `VerifiedArchive` member reads through the snapshot random-access interface. The central directory is copied only after the metadata cap passes, and compressed payloads are no longer exposed to production code as whole slices.
- Path-input receipts now report `source_snapshot: private-file`; caller byte inputs remain `memory-borrowed`, and a borrowed snapshot becomes `memory-owned` only when a returned verified capability must outlive the call.
- The path-input source fingerprint now covers stronger native change evidence than length and best-effort modification time alone. Existing Windows writers cause source admission to fail closed instead of racing the copy.

### Fixed

- A closed or failed stdout stream no longer suppresses the independently emitted receipt on stderr. The CLI attempts both machine streams, preserves completed inspect or materialization effects, and returns an operational failure when either stream cannot be written.
- Snapshot-owned buffer reads now validate the complete offset and length before attempting allocation, so an invalid hostile range cannot trigger a large reservation attempt before it is rejected.
- Snapshot-access failures during structural interpretation now report an indeterminate interpretation with admission not evaluated instead of being mislabeled as malformed archive structure.
- Underlying snapshot I/O failures observed through Deflate now retain `source.io` identity instead of being mislabeled as invalid compressed syntax.
- Later private-snapshot I/O failures from `VerifiedArchive::read_member` now use `MemberReadErrorKind::SourceIo` instead of being conflated with verified-byte integrity disagreement.

## [0.1.0-alpha.4] - 2026-08-22

### Added

- Added the opaque `VerifiedArchive` capability for fully verified admitted outcomes. It retains the exact snapshot and verified IR, supports canonical-path lookup, and returns member bytes only after a caller-supplied limit and a second size, CRC32, and SHA-256 check pass.
- Added a separate Cargo consumer that runs against the extracted packaged crate rather than the workspace source. The required quality job now exercises the intended packaged capability API end to end.
- Added a finite-domain verified-member limit property over Store and Deflate payloads of 0 through 64 bytes and caller limits of 0 through 64. The test compares the API with the independent relation `limit >= measured_size` and checks every successful byte result.
- Added `sealr.identity-conformance.v1` and a separate identity verifier with no dependency on the Sealr crate. Four cases bind exact source and profile bytes, semantic axes, findings, IR evidence, covering ranges, and preview roots. The verifier checks the claimed ZIP32 partition without discovery or inflation and independently reproduces three layout and three content roots.
- Added exhaustive finite-domain checks for interval arithmetic and exact partitions. Offset-plus-length results are compared with a `u128` oracle over 4,624 boundary pairs, and 1,055,758 bounded interval lists are compared with an independent per-byte bitmap model.
- Added a fifth finite-domain property family for atomic quota transitions. It compares 159,528 valid states and increments with independent `u128` arithmetic and confirms that overflow and cap failures leave accounting unchanged.
- Added `apply_with_options`, validated `RetentionPlan` construction, and per-path `RetentionStatus` reporting. Up to 64 exact canonical paths can be selected under bounded path metadata plus caller-selected member and aggregate content ceilings. Successful selections are captured during the original verification stream and borrowed through `VerifiedArchive::retained_member` without another parse, inflation, allocation, or hash.
- Added a sixth finite-domain property family that compares deterministic retention selection with an independent small-domain oracle over 8,125 member-size and limit combinations.
- Added a reproducible, non-shipping compatibility pilot over 20 exact PyPI wheels and 90,417,280 source bytes. Its bounded manifest pins acquisition metadata and digests; analysis uses only Sealr's public outcome and read-only IR. The profile admits 19 artifacts and denies one SciPy artifact for three investigated per-member expansion-ratio findings. Structural inventory also distinguishes top-level wheel metadata from nested vendored `.dist-info` trees.
- Added an offline committed-report verifier to required CI. It binds the wheel report to the analyzer revision plus exact manifest, current interpretation-profile, and default-policy digests; recomputes rollups; and requires canonical JSON and Markdown without downloading or reparsing the corpus.
- Added the opt-in `sealr.profile.zip.strict-ascii.v2` interpretation. Its canonical bytes assign a disposition to all 16 general-purpose flag bits, permit only semantic data-descriptor bit 3, and deny every extra-field identifier. The immutable v1 bytes and default `apply()` behavior remain unchanged.
- Added public profile selection through `ApplyOptions`, canonical profile-byte accessors, a second independently checked profile vector, cross-platform empty-tree identity coverage, and finite-domain regression coverage over all 65,536 flag words and all 65,536 extra-field identifiers.

### Changed

- Reorganized the near-term roadmap into release-sized Alpha.4, Alpha.5, and Alpha.6 increments, started the assurance and wheel-consumer research lanes earlier, and added task-oriented planning documents and a documentation index.
- Made `ArchiveIR` a read-only, Sealr-constructed evidence view exposed through `Outcome::archive_ir()`. Its evolving records and enums are non-exhaustive, internal state transitions are no longer public, and ignored `Outcome` values now produce a compiler warning.
- Replaced the golden derived from a publicly constructible synthetic empty IR with the layout root of an actual canonical 22-byte empty ZIP. Added an exhaustive finite-domain compression-ratio check against an independent quotient-and-remainder oracle.
- Made evolving receipt, view, finding, identity, snapshot-kind, and materialization outputs non-exhaustive. All public receipt field types are now nameable from the crate root, while the snapshot-dependent covering audit remains internal.
- Added an external-crate public API fixture and a packaged-library verification step to the existing required quality job.
- Successful borrowed-byte inputs are copied into process-owned storage when the verified capability is created. Path inputs transfer their already owned snapshot without another archive copy. Cloned capabilities share immutable authority.
- Unified ZIP discovery and codec-free covering audit on one pure checked half-open interval and exact-partition kernel. The audit now rejects offset-plus-length overflow before using an interval in adjacency or containment decisions.
- Unified declared totals, actual totals, remaining capacity, and per-member byte counts on one pure quota transition. Successful updates are monotone, and failed updates cannot partially mutate the counter.
- Preserved `apply()` as the compatibility facade and kept retention outside policy, receipt identity, and admission. Deterministic selection uses canonical-path order; missing paths, directories, limit failures, platform limits, allocation failures, and defensive integrity disagreement remain explicit capability statuses and do not weaken verification.
- Re-executed the 20-wheel pilot under strict ASCII v2. The measured result remains 19 admissions and one policy-ratio denial, confirming that the closed flag and extra-field contract does not change the exact pilot cohort.

### Fixed

- ZIP64 entry-count sentinels now report `zip.diff.c5_zip64` before policy quota evaluation instead of being misclassified as `quota.files` under the default cap.
- File-count enforcement now bounds the number of central headers actually parsed, even when the EOCD understates it, and compares the parsed count to the EOCD without a truncating `usize` to `u16` cast.
- Local-header bounds use checked offset arithmetic, so a hostile near-`usize::MAX` offset returns `zip.diff.c4_offset` instead of overflowing before the bounds check on narrower targets or debug builds.
- The default encryption denial now covers traditional encryption bit 0, strong-encryption bit 6, and masked-header bit 13. A matching LFH/CDH flag pair can no longer bypass `encrypted = "deny"` by omitting bit 0.
- Early source, format, structure, and policy failures now bind the interpretation identity selected in `ApplyOptions` instead of incorrectly reporting the v1 identity for a v2 operation.
- The non-shipping wheel laboratory now follows the workspace release version, and the release-candidate gate rejects version drift before a tag can reach release validation.

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

[Unreleased]: https://github.com/blisspixel/sealr/compare/v0.1.0-alpha.5...HEAD
[0.1.0-alpha.5]: https://github.com/blisspixel/sealr/compare/v0.1.0-alpha.4...v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/blisspixel/sealr/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/blisspixel/sealr/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/blisspixel/sealr/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.1
