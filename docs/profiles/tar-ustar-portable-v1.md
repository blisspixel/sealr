# Portable POSIX ustar profile v1

> Status: supported Alpha.9 preview. Identifier and canonical profile bytes are pinned. The profile is selected explicitly and does not widen `apply()` or any ZIP profile.

`sealr.profile.tar.ustar-portable.v1` interprets one uncompressed POSIX ustar source as portable regular files and directories.

The canonical profile SHA-256 is `3c87c5ec4c1ad5377eb60ebb308e9e394aaf7a4133dddf5587829b4510af1700`.

## Accepted language

- The source is a sequence of complete 512-byte blocks.
- Every member begins with exact `ustar\0` magic and `00` version bytes.
- Header checksum is exactly six ASCII octal digits, NUL, and space, and equals the unsigned byte sum with the checksum field treated as spaces.
- Numeric fields contain one or more ASCII octal digits followed by one or more NUL or space terminators. Leading spaces, embedded terminators, non-octal digits, unterminated full fields, overflow, and GNU base-256 encoding are denied.
- Type `0` and legacy NUL mean a regular file. Type `5` means a directory and must declare size zero.
- Names are the optional ustar prefix plus name, decoded as strict UTF-8 and admitted through the same Unicode 16 portable component, NFC, reserved-name, and full case-fold collision contract as the ZIP portable profile.
- Member payload padding through the next 512-byte boundary is all zero.
- Two consecutive zero blocks terminate the archive. Every remaining complete record-padding block is all zero.
- Payload verification reuses the Store adapter, quotas, SHA-256 evidence, retained reads, later verified reads, and materialization core.

## Denied language

Hard links, symbolic links, devices, FIFOs, PAX local and global headers, GNU long-name and long-link records, sparse files, multi-volume state, concatenated archives, nonzero hidden padding, bytes after the first NUL in fixed text fields, and nonzero reserved header bytes fail closed. Device-number fields for admitted regular files and directories must be either all zero bytes or the canonical octal value zero and are never applied.

Owner names are structurally limited to NUL-padded printable ASCII but are not applied to the destination. Mode and modification time are recorded in format-specific layout evidence; Sealr does not restore owner, group, timestamp, set-ID bits, or special-file effects.

## Evidence and compatibility

The IR schema is `sealr.archive-ir.tar-ustar.v1`. Exact header, payload, padding, terminator, and trailing-zero ranges are recorded. Each member also records mode, modification time, header checksum, and header SHA-256. Public TAR JSON contains TAR-native evidence and omits inapplicable ZIP fields. TAR layout uses `sealrTreeV2`; the verified content tree remains format-neutral.

An independent verifier validates the declared TAR covering geometry and evidence digests, then reconstructs the profile, layout, and content roots without depending on the Sealr crate. The layout vector does not embed source bytes or parse ustar headers. A committed exact sparse corpus separately reconstructs archives produced by GNU tar 1.35, bsdtar 3.8.4, and Python 3.12.10 `tarfile.USTAR_FORMAT`, hashes and applies those exact bytes, and pins their source, layout, content, and verified member results.

The dedicated `tar_ustar_portable_v1` fuzz target is bound by [`tar-seed-manifest.json`](../../fuzz/tar-seed-manifest.json). It caps input at 4 MiB and begins from 15 exact seeds, including valid empty, one-file, directory-plus-file, and GNU tar states plus checksum, type, numeric, padding, path, duplicate, and topology boundaries. A deterministic checked-in generator reproduces the 13 binary seeds. The target drives untouched bytes, repairs checksums on a separate canonical mutation lane so post-checksum fields remain reachable, repeats successful parses at exact quota frontiers, audits source geometry, and exercises inspect-only public application. Its scheduled promotion history starts at zero because the expanded TAR-inclusive campaign cannot inherit runs from the earlier two-target domain.

The compatibility `apply()` facade remains ZIP32 strict ASCII v1. TAR callers select:

```rust
use sealr::{ApplyOptions, Policy, TarInterpretationProfile};

let policy = Policy::default_v2();
let options = ApplyOptions::new()
    .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1);
```

The policy and operation selection are separate gates. `Policy::default_v1()` remains ZIP-only and refuses TAR before reading the source. `Policy::default_v2()` authorizes ZIP and portable ustar, while `ApplyOptions` selects exactly one parser. The CLI constructs the matching policy for the explicit `--format` value.

The CLI selects the same profile with `--format tar-ustar`. Filename suffixes do not select a parser.

The authenticated Linux worker protocol remains ZIP-only in this increment. Selecting TAR with a worker returns typed `IsolationUnavailable` and never falls back to in-process verification.

## Authorities

- [POSIX.1 pax and ustar interchange format](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) defines the ustar block fields and interchange rules.
- [GNU tar archive formats](https://www.gnu.org/software/tar/manual/html_chapter/Formats.html) documents GNU, PAX, base-256, long-name, and sparse extensions that this first profile denies.
