# Strict gzip-wrapped portable ustar profile v1

> Status: supported Alpha.10 in-process preview. Authenticated worker execution fails closed until a later semantic record can bind both snapshot domains and their transform.

Profile ID: `sealr.profile.tar-gzip.ustar-portable.v1`

Profile SHA-256: `914acdc0eab541483309a6838716fe837488ca80a1b7758383f28e47470925e1`

Select this profile explicitly with `TarGzipInterpretationProfile::UstarPortableV1` and authorize it with `Policy::default_v4()`. The CLI selection is `--format tar-gzip-ustar`. `apply()`, `--format zip`, raw TAR selection, source suffixes, and gzip FNAME never select or retry this profile.

## Exact two-domain model

- Domain 0 is the exact caller-supplied gzip source. Receipt source, observed magic, `ArchiveIR::source_digest`, and wrapper ranges refer only to these compressed bytes.
- Domain 1 is one private immutable decoded TAR snapshot. TAR covering and member payload ranges refer only to this domain.
- Exactly one transform connects them. It consumes the complete domain 0 range under `sealr.transform.gzip.rfc1952-single-member.v1` and produces terminal domain 1.
- The transform profile digest is `795a124c278eacf1fb9b4fc3825a74240d6d0e89c29ffdfe6118ff6db53c0a45`.
- The decoder-parameter digest is `c835627b01c4b54041c627319fab4d5af294a203ac26fbe91cadb6d1f17cd5e1`.

The ready boundary rejects a missing, extra, chained, subrange, redirected, or mismatched transform. It independently audits the wrapper over domain 0, the portable ustar covering over domain 1, and the complete cross-layer binding before a destination stage can be created.

## Accepted gzip language

- Exact RFC 1952 magic and compression method 8.
- One member only, with reserved flag bits zero.
- A fixed ten-byte header followed by only the optional fields selected by FLG, in RFC order.
- `FEXTRA`, when present, is an exact XLEN-bounded sequence of complete SI1, SI2, LEN, and data subfields. SI2 cannot be zero and each SI1/SI2 identifier appears at most once.
- FNAME and FCOMMENT are bounded NUL-terminated byte strings. They are evidence only and never archive paths.
- FHCRC is verified when present.
- The Deflate payload must be one exact RFC 1951 stream that consumes the complete recorded compressed-payload range.
- The trailer CRC32 and ISIZE modulo 2^32 must match the complete derived TAR.
- No trailing byte, zero padding, or concatenated member is admitted. A structurally complete additional member is reported as unsupported; malformed or truncated trailing input is malformed.

## Accepted TAR language

The decoded bytes must satisfy the complete [portable POSIX ustar profile v1](tar-ustar-portable-v1.md). Only regular files and directories are admitted. PAX, GNU extensions, links, sparse files, base-256 numbers, devices, FIFOs, concatenated archives, nonzero padding, and hidden data remain denied.

## Resource contract

Policy v4 preserves the existing original-source, file-count, member, total extracted-byte, path, and effect controls and adds `max_derived_archive_bytes`.

- `max_archive_bytes` bounds domain 0.
- `max_derived_archive_bytes` bounds domain 1 while it is decoded.
- `max_metadata_bytes` cumulatively bounds the gzip header and trailer plus TAR headers and terminator.
- `max_ratio` separately bounds decoded TAR bytes against the recorded Deflate payload length and continues to apply to extracted members.
- All sums and range ends use checked integer arithmetic. Ratio comparisons use widened integer arithmetic; equality passes and `null` alone disables the ratio limit.

The default v4 policy sets both original and derived archive caps to 512 MiB. The profile adds no runtime package and reuses the existing `flate2` and `crc32fast` dependency boundary.

## Evidence and identities

The IR schema is `sealr.archive-ir.tar-gzip-ustar.v1`. Wrapper evidence records exact header, optional field, compressed payload, and trailer ranges; fixed header values; subfield count; declared CRC32 and ISIZE; and derived length and SHA-256. Every member carries the gzip-TAR evidence variant, and every payload plan resolves to domain 1.

Source identity is SHA-256 of domain 0. Interpretation identity is the canonical composite profile above. Layout identity is `sealrTreeV4`, labeled `sealr.tree.layout.tar-gzip-ustar.v1`, and binds the transform identifiers, both domain identities, wrapper evidence, and complete inner TAR layout. Content identity remains the format-neutral `sealrTreeV1` over verified paths and bytes.

Consequences:

- Raw TAR and its gzip wrapper have different source, interpretation, and layout identities but the same content identity.
- Two gzip encodings of the same TAR have the same interpretation and content identities. Their source identities differ, and their layout identities differ whenever a bound wrapper field or geometry differs.
- No content identity is available before every admitted member is verified.

The standalone identity verifier reconstructs the canonical profile, wrapper and derived-byte integrity, TAR evidence, `sealrTreeV4`, and `sealrTreeV1` without linking Sealr or invoking a decompressor.

## API example

```rust
use sealr::{ApplyOptions, Policy, TarGzipInterpretationProfile};

let policy = Policy::default_v4();
let options = ApplyOptions::new().with_tar_gzip_interpretation_profile(
    TarGzipInterpretationProfile::UstarPortableV1,
);
```

The policy and selection are separate gates. Policies v1 through v3 refuse this selection before source ingestion. Combining the selection with a worker manifest returns typed isolation-unavailable failure and never falls back to in-process execution.

## Authorities

- [RFC 1952](https://www.rfc-editor.org/rfc/rfc1952) defines the gzip member framing, optional fields, CRC32, and ISIZE.
- [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951) defines the Deflate payload language.
- [POSIX pax and ustar interchange format](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) defines the inner ustar block language.
