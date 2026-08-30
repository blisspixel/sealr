# Strict gzip-wrapped GNU long-name profile v1

> Status: supported in-process preview released in Alpha.12. Authenticated worker execution fails closed until a later semantic record can bind both snapshot domains, their transform, and the carrier state.

Profile ID: `sealr.profile.tar-gzip.gnu-longname-portable.v1`

Profile SHA-256: `622943e9629c4acc7cfeb446eb9f2d16bb245db589c1a200e885a9d69a02295a`

Select this profile explicitly with `TarGzipInterpretationProfile::GnuLongNamePortableV1` and authorize it with `Policy::default_v7()`. The CLI selection is `--format tar-gzip-gnu-longname`. `apply()`, `--format zip`, `--format tar-gzip-ustar`, `--format tar-gzip-pax`, raw GNU selection, source suffixes, and gzip FNAME never select or retry this profile. The composition exists only because the [restricted raw GNU long-name profile](tar-gnu-longname-portable-v1.md) is frozen; the wrapper cannot hide an unsettled inner interpretation.

## Exact two-domain model

- Domain 0 is the exact caller-supplied gzip source. Receipt source, observed magic, `ArchiveIR::source_digest`, and wrapper ranges refer only to these compressed bytes.
- Domain 1 is one private immutable decoded TAR snapshot. The GNU covering, carrier ranges, and member payload ranges refer only to this domain.
- Exactly one transform connects them. It consumes the complete domain 0 range under `sealr.transform.gzip.rfc1952-single-member.v1` and produces terminal domain 1.
- The transform profile digest is `795a124c278eacf1fb9b4fc3825a74240d6d0e89c29ffdfe6118ff6db53c0a45`.
- The decoder-parameter digest is `c835627b01c4b54041c627319fab4d5af294a203ac26fbe91cadb6d1f17cd5e1`.

The ready boundary rejects a missing, extra, chained, subrange, redirected, or mismatched transform. It independently audits the wrapper over domain 0, the GNU covering and carrier-state replay over domain 1, and the complete cross-layer binding before a destination stage can be created.

## Accepted gzip language

The wrapper language is byte-for-byte the language of the [strict gzip-wrapped portable ustar profile](tar-gzip-ustar-portable-v1.md): exact RFC 1952 magic and method 8, exactly one member, reserved flag bits zero, exact optional-field framing with unique nonzero FEXTRA subfield identifiers, FHCRC verification when present, one exact Deflate stream consuming the complete recorded compressed-payload range, trailer CRC32 and ISIZE agreement with the complete derived TAR, and no trailing byte, zero padding, or concatenated member.

## Accepted TAR language

The decoded bytes must satisfy the complete [restricted raw GNU long-name profile v1](tar-gnu-longname-portable-v1.md). Exact old-GNU magic is required, and the only extension is one bounded pathname-only `L` carrier consumed by exactly one immediately following ordinary member. `K` long-link records, sparse records, base-256 numbers, PAX records, mixed state, orphan carriers, links, devices, concatenation, and recovery behavior remain denied.

## Resource contract

Policy v7 preserves the existing original-source, file-count, member, total extracted-byte, path, and effect controls and requires the explicit `max_derived_archive_bytes` cap.

- `max_archive_bytes` bounds domain 0.
- `max_derived_archive_bytes` bounds domain 1 while it is decoded.
- `max_metadata_bytes` cumulatively bounds the gzip header and trailer plus the GNU carrier headers, carrier payloads, member headers, and terminator.
- `max_ratio` separately bounds decoded TAR bytes against the recorded Deflate payload length and continues to apply to extracted members.
- The restricted GNU caps are unchanged: 8,192 carrier payload bytes and 1,024 carriers per archive.

The default v7 policy sets both original and derived archive caps to 512 MiB. The profile adds no runtime package and reuses the existing `flate2` and `crc32fast` dependency boundary.

## Evidence and identities

The IR schema is `sealr.archive-ir.tar-gzip-gnu-longname.v1`. It nests the exact gzip wrapper evidence beside the complete GNU archive evidence: carrier geometry, carrier payload identity, and per-member header-or-carrier path provenance. Every member carries the gzip-GNU evidence variant, and every payload plan resolves to domain 1.

Source identity is SHA-256 of domain 0. Interpretation identity is the canonical composite profile above, which binds the wrapper transform digests and the exact frozen inner GNU profile digest. Layout identity is `sealrTreeV8`, labeled `sealr.tree.layout.tar-gzip-gnu-longname.v1`, and binds the transform identifiers, both domain identities, wrapper evidence, and the complete inner GNU layout including carriers and provenance. Content identity remains the format-neutral `sealrTreeV1` over verified paths and bytes.

Consequences:

- Raw restricted GNU long-name TAR and its gzip wrapper have different source, interpretation, and layout identities but the same content identity.
- Two gzip encodings of the same GNU archive have the same interpretation and content identities. Their source identities differ, and their layout identities differ whenever a bound wrapper field or geometry differs.
- No content identity is available before every admitted member is verified.

The standalone identity verifier reconstructs the canonical composite profile, wrapper and derived-byte integrity, GNU evidence and carrier replay, `sealrTreeV8`, and `sealrTreeV1` without linking Sealr or invoking a decompressor.

## API example

```rust
use sealr::{ApplyOptions, Policy, TarGzipInterpretationProfile};

let policy = Policy::default_v7();
let options = ApplyOptions::new().with_tar_gzip_interpretation_profile(
    TarGzipInterpretationProfile::GnuLongNamePortableV1,
);
```

The policy and selection are separate gates. Policies v1 through v6 refuse this selection before source ingestion. Combining the selection with a worker manifest returns typed isolation-unavailable failure and never falls back to in-process execution.

## Authorities

- [RFC 1952](https://www.rfc-editor.org/rfc/rfc1952) defines the gzip member framing, optional fields, CRC32, and ISIZE.
- [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951) defines the Deflate payload language.
- [GNU tar manual, Basic Tar Format and GNU extensions](https://www.gnu.org/software/tar/manual/html_node/Standard.html) documents the old-GNU `L` long-name carrier convention.
