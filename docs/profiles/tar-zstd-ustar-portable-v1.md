# Strict zstd-wrapped portable ustar profile v1

> Status: supported in-process preview on current main. This is the first promoted codec adapter beyond Deflate. Authenticated worker execution fails closed until a later semantic record can bind both snapshot domains and their transform.

Profile ID: `sealr.profile.tar-zstd.ustar-portable.v1`

Profile SHA-256: `c7d2e708f2f5258eddfb99fbf13661bd2f671a2daa4a45bc1d9603d30d472ae7`

Select this profile explicitly with `TarZstdInterpretationProfile::UstarPortableV1` and authorize it with `Policy::default_v8()`. The CLI selection is `--format tar-zstd-ustar`. `apply()`, `--format zip`, gzip selections, raw TAR selections, and source suffixes never select or retry this profile.

## Exact two-domain model

- Domain 0 is the exact caller-supplied Zstandard source. Receipt source, observed magic, `ArchiveIR::source_digest`, and wrapper ranges refer only to these compressed bytes.
- Domain 1 is one private immutable decoded TAR snapshot. TAR covering and member payload ranges refer only to this domain.
- Exactly one transform connects them. It consumes the complete domain 0 range under `sealr.transform.zstd.rfc8878-single-frame.v1` and produces terminal domain 1.
- The transform profile digest is `86745123584dc79e454f8f1bbf5a1bd1b75d1334902fd629e8eee8f251aa9d19`.
- The decoder-parameter digest is `a4a46d31cf8acbbfe043745ba1df4f43b7a955efc28ee8913804a99bae79d503`.

The ready boundary rejects a missing, extra, chained, subrange, redirected, or mismatched transform. It independently audits the wrapper over domain 0, the portable ustar covering over domain 1, and the complete cross-layer binding — including an independent XXH64 replay of the derived bytes when the frame declares a content checksum — before a destination stage can be created.

## Two decoders, one meaning

Unlike the gzip wrapper, whose framing Sealr parses alone before handing `flate2` a headerless Deflate stream, the `ruzstd` decoder parses the RFC 8878 frame header itself. Sealr therefore parses the header independently for byte-exact evidence and grammar enforcement, then cross-checks its reading against the decoder's: consumed header length, declared frame content size, checksum presence, and total consumption must agree exactly, and any disagreement is an integrity failure that keeps admission not-evaluated. Neither interpretation is ever preferred silently.

## Accepted zstd language

- Exact little-endian magic `0xFD2FB528` at offset zero and exactly one standard frame consuming the complete source.
- The reserved frame-descriptor bit must be zero. The unused frame-descriptor bit must also be zero: RFC 8878 permits it, but the restricted profile closes the language instead of carrying an uninterpreted bit.
- `Dictionary_ID` must be absent. No dictionary is ever registered with the decoder.
- The effective window — the window-descriptor formula for windowed frames, or `Frame_Content_Size` for single-segment frames — must not exceed 8 MiB, the RFC 8878 interoperability ceiling. It is enforced before decoder allocation. Windowed frames below the 1 KiB spec minimum are rejected.
- `Frame_Content_Size`, when present, must equal the decoded length exactly.
- The XXH64 content checksum, when the descriptor declares one, is verified against the decoded bytes by explicit comparison; the decoder's computed and declared values must both exist and agree.
- Skippable frames are rejected wherever they appear. Trailing bytes beginning with a standard or skippable magic are unsupported concatenation; any other trailing byte is malformed.
- Block decoding is bounded and incremental. `decode_all`-style multi-frame conveniences are never used.

## Accepted TAR language

The decoded bytes must satisfy the complete [portable POSIX ustar profile v1](tar-ustar-portable-v1.md). Only regular files and directories are admitted. PAX, GNU extensions, links, sparse files, base-256 numbers, devices, FIFOs, concatenated archives, nonzero padding, and hidden data remain denied.

## Resource contract

Policy v8 preserves the existing original-source, file-count, member, total extracted-byte, path, and effect controls and requires the explicit `max_derived_archive_bytes` cap.

- `max_archive_bytes` bounds domain 0.
- `max_derived_archive_bytes` bounds domain 1 while it is decoded.
- `max_metadata_bytes` cumulatively bounds the zstd frame header and checksum trailer plus TAR headers and terminator. Block headers are part of the compressed payload accounting.
- `max_ratio` separately bounds decoded TAR bytes against the recorded block-payload length and continues to apply to extracted members.
- The 8 MiB window ceiling is a profile constant, not a policy field. The reserved `max_dict_bytes` constructor field remains reserved and compiles only at its default.

The default v8 policy sets both original and derived archive caps to 512 MiB.

## Dependency boundary

This is the first Gate B codec promotion under the [codec dependency gates](../codec-dependency-gates.md). It adds exactly two runtime packages — `ruzstd` 0.9.0 and `twox-hash` 2.1.4 (`xxhash64` feature only) — with no build scripts, no `links` packages, no native code, and MIT licenses inside the existing allowlist. The pinned per-target dependency contract records the +2 delta on all three release floors. `ruzstd`'s `unsafe` surface is confined to its ring buffer and remains a named review item in the promotion evidence; the version floor 0.9.0 postdates the RUSTSEC-2024-0400 fix and includes the first-frame window-cap correction.

## Evidence and identities

The IR schema is `sealr.archive-ir.tar-zstd-ustar.v1`. Wrapper evidence records the exact descriptor byte and decoded flags, window descriptor and effective window size, optional frame content size, header, block payload, and trailer ranges, the declared checksum when present, and derived length and SHA-256. Every member carries the zstd-TAR evidence variant, and every payload plan resolves to domain 1.

Source identity is SHA-256 of domain 0. Interpretation identity is the canonical composite profile above, which binds the wrapper transform digests and the exact frozen inner ustar profile digest. Layout identity is `sealrTreeV9`, labeled `sealr.tree.layout.tar-zstd-ustar.v1`, and binds the transform identifiers, both domain identities, wrapper evidence, and complete inner TAR layout. Content identity remains the format-neutral `sealrTreeV1` over verified paths and bytes.

Consequences:

- Raw TAR, its gzip wrapper, and its zstd wrapper have three distinct source, interpretation, and layout identities but one shared content identity.
- Two zstd encodings of the same TAR (for example, different compression levels) have the same interpretation and content identities while their source and layout identities differ.
- No content identity is available before every admitted member is verified.

The standalone identity verifier reconstructs the canonical composite profile, wrapper grammar, derived-byte integrity including an independently implemented XXH64, TAR evidence, `sealrTreeV9`, and `sealrTreeV1` without linking Sealr or invoking a decompressor.

## Producer coverage

Measured against Zstandard CLI v1.5.7: default-level and level-19 outputs of small inputs are single-segment frames with content size and checksum present; large inputs produce windowed frames of 2 MiB (default) and exactly 8 MiB (level 19), all inside the profile. `zstd --long` output declares windows beyond 8 MiB and is rejected, matching the reference decompressor's own opt-in requirement for long-distance matching. Checksum and content size remain verified-when-present because pure-streaming producers may legally omit them.

## API example

```rust
use sealr::{ApplyOptions, Policy, TarZstdInterpretationProfile};

let policy = Policy::default_v8();
let options = ApplyOptions::new().with_tar_zstd_interpretation_profile(
    TarZstdInterpretationProfile::UstarPortableV1,
);
```

The policy and selection are separate gates. Policies v1 through v7 refuse this selection before source ingestion. Combining the selection with a worker manifest returns typed isolation-unavailable failure and never falls back to in-process execution.

## Authorities

- [RFC 8878](https://www.rfc-editor.org/rfc/rfc8878) defines the Zstandard frame, block, window, dictionary, and checksum language.
- [POSIX pax and ustar interchange format](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) defines the inner ustar block language.
- [ruzstd](https://github.com/KillingSpark/zstd-rs) is the reviewed pure-Rust decoder driven byte-for-byte by this profile.
