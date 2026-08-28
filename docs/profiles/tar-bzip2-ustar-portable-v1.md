# Restricted bzip2-wrapped portable ustar profile v1

> Status: supported in-process preview on current main. This is the third promoted codec adapter. Authenticated worker execution fails closed until a later semantic record can bind both snapshot domains and their transform.

Profile ID: `sealr.profile.tar-bzip2.ustar-portable.v1`

Profile SHA-256: `f6711c0c98cff6e3a2c6b266d159413ef891c202b4898b4e1665081dce0f29ee`

Select this profile explicitly with `TarBzip2InterpretationProfile::UstarPortableV1` and authorize it with `Policy::default_v10()`. The CLI selection is `--format tar-bzip2-ustar`. `apply()`, `--format zip`, gzip, zstd, and xz selections, raw TAR selections, and source suffixes never select or retry this profile.

## Exact two-domain model

- Domain 0 is the exact caller-supplied bzip2 source. Receipt source, observed magic, `ArchiveIR::source_digest`, and wrapper geometry refer only to these compressed bytes.
- Domain 1 is one private immutable decoded TAR snapshot. TAR covering and member payload ranges refer only to this domain.
- Exactly one transform connects them. It consumes the complete domain 0 range under `sealr.transform.bzip2.bzip2fmt-single-stream.v1` and produces terminal domain 1.
- The transform profile digest is `3520def23a770b24a29ae037ae31d3bfefeb3faf7132b07913ae71dbf028ece4`.
- The decoder-parameter digest is `c5c288439edcf5710a640215400fa2481f06fb0a2381ec96db29f7e1ace36195`.

The ready boundary rejects a missing, extra, chained, subrange, redirected, or mismatched transform. It independently audits the wrapper over domain 0, the portable ustar covering over domain 1, and the complete cross-layer binding before a destination stage can be created.

## Two decoders, one bit-aligned container

The `libbz2-rs-sys` decoder parses the container while streaming, and the bzip2 container is bit-aligned — blocks begin at arbitrary bit offsets with no padding between them — so Sealr's independent replay is a bit-level design rather than a byte-range walk:

- The header, first block magic, first block CRC, and the first deprecated `randomised` flag sit at fixed bit offsets and are checked before decoding.
- The footer is recovered from the decoder-established end by trying all eight padding shifts; exactly one shift may place the 48-bit end-of-stream magic flush against the end, the extracted combined CRC must match, and the padding bits themselves must be zero.
- A full-stream scan finds every occurrence of the 48-bit block magic — the same technique production parallel decompressors such as lbzip2 use — yielding an independent block count and per-block CRC list whose chain fold `combined = rotl1(combined) XOR blockCRC` must reproduce the footer's combined CRC exactly. A benign payload can contain the magic pattern by chance with probability about `n_bits × 2⁻⁴⁸` (~3×10⁻⁸ for a 1 GiB stream); that astronomically rare case fails the fold and is rejected — a documented benign mis-rejection bound — while a hostile embedding only breaks the attacker's own admission.
- Exact consumption is cross-checked: the decoder's consumed and produced totals must match the source and derived snapshot exactly. Any disagreement between the two interpretations fails closed as an integrity finding.

## Accepted bzip2 language

- Exact magic `"BZh"` at offset zero with a level digit `'1'..'9'`; the deprecated bzip1 `"BZ0"` container is rejected as unsupported.
- Exactly one stream consuming the complete source. Concatenated streams — the shape pbzip2 and Wikipedia multistream dumps produce — are rejected as unsupported; any other trailing byte is malformed.
- One to 65,536 blocks, counted by the verified magic scan. Multi-block streams are stock output whenever the input exceeds the level's block size.
- The deprecated `randomised` flag must be zero on every block, verified both at the fixed first-block offset before decoding and for every scanned block.
- Zero-block (empty) streams are rejected: an empty stream cannot carry a TAR archive.
- Footer padding bits must be zero, matching every measured producer and the reference encoder.
- Integrity is verified twice where the container makes it possible: the decoder verifies every block CRC and the combined CRC while streaming, and Sealr independently extracts every stored block CRC, replays the chain fold, and — for single-block streams, the common small-TAR case — re-hashes the entire derived snapshot with its own bzip2-variant CRC32 (MSB-first polynomial `0x04C11DB7`, not the reflected zlib CRC). Interior block boundaries in the decoded domain are not observable without decoding, so interior per-block re-hashing of multi-block streams is decoder-owned; the profile states this asymmetry rather than hiding it.

## Accepted TAR language

The decoded bytes must satisfy the complete [portable POSIX ustar profile v1](tar-ustar-portable-v1.md). Only regular files and directories are admitted. PAX, GNU extensions, links, sparse files, base-256 numbers, devices, FIFOs, concatenated archives, nonzero padding, and hidden data remain denied.

## Resource contract

Policy v10 preserves the existing original-source, file-count, member, total extracted-byte, path, and effect controls and requires the explicit `max_derived_archive_bytes` cap.

- `max_archive_bytes` bounds domain 0.
- `max_derived_archive_bytes` bounds domain 1 while it is decoded.
- `max_metadata_bytes` cumulatively bounds the stream header, every block's magic, CRC, and flag bits, and the padded footer — rounded up to whole bytes — plus TAR headers and terminator. Compressed block bodies are payload.
- `max_ratio` bounds decoded TAR bytes against the compressed payload and matters more here than for any earlier wrapper: bzip2's run-length stage permits ~51:1 in-block expansion and the format declares no output size anywhere — there is no ISIZE, frame-content-size, or index to cross-check, so the quota story carries the whole output bound.
- Decoder memory is format-capped, not attacker-declared: the header's level digit fixes allocation at `100k + 4 × blockSize` — at most ~3.7 MB at level 9 — before decoding, comfortably inside the 8 MiB ceiling precedent of the zstd and xz promotions. The reserved `max_dict_bytes` field remains reserved and compiles only at its default.

The default v10 policy sets both original and derived archive caps to 512 MiB.

## Dependency boundary

This is the third Gate B codec promotion under the [codec dependency gates](../codec-dependency-gates.md). It adds exactly two runtime packages — `bzip2` 0.6.1 and `libbz2-rs-sys` 0.2.5, the Trifecta Tech Foundation's pure-Rust translation — with no build scripts, no `links` packages, and no native code. The C path (`bzip2-sys`, `cc`) exists only behind a non-default feature and is structurally excluded by the dependency contract's forbidden-package list. `libbz2-rs-sys` carries the SPDX `bzip2-1.0.6` license, added deliberately to the cargo-deny allowlist as the first widening since the gates were written. The translation was audited by Radically Open Security and runs under Miri; only the raw sans-I/O `Decompress` is used — never the concatenation-tolerant `MultiBzDecoder` reader.

## Evidence and identities

The IR schema is `sealr.archive-ir.tar-bzip2-ustar.v1`. Wrapper evidence records the level, header range, total payload bits and padding bits, every scan-verified block bit offset and CRC, the combined CRC, and derived length and SHA-256 — bit offsets rather than byte ranges, because interior geometry is bit-granular. Every member carries the bzip2-TAR evidence variant, and every payload plan resolves to domain 1.

Source identity is SHA-256 of domain 0. Interpretation identity is the canonical composite profile above, which binds the wrapper transform digests and the exact frozen inner ustar profile digest. Layout identity is `sealrTreeV11`, labeled `sealr.tree.layout.tar-bzip2-ustar.v1`, and binds the transform identifiers, both domain identities, the complete bit-level wrapper evidence, and the complete inner TAR layout. Content identity remains the format-neutral `sealrTreeV1` over verified paths and bytes.

Consequences:

- Raw TAR and its gzip, zstd, xz, and bzip2 wrappers have five distinct source, interpretation, and layout identities but one shared content identity.
- Two bzip2 encodings of the same TAR (for example, different levels) have the same interpretation and content identities while their source and layout identities differ.
- No content identity is available before every admitted member is verified.

The standalone identity verifier reconstructs the canonical composite profile, the bit-level wrapper grammar including the footer shift-scan and chain fold, derived-byte integrity including an independently implemented bzip2-variant CRC32, TAR evidence, `sealrTreeV11`, and `sealrTreeV1` without linking Sealr or invoking a decompressor.

## Producer coverage

Measured against bzip2 1.0.8 and CPython 3.12 `bz2` (bundled libbz2 1.0.8): outputs are deterministic and byte-identical between the CLI and the library; small inputs produce one block at every level with only the level digit differing; inputs beyond the level's block size produce stock multi-block streams whose scanned block CRCs chain-fold exactly to the footer. pbzip2 output is multiple complete concatenated streams and is rejected as unsupported concatenation, the same posture the xz profile takes. The 14-byte empty stream is rejected at the composition layer.

## API example

```rust
use sealr::{ApplyOptions, Policy, TarBzip2InterpretationProfile};

let policy = Policy::default_v10();
let options = ApplyOptions::new()
    .with_tar_bzip2_interpretation_profile(TarBzip2InterpretationProfile::UstarPortableV1);
```

The policy and selection are separate gates. Policies v1 through v9 refuse this selection before source ingestion. Combining the selection with a worker manifest returns typed isolation-unavailable failure and never falls back to in-process execution.

## Authorities

- The bzip2 container has no formal specification; the language is fixed by the reference implementation ([bzip2 1.0.8 manual](https://sourceware.org/bzip2/manual/manual.html)) and its independent descriptions ([Joe Tsai's informal specification](https://github.com/dsnet/compress/blob/master/doc/bzip2-format.pdf)).
- [POSIX pax and ustar interchange format](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) defines the inner ustar block language.
- [libbzip2-rs](https://github.com/trifectatechfoundation/libbzip2-rs) is the audited pure-Rust decoder driven byte-for-byte by this profile.
