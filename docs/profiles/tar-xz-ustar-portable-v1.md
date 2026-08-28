# Restricted xz-wrapped portable ustar profile v1

> Status: supported in-process preview on current main. This is the second promoted codec adapter beyond Deflate. Authenticated worker execution fails closed until a later semantic record can bind both snapshot domains and their transform.

Profile ID: `sealr.profile.tar-xz.ustar-portable.v1`

Profile SHA-256: `16ec815ab3b2c3c5f877ec04e592d1dd1a6ec41f2c7d843dd7aa2bc6b50cfd05`

Select this profile explicitly with `TarXzInterpretationProfile::UstarPortableV1` and authorize it with `Policy::default_v9()`. The CLI selection is `--format tar-xz-ustar`. `apply()`, `--format zip`, gzip and zstd selections, raw TAR selections, and source suffixes never select or retry this profile.

## Exact two-domain model

- Domain 0 is the exact caller-supplied XZ source. Receipt source, observed magic, `ArchiveIR::source_digest`, and wrapper ranges refer only to these compressed bytes.
- Domain 1 is one private immutable decoded TAR snapshot. TAR covering and member payload ranges refer only to this domain.
- Exactly one transform connects them. It consumes the complete domain 0 range under `sealr.transform.xz.xzfmt-single-stream.v1` and produces terminal domain 1.
- The transform profile digest is `b3c323849a366141edc28e0c5ab0028253430d0f6a5bda2ebec728c3a6543667`.
- The decoder-parameter digest is `ebdf4f3d9624cad6b245054d78f84ca50f8cea18a368e0025d2812dae8799032`.

The ready boundary rejects a missing, extra, chained, subrange, redirected, or mismatched transform. It independently audits the wrapper over domain 0, the portable ustar covering over domain 1, and the complete cross-layer binding — including a second independent replay of every block check over the derived bytes — before a destination stage can be created.

## Two decoders, one meaning

Like the zstd wrapper, the `lzma-rust2` decoder parses the XZ container itself. Sealr therefore parses the container independently for byte-exact evidence and grammar enforcement, then cross-checks its reading against the decoder's: total consumption and produced length must agree exactly, and any disagreement is an integrity failure that keeps admission not-evaluated. Because the XZ container cannot be statically partitioned without decoding, Sealr's own parse runs footer-and-index first over exactly the decoder-established consumed range, then walks each recorded block forward and re-verifies every header CRC32, size relation, and check value. Neither interpretation is ever preferred silently.

## Accepted xz language

- Exact magic `FD 37 7A 58 5A 00` at offset zero and exactly one stream consuming the complete source. Stream padding and concatenated streams are rejected: `xz --decompress` accepts them, but the restricted profile closes the language instead of admitting bytes outside the single interpreted stream.
- One to 4096 blocks. Multi-block streams are required language: stock `xz` 5.4+ defaults to multithreaded compression, which splits large inputs into independent blocks.
- Exactly one filter per block, and it must be LZMA2. Delta, BCJ, and every other filter chain are rejected.
- The LZMA2 dictionary must not exceed 8 MiB, enforced from the properties byte before decoder allocation, with the decoder's own 8256 KiB memory limit as an independent second wall.
- The integrity check must be CRC32, CRC64, or SHA-256, and it is verified twice: once by the decoder during streaming, and once by Sealr's own implementation over the final derived bytes. Check `None` is rejected — the profile refuses streams that disclaim integrity.
- Declared compressed and uncompressed block sizes must appear both-or-neither and, when present, must equal the observed values exactly.
- All reserved bits — stream flags, block flags, and header padding — must be zero. Every header CRC32 (stream header, block headers, index, footer) is verified by Sealr independently of the decoder.
- The index must exactly tile the recorded blocks, and the footer's stored backward size must equal the real index size: three verifications the upstream decoder does not perform on its own.
- Stream decoding is bounded and incremental over a sans-I/O core. Reader conveniences that transparently accept concatenated streams are never used.

## Accepted TAR language

The decoded bytes must satisfy the complete [portable POSIX ustar profile v1](tar-ustar-portable-v1.md). Only regular files and directories are admitted. PAX, GNU extensions, links, sparse files, base-256 numbers, devices, FIFOs, concatenated archives, nonzero padding, and hidden data remain denied.

## Resource contract

Policy v9 preserves the existing original-source, file-count, member, total extracted-byte, path, and effect controls and requires the explicit `max_derived_archive_bytes` cap.

- `max_archive_bytes` bounds domain 0.
- `max_derived_archive_bytes` bounds domain 1 while it is decoded.
- `max_metadata_bytes` cumulatively bounds the stream header, block headers, block padding, checks, index, and footer plus TAR headers and terminator. Compressed block payloads are part of the payload accounting.
- `max_ratio` separately bounds decoded TAR bytes against the summed compressed block-payload length and continues to apply to extracted members.
- The 8 MiB dictionary ceiling is a profile constant, not a policy field. The reserved `max_dict_bytes` constructor field remains reserved and compiles only at its default.

The default v9 policy sets both original and derived archive caps to 512 MiB.

## Dependency boundary

This is the second Gate B codec promotion under the [codec dependency gates](../codec-dependency-gates.md). It adds exactly one runtime package — `lzma-rust2` 0.20.0 with `default-features = false` and only the `std` and `xz` features — with no build scripts, no `links` packages, no native code, and an Apache-2.0 license inside the existing allowlist. With the `optimization` feature disabled, the crate compiles under `forbid(unsafe_code)`, verified in the promotion evidence via the feature graph. The pinned per-target dependency contract records the +1 delta on all three release floors. The decoder's memory limit classifies as a pre-allocation safety wall; Sealr's own parse remains the language authority.

## Evidence and identities

The IR schema is `sealr.archive-ir.tar-xz-ustar.v1`. Wrapper evidence records the check identifier, the stream-header range, every block's header, compressed-payload, padding, and check ranges with its dictionary size, optional declared sizes, uncompressed length, and exact check value, the index and footer ranges, and derived length and SHA-256. Every member carries the xz-TAR evidence variant, and every payload plan resolves to domain 1.

Source identity is SHA-256 of domain 0. Interpretation identity is the canonical composite profile above, which binds the wrapper transform digests and the exact frozen inner ustar profile digest. Layout identity is `sealrTreeV10`, labeled `sealr.tree.layout.tar-xz-ustar.v1`, and binds the transform identifiers, both domain identities, wrapper evidence, and complete inner TAR layout. Content identity remains the format-neutral `sealrTreeV1` over verified paths and bytes.

Consequences:

- Raw TAR and its gzip, zstd, and xz wrappers have four distinct source, interpretation, and layout identities but one shared content identity.
- Two xz encodings of the same TAR (for example, different check types or block sizes) have the same interpretation and content identities while their source and layout identities differ.
- No content identity is available before every admitted member is verified.

The standalone identity verifier reconstructs the canonical composite profile, wrapper grammar, derived-byte integrity including independently implemented CRC32, CRC64, and SHA-256 checks, TAR evidence, `sealrTreeV10`, and `sealrTreeV1` without linking Sealr or invoking a decompressor.

## Producer coverage

Measured against XZ Utils v5.8.1: `xz -6` produces a single-block CRC64 stream for small inputs and byte-identical output to CPython 3.12 `lzma.compress` defaults; `-C crc32`, `-C sha256`, and `--block-size` outputs are inside the profile, including the multi-block streams that multithreaded compression emits. `-C none` output is rejected because it disclaims integrity. `xz -9` output declares a 64 MiB dictionary and is rejected by the 8 MiB pre-allocation ceiling. `.lzma` (LZMA1 alone) and concatenated `.xz` files are outside the profile.

## API example

```rust
use sealr::{ApplyOptions, Policy, TarXzInterpretationProfile};

let policy = Policy::default_v9();
let options = ApplyOptions::new()
    .with_tar_xz_interpretation_profile(TarXzInterpretationProfile::UstarPortableV1);
```

The policy and selection are separate gates. Policies v1 through v8 refuse this selection before source ingestion. Combining the selection with a worker manifest returns typed isolation-unavailable failure and never falls back to in-process execution.

## Authorities

- [The .xz File Format v1.2.1](https://tukaani.org/xz/xz-file-format.txt) defines the stream, block, index, footer, filter, and check language.
- [POSIX pax and ustar interchange format](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) defines the inner ustar block language.
- [lzma-rust2](https://github.com/hasenbanck/lzma-rust2) is the reviewed pure-Rust decoder driven byte-for-byte by this profile.
