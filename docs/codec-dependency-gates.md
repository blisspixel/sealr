# Codec dependency gates

Status: active design contract as of 2026-08-28.

Sealr admits one codec at a time. A format does not become supported merely because a general extractor crate can open it. Each codec must fit the same bounded snapshot, exact-consumption, verification, identity, and release-evidence model as Store and Deflate.

Required CI pins the exact normal and build dependency closure for Linux, macOS, and Windows. One promoted codec may add at most two runtime packages. Common native toolchain packages are denied, and every `links` package and build-script package is explicit evidence.

## Gate A: no new dependency

These layers reuse existing primitives or need only bounded structural parsing:

- single-member gzip and MSZIP reuse the existing Deflate adapter;
- PAX and selected GNU TAR extensions extend the TAR structural parser;
- cpio `newc` and `crc`, normal ar, deb composition, RPM structure, CAB Store, and RAR5 Store use local parsers;
- thin ar, links, sparse files, encryption, multivolume discovery, and recovery parsing remain denied in their first profiles.

## Gate B: isolated pure-Rust codec

| Format need | Candidate | Initial feature and language boundary | Promotion blocker |
|---|---|---|---|
| zstd TAR and deb/RPM payloads | [`ruzstd`](https://docs.rs/crate/ruzstd/latest) | One standard frame, no dictionary, skippable frame, or concatenation; cap the frame window before allocation | **Promoted on current main** as `sealr.profile.tar-zstd.ustar-portable.v1` under policy v8; see the executed evidence below |
| XZ and 7z LZMA/LZMA2 | [`lzma-rust2`](https://docs.rs/crate/lzma-rust2/latest) | Disable default features; keep the `optimization` feature off; one XZ stream with LZMA2 only before legacy LZMA_Alone | **Promoted on current main** as `sealr.profile.tar-xz.ustar-portable.v1` under policy v9; see the executed evidence below. 7z LZMA reuse is a separate later gate |
| bzip2 TAR and package payloads | [`bzip2`](https://docs.rs/crate/bzip2/latest) | Rust backend only; forbid the optional C `bzip2-sys` path; one stream with exact EOF | **Promoted on current main** as `sealr.profile.tar-bzip2.ustar-portable.v1` under policy v10; see the executed evidence below |
| LZ4 TAR | [`lz4_flex`](https://docs.rs/lz4_flex/latest/lz4_flex/) | Safe checked decoding; one standard frame with independent blocks; no dictionary, legacy, skippable, or concatenated frames | Header, block, content checksum, allocation, and feature review |
| CAB LZX | [`lzxd`](https://docs.rs/crate/lzxd/latest) | One-cabinet LZX after Store and MSZIP; cap window and folder state before allocation | Microsoft CAB/LZX vectors, folder reset semantics, and exact CFDATA consumption |

Candidate status is not approval. Each promotion updates the machine-readable dependency contract, target-specific license closure, unsafe inventory, MSRV checks, 32-bit checks, conformance vectors, fuzz campaign, and measured memory ceilings in the same change.

### Executed Gate B promotion: ruzstd for the zstd TAR wrapper

The first codec promotion landed on current main as the [zstd-wrapped portable ustar profile](profiles/tar-zstd-ustar-portable-v1.md). The recorded evidence:

- **Dependency delta**: exactly two runtime packages on every release target — `ruzstd =0.9.0` (`default-features = false, features = ["hash", "std"]`, so `dict_builder` and its `fastrand` dependency never enter the graph) and `twox-hash =2.1.4` (`xxhash64` only, zero required transitive packages). The pinned per-target [dependency contract](../tests/dependency-contract/sealr-runtime.json) records the +2 counts and new graph digests for `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, and `x86_64-pc-windows-msvc`. Neither package has a build script or a `links` key; both are MIT and pass cargo-deny.
- **Version floor**: 0.9.0 postdates both the RUSTSEC-2024-0400 ring-buffer fix (patched in 0.7.3) and the 0.8.3 correction that applies the window cap to the first frame of a stream. The workspace pins the exact version.
- **Closed language**: `sealr.transform.zstd.rfc8878-single-frame.v1` — exactly one standard frame, skippable frames and dictionaries denied, reserved and unused descriptor bits zero, effective window at most 8 MiB (the RFC 8878 interoperability ceiling) enforced pre-allocation, content checksum and frame content size verified when present, trailing data denied, bounded incremental block decoding only.
- **Checksum ownership**: `ruzstd` exposes but does not compare the declared and computed XXH64 values; Sealr performs the comparison in the transform layer, and the ready boundary independently re-hashes the derived snapshot with `twox-hash` before any destination stage exists.
- **Dual-parse containment**: `ruzstd` parses the frame header itself, so Sealr cross-checks its own byte-exact header interpretation against the decoder's consumed length, content size, and checksum state; any disagreement fails closed as an integrity finding.
- **Residual review items**: `ruzstd`'s `unsafe` ring buffer (31 blocks in `decoding/ringbuffer.rs`, the RUSTSEC-2024-0400 site) remains a named target for Miri and targeted review; measured decoder memory ceilings at the 8 MiB window remain an assurance-lane measurement; ZIP method 93 reuse of this adapter is a separate later gate. The Trifecta Tech `libzstd-rs-sys` decompressor is the tracked potential successor.

### Executed Gate B promotion: lzma-rust2 for the xz TAR wrapper

The second codec promotion landed on current main as the [xz-wrapped portable ustar profile](profiles/tar-xz-ustar-portable-v1.md). The recorded evidence:

- **Dependency delta**: exactly one runtime package on every release target — `lzma-rust2 =0.20.0` with `default-features = false, features = ["std", "xz"]`, zero required transitive packages, no build script, no `links` key, Apache-2.0, passing cargo-deny. The pinned per-target [dependency contract](../tests/dependency-contract/sealr-runtime.json) records the +1 counts and new graph digests for `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, and `x86_64-pc-windows-msvc`.
- **Unsafe boundary**: the crate declares `#![cfg_attr(not(feature = "optimization"), forbid(unsafe_code))]`; with the selected features, `optimization` stays off (verified through `cargo tree -e features`), so the decoder compiles under `forbid(unsafe_code)` on every target.
- **Closed language**: `sealr.transform.xz.xzfmt-single-stream.v1` — exactly one stream, one to 4096 blocks (multi-block is required language because stock `xz` 5.4+ defaults to multithreaded compression), exactly one LZMA2 filter per block, dictionaries capped at 8 MiB from the properties byte before allocation, checks limited to CRC32, CRC64, and SHA-256 with `None` denied, declared block sizes both-or-neither and verified, reserved bits zero, stream padding and concatenation denied, trailing data denied, bounded incremental sans-I/O decoding only (`XzStream`, never the concatenation-tolerant reader conveniences).
- **Checksum ownership**: the decoder verifies each block check while streaming; Sealr verifies every check a second time with its own CRC32, CRC64, and SHA-256 implementations over the final derived bytes at the ready boundary, before any destination stage exists.
- **Dual-parse containment**: `lzma-rust2` parses the container itself, so Sealr independently parses footer-and-index first over the decoder-established consumed range and re-verifies every header CRC32, the index tiling, the footer's backward size, and every reserved bit — three of which the upstream decoder does not enforce on its own; any disagreement fails closed as an integrity finding.
- **Memory wall**: `XzStream::new_mem_limit(false, 8256)` bounds decoder allocation independently of the profile's pre-allocation dictionary ceiling; the limit classifies as an unsupported-language refusal, never an allocation attempt.
- **Residual review items**: measured decoder memory ceilings at the 8 MiB dictionary remain an assurance-lane measurement; 7z LZMA/LZMA2 reuse of this adapter and legacy LZMA_Alone remain separate later gates; the `optimization` feature must stay excluded by CI feature-graph checks.

### Executed Gate B promotion: bzip2/libbz2-rs-sys for the bzip2 TAR wrapper

The third codec promotion landed on current main as the [bzip2-wrapped portable ustar profile](profiles/tar-bzip2-ustar-portable-v1.md). The recorded evidence:

- **Dependency delta**: exactly two runtime packages on every release target — `bzip2 =0.6.1` (Rust backend default since 0.6.0) and `libbz2-rs-sys =0.2.5` (`default-features = false, features = ["rust-allocator"]`, so `libc` stays out) — with no build scripts and no `links` keys. The C path (`bzip2-sys`, `cc`) exists only behind a non-default feature; the dependency contract adds `bzip2-sys` to `forbidden_packages` so feature unification can never smuggle it in. The pinned per-target [dependency contract](../tests/dependency-contract/sealr-runtime.json) records the +2 counts and new graph digests for all three release floors.
- **License widening**: `libbz2-rs-sys` carries the SPDX `bzip2-1.0.6` license, which was not in the cargo-deny allowlist. The promotion adds it deliberately with a named comment — the first allowlist widening since the gates were written — and extends the third-party license bundles and their pinned counts.
- **Audit posture**: the Trifecta Tech Foundation's c2rust translation of libbzip2 1.0.8 was audited by Radically Open Security ("no significant additional findings") and runs under Miri; the crate retains bounded `unsafe` for its C-ABI-shaped surface, sitting between lzma-rust2's `forbid(unsafe_code)` and ruzstd's unaudited ring buffer. The `bzip2` crate's RUSTSEC-2023-0004 infinite-loop advisory was fixed in 0.4.4, two years before the pinned version.
- **Closed language**: `sealr.transform.bzip2.bzip2fmt-single-stream.v1` — exactly one stream, one to 65,536 blocks, header levels `'1'..'9'` only, the deprecated bzip1 container and `randomised` blocks denied, zero-block streams denied, footer padding bits zero, stream concatenation (the pbzip2 shape) and trailing data denied, bounded incremental decoding through the raw sans-I/O `Decompress` only — never the concatenation-tolerant `MultiBzDecoder`.
- **Bit-level dual-parse containment**: the container is bit-aligned, so Sealr's independent replay recovers the footer by a unique-match eight-shift scan from the decoder-established end, scans the full stream for every 48-bit block magic — the technique production parallel decompressors use — extracts every stored block CRC, and requires the chain fold to reproduce the footer's combined CRC exactly; single-block streams are additionally re-hashed end to end with Sealr's own bzip2-variant CRC32 (MSB-first `0x04C11DB7`). The benign scan false-positive bound (~`n·2⁻⁴⁸`) is documented and fails closed.
- **Memory is format-capped**: the header level digit fixes decoder allocation at `100k + 4 × blockSize` (~3.7 MB at level 9) before decoding — nothing attacker-declared exists to cap, and no memory-limit API is needed.
- **No declared output size**: unlike gzip ISIZE, zstd frame-content-size, and the xz index, nothing in the container cross-checks decoded length; `max_ratio` and `max_derived_archive_bytes` carry the whole output bound against RLE1's ~51:1 in-block expansion, and the profile documentation says so.
- **Residual review items**: exact `unsafe` block inventory of libbz2-rs-sys at the pinned version, decode wall-time measurement at the derived-cap frontier, padding-bit posture against ancient producers, and deb/RPM payload plus ZIP method 12 reuse of the adapter remain named later gates.

## Gate C: complex container engine

7z is a high-priority format, but the trust boundary starts with its coder graph rather than a convenience API. The first profile is signature-at-zero, single-volume, no SFX, no encryption, no external streams, no alternate streams, no links, and an allowlist of Copy, LZMA, and LZMA2 coders with bounded dictionaries and solid blocks.

[`sevenz-rust2`](https://docs.rs/crate/sevenz-rust2/latest) is not accepted as a core dependency today. Its broad default feature set is unnecessary for the first profile, and its current minimal LZMA path must be shown to avoid the `lzma-rust2` unsafe optimization feature. Acceptable outcomes are an upstream feature correction or a small reviewed fork with an exact source and license pin. The official [7z format](https://github.com/ip7z/7zip/blob/main/DOC/7zFormat.txt) and [method identifiers](https://github.com/ip7z/7zip/blob/main/DOC/Methods.txt) remain the authority.

## Gate D: separate legal and runtime boundary

Compressed RAR5 has no accepted Sealr core decoder. Current UnRAR-derived options do not simultaneously satisfy the project's Apache-compatible distribution, minimal dependency, pure-Rust, and in-process assurance requirements. Core work is limited to a strict structural and Store-method profile.

Full compressed RAR5, if pursued, requires legal approval and a separately authenticated, reduced-authority worker with its own license, update, resource, and failure contract. Sealr will not silently invoke a system `unrar` binary. The authorities are the [RAR5 technical note](https://www.rarlab.com/technote.htm), [UnRAR resource notes](https://www.rarlab.com/unrar7notes.htm), and [RAR licensing terms](https://www.rarlab.com/license.htm).

## Promotion checklist

Every codec promotion must prove all of the following:

1. The specification subset is a closed versioned language with exact EOF behavior.
2. Window, dictionary, metadata, input, output, member, total, and ratio limits apply before or during allocation and decoding.
3. Checksums and declared sizes are verified independently where the format provides them.
4. Decoder output becomes an immutable derived snapshot bound to one typed transform record.
5. Parser and covering evidence identify the exact snapshot domain consumed by every member.
6. Existing profile, IR, receipt, semantic-record, and content identities remain byte stable.
7. The dependency contract, license closure, unsafe inventory, MSRV, and all release targets pass.
8. Official vectors, producer fixtures, differential checks, deterministic seeds, and bounded fuzzing cover accepted and rejected forms.

Format specifications are linked from the [format support architecture](format-support.md).
