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
| zstd TAR and deb/RPM payloads | [`ruzstd`](https://docs.rs/crate/ruzstd/latest) | One standard frame, no dictionary, skippable frame, or concatenation; cap the frame window before allocation | Exact frame, checksum, window, and output evidence plus dependency delta review |
| XZ and 7z LZMA/LZMA2 | [`lzma-rust2`](https://docs.rs/crate/lzma-rust2/latest) | Disable default features; keep the `optimization` feature off; one XZ stream with LZMA2 only before legacy LZMA_Alone | Index, Footer, check, dictionary, filter-chain, and unsafe-feature proofs |
| bzip2 TAR and package payloads | [`bzip2`](https://docs.rs/crate/bzip2/latest) | Rust backend only; forbid the optional C `bzip2-sys` path; one stream with exact EOF | Block and combined CRC evidence plus backend and graph pinning |
| LZ4 TAR | [`lz4_flex`](https://docs.rs/lz4_flex/latest/lz4_flex/) | Safe checked decoding; one standard frame with independent blocks; no dictionary, legacy, skippable, or concatenated frames | Header, block, content checksum, allocation, and feature review |
| CAB LZX | [`lzxd`](https://docs.rs/crate/lzxd/latest) | One-cabinet LZX after Store and MSZIP; cap window and folder state before allocation | Microsoft CAB/LZX vectors, folder reset semantics, and exact CFDATA consumption |

Candidate status is not approval. Each promotion updates the machine-readable dependency contract, target-specific license closure, unsafe inventory, MSRV checks, 32-bit checks, conformance vectors, fuzz campaign, and measured memory ceilings in the same change.

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
