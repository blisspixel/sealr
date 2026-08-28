# Format support architecture

Updated 2026-08-28.

Sealr targets the major open archive families used for software distribution, system packaging, and cross-platform exchange. Format breadth does not authorize a fallback extractor, implicit recovery, or an unbounded dependency graph. Every accepted language is an explicit interpretation profile over one immutable source snapshot.

## Target matrix

The matrix separates structural parsing, payload decoding, advanced dialect features, consumer semantics, and supervised parity. A filename suffix is never an interpretation rule. A row marked structural does not imply that every common compression method or higher-level package effect is supported.

| Family | Structural profile | Payload codecs | Advanced or composed semantics | State | Supervised parity | Dependency intent |
|---|---|---|---|---|---|---|
| ZIP | classic ZIP32 | Store, Deflate | Closed ASCII and portable UTF-8 profiles | Shipped | Shipped on x86_64 Linux | Existing `flate2` boundary |
| ZIP64 | saturated legacy fields plus exact ZIP64 records | Reuse ZIP codecs | Redundant-field and descriptor agreement | Explicit current-main in-process preview under policy v3 | Fails closed until semantic-record v3 | Zero new runtime dependencies |
| raw TAR | portable POSIX ustar | Raw payload | Regular files and directories only | Supported preview in v0.1.0-alpha.9 | Pending, typed refusal today | Zero new runtime dependencies |
| rich TAR | separate PAX and GNU profiles | Raw payload | Bounded keyword precedence, long names, links, sparse rules | Planned | Required before promotion | Zero new runtime dependencies |
| gzip-wrapped portable ustar | exact RFC 1952 single-member wrapper plus portable ustar | Deflate | Closed optional fields, no trailing input, two immutable domains, exact transform binding | Explicit current-main in-process preview under policy v4 | Fails closed until a later semantic record | Reuse existing `flate2`; zero new packages |
| zstd | exact frame wrapper profile | Zstandard | Window, skippable-frame, checksum, concatenation, and dictionary rules | Planned | Required before promotion | Review `ruzstd` with a hard maximum window |
| xz and LZMA | exact stream wrapper and coder profiles | LZMA, LZMA2 | Memory limit, concatenation, and exact input consumption | Planned | Required before promotion | Review minimal `lzma-rust2` features |
| bzip2 | exact stream wrapper profile | BWT pipeline | Whole-stream CRC, concatenation, and work budget | Planned | Required before promotion | Review `bzip2` with pure-Rust `libbz2-rs-sys` backend |
| LZ4 frame | exact modern frame wrapper profile | LZ4 blocks | Block bounds, checksums, dictionary, legacy, skippable, and concatenation rules | Planned Tier 2 | Required before promotion | Review `lz4_flex` after the shared xxHash dependency lands |
| 7z | local bounded header and coder-graph interpreter | Copy first, then LZMA and LZMA2 | Packed headers, acyclic bind graph, substreams, solid routing, encryption denial | Planned Tier 1 | Required before promotion | No full extractor crate; reuse reviewed codec adapter |
| cpio | portable `newc` profile | Raw payload | Hardlink identity, trailer, modes, devices, alignment | Planned Tier 2 | Required before promotion | Zero new runtime dependencies |
| ar | common GNU and BSD profiles | Raw payload | Long-name tables, symbol tables, thin-reference denial | Planned Tier 2 | Required before promotion | Zero new runtime dependencies |
| deb | typed common-ar composition | gzip, xz, zstd, bzip2 as promoted | Exact order and constrained `control.tar` plus `data.tar` profiles | Planned Tier 2 | Required before promotion | Reuse promoted wrappers only |
| CAB | local bounded cabinet profile | Store and MSZIP first, LZX later | Folder streams, block checksums, multi-cabinet authority | Planned Tier 2 | Required before promotion | Reuse Deflate; separate LZX decision |
| RPM | local lead, signature, and header profiles | gzip, xz, zstd, bzip2 as promoted | Typed cpio payload composition and signature policy | Planned Tier 2 | Required before promotion | Reuse cpio and promoted wrappers only |
| RAR5 | separate local structural profile | Store first | Bounded vint headers, solid state, filters, services, volumes, encryption | Research gate | Required before promotion | Decoder and license decision required |
| RAR4 | separate local structural profile | Store first | Volumes, solid state, services, recovery, redirections, encryption | Research gate | Required before promotion | Decoder and license decision required |

JAR, wheel, NuGet, Office Open XML, and OpenDocument are consumer profiles over ZIP. APK is ZIP-derived but needs a distinct structural profile because its signing block sits before the central directory. OCI and Docker layers require a TAR dialect plus a stateful layer applier for whiteouts, links, ownership, modes, extended attributes, and prior-tree effects. They are not equivalent to generic raw-TAR extraction. XAR and macOS package files require a later package-specific structural and signature gate. Compression aliases such as `.tgz` select an explicit wrapper plus TAR profile; they do not cause suffix sniffing.

ISO 9660, UDF, DMG, WIM, SquashFS, and other disk or filesystem images are a separate program with different namespace and authority problems. MSI, self-extracting executables, and installer execution also require separate product decisions and are not silently grouped under archive extraction. LHA/LZH, ACE, ARC, Unix `.Z`, lzip, Brotli-wrapped TAR, and similar legacy or niche formats remain Tier 3 research until measured corpus demand justifies their trusted-code cost.

## One execution core

Each container adapter must produce a format-specific covering and a common effect-independent member plan. The shared core owns:

- source snapshot identity and bounded random reads;
- quotas and checked aggregate arithmetic;
- portable path admission and topology collision checks;
- payload verification and exact range consumption;
- bounded retained and later member reads;
- capability-based staged writes, audit, durability evidence, and no-replace publication;
- structured findings, semantic axes, receipts, and content-tree identity.

Format-specific evidence is not forced into ZIP field names. ZIP32 keeps `sealr.archive-ir.v1` and `sealrTreeV1` byte-for-byte stable. Portable ustar uses `sealr.archive-ir.tar-ustar.v1`, exact TAR member and covering evidence, and `sealrTreeV2` for layout. Strict ZIP64 uses `sealr.archive-ir.zip64.v1`, ZIP64-native member and covering evidence, and `sealrTreeV3` for layout. Gzip-wrapped portable ustar uses `sealr.archive-ir.tar-gzip-ustar.v1`, wrapper-native and derived TAR evidence, and `sealrTreeV4` over the exact transform plus inner layout. Every format retains the format-neutral `sealrTreeV1` content encoding.

## Dependency budget

The Alpha.9 `sealr` library has 14 direct runtime dependencies. `cargo tree -p sealr -e normal` resolves 67 unique package lines on the current Windows target, including platform and transitive packages. Raw ustar adds no dependency and does not change the dependency set.

Every proposed runtime dependency must include high-assurance evidence and:

1. a capability that cannot reasonably be implemented with `std` or an existing dependency;
2. exact direct and transitive package changes from `cargo tree`;
3. license, maintenance, unsafe-code, native-code, build-tooling, advisory, and release-history review;
4. a maximum window, dictionary, allocation, input, output, and work budget;
5. proof that the adapter reports exact input consumption and rejects trailing or concatenated data unless the selected wrapper profile explicitly permits it;
6. cross-platform differential fixtures and independent golden evidence;
7. removal criteria if the dependency becomes unmaintained or violates the boundary;
8. evidence that its transitive, native, and `unsafe` footprint is the smallest practical option.

Optional Cargo features are not used to make the default binary unpredictably format-dependent. If a major format becomes supported by the release binary, release evidence names the exact codec graph it ships.

The current dependency ceiling is no more than two new runtime packages for one promoted codec and no new C or C++ build chain. Required CI pins the exact normal and build dependency graph, direct dependencies, build-script packages, and `links` packages for all three release targets, and rejects common native toolchain packages. ZIP64, gzip, PAX, GNU TAR, cpio, ar, deb structure, RPM structure, and CAB Store or MSZIP require no new package. The current candidates are `ruzstd` plus `twox-hash` for zstd, `lzma-rust2` for xz and 7z LZMA, `bzip2` plus pure-Rust `libbz2-rs-sys` for bzip2, `lz4_flex` after xxHash is shared, and `lzxd` for later CAB LZX. Full RAR decompression has no accepted dependency. The exact feature, unsafe-code, licensing, and promotion decisions are maintained in [codec dependency gates](codec-dependency-gates.md).

The ranked delivery order is ZIP64 and gzip-wrapped ustar assurance plus worker-record parity; raw PAX; GNU long-name-only TAR; gzip composition for both dialects; zstd, XZ, and bzip2 wrappers; 7z on the reviewed LZMA layer; then cpio, ar/deb, CAB, RPM, and RAR5. RAR4 remains a separate research gate. ISO 9660, UDF, and other filesystem images are not part of this sequence. Every stage reuses the same snapshot, plan, quota, path, verification, capability, worker, and identity boundary.

## Why ustar is first

POSIX ustar is a fixed 512-byte block language and can prove the multi-format plan, evidence, verification, and materialization seams without adding a decoder. It is still not treated as simple. The initial profile validates every header checksum and numeric field, requires exact magic and version, bounds metadata and members, requires zero member padding and two zero terminator blocks, and rejects links, devices, FIFOs, PAX, GNU long-name records, sparse encodings, base-256 numbers, concatenation, and hidden nonzero trailing blocks.

PAX follows as a separate profile because keyword precedence can replace names and sizes. GNU sparse formats follow only if their reconstructed ranges, logical size, and resource behavior can be expressed without ambiguity. The [GNU tar manual](https://www.gnu.org/software/tar/manual/html_chapter/Formats.html) documents why these are distinct dialects rather than harmless metadata.

7z follows a separate structural threat model. Its [official format description](https://github.com/ip7z/7zip/blob/main/DOC/7zFormat.txt) permits packed headers, folders of coders, multiple input and output streams, bind pairs, and substreams. It cannot safely be modeled as TAR with a different decoder.

RAR remains an explicit target rather than an unmentioned exclusion. The [RAR 5 technical note](https://www.rarlab.com/technote.htm) defines bounded variable integers and header CRCs, but points to UnRAR source for compression algorithms and deeper details. Implementation waits for a written decoder and license decision that preserves Sealr's redistribution and small-TCB requirements.

## Promotion rule

A row moves to shipped only when inspect, retention, later reads, and materialization share one admitted plan; hostile fixtures cover every denied structural branch; source covering is exact; native Linux, macOS, and Windows gates pass; release artifacts carry dependency license closure; and README limitations state the exact profile rather than the file extension.
