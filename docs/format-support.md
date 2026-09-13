# Format support architecture

Updated 2026-08-30.

Sealr targets the major open archive families used for software distribution, system packaging, and cross-platform exchange. Format breadth does not authorize a fallback extractor, implicit recovery, or an unbounded dependency graph. Every accepted language is an explicit interpretation profile over one immutable source snapshot.

## Target matrix

The matrix separates structural parsing, payload decoding, advanced dialect features, consumer semantics, and supervised parity. A filename suffix is never an interpretation rule. A row marked structural does not imply that every common compression method or higher-level package effect is supported.

| Family | Structural profile | Payload codecs | Advanced or composed semantics | State | Supervised parity | Dependency intent |
|---|---|---|---|---|---|---|
| ZIP | classic ZIP32 | Store, Deflate | Closed ASCII and portable UTF-8 profiles | Shipped | Shipped on x86_64 Linux | Existing `flate2` boundary |
| ZIP64 | saturated legacy fields plus exact ZIP64 records | Reuse ZIP codecs | Redundant-field and descriptor agreement | Alpha.10 in-process preview under policy v3 | Fails closed until semantic-record v3 | Zero new runtime dependencies |
| raw TAR | portable POSIX ustar | Raw payload | Regular files and directories only | Supported preview in v0.1.0-alpha.9 | Pending, typed refusal today | Zero new runtime dependencies |
| restricted raw POSIX PAX | exact ustar headers plus local and global extension records | Raw payload | Only canonical `path` and `size`, fixed precedence and provenance, links and sparse denied | Alpha.11 in-process preview under policy v5 | Fails closed until a later semantic record | Zero new runtime dependencies |
| GNU long-name TAR | separate GNU long-name-only profile | Raw payload | Exact `L` carrier adjacency, long links and sparse denied | Alpha.12 in-process preview under policy v6 | Fails closed until a later semantic record | Zero new runtime dependencies |
| gzip-wrapped portable ustar | exact RFC 1952 single-member wrapper plus portable ustar | Deflate | Closed optional fields, no trailing input, two immutable domains, exact transform binding | Alpha.10 in-process preview under policy v4 | Fails closed until a later semantic record | Reuse existing `flate2`; zero new packages |
| gzip-wrapped restricted PAX and GNU TAR | exact existing gzip transform plus one frozen raw dialect | Deflate | Distinct `sealrTreeV7` and `sealrTreeV8` composition identities, unchanged inner precedence and covering rules | Alpha.12 in-process previews under policy v7 | Fails closed until a later semantic record | Reuse existing `flate2`; zero new packages |
| zstd-wrapped portable ustar | exact RFC 8878 single-frame wrapper plus portable ustar | Zstandard | 8 MiB window ceiling, skippable frames and dictionaries denied, checksum and content size verified when present, concatenation denied | Alpha.12 in-process preview under policy v8 | Fails closed until a later semantic record | `ruzstd` 0.9.0 + `twox-hash` 2.1.4; the exact two-package Gate B budget |
| xz-wrapped portable ustar | exact single-stream XZ container plus portable ustar | LZMA2 | 8 MiB dictionary ceiling, LZMA2-only filter chain, checks verified twice with `None` denied, index and backward size verified, stream padding and concatenation denied | Alpha.12 in-process preview under policy v9 | Fails closed until a later semantic record | `lzma-rust2` 0.20.0 (`std`+`xz` features only); a one-package Gate B delta |
| bzip2-wrapped portable ustar | exact single-stream bit-aligned bzip2 container plus portable ustar | BWT pipeline | Levels 1-9 only, randomized blocks and bzip1 denied, footer shift-scan and block-magic chain fold verified, concatenation denied | Alpha.12 in-process preview under policy v10 | Fails closed until a later semantic record | `bzip2` 0.6.1 + `libbz2-rs-sys` 0.2.5; the exact two-package Gate B budget |
| LZ4 frame | exact modern frame wrapper profile | LZ4 blocks | Block bounds, checksums, dictionary, legacy, skippable, and concatenation rules | Planned Tier 2 | Required before promotion | Review `lz4_flex` after the shared xxHash dependency lands |
| 7z Copy container | local raw-header Copy-only interpreter | Copy | Minimal NUMBER encodings, dense covering, all CRCs Sealr-verified, packed headers and every non-Copy coder denied with named remedies | Alpha.12 in-process preview under policy v11 | Fails closed until a later semantic record | Zero new runtime dependencies; LZMA members and packed headers are the named next Gate C steps on the reviewed `lzma-rust2` boundary |
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

Format-specific evidence is not forced into ZIP field names. ZIP32 keeps `sealr.archive-ir.v1` and `sealrTreeV1` byte for byte stable. Portable ustar uses `sealr.archive-ir.tar-ustar.v1` and `sealrTreeV2`; strict ZIP64 uses `sealr.archive-ir.zip64.v1` and `sealrTreeV3`; gzip-wrapped ustar uses `sealr.archive-ir.tar-gzip-ustar.v1` and `sealrTreeV4`; restricted raw PAX uses `sealr.archive-ir.tar-pax.v1` and `sealrTreeV5`; restricted raw GNU long-name TAR uses `sealr.archive-ir.tar-gnu-longname.v1` and `sealrTreeV6`; gzip-wrapped PAX and GNU use `sealr.archive-ir.tar-gzip-pax.v1` and `sealr.archive-ir.tar-gzip-gnu-longname.v1` with `sealrTreeV7` and `sealrTreeV8`; zstd, XZ, and bzip2 ustar compositions use their wrapper-native IRs and `sealrTreeV9` through `sealrTreeV11`; and Copy-only 7z uses `sealr.archive-ir.7z-copy.v1` and `sealrTreeV12`. Every format retains the format-neutral `sealrTreeV1` content encoding after complete verification.

## Dependency budget

Across the three supported targets, the Alpha.12 `sealr` library declares 19 distinct direct runtime dependency names. The pinned Windows normal and build graph resolves 18 direct and 60 external packages; the exact per-target counts and graph digests are in the [TCB report](tcb-report.md#runtime-dependencies-per-release-target). Raw ustar, strict ZIP64, gzip-wrapped ustar, restricted raw PAX, restricted GNU TAR, the gzip compositions, and Copy-only 7z add no dependency. The three promoted codec wrappers account for the bounded dependency widening.

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

The current dependency ceiling is no more than two new runtime packages for one promoted codec and no new C or C++ build chain. Required CI pins the exact normal and build dependency graph, direct dependencies, build-script packages, and `links` packages for all three release targets, and rejects common native toolchain packages. ZIP64, gzip, PAX, GNU TAR, cpio, ar, deb structure, RPM structure, and CAB Store or MSZIP require no new package. The executed promotions are `ruzstd` plus `twox-hash` for zstd (+2 packages), `lzma-rust2` for xz (+1 package, also covering later 7z LZMA), and `bzip2` plus pure-Rust `libbz2-rs-sys` for bzip2 (+2 packages, with `bzip2-sys` structurally forbidden). The remaining candidates are `lz4_flex` after xxHash is shared and `lzxd` for later CAB LZX. Full RAR decompression has no accepted dependency. The exact feature, unsafe-code, licensing, and promotion decisions are maintained in [codec dependency gates](codec-dependency-gates.md).

The ranked delivery order is now the 7z LZMA/LZMA2 member and packed-header steps on the landed Copy-first structure after the usefulness, compatibility, and review milestones. GNU long-name raw TAR, the gzip compositions, the zstd, XZ/LZMA2, and bzip2 wrappers, and the Copy-only 7z container ship in Alpha.12. Cpio, ar/deb, CAB, RPM, and RAR5 follow later. ZIP64 and TAR worker-record parity continues beside that format lane. RAR4 remains a separate research gate. ISO 9660, UDF, and other filesystem images are not part of this sequence. Every stage reuses the same snapshot, plan, quota, path, verification, capability, worker, and identity boundary.

## Why ustar is first

POSIX ustar is a fixed 512-byte block language and can prove the multi-format plan, evidence, verification, and materialization seams without adding a decoder. It is still not treated as simple. The initial profile validates every header checksum and numeric field, requires exact magic and version, bounds metadata and members, requires zero member padding and two zero terminator blocks, and rejects links, devices, FIFOs, PAX, GNU long-name records, sparse encodings, base-256 numbers, concatenation, and hidden nonzero trailing blocks.

Restricted PAX landed as a separate Alpha.11 profile because keyword precedence can replace names and sizes. It admits only exact `path` and `size` records, keeps fixed global and local state with explicit provenance, and independently replays that state before readiness. GNU long-name handling follows as another profile; GNU sparse formats follow only if their reconstructed ranges, logical size, and resource behavior can be expressed without ambiguity. The [GNU tar manual](https://www.gnu.org/software/tar/manual/html_chapter/Formats.html) documents why these are distinct dialects rather than harmless metadata.

7z follows a separate structural threat model. Its [official format description](https://github.com/ip7z/7zip/blob/main/DOC/7zFormat.txt) permits packed headers, folders of coders, multiple input and output streams, bind pairs, and substreams. It cannot safely be modeled as TAR with a different decoder.

RAR remains an explicit target rather than an unmentioned exclusion. The [RAR 5 technical note](https://www.rarlab.com/technote.htm) defines bounded variable integers and header CRCs, but points to UnRAR source for compression algorithms and deeper details. Implementation waits for a written decoder and license decision that preserves Sealr's redistribution and small-TCB requirements.

## Promotion rule

A row moves to shipped only when inspect, retention, later reads, and materialization share one admitted plan; hostile fixtures cover every denied structural branch; source covering is exact; native Linux, macOS, and Windows gates pass; release artifacts carry dependency license closure; and README limitations state the exact profile rather than the file extension.
