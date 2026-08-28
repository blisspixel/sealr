# Format support architecture

Updated 2026-08-27.

Sealr targets the major open archive families used for software distribution, system packaging, and cross-platform exchange. Format breadth does not authorize a fallback extractor, implicit recovery, or an unbounded dependency graph. Every accepted language is an explicit interpretation profile over one immutable source snapshot.

## Target matrix

The matrix separates structural parsing, payload decoding, advanced dialect features, consumer semantics, and supervised parity. A filename suffix is never an interpretation rule. A row marked structural does not imply that every common compression method or higher-level package effect is supported.

| Family | Structural profile | Payload codecs | Advanced or composed semantics | State | Supervised parity | Dependency intent |
|---|---|---|---|---|---|---|
| ZIP | classic ZIP32 | Store, Deflate | Closed ASCII and portable UTF-8 profiles | Shipped | Shipped on x86_64 Linux | Existing `flate2` boundary |
| ZIP64 | saturated legacy fields plus exact ZIP64 records | Reuse ZIP codecs | Redundant-field and descriptor agreement | Next structural increment | Required before promotion | Zero new runtime dependencies |
| raw TAR | portable POSIX ustar | Raw payload | Regular files and directories only | Supported preview in v0.1.0-alpha.9 | Pending, typed refusal today | Zero new runtime dependencies |
| rich TAR | separate PAX and GNU profiles | Raw payload | Bounded keyword precedence, long names, links, sparse rules | Planned | Required before promotion | Zero new runtime dependencies |
| gzip | exact RFC 1952 wrapper profile | Deflate | Single versus concatenated members and trailing data are separate rules | Next wrapper | Required before promotion | Reuse existing `flate2` |
| zstd | exact frame wrapper profile | Zstandard | Window, skippable-frame, checksum, concatenation, and dictionary rules | Planned | Required before promotion | Review `ruzstd` with a hard maximum window |
| xz and LZMA | exact stream wrapper and coder profiles | LZMA, LZMA2 | Memory limit, concatenation, and exact input consumption | Planned | Required before promotion | Review minimal `lzma-rust2` features |
| bzip2 | exact stream wrapper profile | BWT pipeline | Whole-stream CRC, concatenation, and work budget | Planned | Required before promotion | Review `bzip2` with pure-Rust `libbz2-rs-sys` backend |
| 7z | local bounded header and coder-graph interpreter | Copy first, then LZMA and LZMA2 | Packed headers, acyclic bind graph, substreams, solid routing, encryption denial | Planned Tier 1 | Required before promotion | No full extractor crate; reuse reviewed codec adapter |
| RAR4 | separate local structural profile | Store first | Volumes, solid state, services, recovery, redirections, encryption | Research gate | Required before promotion | Decoder and license decision required |
| RAR5 | separate local structural profile | Store first | Bounded vint headers, solid state, filters, services, volumes, encryption | Research gate | Required before promotion | Decoder and license decision required |
| cpio | portable `newc` profile | Raw payload | Hardlink identity, trailer, modes, devices, alignment | Planned Tier 2 | Required before promotion | Zero new runtime dependencies |
| ar | common GNU and BSD profiles | Raw payload | Long-name tables, symbol tables, thin-reference denial | Planned Tier 2 | Required before promotion | Zero new runtime dependencies |
| deb | typed common-ar composition | gzip, xz, zstd, bzip2 as promoted | Exact order and constrained `control.tar` plus `data.tar` profiles | Planned Tier 2 | Required before promotion | Reuse promoted wrappers only |
| RPM | local lead, signature, and header profiles | gzip, xz, zstd, bzip2 as promoted | Typed cpio payload composition and signature policy | Planned Tier 2 | Required before promotion | Reuse cpio and promoted wrappers only |
| CAB | local bounded cabinet profile | Store and MSZIP first, LZX later | Folder streams, block checksums, multi-cabinet authority | Planned Tier 2 | Required before promotion | Reuse Deflate; separate LZX decision |

JAR, wheel, and NuGet are consumer profiles over ZIP. APK is ZIP-derived but needs a distinct structural profile because its signing block sits before the central directory. OCI layers require a TAR dialect plus a stateful layer applier for whiteouts, links, ownership, modes, extended attributes, and prior-tree effects. They are not equivalent to generic raw-TAR extraction. Compression aliases such as `.tgz` select an explicit wrapper plus TAR profile; they do not cause suffix sniffing.

Disk images, filesystem images, self-extracting executables, and installer execution are different authority problems. They require separate product decisions and are not silently grouped under archive extraction.

## One execution core

Each container adapter must produce a format-specific covering and a common effect-independent member plan. The shared core owns:

- source snapshot identity and bounded random reads;
- quotas and checked aggregate arithmetic;
- portable path admission and topology collision checks;
- payload verification and exact range consumption;
- bounded retained and later member reads;
- capability-based staged writes, audit, durability evidence, and no-replace publication;
- structured findings, semantic axes, receipts, and content-tree identity.

Format-specific evidence is not forced into ZIP field names. ZIP keeps `sealr.archive-ir.v1` and `sealrTreeV1` byte-for-byte stable. Portable ustar uses `sealr.archive-ir.tar-ustar.v1`, exact TAR member and covering evidence, and `sealrTreeV2` for layout while retaining the format-neutral content-tree encoding.

## Dependency budget

The Alpha.9 `sealr` library has 14 direct runtime dependencies. `cargo tree -p sealr -e normal` resolves 67 unique package lines on the current Windows target, including platform and transitive packages. Raw ustar adds no dependency and does not change the dependency set.

Every proposed runtime dependency must include:

1. a capability that cannot reasonably be implemented with `std` or an existing dependency;
2. exact direct and transitive package changes from `cargo tree`;
3. license, maintenance, unsafe-code, advisory, and release-history review;
4. a maximum window, dictionary, allocation, input, output, and work budget;
5. proof that the adapter reports exact input consumption and rejects trailing or concatenated data unless the selected wrapper profile explicitly permits it;
6. cross-platform differential fixtures and independent golden evidence;
7. removal criteria if the dependency becomes unmaintained or violates the boundary.

Optional Cargo features are not used to make the default binary unpredictably format-dependent. If a major format becomes supported by the release binary, release evidence names the exact codec graph it ships.

## Why ustar is first

POSIX ustar is a fixed 512-byte block language and can prove the multi-format plan, evidence, verification, and materialization seams without adding a decoder. It is still not treated as simple. The initial profile validates every header checksum and numeric field, requires exact magic and version, bounds metadata and members, requires zero member padding and two zero terminator blocks, and rejects links, devices, FIFOs, PAX, GNU long-name records, sparse encodings, base-256 numbers, concatenation, and hidden nonzero trailing blocks.

PAX follows as a separate profile because keyword precedence can replace names and sizes. GNU sparse formats follow only if their reconstructed ranges, logical size, and resource behavior can be expressed without ambiguity. The [GNU tar manual](https://www.gnu.org/software/tar/manual/html_chapter/Formats.html) documents why these are distinct dialects rather than harmless metadata.

7z follows a separate structural threat model. Its [official format description](https://github.com/ip7z/7zip/blob/main/DOC/7zFormat.txt) permits packed headers, folders of coders, multiple input and output streams, bind pairs, and substreams. It cannot safely be modeled as TAR with a different decoder.

RAR remains an explicit target rather than an unmentioned exclusion. The [RAR 5 technical note](https://www.rarlab.com/technote.htm) defines bounded variable integers and header CRCs, but points to UnRAR source for compression algorithms and deeper details. Implementation waits for a written decoder and license decision that preserves Sealr's redistribution and small-TCB requirements.

## Promotion rule

A row moves to shipped only when inspect, retention, later reads, and materialization share one admitted plan; hostile fixtures cover every denied structural branch; source covering is exact; native Linux, macOS, and Windows gates pass; release artifacts carry dependency license closure; and README limitations state the exact profile rather than the file extension.
