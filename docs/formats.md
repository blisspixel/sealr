# Format strategy

> Current implementation: classic ZIP32 with Store and Deflate, an explicit in-process strict ZIP64 preview under policy v3, raw portable POSIX ustar, strict single-member gzip-wrapped portable ustar under policy v4, and restricted raw POSIX PAX under policy v5. GNU TAR, additional compressed wrappers, and the other tracked families remain profile-specific work. Format sequencing is governed by the [roadmap](../ROADMAP.md) and the detailed [format support architecture](format-support.md).

## Current archive profiles

Sealr exposes four separately identified ZIP32 interpretations. The compatibility default accepts ASCII or explicitly flagged strict UTF-8 names. Strict ASCII v2 rejects non-ASCII names. Portable UTF-8 v1 is the supported Unicode profile. Wheel UTF-8 v1 preserves the narrower Alpha.7 research language. None changes the default. All four share these structural rules:

- central-directory-first structure discovery;
- exact EOCD, central header, local header, and data-descriptor agreement;
- no hidden, overlapping, prefixed, trailing, ZIP64, spanned, encrypted, or recovery-parsed structure;
- methods 0 and 8 only;
- exactly one raw DEFLATE stream consuming every declared compressed byte;
- profile-specific ASCII or strict UTF-8 NFC path rules, with no CP437 fallback;
- no links, devices, nested extraction, or archive mode restoration.

The separately identified [strict ZIP64 profile](profiles/zip64-strict-ascii-v1.md) is selected explicitly and authorized by policy v3. It reuses Store and Deflate but has its own sentinel, extra-field, end-record, locator, descriptor, IR, covering, and `sealrTreeV3` rules. ZIP32 selection never retries or aliases to it, and authenticated worker execution fails closed until semantic-record v3.

The separately identified [portable ustar profile](profiles/tar-ustar-portable-v1.md) validates exact ustar magic, version, checksums, bounded octal fields, record geometry, padding, and termination. It accepts regular files and directories only, uses TAR-native IR evidence and `sealrTreeV2` layout identity, and shares the portable path, quota, verification, retention, read, and atomic materialization core.

The separately identified [gzip-wrapped portable ustar profile](profiles/tar-gzip-ustar-portable-v1.md) authorizes exactly one RFC 1952 member with Deflate payload, closed optional-field grammar, no trailing input, and verified FHCRC when present, CRC32, ISIZE, exact compressed consumption, output, and expansion bounds. It keeps the original gzip and decoded TAR as distinct immutable snapshot domains, uses wrapper-native plus TAR-native evidence, requires one exact transform and composite audit, and publishes `sealrTreeV4`. It adds no runtime dependency.

The separately identified [restricted POSIX PAX profile](profiles/tar-pax-portable-v1.md) is selected as `ArchiveFormat::TarPax`, serialized as `tar-pax`, and authorized only by policy v5. It accepts exact portable-ustar physical headers plus bounded `x` and `g` extension payloads containing only canonical `path` and `size` records. A fixed four-field state model resolves local, then global, then underlying ustar values and preserves exact provenance in `sealr.archive-ir.tar-pax.v1`. An independent audit reparses the source covering and replays precedence before `sealrTreeV5` is available. It adds no runtime dependency and does not widen raw ustar or imply general PAX compatibility.

The [API contract](api.md), [safety specification](safety.md), and [finding registry](findings.md) are normative for current behavior.

## Common codecs

The product destination includes the lossless methods ordinary ZIP and TAR producers actually emit. They are codec adapters, not a second unarchiver. Sequencing is in the [roadmap](../ROADMAP.md#common-compression-one-boundary).

ZIP methods in scope: Store, Deflate, Deflate64, BZip2, LZMA, XZ, and Zstandard. TAR wrappers in scope: uncompressed, gzip, zstd, xz, bzip2, and LZ4 frame. Each adapter must consume declared compressed input exactly, bind every transform and snapshot domain, bound its window and output, fail closed, and reuse the same path, quota, verification, and publication core.

PPMd and encrypted payload decoding are outside the current default direction. RAR4 and RAR5 remain separate research targets subject to decoder-license and trusted-code decisions. Shelling out to another extractor is out of scope. ZIP64 is a structural profile, not a codec.

## Expansion rule

Formats are not added as checkboxes. Each needs:

1. a versioned interpretation profile;
2. a canonical mapping into `ArchiveIR`;
3. exact source-range and codec-consumption rules;
4. resource and path policies;
5. a hostile and benign corpus;
6. a concrete consumer whose semantics are understood;
7. identical canonical evidence on supported Linux, macOS, and Windows targets.

## Wheel profiles are two layers

The supported wheel evaluator does not turn the generic ZIP policy into a package installer.

1. `sealr.profile.zip.portable-utf8.v1` defines the supported container language. It requires strict UTF-8 NFC member names, rejects legacy CP437 and alternate Unicode-name extras, permits exact data descriptors, and uses exhaustive flag and extra-field tables.
2. `sealr.consumer.python-wheel.v1` binds the exact artifact filename, validates verified `WHEEL`, `METADATA`, and `RECORD` members, and produces a scheme-relative installation plan.

The first layer constructs one archive tree. The second assigns Python packaging meaning to that tree. Neither may reparse the source. The detailed supported-preview rules and corpus plan are in the [Python wheel profile](profiles/python-wheel-v1.md).

## Planned order

| Format or profile | Status | Entry condition |
|---|---|---|
| Strict ZIP32 Store and Deflate | Alpha.4 compatibility default | Immutable v1 preview boundary |
| Exact strict ASCII ZIP profile | Alpha.4 implementation complete | Opt-in v2 has an exhaustive flag table, denies every extra field, and is measured against the pinned pilot |
| Private file-backed ZIP snapshot | Alpha.5 released | Copy-hash-retain source capability, checked random access, native mutation controls, required resource bounds, and scheduled 3 GiB sparse evidence |
| Supervised Linux ZIP worker | Alpha.6 released | Explicit x86_64 Linux activation, authenticated packaged helper, Landlock ABI 3 plus seccomp, source replay, and supervisor audit and publication |
| Portable UTF-8 ZIP path and tree profile | Alpha.8 supported preview | Strict UTF-8 NFC, explicit flagging, no extras, component ceilings, target collision model, and independent vector |
| Raw portable POSIX ustar | Alpha.9 supported preview | Explicit selection, policy v2 authorization, no new runtime dependency, TAR-native evidence, independent roots, external producer corpus, native package and fuzz gates |
| Strict ZIP64 | Alpha.10 in-process preview | Explicit policy v3 selection, exact saturated legacy and redundant ZIP64 field agreement, `sealrTreeV3`, and worker refusal pending semantic-record v3 |
| gzip-wrapped portable ustar | Alpha.10 in-process preview | Explicit policy v4 selection, two immutable domains, exact single-member RFC 1952 consumption and checksums, existing `flate2`, `sealrTreeV4`, and worker refusal pending a later semantic record |
| Restricted raw POSIX PAX | Alpha.11 in-process preview | Explicit policy v5 selection, only canonical `path` and `size` records, exact precedence provenance, `sealrTreeV5`, zero new dependencies, and fail-closed worker refusal |
| GNU long-name TAR dialect | Next separate profile | Exact GNU magic plus one `L` carrier consumed by one following ordinary member; long links, sparse files, base-256 numbers, PAX mixing, and recovery denied |
| gzip-wrapped restricted PAX and GNU TAR | After each raw profile is frozen | Reuse the exact Alpha.10 transform while publishing separate composition identities and preserving content identity |
| zstd, xz/LZMA, bzip2, and LZ4 frame wrappers | Independently promoted in that order | One measured decoder at a time with exact input, memory, work, checksum, and dependency evidence |
| ZIP Zstd, XZ/LZMA, BZip2, Deflate64 adapters | After each codec promotion | Same exact-consumption, bounded-window, and dependency rules as Deflate; no second parser |
| Wheel-oriented UTF-8 ZIP profile | Alpha.7 research evidence preserved | Exact research bytes remain available for historical verification |
| Python wheel consumer profile | Alpha.8 supported preview | Verified-member API plus wheel metadata, `RECORD`, artifact identity, scheme-relative install-plan rules, and public-surface corpus replay |
| JAR, wheel, and NuGet | ZIP consumer profiles | Package-specific manifests, signatures, and effects specified independently |
| APK | ZIP-derived structural plus consumer profile | APK signing block and signature semantics cannot pass through ordinary unique-covering ZIP unchanged |
| OCI layers | TAR dialect plus stateful consumer | Whiteouts, links, metadata, and prior-tree application specified independently |
| cpio, ar, deb, RPM, and CAB | Tracked structural and composed profiles | Local parsers, promoted codecs only, equivalent covering, identity, package, and fuzz evidence |
| 7z | Tracked Tier 1 container | Local bounded coder-graph parser, Copy first, reviewed LZMA/LZMA2 adapter later, no full extractor crate |
| RAR4 and RAR5 | Separate research gates | Store-first structure, licensing decision, solid and volume authority model, and equivalent assurance evidence |
| Encrypted or spanned archives | Refused in the current direction | Separate key, volume, and streaming trust models would be required |

## No permissive fallback

Unsupported input receives structured evidence. Sealr does not shell out to another extractor, normalize a rejected archive by best effort, or retry through a more permissive parser.
