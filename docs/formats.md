# Format strategy

> Current implementation: classic ZIP32 with Store and Deflate members only. Every other format or ZIP extension is unsupported, rejected, or deferred. Format sequencing is governed by the [roadmap](../ROADMAP.md), not this page.

## Current profiles

Sealr exposes three separately identified ZIP32 interpretations. The compatibility default and strict ASCII v2 profile reject non-ASCII names. The repository-only wheel research profile accepts only strict UTF-8 NFC names and does not change the default. All three share these structural rules:

- central-directory-first structure discovery;
- exact EOCD, central header, local header, and data-descriptor agreement;
- no hidden, overlapping, prefixed, trailing, ZIP64, spanned, encrypted, or recovery-parsed structure;
- methods 0 and 8 only;
- exactly one raw DEFLATE stream consuming every declared compressed byte;
- profile-specific ASCII or strict UTF-8 NFC path rules, with no CP437 fallback;
- no links, devices, nested extraction, or archive mode restoration.

The [API contract](api.md), [safety specification](safety.md), and [finding registry](findings.md) are normative for current behavior.

## Common codecs

The product destination includes the lossless methods ordinary ZIP and TAR producers actually emit. They are codec adapters, not a second unarchiver. Sequencing is in the [roadmap](../ROADMAP.md#common-compression-one-boundary).

ZIP methods in scope: Store, Deflate, Deflate64, BZip2, LZMA, XZ, and Zstandard. TAR wrappers in scope: uncompressed, gzip, bzip2, xz, and zstd. Each adapter must consume declared compressed input exactly, bound its window, fail closed, and reuse the same `ArchiveIR`, path, quota, and publication core.

PPMd, encrypted methods, RAR, and shelling out to another extractor are out of scope. ZIP64 is a structural profile, not a codec.

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

The repository-only wheel work does not turn the generic ZIP policy into a package installer.

1. `sealr.profile.zip.wheel-utf8.v1` defines the accepted research container language. It requires strict UTF-8 NFC member names, rejects legacy CP437 and alternate Unicode-name extras, and uses exhaustive flag and extra-field tables without waiting for a general legacy-name profile.
2. The `python-wheel.v1-research` consumer profile binds the exact artifact filename, validates verified `WHEEL`, `METADATA`, and `RECORD` members, and produces a scheme-relative installation plan.

The first layer constructs one archive tree. The second assigns Python packaging meaning to that tree. Neither may reparse the source. The detailed candidate rules and corpus plan are in the [Python wheel profile draft](profiles/python-wheel-v1.md).

## Planned order

| Format or profile | Status | Entry condition |
|---|---|---|
| Strict ZIP32 Store and Deflate | Alpha.4 compatibility default | Immutable v1 preview boundary |
| Exact strict ASCII ZIP profile | Alpha.4 implementation complete | Opt-in v2 has an exhaustive flag table, denies every extra field, and is measured against the pinned pilot |
| Private file-backed ZIP snapshot | Alpha.5 released | Copy-hash-retain source capability, checked random access, native mutation controls, required resource bounds, and scheduled 3 GiB sparse evidence |
| Supervised Linux ZIP worker | Alpha.6 released | Explicit x86_64 Linux activation, authenticated packaged helper, Landlock ABI 3 plus seccomp, source replay, and supervisor audit and publication |
| Canonical general ZIP path and tree profile | Phase 0.1 closure | UTF-8 and separately justified legacy CP437 rules, target collision model, and assurance gates |
| ZIP Zstd, XZ/LZMA, BZip2, Deflate64 adapters | After Phase 0.1 | Same exact-consumption, bounded-window, and dependency rules as Deflate; no second parser |
| TAR plus PAX and GNU name handling | Phase 1 | ZIP trust gate and codec adapters exist so TAR wrappers reuse them |
| gzip, bzip2, xz, and zstd wrappers | Phase 1 with TAR | Exact stream, window, metadata, and cancellation semantics via the ZIP codec adapters |
| ZIP64 | Deferred and consumer-driven | A named consumer demonstrates compatibility need and receives new offset, size, and corpus gates |
| Wheel-oriented UTF-8 ZIP profile | Repository laboratory implemented, not current support | Exact UTF-8 path rules, exhaustive ZIP feature table, hostile fixtures, and benign compatibility report |
| Python wheel consumer profile | Repository research implemented; supported promotion remains Phase 0.2 | Verified-member API plus wheel metadata, `RECORD`, artifact identity, scheme-relative install-plan rules, and external bridge |
| JAR, APK, OCI, Office, and other ZIP consumers | Later consumer profiles | Signature, relocation, layer, or document semantics specified independently |
| 7z and other archive families | Deliberately deferred | Concrete consumer, maintained parser strategy, and equivalent assurance evidence |
| Encrypted or spanned archives | Refused in the current direction | Separate key, volume, and streaming trust models would be required |
| RAR | Not planned for the default binary | Licensing, parser, and consumer case do not justify current trusted surface |

## No permissive fallback

Unsupported input receives structured evidence. Sealr does not shell out to another extractor, normalize a rejected archive by best effort, or retry through a more permissive parser.
