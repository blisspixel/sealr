# Format strategy

> Current implementation: classic ZIP32 with Store and Deflate members only. Every other format or ZIP extension is unsupported, rejected, or deferred. Format sequencing is governed by the [roadmap](../ROADMAP.md), not this page.

## Current alpha.3 profile

Sealr applies one strict ZIP32 interpretation:

- central-directory-first structure discovery;
- exact EOCD, central header, local header, and data-descriptor agreement;
- no hidden, overlapping, prefixed, trailing, ZIP64, spanned, encrypted, or recovery-parsed structure;
- methods 0 and 8 only;
- exactly one raw DEFLATE stream consuming every declared compressed byte;
- strict ASCII path subset until canonical CP437 and Unicode rules exist;
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

## Planned order

| Format or profile | Status | Entry condition |
|---|---|---|
| Strict ZIP32 Store and Deflate | Current alpha.3 | Existing preview boundary |
| Canonical ZIP path and tree profile | Phase 0.1 | `ArchiveIR`, outcome axes, profiles, roots, Unicode model, and assurance gates |
| ZIP Zstd, XZ/LZMA, BZip2, Deflate64 adapters | After Phase 0.1 | Same exact-consumption, bounded-window, and dependency rules as Deflate; no second parser |
| TAR plus PAX and GNU name handling | Phase 1 | ZIP trust gate and codec adapters exist so TAR wrappers reuse them |
| gzip, bzip2, xz, and zstd wrappers | Phase 1 with TAR | Exact stream, window, metadata, and cancellation semantics via the ZIP codec adapters |
| ZIP64 | Deferred and consumer-driven | A named consumer demonstrates compatibility need and receives new offset, size, and corpus gates |
| Python wheel profile | Phase 0.2, first canonical consumer | Phase 0.1 complete; ZIP container plus wheel metadata and installed-tree rules |
| JAR, APK, OCI, Office, and other ZIP consumers | Later consumer profiles | Signature, relocation, layer, or document semantics specified independently |
| 7z and other archive families | Deliberately deferred | Concrete consumer, maintained parser strategy, and equivalent assurance evidence |
| Encrypted or spanned archives | Refused in the current direction | Separate key, volume, and streaming trust models would be required |
| RAR | Not planned for the default binary | Licensing, parser, and consumer case do not justify current trusted surface |

## No permissive fallback

Unsupported input receives structured evidence. Sealr does not shell out to another extractor, normalize a rejected archive by best effort, or retry through a more permissive parser.
