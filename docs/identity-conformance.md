# Identity conformance and independent verification

> Status: introduced in Alpha.4, extended through Alpha.8 with the repository-only wheel and supported portable UTF-8 profiles, extended in Alpha.9 with portable ustar, extended in Alpha.10 with strict ZIP64 `sealrTreeV3` plus strict gzip-wrapped ustar `sealrTreeV4`, extended in Alpha.11 with restricted raw PAX `sealrTreeV5`, and extended on current main with restricted GNU long-name `sealrTreeV6`, the gzip-wrapped PAX `sealrTreeV7` and gzip-wrapped GNU `sealrTreeV8` compositions, the zstd-wrapped ustar `sealrTreeV9` profile, and the xz-wrapped ustar `sealrTreeV10` profile. The vectors and verifier protect preview identities. They do not make any profile stable or turn unsigned evidence into an attestation.

Sealr now publishes a small, versioned identity-conformance bundle and checks it two ways:

- the production integration tests apply the embedded ZIP, gzip-TAR, restricted PAX, restricted GNU, and gzip-composition source bytes plus separately reconstructed exact raw-TAR producer bytes, requiring their semantic axes, findings, `ArchiveIR`, and roots to equal the committed evidence;
- the separate `sealr-identity-verifier` workspace tool consumes those recorded facts without depending on the `sealr` crate. It checks exact ZIP, gzip wrapper, PAX, and GNU sources and coverings, validates raw and derived TAR covering geometry, PAX state and provenance, GNU carrier state, and evidence digests, and independently reconstructs each profile, layout, and content preimage.

The canonical artifacts are the [ZIP32 v1 conformance manifest](../crates/sealr/tests/conformance/identity-v1.json), the [ZIP64 v1 conformance manifest](../crates/sealr/tests/conformance/zip64-identity-v1.json), the [portable ustar profile vector](../crates/sealr/tests/conformance/tar-ustar-portable-v1.json), the [TAR layout v2 vector](../crates/sealr/tests/conformance/tar-layout-v2.json), the [gzip-TAR TreeV4 manifest](../crates/sealr/tests/conformance/tar-gzip-identity-v1.json), the [restricted PAX profile vector](../crates/sealr/tests/conformance/tar-pax-profile-v1.json), the [PAX TreeV5 manifest](../crates/sealr/tests/conformance/tar-pax-identity-v1.json), the [GNU long-name profile vector](../crates/sealr/tests/conformance/tar-gnu-longname-profile-v1.json), the [GNU TreeV6 manifest](../crates/sealr/tests/conformance/tar-gnu-longname-identity-v1.json), the [gzip-PAX TreeV7 manifest](../crates/sealr/tests/conformance/tar-gzip-pax-identity-v1.json), the [gzip-GNU TreeV8 manifest](../crates/sealr/tests/conformance/tar-gzip-gnu-longname-identity-v1.json), the [zstd TreeV9 manifest](../crates/sealr/tests/conformance/tar-zstd-identity-v1.json), the [xz TreeV10 manifest](../crates/sealr/tests/conformance/tar-xz-identity-v1.json), the [independent verifier](../tools/identity-verifier), and the production [ZIP32](../crates/sealr/tests/golden_identity.rs), [ZIP64](../crates/sealr/tests/zip64_public_api.rs), [raw TAR](../crates/sealr/tests/tar_public_api.rs), [gzip-TAR](../crates/sealr/tests/tar_gzip_public_api.rs), [PAX](../crates/sealr/tests/tar_pax_public_api.rs), [GNU long-name](../crates/sealr/tests/tar_gnu_longname_public_api.rs), [gzip-PAX](../crates/sealr/tests/tar_gzip_pax_public_api.rs), [gzip-GNU](../crates/sealr/tests/tar_gzip_gnu_longname_public_api.rs), [zstd](../crates/sealr/tests/tar_zstd_public_api.rs), and [xz](../crates/sealr/tests/tar_xz_public_api.rs) tests.

## Verification boundary

The verifier has no Sealr dependency, ZIP or TAR discovery parser, decompressor, path-policy implementation, or filesystem effect. Its deliberate duplication is limited to strict vector models, codec-free range checkers, and the documented identity encodings.

For each bundle it checks:

1. The manifest schema and tree encoding are supported, every object rejects unknown fields, identifiers are unique, and the complete file is at most 16 MiB.
2. Every lowercase hexadecimal field is well formed. Exact ZIP, gzip-TAR, and PAX source bytes plus exact canonical profile bytes reproduce their SHA-256 values. Raw TAR producer source-byte reproduction belongs to the separately pinned sparse fixtures.
3. A case references a published profile vector, and its IR repeats the same source and interpretation identities.
4. Semantic axes are coherent. Complete verification requires interpreted, admitted, complete evidence; committed effect requires admission and complete verification; a partial view names a finding that caused it.
5. The claimed ZIP32 covering forms an exact partition of the embedded bytes. Fixed signatures occur at the claimed LFH, CDH, EOCD, and signed-descriptor offsets; EOCD counts and ranges match; and member local and central ranges form complete nonoverlapping partitions. The checker follows recorded offsets and never searches for an EOCD.
6. Canonical paths are unique, range arithmetic is checked, encoding counts fit their specified widths, and verified members carry measured size, CRC32, and SHA-256 facts.
7. Independently encoded layout and content preimages reproduce the committed roots. For gzip-TAR, the verifier also binds committed derived TAR bytes through CRC32, ISIZE, length, SHA-256, wrapper geometry, inner TAR evidence, and the closed transform constants without invoking a decompressor. For PAX, it independently checks exact ustar framing, extension and ordinary-member adjacency, canonical records, global and local state replay, effective values, provenance, `sealrTreeV5`, and the format-neutral content root. Unavailable IR cannot carry a root, and incomplete verification cannot carry a content root.

For `tar-layout-v2.json`, it separately checks complete header, payload, padding, two-block terminator, and trailing-zero geometry; well-formed member evidence and header digests; the ustar profile digest; and the `sealr.tree.layout.v2` and format-neutral content preimages. It does not carry source bytes. Production tests reconstruct exact GNU tar, bsdtar, and Python archives from sparse fixtures, hash those bytes, apply them, and compare their roots and member content. Mutation tests change every bound TAR field family and require either structural rejection or a root mismatch.

The verifier does not inflate ZIP or gzip payloads, implement a general archive-discovery parser, prove SHA-256, authenticate a signer, or establish behavior outside the finite published cases. For gzip-TAR it parses the committed derived ustar bytes and validates their declared evidence, but it relies on the closed transform identity plus wrapper CRC32, ISIZE, derived length, and derived SHA-256 to bind them to the committed outer source. For PAX it parses only the exact committed source and follows the manifest's bounded profile, not a broad TAR compatibility language. Production verification supplies decoded bytes and complete member verification; the standalone tool verifies the evidence structure and identities independently.

## Manifest contract

`sealr.identity-conformance.v1` contains:

| Field | Bound fact |
|---|---|
| `tree_encoding` | Exact supported tree algorithm identifier |
| `profiles` | Profile ID, expected SHA-256, and exact canonical profile bytes |
| `cases[].source_bytes_hex` | Small complete source fixture, not a pathname or acquisition hint |
| `cases[].source` | SHA-256 of those exact source bytes |
| `cases[].interpretation` | Profile ID and digest selected for the case |
| `cases[].axes` | Interpretation, admission, verification, effect, and completeness states |
| `cases[].findings` | Exact finding records for that case |
| `cases[].archive_ir` | Full serializable IR evidence, or `null` when no IR exists |
| `layout_root`, `content_root` | `sealrTreeV1` root or explicit unavailability |

The ZIP32 bundle has four profile vectors and four source cases. The strict ASCII v1, strict ASCII v2, wheel UTF-8 v1, and portable UTF-8 v1 canonical profile bytes are compared directly with production serialization before the standalone verifier independently hashes them. Source cases exercise strict ASCII v1 tree evidence; separate cross-platform production goldens pin strict ASCII v2 empty-tree identities and the supported wheel consumer source, archive-tree, artifact, and install-plan identities. The separate ZIP64 manifest binds the strict profile bytes, ZIP64-native member and covering evidence, and `sealrTreeV3` layout cases. The standalone verifier consumes and reconstructs that manifest independently. The raw TAR vectors bind portable ustar canonical bytes, one complete declared source covering, three TAR-native member records, a `sealrTreeV2` layout root, and a format-neutral content root. The gzip-TAR manifest adds two distinct Deflate encodings over one committed derived TAR. It binds separate source and `sealrTreeV4` roots, one raw `sealrTreeV2` relationship, and one shared `sealrTreeV1` content root. The PAX manifest binds canonical profile digest `db951f620acf54e67845144e138f9f16994439847a97601e20a424dfea7f4445`, exact extension carrier and record evidence, underlying and effective member facts, source references for both effective fields, a `sealrTreeV5` layout root, and the shared `sealrTreeV1` content encoding.

The source cases are:

| Case | Purpose |
|---|---|
| `empty-zip` | Empty covering, empty layout, and empty content-tree behavior |
| `walkthrough-allowed` | Two regular stored files and the public walkthrough identities |
| `layout-features` | Directory kind, Store content, signed descriptor, local and central extras, both normalization actions, source ranges, and canonical sorting |
| `walkthrough-parent-path-denied` | Denied admission, partial completeness, exact finding, absent IR, and unavailable roots |

## `sealrTreeV1` bytes

Both roots hash a Git-style preimage:

```text
ASCII label || 0x20 || decimal body length || 0x00 || body
```

All integers in the body are little endian. Variable byte strings use a `u32` byte length followed by the bytes. Members are sorted by the byte sequence of `canonical_path`.

The layout body starts with the local-record, central-directory, EOCD, and comment ranges as `(u64 offset, u64 length)`, followed by a `u32` member count. Each member then binds canonical path, kind (`file = 1`, `directory = 2`), raw name, method, flags, declared compressed and uncompressed sizes, declared CRC32, local-header range, compressed-payload range, optional descriptor marker and range, and central-header range.

Extra records are sorted by `(site tag, id, data offset)`. Their encoding is site (`local = 1`, `central = 2`), ID, disposition (`ignored = 1`, `semantic = 2`, `denied = 3`), data offset, and `u16` data length. Normalization actions retain IR order: strip-directory-trailing-slash is tag 1; drop-dot-component is tag 2 followed by its `u32` component index.

The content body starts with a `u32` member count. Each member binds canonical path, kind, actual uncompressed size as `u64`, and the raw 32-byte member SHA-256. Its domain label is `sealr.tree.content.v1`; layout uses `sealr.tree.layout.v1`. The interpretation profile is a sibling identity and is never mixed into either tree body.

## Gzip-TAR `sealrTreeV4`

The gzip-TAR layout uses the label `sealr.tree.layout.tar-gzip-ustar.v1`. Its body binds the transform profile ID and digest, decoder-parameter digest, original domain and complete input range, original SHA-256, output domain, derived length and SHA-256, every wrapper fixed and optional field, payload and trailer ranges, declared CRC32 and ISIZE, and the complete inner portable-ustar layout body. Integers, ranges, optional ranges, byte strings, and hashes use the same fixed encodings as the earlier tree versions.

The conformance manifest contains `optional-default` and `minimal-stored-deflate`. They encode the same 2,048-byte derived TAR through different Deflate streams. Their source and TreeV4 roots differ, while both share the raw TAR's TreeV1 content root. The verifier rejects mutations across transform constants, domains, wrapper fields, derived-byte integrity, inner TAR geometry, raw TreeV2, wrapped TreeV4, and shared TreeV1 evidence.

## Restricted PAX `sealrTreeV5`

The PAX layout uses the label `sealr.tree.layout.tar-pax.v1`. Its body binds the complete source covering, ordered global and local extension carriers, carrier names and ranges, mode, modification time, checksum, header and payload digests, ordered record kinds, record and value ranges, raw values, parsed sizes, every ordinary member's underlying ustar name and size, effective path and size, and exact ustar, global-extension, or local-extension provenance. Integer, range, byte-string, and hash encodings retain the fixed conventions of earlier tree versions.

The verifier reparses only the closed `path` and `size` grammar and replays the fixed four-field PAX state. A redundant override changes `sealrTreeV5` even if the effective files are unchanged. A portable ustar and restricted PAX source may share `sealrTreeV1` only after complete content verification; their interpretation and layout identities remain distinct.

## Restricted GNU long-name `sealrTreeV6`

The GNU layout uses the label `sealr.tree.layout.tar-gnu-longname.v1`. Its body binds the complete source covering, ordered `L` carriers, carrier names and ranges, carrier path bytes and payload digests, every ordinary member's underlying header name, and exact header-or-carrier path provenance. The verifier independently replays the single-depth carrier state: every carrier must be consumed by exactly the next ordinary member, and orphan or chained carriers fail.

## Gzip compositions `sealrTreeV7` and `sealrTreeV8`

The gzip-wrapped restricted PAX layout uses the label `sealr.tree.layout.tar-gzip-pax.v1`, and the gzip-wrapped GNU long-name layout uses `sealr.tree.layout.tar-gzip-gnu-longname.v1`. Each body binds the same wrapper prefix as `sealrTreeV4` — transform profile ID and digest, decoder-parameter digest, original domain and complete input range, original SHA-256, output domain, derived length and SHA-256, every wrapper fixed and optional field, payload and trailer ranges, declared CRC32 and ISIZE — followed by the complete inner `sealrTreeV5` or `sealrTreeV6` layout body over the derived domain.

Each composition manifest contains `optional-default` and `minimal-stored-deflate` cases encoding one committed derived dialect TAR through different Deflate streams. Their source and composed roots differ, while both share the raw dialect's `sealrTreeV1` content root, and the manifest additionally binds the raw dialect layout root of the derived bytes. The verifier rejects mutations across transform constants, wrapper fields, derived-byte integrity, inner dialect geometry and provenance, and every root.

## Zstd-wrapped ustar `sealrTreeV9`

The zstd layout uses the label `sealr.tree.layout.tar-zstd-ustar.v1`. Its body binds the zstd transform identifiers, both domain identities, the exact frame descriptor and decoded flags, window descriptor and effective window, optional frame content size, header, block-payload, and trailer ranges, the declared XXH64 checksum when present, and the complete inner portable-ustar layout body. Its manifest carries a pinned Zstandard CLI 1.5.7 producer case beside a handcrafted raw-block case over one committed derived TAR, and the verifier independently replays the wrapper grammar, re-hashes the derived bytes with a self-contained XXH64, and reconstructs `sealrTreeV9`, the raw `sealrTreeV2` relationship, and the shared `sealrTreeV1` content root without a decompressor.

## Xz-wrapped ustar `sealrTreeV10`

The xz layout uses the label `sealr.tree.layout.tar-xz-ustar.v1`. Its body binds the xz transform identifiers, both domain identities, the check identifier, the stream-header range, every block's header, compressed, padding, and check ranges with dictionary size, declared sizes, uncompressed length, and exact check value, the index and footer ranges, and the complete inner portable-ustar layout body. Its manifest carries pinned XZ Utils 5.8.1 producer cases — default CRC64, multi-block, SHA-256, and CRC32 — beside a handcrafted uncompressed-LZMA2 case over one committed derived TAR, and the verifier independently replays the container grammar including every header CRC32, index tiling, and backward-size relation, re-verifies every block check with self-contained CRC32, CRC64, and SHA-256, and reconstructs `sealrTreeV10`, the raw `sealrTreeV2` relationship, and the shared `sealrTreeV1` content root without a decompressor.

## Run locally

```powershell
cargo test --locked -p sealr-identity-verifier
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/zip64-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-gzip-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-pax-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-gnu-longname-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-gzip-pax-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-gzip-gnu-longname-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-zstd-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-xz-identity-v1.json
cargo test --locked -p sealr --test golden_identity
cargo test --locked -p sealr --test tar_public_api
cargo test --locked -p sealr --test tar_gzip_public_api
cargo test --locked -p sealr --test tar_pax_public_api
cargo test --locked -p sealr --test tar_gnu_longname_public_api
cargo test --locked -p sealr --test tar_gzip_pax_public_api
cargo test --locked -p sealr --test tar_gzip_gnu_longname_public_api
cargo test --locked -p sealr --test tar_zstd_public_api
cargo test --locked -p sealr --test tar_xz_public_api
```

Required CI runs the production comparison, verifier tamper tests, and the verifier command. A change to a source fixture, serialized IR, profile bytes, semantic state, finding, range, or root therefore needs one deliberate manifest review.

## Extending the bundle

Add a case when an identity encoding branch, outcome state, or published profile is introduced. Prefer small hand-auditable source bytes. The production test must first prove that Sealr emits the committed evidence, then the standalone verifier must reproduce its covering and roots. Tampered variants belong in verifier tests and parser disagreements belong in the hostile corpus rather than being represented as accepted identity vectors.

An intentional incompatible interpretation needs a new profile identity. An intentional incompatible tree encoding needs a new tree-encoding identifier. Do not rewrite an already published stable identity under its old name.
