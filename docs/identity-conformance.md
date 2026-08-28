# Identity conformance and independent verification

> Status: introduced in Alpha.4, extended through Alpha.8 with the repository-only wheel and supported portable UTF-8 profiles, extended in Alpha.9 with portable ustar, and extended in Alpha.10 with strict ZIP64 `sealrTreeV3` plus strict gzip-wrapped ustar `sealrTreeV4` vectors. The vectors and verifier protect preview identities. They do not make any profile stable or turn unsigned evidence into an attestation.

Sealr now publishes a small, versioned identity-conformance bundle and checks it two ways:

- the production integration tests apply the embedded ZIP and gzip-TAR source bytes plus separately reconstructed exact raw-TAR producer bytes, requiring their semantic axes, findings, `ArchiveIR`, and roots to equal the committed evidence;
- the separate `sealr-identity-verifier` workspace tool consumes those recorded facts without depending on the `sealr` crate. It checks exact ZIP and gzip wrapper sources and coverings, validates raw and derived TAR covering geometry and evidence digests, and independently reconstructs each profile, layout, and content preimage.

The canonical artifacts are the [ZIP32 v1 conformance manifest](../crates/sealr/tests/conformance/identity-v1.json), the [ZIP64 v1 conformance manifest](../crates/sealr/tests/conformance/zip64-identity-v1.json), the [portable ustar profile vector](../crates/sealr/tests/conformance/tar-ustar-portable-v1.json), the [TAR layout v2 vector](../crates/sealr/tests/conformance/tar-layout-v2.json), the [gzip-TAR TreeV4 manifest](../crates/sealr/tests/conformance/tar-gzip-identity-v1.json), the [independent verifier](../tools/identity-verifier), and the production [ZIP32](../crates/sealr/tests/golden_identity.rs), [ZIP64](../crates/sealr/tests/zip64_public_api.rs), [raw TAR](../crates/sealr/tests/tar_public_api.rs), and [gzip-TAR](../crates/sealr/tests/tar_gzip_public_api.rs) tests.

## Verification boundary

The verifier has no Sealr dependency, ZIP or TAR discovery parser, decompressor, path-policy implementation, or filesystem effect. Its deliberate duplication is limited to strict vector models, codec-free range checkers, and the documented identity encodings.

For each bundle it checks:

1. The manifest schema and tree encoding are supported, every object rejects unknown fields, identifiers are unique, and the complete file is at most 16 MiB.
2. Every lowercase hexadecimal field is well formed. Exact ZIP and gzip-TAR source bytes plus exact canonical profile bytes reproduce their SHA-256 values. Raw TAR producer source-byte reproduction belongs to the separately pinned sparse fixtures.
3. A case references a published profile vector, and its IR repeats the same source and interpretation identities.
4. Semantic axes are coherent. Complete verification requires interpreted, admitted, complete evidence; committed effect requires admission and complete verification; a partial view names a finding that caused it.
5. The claimed ZIP32 covering forms an exact partition of the embedded bytes. Fixed signatures occur at the claimed LFH, CDH, EOCD, and signed-descriptor offsets; EOCD counts and ranges match; and member local and central ranges form complete nonoverlapping partitions. The checker follows recorded offsets and never searches for an EOCD.
6. Canonical paths are unique, range arithmetic is checked, encoding counts fit their specified widths, and verified members carry measured size, CRC32, and SHA-256 facts.
7. Independently encoded layout and content preimages reproduce the committed roots. For gzip-TAR, the verifier also binds committed derived TAR bytes through CRC32, ISIZE, length, SHA-256, wrapper geometry, inner TAR evidence, and the closed transform constants without invoking a decompressor. Unavailable IR cannot carry a root, and incomplete verification cannot carry a content root.

For `tar-layout-v2.json`, it separately checks complete header, payload, padding, two-block terminator, and trailing-zero geometry; well-formed member evidence and header digests; the ustar profile digest; and the `sealr.tree.layout.v2` and format-neutral content preimages. It does not carry source bytes. Production tests reconstruct exact GNU tar, bsdtar, and Python archives from sparse fixtures, hash those bytes, apply them, and compare their roots and member content. Mutation tests change every bound TAR field family and require either structural rejection or a root mismatch.

The verifier does not inflate ZIP or gzip payloads, implement a general archive-discovery parser, prove SHA-256, authenticate a signer, or establish behavior outside the finite published cases. For gzip-TAR it parses the committed derived ustar bytes and validates their declared evidence, but it relies on the closed transform identity plus wrapper CRC32, ISIZE, derived length, and derived SHA-256 to bind them to the committed outer source. Production verification supplies decoded bytes and complete member verification; the standalone tool verifies the evidence structure and identities independently.

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

The ZIP32 bundle has four profile vectors and four source cases. The strict ASCII v1, strict ASCII v2, wheel UTF-8 v1, and portable UTF-8 v1 canonical profile bytes are compared directly with production serialization before the standalone verifier independently hashes them. Source cases exercise strict ASCII v1 tree evidence; separate cross-platform production goldens pin strict ASCII v2 empty-tree identities and the supported wheel consumer source, archive-tree, artifact, and install-plan identities. The separate ZIP64 manifest binds the strict profile bytes, ZIP64-native member and covering evidence, and `sealrTreeV3` layout cases. The standalone verifier consumes and reconstructs that manifest independently. The raw TAR vectors bind portable ustar canonical bytes, one complete declared source covering, three TAR-native member records, a `sealrTreeV2` layout root, and a format-neutral content root. The gzip-TAR manifest adds two distinct Deflate encodings over one committed derived TAR. It binds separate source and `sealrTreeV4` roots, one raw `sealrTreeV2` relationship, and one shared `sealrTreeV1` content root.

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

## Run locally

```powershell
cargo test --locked -p sealr-identity-verifier
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/zip64-identity-v1.json
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/tar-gzip-identity-v1.json
cargo test --locked -p sealr --test golden_identity
cargo test --locked -p sealr --test tar_public_api
cargo test --locked -p sealr --test tar_gzip_public_api
```

Required CI runs the production comparison, verifier tamper tests, and the verifier command. A change to a source fixture, serialized IR, profile bytes, semantic state, finding, range, or root therefore needs one deliberate manifest review.

## Extending the bundle

Add a case when an identity encoding branch, outcome state, or published profile is introduced. Prefer small hand-auditable source bytes. The production test must first prove that Sealr emits the committed evidence, then the standalone verifier must reproduce its covering and roots. Tampered variants belong in verifier tests and parser disagreements belong in the hostile corpus rather than being represented as accepted identity vectors.

An intentional incompatible interpretation needs a new profile identity. An intentional incompatible tree encoding needs a new tree-encoding identifier. Do not rewrite an already published stable identity under its old name.
