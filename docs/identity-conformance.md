# Identity conformance and independent verification

> Status: introduced in Alpha.4 and extended with the repository-only wheel profile. The vectors and verifier protect preview identities. They do not make any profile stable or turn unsigned evidence into an attestation.

Sealr now publishes a small, versioned identity-conformance bundle and checks it two ways:

- the production integration test applies the embedded source bytes and requires its semantic axes, findings, `ArchiveIR`, and roots to equal the committed cases;
- the separate `sealr-identity-verifier` workspace tool consumes those recorded facts without depending on the `sealr` crate and independently reconstructs the covering, profile digest, layout preimage, and content preimage.

The canonical artifacts are the [v1 conformance manifest](../crates/sealr/tests/conformance/identity-v1.json), the [independent verifier](../tools/identity-verifier), and the [production golden test](../crates/sealr/tests/golden_identity.rs).

## Verification boundary

The verifier has no Sealr dependency, ZIP discovery parser, decompressor, path-policy implementation, or filesystem effect. Its deliberate duplication is limited to a strict manifest model, a codec-free range checker, and the documented identity encodings.

For each bundle it checks:

1. The manifest schema and tree encoding are supported, every object rejects unknown fields, identifiers are unique, and the complete file is at most 16 MiB.
2. Every lowercase hexadecimal field is well formed. Exact embedded source bytes and exact canonical profile bytes reproduce their SHA-256 values.
3. A case references a published profile vector, and its IR repeats the same source and interpretation identities.
4. Semantic axes are coherent. Complete verification requires interpreted, admitted, complete evidence; committed effect requires admission and complete verification; a partial view names a finding that caused it.
5. The claimed ZIP32 covering forms an exact partition of the embedded bytes. Fixed signatures occur at the claimed LFH, CDH, EOCD, and signed-descriptor offsets; EOCD counts and ranges match; and member local and central ranges form complete nonoverlapping partitions. The checker follows recorded offsets and never searches for an EOCD.
6. Canonical paths are unique, range arithmetic is checked, encoding counts fit their specified widths, and verified members carry measured size, CRC32, and SHA-256 facts.
7. Independently encoded layout and content preimages reproduce the committed roots. Unavailable IR cannot carry a root, and incomplete verification cannot carry a content root.

The verifier does not independently interpret ZIP flags, names, extras, or methods. It does not inflate content, recompute member CRC32 or content SHA-256 from compressed payloads, prove SHA-256, authenticate a signer, or establish behavior outside the finite published cases. Production verification supplies member content facts; this tool verifies the evidence structure and its identities.

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

The current bundle has three profile vectors and four source cases. The strict ASCII v1, strict ASCII v2, and wheel UTF-8 v1 canonical profile bytes are compared directly with production serialization before the standalone verifier independently hashes them. Source cases currently exercise strict ASCII v1 tree evidence; a separate cross-platform production golden pins the strict ASCII v2 empty-tree identities. The wheel vector pins its closed container-language bytes and digest without claiming that the repository-only consumer is supported.

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

## Run locally

```powershell
cargo test --locked -p sealr-identity-verifier
cargo run --locked -p sealr-identity-verifier -- crates/sealr/tests/conformance/identity-v1.json
cargo test --locked -p sealr --test golden_identity
```

Required CI runs the production comparison, verifier tamper tests, and the verifier command. A change to a source fixture, serialized IR, profile bytes, semantic state, finding, range, or root therefore needs one deliberate manifest review.

## Extending the bundle

Add a case when an identity encoding branch, outcome state, or published profile is introduced. Prefer small hand-auditable source bytes. The production test must first prove that Sealr emits the committed evidence, then the standalone verifier must reproduce its covering and roots. Tampered variants belong in verifier tests and parser disagreements belong in the hostile corpus rather than being represented as accepted identity vectors.

An intentional incompatible interpretation needs a new profile identity. An intentional incompatible tree encoding needs a new tree-encoding identifier. Do not rewrite an already published stable identity under its old name.
