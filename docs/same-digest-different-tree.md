# Same digest is not same tree

> The archive-confusion research — the 2025 ZipDiff study, the uv ZIP-parser advisories, pip's path-traversal fixes, PyPI's upload-time rejection of ambiguous wheels — all share one shape: the same archive bytes are made to mean different installed trees by different parsers. This page is that lesson turned into a sealr artifact rather than a citation.

## The demonstration

```text
cargo run --locked -p sealr --example same_digest_different_tree
```

The example admits one wheel through the supported `python-wheel.v1` consumer, **deletes the file**, and then evaluates the retained `VerifiedArchive` under three outer filenames a caller might present. Nothing after admission reopens the archive.

| Outer filename | Outcome | source & archive-tree identity | artifact & plan identity |
|---|---|---|---|
| `demo-1.0-py3-none-any.whl` | admitted | fixed by the bytes | identity A |
| `Demo-1.0-py3-none-any.whl` | admitted | **identical** to above | **different** — identity B |
| `other-1.0-py3-none-any.whl` | denied `wheel.artifact-root-disagreement` | — | no tree at all |

## What it proves

sealr **inverts** the confusion attack. The bytes admit through exactly one interpretation, so:

- **The source digest and the archive-tree identity are properties of the bytes alone.** They are byte-for-byte identical across the two admitted filenames, because the content of the tree is the content of the tree.
- **The installed target set is identical too** — the example asserts that every scheme, relative path, and content hash in the install plan matches across the two admitted spellings. Renaming the wheel did not silently produce a different tree, which is precisely the failure the archive-confusion advisories describe.
- **Any consumer-level difference is explicit and bound.** The artifact and install-plan identities differ between the two spellings, because both commit to the exact filename the caller claimed. The difference is a named, digest-visible fact, not a silent divergence — a caller that presented a different name gets a different identity, never a different tree behind the same identity.
- **A disagreeing name yields nothing.** The third filename, whose distribution disagrees with the embedded metadata, is denied with a typed finding. The same bytes produce one tree, a differently-identified claim on that same tree, or a refusal — never two silently different trees.

The contrast with the research is the whole point: where two ZIP parsers can make one wheel install two different file sets, sealr makes the archive tree provably singular and forces every remaining consumer distinction into an identity a downstream system can hash and check.

## What it is not

This is a mechanism demonstration on committed synthetic bytes, not a claim of external adoption. No installer or build backend yet treats the `VerifiedArchive` representation as authority; until one does, the category is demonstrated but not yet *used*. Receipts remain unsigned and the tree encodings are preview. See [the usefulness test](usefulness.md) for the standing bar and [the evidence encoding contract](evidence-encoding.md) for the identities' encoding.
