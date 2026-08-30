# Evidence and attestations

> Current status: the default lineage emits deterministic unsigned `sealr.view.v1` and `sealr.receipt.v2` JSON. The opt-in canonical lineage emits byte-exact RFC 8785 `sealr.view.v2` and `sealr.receipt.v3` JSON. A no-Sealr-dependency verifier checks live canonical pairs and five committed evidence cases. Stable lock semantics, authenticated-envelope verification, SBOM output, and an external adopter remain planned work.

The current receipt is always returned, including on rejection. `sealr.receipt.v2` records source digest availability, interpretation/admission/verification/effect/completeness axes, the invocation-specific view digest, tool and environment fields, materialization lifecycle evidence, the compatibility verdict, and findings. `Outcome::canonical_evidence()` and CLI `--canonical` expose the same finished evidence as view v2 and receipt v3, with exact RFC 8785 bytes and explicit canonicalization bindings.

It is an **EvidenceRecord**, not an attestation. The practical flow for wrapping a receipt file into an externally signed in-toto/DSSE attestation is [receipt attestation](attestation.md). `signed: false` is explicit. It proves neither signer identity nor freshness. `view_digest` is still invocation evidence. Receipts also carry unsigned preview `sealrTreeV1` layout and content-tree identities derived from `ArchiveIR`.

Use **attestation** only for an authenticated claim whose signature, signer identity, and timestamp or freshness policy have been verified.

## Target evidence decomposition

Do not place every fact into one large custom predicate. The target model separates narrowly typed claims.

### Interpretation record

Binds exact source bytes to an interpretation profile and canonical `ArchiveIR`. After tree identity is specified, it can bind source identity to layout identity.

### Verification record

States which members and properties were verified, which resource bounds were enforced, and whether verification is structure-only, partial, or complete. A partial result includes its verified and pending frontier.

### Admission record

Binds the interpreted tree to the policy, target filesystem model, consumer profile, rule versions, and admission outcome.

### Effect record

Describes the requested realization, stage controls, component resolution, staged-tree audit, publication primitive, cleanup, durability, and effect outcome. A failed effect does not retroactively change admission.

### Evidence manifest

Contains structured member facts, source ranges, findings, actual sizes, hashes, rule evaluations, and completeness. Human-readable finding messages are presentation. Stable rule identifiers and deterministic fields are the machine contract.

These records may be distributed together, but their independent meanings must remain visible.

## Standard envelopes

The target authenticated form should use existing envelope and identity systems where they fit:

1. DSSE for the signed payload envelope.
2. in-toto Statement v1 for subject and predicate structure.
3. An existing in-toto predicate when it can express the claim without ambiguity.
4. A narrowly scoped Sealr predicate only after the need and compatibility story are validated publicly.
5. Sigstore keyless identity for GitHub release or workflow claims where appropriate.

GitHub Artifact Attestations are a possible distribution path for standard envelopes, not a separate trust model. A signature alone is insufficient. Consumers must verify the expected signer identity, workflow or issuer constraints, subject digest, and time policy.

Sealr does not sign archive decisions. The repository statement builder verifies canonical receipt v3 against its matching view and actual source archive, then embeds the original receipt token in an unsigned in-toto Statement v1 for an external DSSE signer. Separately, the GitHub release workflow records build provenance attestations for native release archives. That provenance binds a packaged binary to its source workflow; it does not authenticate an individual Sealr decision receipt.

## Tree subjects

Future authenticated claims should distinguish:

- archive source digest;
- interpretation profile identity;
- canonical layout root;
- complete content-tree root;
- invocation and effect identity.

The existing `view_digest` cannot stand in for the layout or content-tree root because it covers invocation-specific fields such as source metadata, policy, verdict, findings, and write outcome.

`sealrTreeV1` now has a documented canonical encoding, committed cross-platform preview vectors, and a separate tool that independently reproduces those finite vectors. Canonical claim bytes are available and the live verifier independently reconstructs the format-neutral content root from view members. Profile stability and authenticated-envelope verification remain open before it can be a stable authenticated subject. in-toto `dirHash1`, Git trees, and OCI `DiffID` are interoperability references, not drop-in replacements for all Sealr semantics.

## Independent verifier

The [identity-conformance verifier](identity-conformance.md) has two bounded roles. For committed format manifests it validates profile and tree-root derivation, exact small source fixtures, semantic-axis consistency, and claimed structural coverings without extracting. For live canonical evidence it rejects noncanonical or duplicate JSON, checks the view and receipt binding, optionally hashes the observed source, pins registered interpretation and known default-policy digests, validates axes and effects, and reconstructs the format-neutral content root from view members.

Live verification does not rediscover the archive layout or execute codecs. Its layout root, member hashes, custom policy meaning, and producer environment remain producer claims unless another independently authenticated record supplies them. Signature, signer identity, issuer, and time-policy verification also remain outside the tool. A successful result must not be described as proof that decompression or archive interpretation was independently rerun.

## File manifest versus SBOM

An arbitrary archive member is not necessarily a software component. For generic ZIP admission, emit an evidence or file manifest.

CycloneDX or SPDX output becomes appropriate only when a consumer profile establishes component or package semantics, such as a Python wheel, JAR, image layer, or model bundle. Unknown license and component facts remain explicitly unknown rather than guessed. SHA-256 is the current cryptographic content hash; CRC32 is an integrity field, not a cryptographic identity. BLAKE3 is not implemented.

This avoids competing with package-graph tools while still allowing package-aware profiles to export interoperable SBOMs.

## Current CLI behavior

Every invocation emits one view on stdout and one unsigned receipt on stderr. File capture may select the canonical lineage:

```text
sealr foo.zip
sealr foo.zip --dest D:\out
sealr foo.zip --view view.json --receipt receipt.json --canonical
```

The first form is inspect-only and returns `Allowed { wrote: false }` when successful. The second requests transactional materialization. If materialization fails, the compatibility verdict is `Rejected`, the precise axes record `admission: admitted` and `effect: failed` when applicable, the CLI exits `3`, and the materialization object records lifecycle and cleanup details.

There is no current `--sbom`, `attest`, `lock`, or signed-output command in the shipped CLI. The repository-only statement builder prepares an unsigned in-toto payload for external signing.

## What Sealr will not do

- invent a custom signed-JSON cryptosystem;
- call unsigned output an attestation;
- imply that CRC32 is a cryptographic hash;
- label a generic file list as an SBOM without component semantics;
- claim that a receipt protects a consumer that reparses the original archive;
- make signature presence equivalent to policy verification.

See [semantic-model.md](semantic-model.md) for the identity model and [API contract](api.md) for current fields.
