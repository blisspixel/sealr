# Evidence and attestations

> Current status: Alpha.4 emits a versioned deterministic unsigned JSON receipt and preview `sealrTreeV1` identities. A separate verifier checks finite identity-conformance vectors. RFC 8785 canonicalization, stable lock semantics, DSSE, Sigstore, standardized predicates, SBOM output, and a general authenticated-evidence verifier remain planned work.

The current receipt is always returned, including on rejection. `sealr.receipt.v2` records source digest availability, interpretation/admission/verification/effect/completeness axes, the invocation-specific view digest, tool and environment fields, materialization lifecycle evidence, the compatibility verdict, and findings.

It is an **EvidenceRecord**, not an attestation. `signed: false` is explicit. It proves neither signer identity nor freshness. `view_digest` is still invocation evidence. Receipts also carry unsigned preview `sealrTreeV1` layout and content-tree identities derived from `ArchiveIR`.

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

The Alpha.4 program does not produce DSSE, in-toto, Sigstore, or GitHub Artifact Attestations for archive decisions. Separately, the GitHub release workflow records build provenance attestations for the native release archives. That provenance binds a packaged binary to its source workflow; it does not authenticate an individual Sealr decision receipt.

## Tree subjects

Future authenticated claims should distinguish:

- archive source digest;
- interpretation profile identity;
- canonical layout root;
- complete content-tree root;
- invocation and effect identity.

The existing `view_digest` cannot stand in for the layout or content-tree root because it covers invocation-specific fields such as source metadata, policy, verdict, findings, and write outcome.

`sealrTreeV1` now has a documented canonical encoding, committed cross-platform preview vectors, and a separate tool that independently reproduces those finite vectors. It still requires profile closure, stability rules, canonical claim bytes, and authenticated-envelope verification before it can be an authenticated subject. in-toto `dirHash1`, Git trees, and OCI `DiffID` are interoperability references, not drop-in replacements for all Sealr semantics.

## Independent verifier

The current [identity-conformance verifier](identity-conformance.md) validates profile and tree-root derivation, exact small source fixtures, finite semantic-axis consistency, and their claimed structural covering without extracting. A future general verifier should add:

- canonical evidence serialization;
- profile and rule identities;
- tree-root derivation from an evidence manifest;
- source-range non-overlap and coverage claims;
- policy and admission consistency;
- effect-record consistency;
- DSSE signature, signer identity, issuer, and time policy when authenticated.

The general verifier may rely on an authenticated producer for expensive codec execution. Its result must not be described as a proof that independently reran decompression.

## File manifest versus SBOM

An arbitrary archive member is not necessarily a software component. For generic ZIP admission, emit an evidence or file manifest.

CycloneDX or SPDX output becomes appropriate only when a consumer profile establishes component or package semantics, such as a Python wheel, JAR, image layer, or model bundle. Unknown license and component facts remain explicitly unknown rather than guessed. SHA-256 is the current cryptographic content hash; CRC32 is an integrity field, not a cryptographic identity. BLAKE3 is not implemented.

This avoids competing with package-graph tools while still allowing package-aware profiles to export interoperable SBOMs.

## Current CLI behavior

Every invocation emits one view on stdout and one unsigned receipt on stderr:

```text
sealr foo.zip
sealr foo.zip --dest D:\out
```

The first form is inspect-only and returns `Allowed { wrote: false }` when successful. The second requests transactional materialization. If materialization fails, the compatibility verdict is `Rejected`, the precise axes record `admission: admitted` and `effect: failed` when applicable, the CLI exits `3`, and the materialization object records lifecycle and cleanup details.

There is no current `--sbom`, `attest`, `lock`, or signed-output command.

## What Sealr will not do

- invent a custom signed-JSON cryptosystem;
- call unsigned output an attestation;
- imply that CRC32 is a cryptographic hash;
- label a generic file list as an SBOM without component semantics;
- claim that a receipt protects a consumer that reparses the original archive;
- make signature presence equivalent to policy verification.

See [semantic-model.md](semantic-model.md) for the identity model and [API contract](api.md) for current fields.
