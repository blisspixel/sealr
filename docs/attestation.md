# Receipt attestation

> Vocabulary note: per the [evidence and attestations model](attestations.md), a sealr receipt is an EvidenceRecord, not an attestation — an attestation is an authenticated claim whose signature, signer identity, and freshness have been verified. This page is the practical flow for producing such an authenticated claim from a receipt with external tooling.

> Status: supported evidence flow using external, already-audited signing tools. Sealr's trusted computing base contains no signature cryptography by deliberate decision: canonical receipt bytes are what make a receipt signable, and envelope, key custody, and transparency logging belong to tools built for them.

## What is being attested

A sealr receipt binds the verified source digest, the policy identity, the interpretation, the findings, and the tree identities of one admission decision. An attestation wraps that receipt as the predicate of an [in-toto Statement v1](https://in-toto.io/Statement/v1) whose subject is the receipt's own verified source digest — so the signed claim reads: *this exact archive, under this exact policy, produced this exact decision and evidence.*

Receipts whose source digest is unavailable (failures before a complete snapshot) are refused as attestation predicates: an attestation must bind exact evaluated bytes.

## The direct cosign flow

Capture canonical evidence, verify it, then let cosign build, sign, and log the attestation keylessly. cosign computes the subject digest from the artifact itself, which must equal the receipt's `source.sha256`:

```text
sealr archive.zip --view view.json --receipt receipt.json --canonical
cargo run --locked -p sealr-identity-verifier -- evidence \
  --view view.json --receipt receipt.json --source archive.zip
cosign attest-blob --predicate receipt.json \
  --type https://github.com/blisspixel/sealr/receipt/v3 \
  --bundle receipt.attestation.jsonl archive.zip
```

Verification is the mirror image:

```text
cosign verify-blob-attestation --bundle receipt.attestation.jsonl \
  --type https://github.com/blisspixel/sealr/receipt/v3 \
  --certificate-identity <signer> --certificate-oidc-issuer <issuer> archive.zip
```

## The signer-agnostic statement builder

For DSSE signers other than cosign, `tools/attest` assembles the unsigned in-toto Statement from the receipt file with pure JSON handling and no cryptography:

```text
cargo run --locked -p sealr-attest -- statement \
  --view view.json --receipt receipt.json --source archive.zip \
  --out statement.json
```

For receipt v3, the builder requires the matching view and actual source archive. It applies the independent canonical-evidence verifier before creating output. The original receipt JSON token appears verbatim as the predicate, the subject carries the observed source SHA-256, and the default predicate type is `https://github.com/blisspixel/sealr/receipt/v3`. `--subject-name` and `--predicate-type` override their defaults. The output file must not already exist. Any DSSE implementation then signs the statement as payload type `application/vnd.in-toto+json` with the pre-authentication encoding `"DSSEv1" SP len(type) SP type SP len(body) SP body`.

Legacy receipt v2 remains accepted for compatibility and defaults to the versioned v2 predicate URI. Because v2 does not carry canonical view bindings, it does not receive the v3 pair verification. Supplying `--source` still checks its subject digest against the archive.

## Honest limitations

- Receipts remain unsigned by sealr itself; `signed: false` inside the receipt stays true. The signature lives in the external envelope.
- A default-lineage receipt file is pretty-printed presentation: the digests inside it cover the compact declaration-order encoding, so a verifier of the *predicate content* re-serializes per the evidence encoding contract, while the DSSE signature covers the exact file bytes either way. A `sealr.receipt.v3` canonical-lineage file has no such split; its bytes are exactly the digested bytes.
- The v3 builder checks byte canonicality, pair consistency, source identity, registered interpretation and known default-policy identities, outcome axes, effect evidence, and the format-neutral content root. It does not execute codecs or independently reconstruct the format-specific layout root.
- The predicate-type URI is repo-anchored and versioned to the receipt schema. A receipt schema revision gets a new URI.
- Verifying signatures *inside* sealr (for example, admitting only signed policy files) is a separate future decision with its own dependency review; nothing here pre-commits to it.
