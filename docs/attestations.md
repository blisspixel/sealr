# SBOM and extraction receipts

> Current status: `apply()` emits a deterministic unsigned JSON receipt with source, policy, view, tool, environment, verdict, and findings. RFC 8785 canonicalization, DSSE, Sigstore, CycloneDX output, and standardized predicates are planned work.

The receipt is not optional output. It is a factor of the return type, including on **reject**. View (tree + findings) is the other always-on factor. Do not invent envelope formats.

## SBOM of *this unpack*

This is not Syft (package graph of a disk image). It is: **these members, these hashes, this archive, this policy.**

- Emit **CycloneDX 1.7** JSON (primary; ECMA-424 2nd ed.) and optionally **SPDX 2.3** (GitHub’s common example) / **SPDX 3.0.1**.
- Align fields with **CISA 2026 Minimum Elements** (published 29 July 2026, replaces NTIA 2021): author, tool name/version, generation context, component names, **component hashes + algorithm**, licenses if known, format name/version, unknowns explicit.
- Components = archive members (path, size, CRC, SHA-256/BLAKE3, detected type). The archive itself is the parent component (`hash` of the blob).

Unknown license → explicit unknown, not guessed.

## Extraction attestation (we may be first)

No widely adopted **“extraction”** in-toto predicate existed as of 2026-08-19 (vetted predicates: SPDX/CDX SBOM, SLSA provenance, vulns). Syft attests package SBOMs, not “this unpack under this policy.” **We’d be first** on that predicate; define it and try to upstream. Do not invent a wrapper envelope.

Envelope:

1. **DSSE** payload type `application/vnd.in-toto+json`
2. **in-toto Statement** v1
3. Predicate `https://sealr.dev/attestation/extraction/v1` (name TBD) containing:

```
source:
  uri:  ...
  digest: { sha256: ... }          # archive blob
policy:
  id: default | unix-tarball-v1 | ...
  digest: { sha256: ... }          # canonical policy bytes
tool:
  name: sealr
  version: 0.x.y
  dest: inspect | materialize | mount
environment:                       # coarse: os, arch, kernel_jail
  os, arch
  kernel_jail: landlock-vN | unavailable
timestamp: RFC3339
# The receipt is a return-type factor: policy + digests + environment, including on reject.
findings: [ { code, severity, member } ]
members: [ { path, size, crc32, sha256, mime } ]
```

4. Sign with **Sigstore keyless** (GitHub/OIDC) when available; otherwise a local key. Unsigned receipts are still useful as JSON logs; label `signed: false`.

Downstream policy engines verify: “this tree came from digest D under policy P with tool V.” That is the sentence enterprises and agent session logs need.

GitHub Artifact Attestations are a **distribution path** for the same DSSE blob, not a different format.

## CLI

Façade of [api.md](api.md). Every invocation emits view + receipt.

```
sealr foo.zip                              # Allowed { wrote: false } + view + receipt
sealr foo.zip --dest D:\out                # materialize if policy yes
sealr foo.zip --sbom cyclonedx
```

`receipt.view_digest` matches the view JSON. If `--atomic` rolls back, `verdict` is `Rejected` and the receipt records the rollback - still emitted.

## What we will not do

- A custom signed-JSON crypto scheme.
- Competing with Syft on OS package graphs.
- Implying CRC32 in the SBOM is a cryptographic hash (CISA wants real hashes; we emit SHA-256/BLAKE3 as the component hash, CRC as extra).
