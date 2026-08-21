# Project-specific research notes

> Reviewed 2026-08-21. Upstream projects change. These notes identify ideas to study and boundaries not to overclaim; they do not rank tools or assert that a project is secure for a particular deployment.

## Tools to study

### HashiCorp go-extract

[go-extract](https://github.com/hashicorp/go-extract) demonstrates a practical multi-format extraction API with resource and path controls. It is a useful safety baseline. Sealr's separate research question is whether one versioned interpretation and reusable evidence can prevent downstream parser disagreement.

### exarch

[exarch](https://github.com/bug-ops/exarch) is useful prior art for typed security configuration and language-facing APIs. Sealr should study its ergonomics without adding bindings or format breadth before one canonical consumer needs them.

### ripunzip and ripzip

[ripunzip](https://github.com/GoogleChrome/ripunzip) and [ripzip](https://github.com/velopack/ripzip-rs) show that independent ZIP members can be processed efficiently. Sealr should compare against them only on named corpora with CRC, cryptographic hashing, path checks, quotas, and the real destination enabled.

### ouch

[ouch](https://github.com/ouch-org/ouch) provides a unified archive command and has explored optional Landlock confinement. It is useful operational prior art. Sealr's planned worker differs by retaining publication authority in a trusted supervisor and treating the worker result as untrusted.

### ratarmount and archivemount

[ratarmount](https://github.com/mxmlnkn/ratarmount) and [archivemount](https://github.com/cybernoid/archivemount) demonstrate read-only or filesystem-style access to archive content. A future Sealr projection would need a different contract: it must consume the canonical admitted tree, preserve an immutable source snapshot, and report a partial verification frontier.

### 7-Zip and platform archive tools

[7-Zip](https://7-zip.org/) and operating-system archive tools set the compatibility and user-experience expectations for ordinary extraction. Sealr is not trying to replace their format breadth or desktop role.

## Research that shapes the boundary

[ZipDiff](https://github.com/ouuan/ZipDiff) is the most direct input to the current design. Its constructions turn parser disagreement into executable fixtures. Python wheel advisories provide a concrete consumer case where identical archive bytes can produce different installed trees.

[in-toto](https://in-toto.io/), [Sigstore](https://www.sigstore.dev/), OCI identities, and Git tree objects are useful evidence and content-identity precedents. None is adopted as a complete Sealr tree algorithm without a normative mapping and test vectors.

## Decision

The project should learn configuration ergonomics, performance measurement, projection mechanics, and standard evidence envelopes from adjacent work. It should not claim novelty merely because those pieces are combined.

The next meaningful result is narrower: demonstrate that a versioned admitted tree and its evidence stay identical across supported platforms and are consumed without another archive parser. The [roadmap](../ROADMAP.md#active-execution-queue) defines that test.
