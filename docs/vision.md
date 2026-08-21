# Vision: one archive, one tree, evidence

> This document describes the product direction. Current alpha.2 behavior and limitations are defined by the [README](../README.md) and [API contract](api.md). The target semantic design is specified in [semantic-model.md](semantic-model.md).

Sealr is not a general-purpose unarchiver, archive GUI, malware scanner, agent-execution proxy, model verifier, credential broker, or enterprise control plane.

Its intended category is a canonical archive-to-tree compiler and admission authority:

```text
untrusted archive bytes
    -> one immutable, policy-checked logical tree, or no admitted tree
    -> explicit evidence about interpretation, verification, admission, and effects
```

Archive bytes are a weak program in a language with disagreeing interpreters. Path traversal, links, resource exhaustion, and filesystem races are critical hazards, but parser disagreement is the deeper problem. A byte digest proves that two consumers received the same bytes. It does not prove they constructed the same tree.

Sealr owns that semantic boundary first. Materialization, projection, caching, language bindings, consumer integrations, and acceleration are consumers of the boundary.

## The alpha.2 foundation

The current Rust library provides one `apply()` path:

```text
UntrustedArchive x Policy
  -> (Allowed { wrote } | Rejected) x Receipt x View
```

Inspect and materialize share one planned tree. Every outcome includes structured findings, a view, and deterministic unsigned receipt data. Accepted members are content-verified, and requested files are staged and published through capability-relative, native no-replace materialization on the documented Linux, macOS, and Windows filesystem matrix.

This is the foundation, not the finished semantic API. Alpha.2 does not produce `ArchiveIR`, canonical tree roots, semantic locks, signed attestations, read-only projection, content-addressed reuse, wheel admission, or proof certificates.

## The target contract

The target separates four independent decisions and one completeness signal:

```text
Interpret(source, profile)       -> Interpreted | Malformed | Unsupported | Indeterminate
Evaluate(tree, policy, context)  -> Admitted | Denied | NotEvaluated
Verify(tree)                     -> StructureOnly | Partial | Complete
Realize(tree, effect)            -> NotRequested | Committed | Failed
View                             -> Complete | Partial { phase, cause }
```

This separation is product semantics, not API decoration. A safe tree can remain admitted when one destination write fails. A source read failure is not a policy denial. A projected tree can be admitted while content verification is partial.

The canonical object between these stages is a versioned `ArchiveIR`. Every downstream path consumes that IR and its immutable `SourceSnapshot`. No downstream integration may reopen the source through another archive parser.

## Why this boundary matters

The 2025 ZipDiff study compared 50 ZIP parsers across 19 languages, identified 14 ambiguity classes, and found disagreements among almost every parser pair. Real Python wheel advisories have shown that one digest can lead to different installed payloads in different tools.

Sealr's enduring claim should therefore be:

> Given exact source bytes and a versioned interpretation profile, construct one canonical tree with explicit verification completeness, or produce no admitted tree.

The claim becomes reusable only when consumers receive the admitted representation rather than a receipt beside the original archive.

## Product priorities

### 1. Semantic identity

Define the canonical `ArchiveIR`, immutable source snapshot, interpretation profiles, target filesystem models, consumer profiles, layout root, content-tree root, and target outcome axes. Stabilize exact codec-consumption and policy-compilation rules.

### 2. Measured trust

Combine the hostile ZipDiff gate with a benign ecosystem corpus, source-mutation tests, cross-platform semantic goldens, fuzzing, small proof harnesses, reduced-authority execution, and a small independent evidence verifier.

### 3. One canonical consumer

Python wheel admission is the first candidate. It has a documented same-bytes, different-installed-tree problem and meaningful consumer semantics beyond ZIP. A future `python-wheel.v1` must validate wheel metadata, `RECORD`, `.data` relocation, target paths, and installed-tree identity. It is not current functionality.

### 4. Reusable admitted trees

Add semantic locks, verified content-addressed blobs, read-only projection, and materialization from verified content. The goal is to avoid reparsing, reinflating, and rewriting the same admitted tree.

### 5. Expansion driven by consumers

Agent workspaces and hermetic build inputs are promising next profiles. OCI layers, TAR, JAR, APK, and other formats follow only when their consumer semantics and compatibility requirements are explicit.

## Durable project surface

The durable open-source surface is not the number of formats or language bindings. It is:

```text
normative interpretation profiles
+ canonical ArchiveIR and tree identity
+ hostile and benign corpora
+ consumer-specific policy packs
+ independent evidence verification
+ downstream integrations that consume the admitted representation
```

That surface compounds semantic knowledge, compatibility data, test fixtures, auditability, and ecosystem trust.

## Evidence discipline

Alpha.2 receipts are deterministic unsigned evidence records. They are not attestations. Future authenticated claims should use standard envelopes and verified identities, keep interpretation, verification, admission, and effect claims distinct, and use SBOM formats only where a consumer profile establishes package or component semantics.

Do not use a numeric risk score. Current findings provide stable codes, severity, member context, and detail. The target finding schema adds explicit rule versions, phases, deterministic evidence, source spans where applicable, and remediation without turning the human message into the machine contract.

Do not claim a proof-carrying tree until a canonical tree specification, certificate format, and independent verifier exist. The current truthful phrase is "One archive. One tree. Evidence."

## Performance discipline

Performance is not one unzip-throughput number. Measure structure, verification, realization, and reuse separately. The strongest future result is that one full verification can serve later consumers without a second parse, inflation, or filesystem write.

GPU, hardware codecs, alternate runtimes, mmap, and broad parallelism are backend decisions. They follow a measured bottleneck and may not alter interpretation, exact input consumption, output bytes, findings, verification state, or tree identity.

## What stays out of scope

- permissive recovery parsing;
- a generic `--insecure` mode;
- broad format support without a canonical consumer;
- a desktop extraction GUI;
- recursive malware classification in the core;
- an opaque numeric risk score;
- many bindings before one external dependent;
- a hosted service that requires private archive upload;
- projection presented as process containment;
- signing presented as sufficient verification.

## Documentation map

| Document | Purpose |
|---|---|
| [semantic-model.md](semantic-model.md) | Target outcome axes, `ArchiveIR`, identities, profiles, locks, and sequencing |
| [api.md](api.md) | Implemented alpha.2 contract and future type-state direction |
| [architecture.md](architecture.md) | Current trust boundaries and target pipeline |
| [threat-model.md](threat-model.md) | Adversaries and protected properties |
| [invariants.md](invariants.md) | Testable safety invariants |
| [differentials.md](differentials.md) | Single interpretation and ambiguity corpus |
| [safety.md](safety.md) | Path, quota, layout, and materialization controls |
| [sandbox.md](sandbox.md) | Process isolation and projection boundaries |
| [attestations.md](attestations.md) | Unsigned evidence and future authenticated claims |
| [assurance.md](assurance.md) | Hostile and benign corpora, fuzzing, proofs, and audit |
| [backends.md](backends.md) | Performance gates for optional backends |
| [policy.md](policy.md) | Current policy object and limitations |
| [findings.md](findings.md) | Stable finding registry |

## Primary references

- [ZipDiff, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [uv ZIP ambiguity advisory, 2025](https://github.com/advisories/GHSA-8qf3-x8v5-2pj8)
- [Python wheel parser differential advisory, 2026](https://github.com/google/security-research/security/advisories/GHSA-w97x-xxj5-gpjx)
