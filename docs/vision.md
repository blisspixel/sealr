# Vision: one archive, one tree, evidence

> This document describes the product direction. Published Alpha.14 behavior is defined by the [README](../README.md) and [API contract](api.md). The target semantic design is specified in [semantic-model.md](semantic-model.md).

Sealr is not a general-purpose unarchiver, archive GUI, malware scanner, agent-execution proxy, model verifier, credential broker, or enterprise control plane.

Its intended category is a canonical archive-to-tree compiler and admission authority:

```text
untrusted archive bytes
    -> one immutable, policy-checked logical tree, or no admitted tree
    -> explicit evidence about interpretation, verification, admission, and effects
```

Archive bytes are a weak program in a language with disagreeing interpreters. Path traversal, links, resource exhaustion, and filesystem races are critical hazards, but parser disagreement is the deeper problem. A byte digest proves that two consumers received the same bytes. It does not prove they constructed the same tree.

Sealr owns that semantic boundary first. Materialization, projection, caching, language bindings, consumer integrations, and acceleration are consumers of the boundary. The [usefulness test](usefulness.md) is whether another program calls that boundary and stops opening the ZIP.

## The current foundation

The current Rust library preserves one compatibility `apply()` path and provides an explicit supervised x86_64 Linux path:

```text
UntrustedArchive x Policy
  -> (Allowed { wrote } | Rejected) x Receipt x View
```

Inspect and materialize share one planned tree. Every outcome includes structured findings, a view, and deterministic unsigned receipt data. Accepted members are content-verified, and requested files are staged and published through capability-relative, native no-replace materialization on the documented Linux, macOS, and Windows filesystem matrix.

The preview line now includes `ArchiveIR`, separately identified layout and content roots, private file-backed snapshots, checked random access, bounded resource evidence, twelve explicit container and codec selections, an authenticated Linux worker for supported ZIP32 records, canonical RFC 8785 evidence, an independently implemented packaged verifier, and a public capability-only Python wheel evaluator. The packaged PyPA handoff and exact Poetry fixture prove the consumer mechanism inside this repository.

This remains a foundation, not a stable product claim. Structural planning still runs in the supervisor, the worker does not establish general process containment, receipts are unsigned, crash recovery and full durability are unfinished, and no separately maintained project has adopted the capability as authoritative. Semantic locks, read-only projection, content-addressed reuse, broader worker-record support, and proof certificates remain future work.

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

The claim becomes reusable only when consumers receive the admitted representation rather than a receipt beside the original archive. The research framing of that claim is [theory.md](theory.md).

## Reliability and trusted computing base

The product bar is high-consequence ingest: fail closed, one interpretation, evidence for every decision, and a dependency graph small enough to review. Common compression is in scope as adapters on that boundary. A large codec framework, a subprocess extractor, or a recovery parser is not. Codec breadth waits until the ZIP trust gate can be reused; it does not wait forever.

## Product priorities

The current implementation order is in the [roadmap](../ROADMAP.md), and the bounded post-Alpha.14 work is in the [near-term execution plan](near-term.md).

### 1. External usefulness

Move the proven repository mechanism into one separately maintained consumer. That consumer must treat `VerifiedArchive` and independently checked evidence as authoritative, make the original source unavailable after admission, and finish without another archive parser. This is the next test of the product category.

### 2. Stable semantic surface

Use adopter feedback to review the public API, interpretation profiles, policies, identity encodings, evidence schemas, CLI machine output, MSRV, and package layout. Freeze only the surfaces backed by compatibility fixtures and migration rules. A profile or encoding change receives a new identifier rather than changing old meaning in place.

### 3. Measured trust

Combine the hostile ZipDiff gate with targeted benign compatibility, source-mutation tests, cross-platform semantic goldens, independent property oracles, bounded model checking, fuzzing, native systems stress, reduced-authority execution, TCB measurement, and independent review. Each evidence type keeps its stated domain and nonclaim. Current wheel evidence should target Unicode paths and data descriptors rather than merely enlarging a sample that observed neither gap.

### 4. Reusable admitted trees

Add semantic locks, verified content-addressed blobs, read-only projection, and materialization from verified content. The goal is to avoid reparsing, reinflating, and rewriting the same admitted tree.

### 5. Evidence-led breadth

The shipped zstd, XZ/LZMA2, and bzip2 TAR wrappers demonstrate the codec-promotion path, and the Copy-only 7z profile demonstrates the first separate container step. Further 7z, ZIP codec, and major-format work resumes after external usefulness and review. Agent workspaces and hermetic build inputs are promising later consumer profiles. OCI, JAR, APK, and language bindings follow only when their consumer semantics are explicit. No format is added by bundling another unarchiver.

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

Alpha.14 receipts are deterministic unsigned evidence records, and the opt-in canonical lineage can be checked by the independently implemented packaged verifier. They are not authenticated attestations. Future authenticated claims should use standard envelopes and verified identities, keep interpretation, verification, admission, and effect claims distinct, and use SBOM formats only where a consumer profile establishes package or component semantics.

Do not use a numeric risk score. Current findings provide stable codes, severity, member context, and detail. The target finding schema adds explicit rule versions, phases, deterministic evidence, source spans where applicable, and remediation without turning the human message into the machine contract.

Do not claim a proof-carrying tree until the tree specification and profile are stable, a general certificate format exists, and the broader evidence verifier covers it. The current identity verifier reproduces finite preview vectors only. The truthful phrase remains "One archive. One tree. Evidence."

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

The complete task-oriented map is the [documentation index](index.md).

| Document | Purpose |
|---|---|
| [near-term.md](near-term.md) | Post-Alpha.14 external-adoption work packages and acceptance gates |
| [adopter-pilot.md](adopter-pilot.md) | Exact first-pilot baseline, proofs, and nonclaims |
| [candidate-surface.md](candidate-surface.md) | Classified public identities; inventory, not a freeze |
| [milestones.md](milestones.md) | Completed preview outcomes and links to immutable release detail |
| [profiles/python-wheel-v1.md](profiles/python-wheel-v1.md) | First-consumer design and corpus plan |
| [semantic-model.md](semantic-model.md) | Target outcome axes, `ArchiveIR`, identities, profiles, locks, and sequencing |
| [api.md](api.md) | Implemented Alpha.14 contract and future type-state direction |
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
