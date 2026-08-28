# Documentation

Start with the [README](../README.md) for the published Alpha.9 boundary and a short walkthrough. This index separates current contracts from plans and research notes.

## Start and integrate

| Document | Purpose |
|---|---|
| [Usage](usage.md) | Current CLI behavior and examples |
| [API contract](api.md) | Current Rust and JSON surface, plus clearly marked target notation |
| [Current release notes](releases/v0.1.0-alpha.9.md) | Alpha.9 contents and limitations |
| [Release verification](release-verification.md) | Verify checksums, provenance, tag, and immutable release state |
| [Distribution contract](distribution-contract.md) | Exact source-package scope, compatibility policy, and native archive floors |

## Trust boundary

| Document | Purpose |
|---|---|
| [Safety specification](safety.md) | Normative safety rules |
| [Threat model](threat-model.md) | Adversaries, exclusions, and parser-differential threats |
| [Invariants](invariants.md) | Properties that implementation and evidence must preserve |
| [Assurance](assurance.md) | Current evidence and the layered verification program |
| [Assurance discovery and promotion](assurance-promotion.md) | Pinned Kani, mutation, coverage, report, and promotion contracts |
| [Identity conformance](identity-conformance.md) | Current vectors, standalone verifier, exact root bytes, and bounded claims |
| [Wheel compatibility pilot](wheel-compatibility-pilot.md) | Initial non-shipping corpus measurement and investigated denial evidence |
| [Wheel semantic inventory v2](wheel-compatibility-v2.md) | Predecessor-bound wheel-profile and consumer evaluation over the same pinned bytes |
| [Wheel supported-preview inventory v3](wheel-compatibility-v3.md) | Public portable-profile evaluator replay over the same pinned bytes |
| [Strict ASCII ZIP32 profile v2](profiles/zip-strict-ascii-v2.md) | Executable exhaustive flag and extra-field interpretation contract |
| [Portable UTF-8 ZIP32 profile v1](profiles/zip-portable-utf8-v1.md) | Supported Unicode flag, extra-field, NFC, component, and collision contract |
| [Portable POSIX ustar profile v1](profiles/tar-ustar-portable-v1.md) | Explicit zero-dependency TAR language, evidence, identity, producer, and fuzz contract |
| [Strict ASCII ZIP64 profile v1](profiles/zip64-strict-ascii-v1.md) | Explicit policy-v3 in-process ZIP64 language, identity, and worker limitation |
| [Python wheel consumer v1](profiles/python-wheel-v1.md) | Supported bounded wheel artifact and scheme-relative plan evaluator |
| [Differentials](differentials.md) | Single-interpretation rules and the ZipDiff corpus |
| [Reduced-authority execution](sandbox.md) | Supervisor and worker design |
| [Linux helper packaging](helper-packaging.md) | Fixed archive placement, manifest, license closure, and extracted-artifact verification |
| [Real-kernel restriction floor](../tests/kernel-floor/README.md) | Pinned Landlock ABI 2 fail-closed fixture and QEMU execution contract |
| [Finding registry](findings.md) | Stable machine finding codes |
| [Worker protocol v1](worker-protocol.md) | Bounded control frames, capability slots, decoder rules, and fuzz evidence |
| [Alpha.6 semantic ownership](decisions/0001-alpha6-semantic-ownership.md) | Accepted private record experiment and provisional public capability gates |
| [Private semantic record](semantic-record.md) | Crate-private split-phase codec and worker executor, hostile validation, current evidence, and remaining gates |
| [Policy](policy.md) | Current policy schema, compilation, and defaults |

Repository vulnerability reporting and supported-version policy are in [SECURITY.md](../SECURITY.md).

## Semantics and architecture

| Document | Purpose |
|---|---|
| [Semantic model](semantic-model.md) | Outcome axes, `ArchiveIR`, identities, profiles, locks, and consumers |
| [Architecture](architecture.md) | Current and target component boundaries |
| [Design](design.md) | Implementation design decisions |
| [Interpretation theory](theory.md) | Research notes, conjectures, and proof obligations |
| [Format strategy](formats.md) | Format and codec sequencing |
| [Format support architecture](format-support.md) | Major container, wrapper, consumer, dependency, and promotion matrix |
| [Attestations](attestations.md) | Evidence authentication boundaries |

## Plans and product direction

| Document | Purpose |
|---|---|
| [Roadmap](../ROADMAP.md) | Long-range capability order and release gates |
| [Near-term execution plan](near-term.md) | Release-sized work packages through Alpha.9 and the next acceptance gates |
| [Vision](vision.md) | Durable category and priorities |
| [Usefulness test](usefulness.md) | Proof that a downstream consumer stops reparsing |
| [Competitive context](competitive.md) | Category boundaries and alternatives |
| [Related work](who-else.md) | Projects and research that inform the design |
| [Why now](now.md) | Practical research and platform context |
| [Longer-term reuse](bigger.md) | Admitted-tree reuse and broader applications |
| [Backend strategy](backends.md) | Codec, I/O, concurrency, and acceleration boundaries |

## Repository operations

| Document | Purpose |
|---|---|
| [Tooling](tooling.md) | Cross-platform repository tooling and dependency discipline |
| [Release process](releasing.md) | Protected-main release workflow |
| [Changelog](../CHANGELOG.md) | Release history |
