# Documentation

Start with the [README](../README.md) for the published Alpha.5 boundary and a short walkthrough. This index separates current contracts from plans and research notes.

## Start and integrate

| Document | Purpose |
|---|---|
| [Usage](usage.md) | Current CLI behavior and examples |
| [API contract](api.md) | Current Rust and JSON surface, plus clearly marked target notation |
| [Current release notes](releases/v0.1.0-alpha.5.md) | Alpha.5 contents and limitations |
| [Release verification](release-verification.md) | Verify checksums, provenance, tag, and immutable release state |

## Trust boundary

| Document | Purpose |
|---|---|
| [Safety specification](safety.md) | Normative safety rules |
| [Threat model](threat-model.md) | Adversaries, exclusions, and parser-differential threats |
| [Invariants](invariants.md) | Properties that implementation and evidence must preserve |
| [Assurance](assurance.md) | Current evidence and the layered verification program |
| [Identity conformance](identity-conformance.md) | Current vectors, standalone verifier, exact root bytes, and bounded claims |
| [Wheel compatibility pilot](wheel-compatibility-pilot.md) | Initial non-shipping corpus measurement and investigated denial evidence |
| [Strict ASCII ZIP32 profile v2](profiles/zip-strict-ascii-v2.md) | Executable exhaustive flag and extra-field interpretation contract |
| [Differentials](differentials.md) | Single-interpretation rules and the ZipDiff corpus |
| [Reduced-authority execution](sandbox.md) | Supervisor and worker design |
| [Linux helper packaging](helper-packaging.md) | Fixed archive placement, manifest, license closure, and extracted-artifact verification |
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
| [Attestations](attestations.md) | Evidence authentication boundaries |

## Plans and product direction

| Document | Purpose |
|---|---|
| [Roadmap](../ROADMAP.md) | Long-range capability order and release gates |
| [Near-term execution plan](near-term.md) | Alpha.4 through Alpha.6 work packages and acceptance gates |
| [Python wheel profile draft](profiles/python-wheel-v1.md) | First-consumer semantics and research plan |
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
