# Documentation

Start with the [getting started guide](getting-started.md) and [illustrated CLI walkthrough](walkthrough.md). This index separates current contracts from plans and research notes. The [README](../README.md) provides a short introduction and current release status.

## Start and integrate

| Document | Purpose |
|---|---|
| [Getting started](getting-started.md) | Native installation, source builds, evidence verification, and Rust capability example |
| [Illustrated walkthrough](walkthrough.md) | Linux examples for inspection, path rejection, and materialization |
| [Visual identity](brand.md) | Vector logo, theme variants, and documentation style |
| [Wheel-content release gate](wheel-content-gate.md) | A real publisher decision through the public capability, without installation |
| [Usage](usage.md) | Current CLI behavior and examples |
| [API contract](api.md) | Current Rust and JSON surface, plus clearly marked target notation |
| [Copyable PyPA `WheelSource` handoff](../crates/sealr/examples/pypa_installer_handoff/README.md) | Public-API-only supervised admission, reduced digest-bound manifest, source deletion, real installer effects, and Rust-owned result audit |
| [External adopter pilot contract](adopter-pilot.md) | Verified baseline, new-release gate, semantic identities, downstream proof, negative matrix, and report requirements |
| [Unicode and streaming wheel evidence](wheel-producer-compatibility.md) | Reproducible producer matrix, exact refusals, and complete capability handoffs |
| [Candidate surface inventory](candidate-surface.md) | Classified public identities for the first pilot; inventory only, not a freeze |
| [Exact Poetry 2.4.2 repository fixture](../tests/poetry-consumer/README.md) | Hash-pinned private update seam, PREPARED ordering, abort safety, stock parity, and realization audit |
| [Current release notes](releases/v0.1.0-alpha.15.md) | Alpha.15 contents and limitations |
| [Release verification](release-verification.md) | Verify checksums, provenance, tag, and immutable release state |
| [Distribution contract](distribution-contract.md) | Exact source-package scope, compatibility policy, and native archive floors |

## Trust boundary

| Document | Purpose |
|---|---|
| [Implementation and security boundary](implementation.md) | Current implementation, measured evidence, limits, and research basis |
| [Safety specification](safety.md) | Normative safety rules |
| [Threat model](threat-model.md) | Adversaries, exclusions, and parser-differential threats |
| [Invariants](invariants.md) | Properties that implementation and evidence must preserve |
| [Assurance](assurance.md) | Current evidence and the layered verification program |
| [Assurance discovery and promotion](assurance-promotion.md) | Pinned Kani, mutation, coverage, report, and promotion contracts |
| [Identity conformance](identity-conformance.md) | Current vectors, live canonical evidence verification, exact root bytes, and bounded claims |
| [Wheel compatibility pilot](wheel-compatibility-pilot.md) | Initial non-shipping corpus measurement and investigated denial evidence |
| [Wheel semantic inventory v2](wheel-compatibility-v2.md) | Predecessor-bound wheel-profile and consumer evaluation over the same pinned bytes |
| [Wheel supported-preview inventory v3](wheel-compatibility-v3.md) | Public portable-profile evaluator replay over the same pinned bytes |
| [Strict ASCII ZIP32 profile v2](profiles/zip-strict-ascii-v2.md) | Executable exhaustive flag and extra-field interpretation contract |
| [Portable UTF-8 ZIP32 profile v1](profiles/zip-portable-utf8-v1.md) | Supported Unicode flag, extra-field, NFC, component, and collision contract |
| [Portable POSIX ustar profile v1](profiles/tar-ustar-portable-v1.md) | Explicit zero-dependency TAR language, evidence, identity, producer, and fuzz contract |
| [Strict ASCII ZIP64 profile v1](profiles/zip64-strict-ascii-v1.md) | Explicit policy-v3 in-process ZIP64 language, identity, and worker limitation |
| [Gzip-wrapped portable ustar profile v1](profiles/tar-gzip-ustar-portable-v1.md) | Explicit policy-v4 single-member wrapper, transform, two-domain evidence, and limits |
| [Restricted POSIX PAX profile v1](profiles/tar-pax-portable-v1.md) | Explicit policy-v5 two-key PAX language, fixed precedence, provenance, and `sealrTreeV5` contract |
| [Restricted GNU long-name profile v1](profiles/tar-gnu-longname-portable-v1.md) | Explicit policy-v6 `L`-carrier-only old-GNU language, provenance, and `sealrTreeV6` contract |
| [Gzip-wrapped restricted PAX profile v1](profiles/tar-gzip-pax-portable-v1.md) | Explicit policy-v7 composition of the frozen wrapper and PAX languages with `sealrTreeV7` |
| [Gzip-wrapped GNU long-name profile v1](profiles/tar-gzip-gnu-longname-portable-v1.md) | Explicit policy-v7 composition of the frozen wrapper and GNU languages with `sealrTreeV8` |
| [Zstd-wrapped portable ustar profile v1](profiles/tar-zstd-ustar-portable-v1.md) | Explicit policy-v8 first promoted codec adapter with the ruzstd Gate B review and `sealrTreeV9` |
| [Xz-wrapped portable ustar profile v1](profiles/tar-xz-ustar-portable-v1.md) | Explicit policy-v9 second promoted codec adapter with the lzma-rust2 Gate B review and `sealrTreeV10` |
| [Bzip2-wrapped portable ustar profile v1](profiles/tar-bzip2-ustar-portable-v1.md) | Explicit policy-v10 third promoted codec adapter with the bzip2/libbz2-rs-sys Gate B review and `sealrTreeV11` |
| [Copy-only 7z container profile v1](profiles/7z-copy-portable-v1.md) | Explicit policy-v11 first Gate C container step with zero new dependencies, `sealrTreeV12`, and the first cross-container content parity |
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
| [Receipt attestation](attestation.md) | Signing receipts with external DSSE tools and the signer-agnostic statement builder |
| [Evidence encoding contract](evidence-encoding.md) | The frozen declaration-order lineage and byte-exact RFC 8785 canonical evidence lineage |
| [Public API surface contract](api-surface.md) | The role-grouped supported surface, compile-time pinned by `tests/api_surface.rs` |

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
| [Codec dependency gates](codec-dependency-gates.md) | Exact zero-dependency, pure-Rust codec, complex-engine, and legal-boundary decisions |
| [Attestations](attestations.md) | Evidence authentication boundaries |

## Plans and product direction

| Document | Purpose |
|---|---|
| [Roadmap](../ROADMAP.md) | Current execution order, stable gates, later work, and decision rules |
| [Near-term execution plan](near-term.md) | Post-Alpha.15 external-adoption work packages and acceptance criteria |
| [Unicode and streaming wheel evidence](wheel-producer-compatibility.md) | Reproducible producer matrix, exact refusals, and complete capability handoffs |
| [Candidate surface inventory](candidate-surface.md) | Inventory of public identities the first pilot may pin; not a freeze |
| [Milestone history](milestones.md) | Alpha.1 through Alpha.15 outcomes with links to immutable release notes and maintained topic contracts |
| [Vision](vision.md) | Durable category and priorities |
| [Usefulness test](usefulness.md) | Proof that a downstream consumer stops reparsing |
| [Capability reuse experiment](capability-reuse-experiment.md) | Measured working-set results, the resulting content gate, and remaining proposals |
| [Same digest is not same tree](same-digest-different-tree.md) | The archive-confusion lesson as a runnable capability-path demonstration |
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
