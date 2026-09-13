# Usefulness test

Updated 2026-09-13.

The historical artifact replays below precede the Alpha.17 distribution reset.
Their old remote releases and tags are retired; a current acquisition claim
requires a new Alpha.17 replay. See [distribution history](distribution-history.md).

Sealr is an admission boundary other software calls. Its technical usefulness test is:

```text
same bytes + same policy
    -> one tree, or no tree
    on each supported platform

the next tool consumes that admitted tree
    and does not open the archive again
```

Technical conformance is determined by executable evidence. Independent adoption is a separate observation: no external adopter treats the public representation as authority today. Recruiting one is not a dependency for development, candidate stability, or release readiness. The [optional external pilot](adopter-pilot.md) defines when that adoption claim may change.

## What counts as passing

1. The same admitted source and policy produce identical layout and content roots across supported platforms. Golden vectors pin the identities.
2. A `python-wheel.v1` consumer validates the filename, metadata, RECORD, and relocation plan against verified members without a second ZIP parser.
3. An isolated consumer acquires exact source and authenticated native artifacts without workspace dependencies, internal features, or a local path patch. It completes its declared publisher or installation decision after the original source becomes unavailable.
4. An open hook or equivalent trace confirms no source reopen after admission. Source, evidence, staged-member, manifest, and output mutations fail before an accepted decision or unaudited installation.
5. Typed machine results distinguish operational failure, archive refusal, wheel-semantic refusal, and consumer-policy refusal. Only an accepted result carries a successful consumer decision.
6. The integration publishes artifact pins, scope, resource observations, failure behavior, and nonclaims. Owner-maintained conformance is labeled accurately.

The narrow publisher scope now has local evidence for items 3 through 5 together, recorded in the [execution plan](near-term.md). A narrow publisher decision does not claim complete installation. An installer path additionally requires exact output, file-kind, mode, and realization-identity audits.

## Existing evidence

The public `VerifiedArchive` capability, portable UTF-8 profile, and wheel evaluator support source removal, bounded member reads, wheel metadata and RECORD verification, and separate source, tree, artifact, plan, and realization identities. The `wheel_admission` and `same_digest_different_tree` examples exercise this public path. The [same-digest demonstration](same-digest-different-tree.md) explains the authority distinction.

The [packaged PyPA kit](../tests/pypa-installer-consumer/README.md) compiles against Cargo's extracted crate, independently verifies canonical evidence, removes the source, stages bounded capability members, denies wheel opens, performs installer 1.0.1 effects, and audits the outputs. The [copyable handoff](../crates/sealr/examples/pypa_installer_handoff/README.md) also checks supervised inspect and materialize origins. Its extracted-package path patch is a packaging test; ordinary artifact acquisition remains separate work.

The [exact Poetry 2.4.2 fixture](../tests/poetry-consumer/README.md) tests one private update seam, PREPARED ordering, source removal, abort safety, denied wheel opens, and stock-output parity. It establishes behavior in one pinned environment and does not establish general Poetry support.

The [Unicode and streaming matrix](wheel-producer-compatibility.md) adds controlled producer evidence and exposed an incomplete Deflate stream admission defect, fixed in Alpha.14. The [Alpha.15 content gate](wheel-content-gate.md) checks real publisher requirements without installing files. The separate owner-maintained [validation project](https://github.com/blisspixel/sealr-validation) consumes released Deepr, Primr, and Recon wheels and records retention experiments.

The separate publisher replay combines ordinary immutable Alpha.15 acquisition with two accepted variants, ten typed refusals, and bounded post-deletion source-open observations. It closes that narrow technical conformance increment. Alpha.17 carries the typed outcome and consumer migration changes; the older report remains Alpha.15 artifact evidence. Independent adoption and an independent security audit remain unproven. The next work attributes measured repeated-read costs and closes explicit lifecycle gaps.

## Boundary rules

- Inspection and materialization share one explicit interpretation. No recovery parser or fallback extractor.
- Policy and semantic identities remain bound into evidence. Unsupported selections fail closed.
- Verification covers every member even when the consumer uses only names or a small retained working set.
- A source digest is distinct from a tree, artifact, or installation identity.
- Publication occurs only after verification and stage audit, with no replacement and no link following.
- Supervised operations retain authenticated packaging, supported Linux restrictions, exact completion, and worker cleanup requirements.
- Same-user attackers, abandoned stages, and power-loss durability retain their documented limitations until specific tested contracts replace them.
- Archive admission does not establish that executable content is safe. Automated checks do not establish an independent audit.

The [roadmap](../ROADMAP.md#active-execution-queue) orders remaining work. See the [semantic model](semantic-model.md#the-consumption-rule), [wheel profile](profiles/python-wheel-v1.md), and [implementation boundary](implementation.md) for exact contracts.
