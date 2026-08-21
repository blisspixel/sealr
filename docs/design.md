# Design principles

> Current alpha.2 behavior is defined by the [README](../README.md), [API contract](api.md), and [security policy](../SECURITY.md). Product sequencing is defined only by the [roadmap](../ROADMAP.md).

Sealr is trying to become a dependable archive-to-tree admission boundary. It is not trying to be a general unarchiver, codec benchmark, or scheduler.

## One interpretation

One bounded source invocation receives one versioned interpretation. Inspect, materialize, evidence, and future consumers must use the same immutable representation. No recovery parser or downstream reparse may assign a second meaning to the archive.

Alpha.2 implements this rule through one `apply()` path and one planned member set. Phase 0.1 turns that internal plan into a versioned, effect-independent `ArchiveIR` with canonical layout and content-tree identities.

## Admission and effects are different facts

The current `Allowed { wrote } | Rejected` result is an honest preview contract, but it combines semantic and operational outcomes. The target separates interpretation, admission, verification, effect, and view completeness. A destination I/O failure must not redefine an otherwise admitted archive as unsafe.

## Filesystem access is capability based

Validated path components enter a component-bound materializer. Member creation is relative to retained directory handles, no-follow, and create-new. Publication is same-volume and no-replace on supported Linux, macOS, and Windows filesystems. Unsupported platforms and storage semantics fail closed.

A future worker reduces parser authority. It does not replace the path grammar, quotas, staged-tree audit, or platform publication controls.

## Evidence names only established facts

Alpha.2 emits deterministic unsigned evidence. It does not emit an authenticated attestation, semantic tree root, or formal proof. Future evidence keeps source, interpretation, layout, content, policy, and effect identities distinct.

## Compatibility is measured

Strict rejection is useful only within a named supported domain. Each stable profile needs a hostile conformance corpus and a benign ecosystem corpus, with reproducible acceptance rates and investigated rejection classes.

## Performance follows semantics

Measure structure, full verification, realization, and reuse separately. The strategic result is avoiding a second parse, decompression, or write after one complete verification. Parallelism and alternate codecs are optional backends only after they preserve exact input consumption, output bytes, findings, and tree identities.

## Expansion follows consumers

Python wheel admission is the first candidate consumer after the semantic core. TAR, OCI, JAR, APK, agent workspaces, projection, bindings, and acceleration follow only when a concrete consumer and its semantics are specified.

See [semantic-model.md](semantic-model.md) for the target types and [ROADMAP.md](../ROADMAP.md#active-execution-queue) for the active implementation order.
