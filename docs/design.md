# Design principles

> Current Alpha.8 behavior is defined by the [README](../README.md), [API contract](api.md), and [security policy](../SECURITY.md). Product sequencing is defined only by the [roadmap](../ROADMAP.md).

Sealr is trying to become a dependable archive-to-tree admission boundary. It is not trying to be a general unarchiver, codec benchmark, or scheduler.

## One interpretation

One bounded source invocation receives one versioned interpretation. Inspect, materialize, evidence, and future consumers must use the same immutable representation. No recovery parser or downstream reparse may assign a second meaning to the archive.

Alpha.6 preserves this rule through the compatibility `apply()` path and the explicit supervised path, both using one versioned, effect-independent `ArchiveIR`. Inspect and materialize consume the same IR and private or borrowed snapshot, and preview layout and content-tree identities are derived from it.

## Admission and effects are different facts

The compatibility `Allowed { wrote } | Rejected` result combines semantic and operational outcomes. Alpha.6 exposes separate interpretation, admission, verification, effect, and view-completeness axes, and CLI exit `3` identifies an admitted archive whose requested destination effect failed.

## Filesystem access is capability based

Validated path components enter a component-bound materializer. Member creation is relative to retained directory handles, no-follow, and create-new. Publication is same-volume and no-replace on supported Linux, macOS, and Windows filesystems. Unsupported platforms and storage semantics fail closed.

A future worker reduces parser authority. It does not replace the path grammar, quotas, staged-tree audit, or platform publication controls.

## Evidence names only established facts

Alpha.6 emits deterministic unsigned evidence plus preview semantic tree roots. It does not emit an authenticated archive-decision attestation, stable lock, or formal proof. Future evidence keeps source, interpretation, layout, content, policy, and effect identities distinct.

## Compatibility is measured

Strict rejection is useful only within a named supported domain. Each stable profile needs a hostile conformance corpus and a benign ecosystem corpus, with reproducible acceptance rates and investigated rejection classes.

## Performance follows semantics

Measure structure, full verification, realization, and reuse separately. The strategic result is avoiding a second parse, decompression, or write after one complete verification. Parallelism and alternate codecs are optional backends only after they preserve exact input consumption, output bytes, findings, and tree identities.

## Expansion follows the boundary, then consumers

Python wheel admission is the first candidate consumer after the semantic core and can stay on Store and Deflate. Common ZIP methods (Zstd, XZ/LZMA, BZip2, Deflate64) and TAR wrappers are codec adapters on the same boundary, added only with exact consumption, bounded windows, and a justified tiny dependency. OCI, JAR, APK, agent workspaces, projection, bindings, and acceleration follow when a concrete consumer and its semantics are specified. A second unarchiver is never the expansion strategy.

See [semantic-model.md](semantic-model.md) for the target types and [ROADMAP.md](../ROADMAP.md#active-execution-queue) for the active implementation order.
