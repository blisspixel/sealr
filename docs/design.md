# Design principles

> Published Alpha.15 behavior is defined by the [README](../README.md), [API contract](api.md), and [security policy](../SECURITY.md). Product sequencing is defined only by the [roadmap](../ROADMAP.md).

Sealr is trying to become a dependable archive-to-tree admission boundary. It is not trying to be a general unarchiver, codec benchmark, or scheduler.

## One interpretation

One bounded source invocation receives one versioned interpretation. Inspect, materialize, evidence, and future consumers must use the same immutable representation. No recovery parser or downstream reparse may assign a second meaning to the archive.

Alpha.15 preserves this rule through the compatibility `apply()` path and the explicit supervised path, both using one versioned, effect-independent `ArchiveIR`. Inspect, materialize, verified-member reads, and the wheel evaluator consume the admitted representation and private or borrowed snapshot without another structural parse. Preview layout and content-tree identities are derived from that representation.

## Admission and effects are different facts

The compatibility `Allowed { wrote } | Rejected` result combines semantic and operational outcomes. The current API exposes separate interpretation, admission, verification, effect, and view-completeness axes, and CLI exit `3` identifies an admitted archive whose requested destination effect failed.

## Filesystem access is capability based

Validated path components enter a component-bound materializer. Member creation is relative to retained directory handles, no-follow, and create-new. Publication is same-volume and no-replace on supported Linux, macOS, and Windows filesystems. Unsupported platforms and storage semantics fail closed.

The explicit x86_64 Linux worker reduces authority for supported ZIP32 payload verification, stage writes, and later reads. It does not replace the path grammar, quotas, staged-tree audit, or platform publication controls, and structural planning remains supervisor-owned.

## Evidence names only established facts

Alpha.15 emits deterministic unsigned evidence, opt-in byte-exact canonical evidence, and preview semantic tree roots. The packaged independent verifier checks canonical evidence but does not authenticate it. Sealr does not yet emit a stable lock, authenticated archive-decision claim, or formal proof. Future evidence keeps source, interpretation, layout, content, policy, and effect identities distinct.

## Compatibility is measured

Strict rejection is useful only within a named supported domain. Each stable profile needs a hostile conformance corpus and a benign ecosystem corpus, with reproducible acceptance rates and investigated rejection classes.

## Performance follows semantics

Measure structure, full verification, realization, and reuse separately. The strategic result is avoiding a second parse, decompression, or write after one complete verification. Parallelism and alternate codecs are optional backends only after they preserve exact input consumption, output bytes, findings, and tree identities.

## Expansion follows the boundary, then consumers

Python wheel admission is the first supported-preview consumer and stays on Store and Deflate. The shipped TAR wrappers prove that zstd, XZ/LZMA2, and bzip2 can be separately promoted as adapters on the same boundary. Further ZIP methods, 7z structure, and major formats wait for external usefulness and review. OCI, JAR, APK, agent workspaces, projection, bindings, and acceleration follow when a concrete consumer and its semantics are specified. A second unarchiver is never the expansion strategy.

See [semantic-model.md](semantic-model.md) for the target types and [ROADMAP.md](../ROADMAP.md#active-execution-queue) for the active implementation order.
