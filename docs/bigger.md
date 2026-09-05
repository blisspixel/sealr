# Reusable admitted trees

> Target research direction. Alpha.15 does not implement projection, mounting, content-addressed reuse, overlays, or lazy verification. The [active execution queue](../ROADMAP.md#active-execution-queue) puts independent adoption and candidate stability before this work.

The larger opportunity is not faster extraction. It is letting multiple consumers use the exact admitted tree without assigning the archive another meaning.

```text
immutable source snapshot
    -> canonical ArchiveIR
    -> admitted tree
       -> materialize
       -> read-only projection
       -> verified content-addressed blobs
       -> consumer-specific view
```

## Why projection can matter

Traditional extraction creates every file before a consumer can inspect one member. A read-only projection could expose the admitted namespace, verify a member on first read, cache verified content by digest, and make verification completeness explicit.

That can avoid unnecessary filesystem creation and repeated decompression. It also preserves Sealr's semantic authority only if directory listing, member reads, materialization, and evidence all consume the same `ArchiveIR` and immutable `SourceSnapshot`.

## Required contract

The first projection, if implemented, must:

- be read-only;
- expose no links, devices, write overlay, hidden network access, or implicit promotion;
- preserve canonical names and target-model collision rules;
- record a partial verification frontier until every required member is verified;
- bind cached blobs to content hashes and the canonical tree identity;
- fail closed when the source snapshot, profile, policy, or verification state does not match;
- remain distinct from process containment.

A mount is a destination representation, not a sandbox. A caller can copy bytes out unless its own process authority is constrained separately.

## Source stability

Lazy reads make source immutability mandatory. Holding a path or file descriptor is insufficient when another writer can change the underlying bytes between structure interpretation and content verification. Projection therefore follows the `SourceSnapshot` contract and snapshot-backed bounded random access.

## Platform order

No projection platform is selected for implementation yet. Linux FUSE, macOS FSKit or a compatible filesystem extension, and Windows ProjFS have different packaging and security properties. A platform is selected only after the common IR, verification frontier, cache identity, and worker boundary are stable.

## Performance claim

The relevant measurements are:

```text
T_structure  construct and evaluate the layout
T_verify     expand and hash required content
T_realize    build and publish a destination
T_reuse      provide an already verified tree
```

The target is not a headline unzip number. It is one complete verification followed by exact reuse without another parse or inflation when policy permits.

See [semantic-model.md](semantic-model.md) for the normative target and [backends.md](backends.md) for deferred acceleration rules.
