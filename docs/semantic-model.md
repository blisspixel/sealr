# Semantic model

> Status: target architecture. This document does not describe capabilities already present unless a section is explicitly labeled current. The current alpha behavior is defined by the [README](../README.md), [API contract](api.md), and [security limitations](../README.md#security-limitations).

## Product boundary

Sealr is intended to become the canonical archive-to-tree compiler and admission authority:

```text
untrusted bytes + interpretation profile
    -> one canonical logical tree, or no admitted tree
```

Policy evaluation, content verification, materialization, projection, caching, and evidence all consume that one interpretation. None may reparse the original archive through a second parser.

This is a stronger and narrower claim than safe extraction. Archive formats contain redundant metadata and consumer-specific semantics. The same byte digest can produce different trees when parsers disagree. The ZipDiff study found 14 ambiguity classes across 50 ZIP parsers in 19 languages, and Python wheel advisories have demonstrated same-bytes, different-installation behavior in practice.

The intended mathematics of that statement, including unique covering, partial interpretation, and effect independence, is sketched in [theory.md](theory.md). That sketch is a research program, not a claim that Alpha.4 has a uniqueness proof.

The short product statement is:

> One archive. One tree. Evidence.

Do not use "proven" in current product claims. Alpha.4 emits deterministic unsigned evidence and a preview `sealrTreeV1` encoding. It does not emit an authenticated attestation or a formal uniqueness proof.

## Research disposition

The architecture review produced useful priorities, speculative extensions, and implementation findings. This table records the disposition so ideas do not become implied features or disappear into prose.

| Research idea | Disposition | Reason and status |
|---|---|---|
| Canonical archive-to-tree admission authority | Adopted as product direction | It best matches the existing single-interpretation parser, shared inspect/materialize plan, findings, and evidence boundary. |
| Exact compressed-input consumption and distinct codec findings | Adopted for immediate hardening | This is required by the current one-interpretation claim and has direct differential-parser precedent. |
| Unsigned evidence terminology | Adopted now | Current JSON is an EvidenceRecord or receipt, not an authenticated attestation. |
| Separate interpretation, admission, verification, effect, and completeness axes | Landed in receipt v2 and the view | The `Allowed` or `Rejected` compatibility verdict remains, but the axes and CLI exit classes expose the independent facts. |
| Versioned `ArchiveIR` and separate source, interpretation, layout, content, and effect identities | ArchiveIR landed; preview tree identities landed | `sealr.archive-ir.v1` is the inspect/materialize member plan and now records ranges, extra-field dispositions, and normalization actions. Receipts carry `sealrTreeV1` layout and content roots. Golden ZIP fixtures and lock semantics remain. |
| Immutable `SourceSnapshot` abstraction | Checked access landed for in-memory sources | Path inputs become owned whole-buffer bytes and byte inputs are borrowed immutably for the call. Interpretation and verification now use checked `u64` exact reads and range-limited readers; the private file-backed object remains open. |
| Typed interpretation, budget, target, consumer, and effect profiles | Preview compilation landed | `Policy::compile()` produces typed supported controls before ingest. The long-term external five-layer document is still unspecified. |
| Semantic lock | Scheduled after canonical encoding and roots | A lock is useful only when profile and tree identities are normative and stable. |
| Hostile and benign compatibility corpora | Scheduled for trust gate | Strictness must be measured within named supported domains on all release platforms. |
| Python wheel admission | Selected first consumer candidate | It has a concrete parser-differential problem and artifact semantics beyond generic ZIP. It follows the semantic core. |
| Read-only agent workspace projection and hermetic build inputs | Selected later consumers | They benefit from reusable admitted trees but depend on verification-frontier and snapshot semantics. |
| Independent evidence verifier and standard authenticated envelopes | Identity-conformance subset landed; authenticated evidence remains scheduled | Keep the verifier small and use standard signature and identity systems. |
| Content-addressed reuse and performance measured by avoided work | Scheduled after tree identity | Reuse needs stable content identity and verification completeness. |
| Job-oriented `gate`, `verify`, `lock`, `explain`, and policy tooling | Scheduled after semantic types stabilize | User-facing verbs and remediation should expose the separated outcome axes rather than freeze the current combined verdict. |
| TAR, OCI, JAR, APK, 7z, broad bindings, and generalized mount support | Deliberately deferred | Add each only for a concrete consumer whose semantics are specified. |
| GPU, QAT, Mojo, and alternate codec acceleration | Deliberately deferred | A measured workload and exact semantic equivalence are prerequisites. |
| Generic SBOM for every archive | Not adopted | A file manifest is the honest generic artifact; SBOMs require package or component semantics. |
| Large custom attestation predicate as the first evidence format | Not adopted | Start with narrow records and existing envelopes; introduce a custom predicate only if a validated gap remains. |
| Numeric risk scoring, permissive recovery, or best-effort interpretation | Rejected | These weaken deterministic, explainable, fail-closed admission. |
| Malware, prompt-injection, model-identity, or credential governance in the core | Out of scope | Sealr establishes archive structure, resource, namespace, content-integrity, and provenance properties. |

## Published Alpha.4 baseline

Alpha.4 has one Rust `apply()` path for inspect and materialize. It uses one bounded in-memory ZIP32 source: path inputs become owned bytes, while byte inputs are borrowed immutably for the call. It applies the selected strict ASCII ZIP interpretation, builds one `ArchiveIR`, verifies accepted Store and Deflate members, emits a view and unsigned receipt, and optionally realizes and audits the same planned members through a capability-relative staged materializer.

Alpha.4 adds `VerifiedArchive` and the explicitly selectable strict ASCII v2 interpretation. A completely verified admitted outcome retains the exact snapshot and IR behind an opaque capability. Canonical member reads enforce a caller limit before allocation and recheck size, CRC32, and SHA-256 when reading from the recorded payload. Callers may instead request a bounded exact-path set whose bytes are retained from the original checked verification stream. Neither path reopens the input or runs a second parser. Content-addressed reuse and reuse of the complete tree remain later work.

The current public outcome is:

```text
UntrustedArchive x Policy
  -> axes x (Allowed { wrote } | Rejected) x Receipt v2 x View v1
```

`Outcome`, `sealr.view.v1`, and `sealr.receipt.v2` carry interpretation, admission, verification, effect, and view-completeness. The compatibility `Allowed`/`Rejected` adapter remains, so an admitted archive with a failed destination is still `verdict: rejected`, while CLI exit `3` and the axes preserve the precise state. `view_digest` binds that invocation-specific view. Layout and content-tree roots are separate `sealrTreeV1` identities on the receipt.

## Target outcome model

The target API separates five axes:

```text
InterpretationStatus
  = Interpreted
  | Malformed
  | Unsupported
  | Indeterminate

AdmissionStatus
  = Admitted
  | Denied
  | NotEvaluated

VerificationStatus
  = StructureOnly
  | Partial { verified_members, pending_members }
  | Complete

EffectStatus
  = NotRequested
  | Committed
  | Failed

ViewCompleteness
  = Complete
  | Partial { phase, cause }
```

These axes prevent operational failures from changing semantic claims. For example, a destination publication error can be `Interpreted + Admitted + Complete + Failed`. The archive did not become unsafe because one filesystem operation failed. A source read error is `Indeterminate`, not a policy denial. A lazy read-only projection can be admitted while its verification state remains partial.

The axes are visible in Rust types, view JSON, and receipt JSON. CLI exit `2` means admission did not succeed, while exit `3` means admission succeeded but the requested effect failed. Future authenticated claims and a job-oriented CLI should consume the axes rather than freeze `Verdict`.

## Canonical `ArchiveIR`

The primary target artifact is a normative, versioned `ArchiveIR`:

```text
SourceSnapshot
    -> interpretation profile
ArchiveIR
    -> policy + target model + consumer profile
AdmittedArchive
    -> verify | materialize | project | cache | normalize
```

Every destination consumes the same immutable IR. It does not reconstruct a tree from archive bytes.

Each member should preserve at least:

```text
raw_name_bytes
decoded_name
canonical_logical_path
kind
source_header_ranges
compressed_payload_range
compression_method
general_purpose_flags
semantic_extra_fields
ignored_or_denied_extra_fields
declared_compressed_size
declared_uncompressed_size
actual_uncompressed_size
content_digest
verification_state
normalization_actions
```

Raw and canonical names are different evidence. Future Unicode profiles must bind the source encoding rule, Unicode version, normalization form, case-folding table, compatibility-character behavior, and target projection rules. The host operating system must not silently choose these semantics.

## Five identities

Sealr should keep these identities distinct:

1. **Source identity**: SHA-256 of the exact source bytes.
2. **Interpretation identity**: version and digest of the interpretation profile.
3. **Layout identity**: a normative root over canonical paths, kinds, structural metadata, and relevant source ranges.
4. **Content-tree identity**: a normative root over canonical paths, kinds, content hashes, and security-relevant metadata after required content verification completes.
5. **Invocation and effect identity**: policy, environment, destination controls, findings, lifecycle, and realization outcome.

`sealrTreeV1` now specifies canonical byte encoding, ordering, domain separation, empty-tree behavior, path representation, metadata coverage, and preview vectors. A separate verifier independently reproduces the committed profile, layout, and content vectors without depending on Sealr. The encoding remains unstable until the interpretation profile closes its extra-field rules and the semantic surface freezes. Existing schemes such as in-toto `dirHash1`, Git trees, and OCI `DiffID` are useful interoperability references, but do not commit to every semantic fact Sealr needs.

## Immutable source snapshots

The current bounded in-memory source provides invocation-scoped immutability: path inputs are owned after ingestion and borrowed bytes are immutable for the call through the safe Rust API. Replacing it with arbitrary `ReadAt` would lose that property.

The target API names and generalizes this property as an immutable snapshot:

```text
SourceSnapshot
  = CallerOwnedImmutableBytes
  | SealrOwnedCASObject
  | PrivateSpool
  | VerifiedImmutableFilesystemObject
```

The current owned and borrowed byte variants now implement this abstraction as `SourceSnapshot`. Parsing, payload reads, and digest recording use that one object. A later file-backed implementation can use a private spool or content-addressed object behind the same bounded access interface, but holding a file descriptor, ETag, length, or path alone is not enough if another writer can mutate the underlying bytes. Source truncation, growth, replacement, and same-file mutation need deterministic adversarial tests on Linux, macOS, and Windows.

Current main has separated access from backing: parser discovery, metadata reads, covering checks, and content verification use checked `u64` exact reads or range-limited readers. The central directory is buffered only after its size passes the metadata budget, while compressed payloads are streamed. This is an implementation seam, not the Alpha.5 memory claim. Both current variants still retain the complete archive in memory until the private spool backend and its mutation and memory evidence land.

## Profiles and compiled policy

The target configuration separates five layers.

### Interpretation profile

Defines what source bytes mean. It binds redundant metadata rules, encodings, allowed flags, extra fields, offsets, and structural layout. `sealr.profile.zip.strict-ascii.v1` remains the `apply()` compatibility default. [`sealr.profile.zip.strict-ascii.v2`](profiles/zip-strict-ascii-v2.md) is explicitly selectable through the Rust options API and closes every flag and extra-field disposition. A future Unicode profile receives a separate identifier and evidence.

### Deterministic resource budget

Defines entry, byte, depth, expansion, dictionary, and nested-content limits. Ratios should use checked integer or rational arithmetic. Wall-clock cancellation is an operational result such as `Indeterminate` or `Cancelled`, not a semantic admission decision.

### Target filesystem model

Defines projection semantics independently of the host. Future named models may include `portable.v1`, `posix.v1`, `windows-ntfs.v1`, and `macos-default.v1`.

### Consumer profile

Defines the invariants of the downstream artifact, such as a Python wheel, agent workspace, hermetic build source, or OCI layer. A wheel, JAR, APK, and Office document are not merely interchangeable ZIP files.

### Effect policy

Defines what may be done with an admitted tree, such as inspect, verify, materialize-new, project-read-only, or publish-to-CAS. Transactional no-replace publication and durability must be separate controls.

External policy data should compile into a typed validated object before source ingestion. Unknown fields, unsupported controls, impossible combinations, and unimplemented rules fail closed. Future overlays should be monotone by default so a narrower policy cannot silently loosen its parent.

## Verification completeness

Target operations establish different facts:

| Operation | Structural interpretation | Content verification | Filesystem effect |
|---|---:|---:|---:|
| `structure` | complete | none | none |
| `verify` | complete | complete | none |
| `materialize` | complete | complete while writing | transactional publication |
| `project` | complete | partial, advancing on read | read-only namespace |

Alpha.4 `inspect` currently verifies accepted members fully rather than performing a structure-only pass. The target operation names above are not current CLI verbs.

A partial view must say where and why it stopped. A partial member list must never look complete. A projected tree receives a complete content-tree identity only after all required members have been verified.

## Semantic lock

After the profile and tree-root specifications are stable, `sealr.lock` can bind source identity to interpreted meaning:

```json
{
  "schema": "sealr.lock.v1",
  "source": { "sha256": "..." },
  "interpretation": {
    "id": "sealr:interpretation/zip-strict/v1",
    "sha256": "..."
  },
  "consumer": { "id": "sealr:consumer/python-wheel/v1" },
  "policy": {
    "id": "org.example/package-ingress/v3",
    "sha256": "..."
  },
  "layout_root": { "sealrTreeV1": "..." },
  "content_root": { "sealrTreeV1": "..." }
}
```

This example is a target schema only. The lock must not ship before canonical encoding, profile stability, root test vectors, verification completeness, and compatibility rules are specified.

## The consumption rule

Evidence is not enough if a downstream consumer opens the original archive with another parser. The parser differential then returns. That is the [usefulness test](usefulness.md): a receipt without a dependent that consumes the admitted tree does not prove the category.

Consumers of a successful admission must receive one of:

- an immutable `AdmittedArchive` handle;
- a tree materialized from the IR;
- a read-only projected namespace backed by the IR;
- a content-addressed manifest and blob set;
- a normalized representation whose semantics are specified and cannot reintroduce ambiguity.

Package integrations, language bindings, projection, and caches must preserve this rule. They are consumers of semantic authority, not alternative interpreters.

## Evidence and authenticated claims

Use narrow terms:

- **EvidenceRecord** or **AdmissionRecord** for an unsigned deterministic record.
- **Attestation** only for an authenticated claim whose signature, signer identity, and freshness or timestamp have been verified.

The target evidence model should keep interpretation, verification, and filesystem effect claims separable. A generic archive member inventory is an evidence manifest, not automatically an SBOM. CycloneDX or SPDX is appropriate only when a consumer profile establishes package or component semantics.

A future small independent verifier should validate canonical evidence serialization, tree-root derivation, profile identity, interval coverage, rule outcomes, effect-record consistency, and authenticated envelopes without extracting the archive. It should not be described as a complete proof of codec execution.

## Consumer sequence

Research the first consumer while semantic identity stabilizes, then ship it only after its dependencies are executable. The [wheel profile draft](profiles/python-wheel-v1.md) is the current design probe.

For wheels, the proposed semantic pipeline is:

```text
verified ArchiveIR
    -> WheelArtifactIR
    -> scheme-relative WheelInstallPlan
    -> target-specific realization
```

These stages have distinct identities. `WheelArtifactIR` binds the exact outer artifact filename because its distribution, version, build, Python, ABI, and platform tags are consumer inputs that are not part of the ZIP tree. `WheelInstallPlan` binds relocation and transformation intent to labeled schemes without querying the host. A realized installed tree is target-specific because installation may rewrite scripts, generate wrappers, update installed `RECORD`, write installer metadata, or compile bytecode.

The archive content root therefore cannot be relabeled as a universal installed-tree root. A consumer profile must state which artifact and plan transformations it authorizes, which target model it uses, and which identity each claim names.

1. **Python wheel admission**: first candidate because wheel parser differentials have produced real same-bytes, different-installed-tree advisories. A future `python-wheel.v1` must bind the artifact filename and validate wheel metadata, `.dist-info`, `RECORD`, relocation, path uniqueness, and scheme-relative plan identity rather than merely applying strict ZIP checks.
2. **Agent workspace admission**: inspect first, expose a read-only admitted tree, verify content on read, and require explicit promotion. This does not claim to detect malware, malicious source, prompt injection, or unsafe build scripts.
3. **Hermetic build inputs**: make the canonical tree, not a second extraction, the build input and cache key.
4. **OCI layers and other rich formats**: later, because whiteouts, ownership, xattrs, links, devices, and ordered application require a dedicated consumer model.

No wheel consumer profile, projection, content-addressed store, semantic lock, or GitHub admission action exists in Alpha.4.

## Compatibility is part of assurance

Strict rejection is useful only when the supported domain is explicit and measured.

Maintain two corpora:

- a hostile conformance corpus with source digests, profile versions, expected outcomes, finding codes, source spans, and roots where applicable;
- a benign ecosystem corpus covering real producers and artifacts on Linux, macOS, and Windows.

Publish acceptance rate, top rejection codes, producer distribution, investigated false positives, and changes by release. The objective is to reject known ambiguous constructions while accepting nearly all artifacts inside each named profile's stated domain. Do not add a generic permissive or recovery mode to improve the number.

## Performance by avoided work

Measure four costs separately:

```text
T_structure  parse enough metadata to construct and evaluate layout
T_verify     expand and hash all required content
T_realize    create and transactionally publish the destination tree
T_reuse      provide an already verified tree without reparsing or reinflating
```

The strategic performance result is reuse of the exact admitted tree. Cores belong on independent member verification and on reuse copies after one covering exists, not on a second parse. Benchmark cold and warm cache, large and tiny-member workloads, local and network storage, antivirus-enabled Windows, peak memory, open handles, cancellation latency, worker count, and adversarial inputs. Hardware acceleration follows a demonstrated named workload and may not change interpretation or exact-consumption rules.

## Delivery gates

### Gate 1: semantic identity

- refined outcome axes;
- defined `SourceSnapshot` abstraction with current owned and caller-borrowed immutable byte implementations;
- canonical versioned `ArchiveIR`;
- exact codec input-consumption rules;
- normative layout and content roots;
- explicit verification completeness;
- typed policy compilation and versioned profiles;
- no placeholder digest or apparently enforced unsupported policy.

Bounded random-access I/O is not required to complete this semantic definition. It is a later memory-scaling step that must implement the snapshot contract without reopening mutation races.

Definition of done:

```text
same source bytes + same interpretation profile
    -> same ArchiveIR and layout root
on every supported operating system and architecture
```

### Gate 2: trust

- hostile and benign corpora;
- grammar, mutation, backend, and source-race testing;
- reduced-authority worker;
- small independent evidence verifier;
- reproducible release provenance;
- independent security review.

### Gate 3: canonical consumer

- `python-wheel.v1`;
- semantic lock;
- GitHub integration using authenticated standard envelopes;
- a public differential-wheel demonstration;
- one external consumer that treats Sealr's admitted representation as authoritative.

### Gate 4: reusable trees

- content-addressed verified blobs;
- read-only projection;
- explicit verification frontier;
- materialization from verified content;
- cache identity based on the content-tree root.

Format breadth, language bindings, generalized mounts, and acceleration follow these gates when a concrete consumer requires them.

## Deliberate deferrals

Do not make the next major cycle about broad formats, a desktop extraction GUI, GPU integration, many language bindings, recursive malware scanning, numeric risk scores, best-effort normalization, recovery parsing, or a hosted service for private archives.

The durable open-source surface is:

```text
normative interpretation profiles
+ canonical ArchiveIR
+ tree identity
+ hostile and benign corpora
+ consumer-specific policy packs
+ evidence verifier
+ canonical downstream integrations
```

## Primary references

- [ZipDiff, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [uv ZIP ambiguity advisory, 2025](https://github.com/advisories/GHSA-8qf3-x8v5-2pj8)
- [Python wheel parser differential advisory, 2026](https://github.com/google/security-research/security/advisories/GHSA-w97x-xxj5-gpjx)
- [in-toto digest set specification](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md)
- [in-toto Link predicate](https://github.com/in-toto/attestation/blob/main/spec/predicates/link.md)
- [GitHub artifact attestation action](https://github.com/actions/attest)
- [OCI image configuration and DiffID](https://github.com/opencontainers/image-spec/blob/main/config.md)
