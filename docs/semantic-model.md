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

The intended mathematics of that statement, including unique covering, partial interpretation, and effect independence, is sketched in [theory.md](theory.md). That sketch is a research program, not a claim that Alpha.6 has a uniqueness proof.

The short product statement is:

> One archive. One tree. Evidence.

Do not use "proven" in current product claims. Alpha.6 emits deterministic unsigned evidence and a preview `sealrTreeV1` encoding. It does not emit an authenticated archive-decision attestation or a formal uniqueness proof.

## Research disposition

The architecture review produced useful priorities, speculative extensions, and implementation findings. This table records the disposition so ideas do not become implied features or disappear into prose.

| Research idea | Disposition | Reason and status |
|---|---|---|
| Canonical archive-to-tree admission authority | Adopted as product direction | It best matches the existing single-interpretation parser, shared inspect/materialize plan, findings, and evidence boundary. |
| Exact compressed-input consumption and distinct codec findings | Adopted for immediate hardening | This is required by the current one-interpretation claim and has direct differential-parser precedent. |
| Unsigned evidence terminology | Adopted now | Current JSON is an EvidenceRecord or receipt, not an authenticated attestation. |
| Separate interpretation, admission, verification, effect, and completeness axes | Landed in receipt v2 and the view | The `Allowed` or `Rejected` compatibility verdict remains, but the axes and CLI exit classes expose the independent facts. |
| Versioned `ArchiveIR` and separate source, interpretation, layout, content, and effect identities | ArchiveIR landed; preview tree identities landed | `sealr.archive-ir.v1` is the inspect/materialize member plan and now records ranges, extra-field dispositions, and normalization actions. Receipts carry `sealrTreeV1` layout and content roots. Golden ZIP fixtures and lock semantics remain. |
| Immutable `SourceSnapshot` abstraction | Private path spool, checked access, source-change controls, and resource gates landed | Path inputs are copied and hashed once into a Sealr-owned private file, while byte inputs are borrowed immutably for the call. Interpretation and verification use the same checked `u64` exact reads and range-limited readers for both backends. Windows writer exclusion, Unix change fingerprints, required heap and peak-resident-memory comparisons, and a scheduled native 3 GiB sparse gate protect the path backend. |
| Typed interpretation, budget, target, consumer, and effect profiles | Preview compilation landed | `Policy::compile()` produces typed supported controls before ingest. The long-term external five-layer document is still unspecified. |
| Semantic lock | Scheduled after canonical encoding and roots | A lock is useful only when profile and tree identities are normative and stable. |
| Hostile and benign compatibility corpora | Scheduled for trust gate | Strictness must be measured within named supported domains on all release platforms. |
| Python wheel admission | Selected first consumer candidate | It has a concrete parser-differential problem and artifact semantics beyond generic ZIP. It follows the semantic core. |
| Read-only agent workspace projection and hermetic build inputs | Selected later consumers | They benefit from reusable admitted trees but depend on verification-frontier and snapshot semantics. |
| Independent evidence verifier and standard authenticated envelopes | Identity-conformance subset landed; authenticated evidence remains scheduled | Keep the verifier small and use standard signature and identity systems. |
| Content-addressed reuse and performance measured by avoided work | Scheduled after tree identity | Reuse needs stable content identity and verification completeness. |
| Job-oriented `gate`, `verify`, `lock`, `explain`, and policy tooling | Scheduled after semantic types stabilize | User-facing verbs and remediation should expose the separated outcome axes rather than freeze the current combined verdict. |
| Raw portable POSIX ustar | Initial container profile implemented in Alpha.9 | Regular files and directories only, with explicit selection, policy authorization, TAR-native evidence, and separate layout identity. |
| Strict ZIP64 | Explicit current-main in-process preview | Policy v3 authorizes a separate strict profile with ZIP64-native IR, covering, and `sealrTreeV3`; ZIP32 does not alias, and the worker refuses it until semantic-record v3. |
| Strict gzip-wrapped portable ustar | Explicit current-main in-process preview | Policy v4 authorizes one exact RFC 1952 member and portable ustar interpretation over separate immutable source and derived domains, with a full-source transform, three audits, and `sealrTreeV4`; the worker refuses it until a later semantic record. |
| Restricted raw POSIX PAX | Explicit Alpha.11 in-process preview | Policy v5 authorizes a closed two-key extension language with fixed precedence, exact provenance, an independent covering and state replay, and `sealrTreeV5`; the worker refuses it until a later semantic record. |
| Restricted raw GNU long-name | Explicit current-main in-process preview | Policy v6 authorizes exact old-GNU magic with one bounded `L` carrier per member, carrier provenance, an independent covering replay, and `sealrTreeV6`; the worker refuses it until a later semantic record. |
| Gzip-wrapped restricted PAX and GNU compositions | Explicit current-main in-process previews | Policy v7 authorizes each frozen raw dialect behind the exact single-member gzip transform with distinct `sealrTreeV7` and `sealrTreeV8` identities and the shared content root; the worker refuses both until a later semantic record. |
| Zstd-wrapped portable ustar | Explicit current-main in-process preview | Policy v8 authorizes the first promoted codec adapter: one RFC 8878 frame through the reviewed two-package ruzstd boundary with an 8 MiB window ceiling, cross-checked dual header interpretation, `sealrTreeV9`, and the shared content root; the worker refuses it until a later semantic record. |
| Rich TAR, OCI, JAR, NuGet, APK, 7z, RAR4, RAR5, cpio, ar/deb, RPM, CAB, broad bindings, and generalized mount support | Profile-specific roadmap | Add each structural or consumer layer only with specified semantics, dependency budget, and equivalent assurance evidence. |
| GPU, QAT, Mojo, and alternate codec acceleration | Deliberately deferred | A measured workload and exact semantic equivalence are prerequisites. |
| Generic SBOM for every archive | Not adopted | A file manifest is the honest generic artifact; SBOMs require package or component semantics. |
| Large custom attestation predicate as the first evidence format | Not adopted | Start with narrow records and existing envelopes; introduce a custom predicate only if a validated gap remains. |
| Numeric risk scoring, permissive recovery, or best-effort interpretation | Rejected | These weaken deterministic, explainable, fail-closed admission. |
| Malware, prompt-injection, model-identity, or credential governance in the core | Out of scope | Sealr establishes archive structure, resource, namespace, content-integrity, and provenance properties. |

## Current implemented baseline and repository-only Alpha.6 evidence

Alpha.4 has one Rust `apply()` path for inspect and materialize. It uses one bounded in-memory ZIP32 source: path inputs become owned bytes, while byte inputs are borrowed immutably for the call. It applies the selected strict ASCII ZIP interpretation, builds one `ArchiveIR`, verifies accepted Store and Deflate members, emits a view and unsigned receipt, and optionally realizes and audits the same planned members through a capability-relative staged materializer.

Alpha.4 adds `VerifiedArchive` and the explicitly selectable strict ASCII v2 interpretation. A completely verified admitted outcome retains the exact snapshot and IR behind an opaque capability. Canonical member reads enforce a caller limit before allocation and recheck size, CRC32, and SHA-256 when reading from the recorded payload. Callers may instead request a bounded exact-path set whose bytes are retained from the original checked verification stream. Neither path reopens the input or runs a second parser. Content-addressed reuse and reuse of the complete tree remain later work.

Alpha.5 adds the private file-backed source without changing the Alpha.4 interpretation profiles or tree encodings. Successful path ingest reports `private-file`, uses a capped fixed-buffer copy and digest pass into a native-private directory, reopens the spool read-only, removes its filename, and retains the unnamed positional-I/O handle. Caller byte inputs remain `memory-borrowed` in the receipt and become process-owned only inside a returned capability that must outlive the borrow. The two backends produce identical IR, findings, and roots for the same bytes.

The Alpha.5 [worker protocol v1](worker-protocol.md) preparation encodes the selected source, profile, policy, resource limits, and authority slots without serializing the archive. Its reduced result manifest is a bounded, correlated claim from a future worker. Request-bound validation checks the returned profile and representable manifest limits, but version 1 returns neither the source nor policy digest and carries neither a complete `ArchiveIR` nor the independent public outcome axes. It cannot construct `Outcome` or `VerifiedArchive`, preserve later bounded member reads, or support a claim that the supervisor independently verifies archive semantics.

Alpha.6 also has a production-compiled, crate-private owning planner and [private split-phase semantic records](semantic-record.md). After successful policy compilation, the planner acquires the exact snapshot, performs detection, parsing, admission, pending IR construction, and covering audit, then returns a terminal result or a non-cloneable Ready value with the snapshot and complete planning context. Ordinary `apply()` consumes Ready directly into its in-process continuation. The supported Linux `apply_supervised` path encodes the same ready plan for an authenticated restricted helper, then accepts completion only after clean reap and exact source-derived replay. Planning records bind the complete invocation and pending source-ordered IR; completion binds one verification vector to the exact request and plan. Source-owning inspect and materialize executors read only planned Store and Deflate payload ranges through the shared bounded verifier without structural reparse. The materialize executor writes only through a supervisor-created stage capability. Later non-retained reads bind a fresh operation, accepted plan, exact completion, source-order member index, canonical path, caller limit, and originating inspect or materialize effect. The supervisor gives each reader no stage or destination and releases no output until exact EOF, correlated success, integrity, clean exit, and reap agree. Planning and completion records carry no final receipt, verdict, publication, or cleanup claim; those remain supervisor-owned. A required pinned-kernel QEMU gate proves both public effects fail closed on actual Landlock ABI 2. Broader parity, global operation replay control, and CLI and packaged-consumer activation remain Alpha.6 gates. Protocol v2 is not required for this private boundary.

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

The axes are visible in Rust types, view JSON, and receipt JSON. CLI exit `0` requires admitted and complete verification without an effect failure. Exit `2` means admission or verification did not complete successfully, while exit `3` means admission succeeded but the requested effect failed. Future authenticated claims and a job-oriented CLI should consume the axes rather than freeze `Verdict`.

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

The current source provides invocation-scoped immutability through two concrete ownership modes. A path is opened once and copied into a Sealr-owned private file before interpretation; caller bytes are immutable for the call through the safe Rust API. Replacing either with arbitrary `ReadAt` would lose that property.

The target API names and generalizes this property as an immutable snapshot:

```text
SourceSnapshot
  = BorrowedImmutableBytes
  | ProcessOwnedImmutableBytes
  | SealrOwnedCASObject
  | PrivateSpool
  | VerifiedImmutableFilesystemObject
```

Owned and borrowed memory plus the first private spool implement this abstraction as `SourceSnapshot`. Parsing, payload reads, and digest recording use that one object. The spool does not treat the caller's file descriptor as immutable: it copies once while hashing and enforcing the cap, checks the exact copied length and a native source fingerprint, closes its writer, reopens only its own file read-only, and removes the spool filename. Windows denies write sharing for the source handle during the copy. Unix compares device, inode, mode, length, mtime, and ctime around the copy. Holding a caller file descriptor, ETag, length, or path alone would not be enough if another writer could mutate the underlying bytes. Truncation, cap growth, same-length mutation, writer exclusion, replacement after open, short reads, interruption, cleanup, and backend parity have deterministic tests. Broader native stress remains open.

Current main has separated access from backing: parser discovery, metadata reads, covering checks, and content verification use checked `u64` exact reads or range-limited readers. The central directory is buffered only after its size passes the metadata budget, while compressed payloads are streamed. A required physically sparse 1 MiB versus 128 MiB probe caps tracked heap allocation at 8 MiB with a 1 MiB delta and peak resident memory at 256 MiB with a 64 MiB delta. The latest Windows run measured 210,367 tracked heap bytes for both inputs and about 7.3 MiB peak resident memory for each. A locally executed 3 GiB case used 131,072 allocated source bytes and 210,427 tracked heap bytes; the same exact gate runs monthly across the native platform matrix. These are named regression measurements, not a universal resource proof.

## Profiles and compiled policy

The target configuration separates five layers.

### Interpretation profile

Defines what source bytes mean. It binds redundant metadata rules, encodings, allowed flags, extra fields, offsets, and structural layout. `sealr.profile.zip.strict-ascii.v1` remains the `apply()` compatibility default. [`sealr.profile.zip.strict-ascii.v2`](profiles/zip-strict-ascii-v2.md) closes every flag and extra-field disposition. [`sealr.profile.zip.portable-utf8.v1`](profiles/zip-portable-utf8-v1.md) is the supported Unicode preview. `sealr.profile.zip.wheel-utf8.v1` preserves the Alpha.7 research language. A legacy CP437 profile still requires its own identifier and evidence.

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

Alpha.6 `inspect` currently verifies accepted members fully rather than performing a structure-only pass. The target operation names above are not current CLI verbs.

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

Research established the first consumer while semantic identity stabilized. The [wheel profile](profiles/python-wheel-v1.md) now describes the supported Alpha.8 preview and its remaining stability gates.

For wheels, the supported library executes this semantic pipeline:

```text
verified ArchiveIR
    -> WheelArtifactIR
    -> scheme-relative WheelInstallPlan
    -> target-specific realization
```

These stages have distinct identities. `WheelArtifactIR` binds the exact outer artifact filename because its distribution, version, build, Python, ABI, and platform tags are consumer inputs that are not part of the ZIP tree. `WheelInstallPlan` binds relocation and transformation intent to labeled schemes without querying the host. A realized installed tree is target-specific because installation may rewrite scripts, generate wrappers, update installed `RECORD`, write installer metadata, or compile bytecode.

The archive content root therefore cannot be relabeled as a universal installed-tree root. A consumer profile must state which artifact and plan transformations it authorizes, which target model it uses, and which identity each claim names.

1. **Python wheel admission**: first consumer because wheel parser differentials have produced real same-bytes, different-installed-tree advisories. The supported-preview `sealr.consumer.python-wheel.v1` implementation binds the artifact filename and validates wheel metadata, `.dist-info`, `RECORD`, relocation, path uniqueness, and scheme-relative plan identity rather than merely applying strict ZIP checks.
2. **Agent workspace admission**: inspect first, expose a read-only admitted tree, verify content on read, and require explicit promotion. This does not claim to detect malware, malicious source, prompt injection, or unsafe build scripts.
3. **Hermetic build inputs**: make the canonical tree, not a second extraction, the build input and cache key.
4. **OCI layers and other rich formats**: later, because whiteouts, ownership, xattrs, links, devices, and ordered application require a dedicated consumer model.

No wheel installation effect, projection, content-addressed store, semantic lock, or GitHub admission action exists in Alpha.8. Pure wheel evaluation does.

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
- defined `SourceSnapshot` abstraction with owned-memory, caller-borrowed-memory, and Sealr-owned private-file implementations;
- canonical versioned `ArchiveIR`;
- exact codec input-consumption rules;
- normative layout and content roots;
- explicit verification completeness;
- typed policy compilation and versioned profiles;
- no placeholder digest or apparently enforced unsupported policy.

Bounded random-access I/O was not required to define semantic identity, but it now implements the same snapshot contract for memory and private-file backends. Remaining scale work must preserve that contract without reopening mutation races.

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
