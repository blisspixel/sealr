# Architecture

> This page separates the implemented alpha.3 architecture from the target semantic architecture. Projection, process isolation, acceleration, stable lock semantics, and an expanded crate graph are not current features. See [semantic-model.md](semantic-model.md) for the normative target.

## Implemented in alpha.3

Sealr is a two-crate Rust workspace:

```text
crates/sealr      security boundary, parser, policy, verification, evidence, materializer
crates/sealr-cli  thin command-line facade
```

The library exposes one `apply()` path for inspect and materialize. Both modes use the same interpreted member plan. There is no recovery parser and no second extraction implementation.

The current input and interpretation boundary is:

1. Ingest a `SourceSnapshot`. Path inputs become owned bytes; borrowed byte inputs remain borrowed for the call. The digest is SHA-256 of that object.
2. Locate and validate ZIP32 EOCD and the central directory.
3. Compare redundant central and local metadata, validate source ranges, reject overlaps and hidden structural records, and apply the strict path grammar.
4. If a destination was requested, create and retain its private stage after structural planning and before member processing.
5. Stream accepted Store and Deflate content through resource bounds, exact DEFLATE input-consumption checks, actual size checks, CRC32, and SHA-256. Write the same verified bytes into the private stage when one exists.
6. Audit the stage against the admitted IR with streaming size and SHA-256 verification plus an exact path-set comparison.
7. Publish the complete stage without replacement only after every member and the audit pass. Abort and report cleanup on any member, audit, or publication failure.
8. Emit the versioned view and deterministic unsigned receipt for the actual final outcome.

Current support is seekable ZIP32 with Store and Deflate members plus validated data descriptors. Encryption, ZIP64, spanned archives, recovery parsing, recursive nested extraction, links, devices, and unsupported structures fail closed. The [README](../README.md) is authoritative for the complete support and limitation list.

Safe Rust is the default. The current `unsafe` blocks are isolated in the macOS descriptor-ACL module and the Windows native storage, security-descriptor, stage, and publication module. Those modules are the explicit platform FFI audit boundary.

## Implemented materialization boundary

The materializer applies one admission and publication sequence:

1. Require the destination parent to exist, canonicalize it once, and retain an opened directory capability. Do not create missing parents.
2. Refuse an existing destination. On Linux and macOS, require parent ownership by the effective user or root and reject group or other write unless the trusted owner has set sticky. On macOS, reject an extended ACL or descriptor ACL query failure.
3. Create a random 128-bit same-volume stage. Linux and macOS use mode `0700`, then verify effective-user ownership, mode, and the macOS descriptor ACL. Windows requires non-remote, writable NTFS with persistent ACLs, then uses parent-rooted `NtCreateFile` with exclusive creation, reparse-point-open semantics, and a protected effective-TokenUser-only inheritable DACL. It retains the handle without delete sharing and verifies the owner and exact DACL through that handle before member writes. Descendants inherit the sole TokenUser DACL but receive the creating token's default owner.
4. Create each validated member with component-by-component no-follow directory capabilities and exclusive file creation. Windows also checks opened handles for the reparse-point attribute.
5. Publish without replacement. Linux uses `renameat2(RENAME_NOREPLACE)`, macOS uses `renameatx_np(RENAME_EXCL)`, and Windows calls `NtSetInformationFile` on the retained stage handle with the retained parent as `RootDirectory` and replacement disabled.
6. On ordinary rejection, attempt cleanup and retry once after failure before constructing the receipt. Setup failure after stage creation uses the retained handle first and a parent-relative retry. Record setup, staging, publication, abort, and final cleanup outcomes. Two failed attempts leave the stage for explicit recovery and report `cleanup: failed`.

Linux, macOS, and Windows on the documented filesystem matrix are the supported materialization platforms. Other targets and unsupported Windows filesystems fail closed. Root, administrators, principals matching the effective token's default-owner SID, same-principal processes, filesystem-override capabilities, and debugging or handle-duplication rights remain outside this in-process boundary.

The receipt's `materialization` object records the selected backend, stage protection, creation primitive, member resolution, durability mode, publication primitive, lifecycle outcome, and cleanup result. Windows also records non-sensitive storage-policy observations and stage-ACL verification. These fields expose which control path ran. They do not authenticate the unsigned receipt.

## Current trust boundaries

The format parser, path grammar, quota counters, content verification, and policy decision share one in-process trust boundary. The materializer receives validated relative components rather than archive-controlled ambient paths.

Alpha.3's bounded in-memory source is a named `SourceSnapshot`: path inputs become owned bytes, caller byte inputs remain borrowed, and the recorded digest is SHA-256 of the complete object. ZIP payload reads use checked ranges over the snapshot. Receipt v2 reports `source_snapshot` as `memory-owned`, `memory-borrowed`, or `unavailable`. It does not yet:

- freeze preview `sealrTreeV1` roots as a stable lock or authenticated subject; committed cross-platform golden fixtures now pin the preview encoding;
- replace whole-archive buffering with a private spool or verified filesystem snapshot;
- run parsing in a reduced-authority worker;
- expose a read-only projection or content-addressed store;
- sign or independently verify evidence.

## Target semantic pipeline

The next architecture is centered on one canonical intermediate representation:

```text
untrusted source
    -> immutable SourceSnapshot
    -> versioned interpretation profile
    -> canonical ArchiveIR
    -> admission policy + target model + consumer profile
    -> AdmittedArchive
       -> verify
       -> materialize
       -> project read-only
       -> publish to content-addressed storage
       -> emit evidence
```

The critical rule is that every operation after interpretation consumes the IR and its immutable source snapshot. No facade, language binding, materializer, projection, or consumer profile may reparse the source archive.

### Source ownership

Bounded random access must preserve the security property currently provided by the in-memory source. The target `SourceSnapshot` first names the existing owned and caller-borrowed byte cases, then supports immutable alternatives for the complete interpretation and verification lifetime. A caller path can later be copied, cloned, or reflinked into a private spool or content-addressed object while hashing. Remote metadata such as an ETag or content length does not replace possession of the exact bytes. The bounded random-access implementation is a later memory-scaling milestone, not a prerequisite for defining the semantic abstraction.

### Canonical intermediate representation

The versioned `ArchiveIR` preserves raw name bytes, decoded and canonical names, source ranges, flags, extra-field dispositions, declared and actual sizes, content commitments, and verification state. It is the source of preview layout and content-tree identities. The encoding and committed cross-platform test vectors now exist, but the roots remain explicitly unstable until the profile's extra-field rules close and an independent verifier reproduces them.

### Separated policy layers

Interpretation profile, deterministic resource budget, target filesystem model, consumer profile, and effect policy are separate compiled inputs. Unknown or unsupported controls fail before source ingestion. Publication atomicity and durability are different effect properties.

### Reduced-authority worker

After semantic types stabilize, a trusted supervisor can own the archive snapshot, destination parent, private stage, lifecycle, staged-tree audit, and publication authority. A worker receives only bounded archive and stage capabilities through a versioned protocol. On Linux, runtime-probed Landlock and `no_new_privs` can restrict that worker before it reads the first archive byte. Equivalent credible packaging boundaries for macOS and Windows require separate work.

The supervisor treats worker output as untrusted and audits the staged tree against the admitted IR before publication. Process isolation strengthens containment, but does not define archive semantics and must not own a second parser.

## Realization and reuse

Materialization, read-only projection, and content-addressed reuse are representations of one admitted tree.

The first projection, when implemented, must be read-only with no links, write overlay, hidden network access, or implicit promotion. Its verification state begins partial and advances as members are read. Projection is not a process sandbox.

A future content-addressed store can amortize verification and filesystem writes across repeated consumers. Reuse is valid only when source identity, interpretation profile, tree identity, policy requirements, and verification completeness match.

## Performance architecture

Measure the boundary as four costs:

```text
T_structure  construct and evaluate the logical layout
T_verify     expand and hash required content
T_realize    build and publish a destination tree
T_reuse      provide an already verified admitted tree
```

Avoided parsing, inflation, and writes are the strategic optimization. Cores are not wasted by keeping interpretation on one thread. The covering is a chain: EOCD selection, central-directory walk, local-record abutment, and path injectivity are data-dependent. Running two of those walks is a second parser. Independent work starts after one IR exists. `audit_covering` rechecks the claimed ranges and signatures without searching or inflating. Materialization audits the staged tree against that IR before the no-replace rename.

```text
T_structure   sequential unique covering and jail   (one core is correct)
T_verify      independent members over an immutable snapshot
T_realize     directories in topological order, then independent file writes
T_reuse       no inflate; cores only if many blobs are copied
```

`T_verify` is the first honest multi-core cut: each admitted file member is a codec morphism over a disjoint payload range. Directory members are O(1). Quota combining is checked addition of per-member actuals after the declared total has already been admitted. Findings and partial-stop identity stay in central-directory order so receipts remain deterministic. Realization may write independent files in parallel only after parent components exist; publication stays a single no-replace rename.

Do not add Rayon, Tokio, or a GPU runtime to the library to get that cut. `std::thread` and an explicit worker bound are enough. `SEALR_JOBS` may cap parallelism for tools; it is not a policy field and must not change trees, findings, or roots. Intra-codec SIMD already present in `zlib-rs` is fine. Hardware offload remains a named, optional backend after a measured bottleneck.

Parallel member verification, clone or link materialization, alternate codec backends, remote range ingestion, and hardware acceleration follow only after the semantic workload is stable. An optional backend must preserve exact input consumption, output bytes, findings, tree identities, and verification state.

## Format and consumer expansion

Add a format only with a concrete consumer and a profile whose semantics are specified. ZIP remains the semantic core until `ArchiveIR`, tree identity, snapshots, and evidence are stable. Python wheel admission is the first candidate consumer. TAR for hermetic build inputs and OCI layers requires its own link, ownership, sparse-file, extension-header, and application semantics. A generic format checkbox is not sufficient.

## Platform contract

Every semantic change must remain deterministic on supported Linux, macOS, and Windows targets. The host may select an effect backend, but may not silently select name decoding, normalization, path comparison, or archive interpretation. Platform-specific output constraints belong in an explicit target filesystem model.

Dependency versions are pinned in `Cargo.lock`. This page records trust and semantic boundaries rather than serving as a second dependency manifest.
