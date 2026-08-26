# Architecture

> This page separates the architecture implemented on current main from the target semantic architecture. Projection, process isolation, acceleration, stable lock semantics, and an expanded shipping crate graph are not current features. See [semantic-model.md](semantic-model.md) for the normative target.

## Implemented on current main

Sealr is a six-package Rust workspace. The library and CLI are the release-facing components; four packages remain repository-only protocol, conformance, bootstrap, or compatibility tools:

```text
crates/sealr             unpublished preview library boundary, parser, policy, verification, evidence, materializer
crates/sealr-cli         native command-line facade
crates/sealr-protocol    non-published bounded worker protocol experiment
tools/identity-verifier  independent conformance verifier with no sealr dependency
tools/worker-bootstrap   repository-only Linux authority and lifecycle conformance lab
tools/wheel-lab          non-shipping compatibility measurement and report verifier
```

The library exposes one `apply()` path for inspect and materialize. Both modes use the same interpreted member plan. There is no recovery parser and no second extraction implementation.

The current input and interpretation boundary is:

1. Ingest a `SourceSnapshot`. A path is opened once and copied under the archive cap into a Sealr-owned private file while SHA-256 is computed; borrowed byte inputs remain borrowed for the call. The exact length and digest belong to the resulting snapshot object.
2. Locate and validate ZIP32 EOCD through bounded tail access, then copy the central directory only after its declared size passes the metadata cap.
3. Read fixed headers and bounded metadata through checked `u64` ranges, compare redundant central and local metadata, validate source ranges, reject overlaps and hidden structural records, and apply the strict path grammar.
4. If a destination was requested, create and retain its private stage after structural planning and before member processing.
5. Stream each exact compressed payload range through a range-limited snapshot reader and fixed 64 KiB buffers, enforcing resource bounds, exact DEFLATE input consumption, actual size, CRC32, and SHA-256. Write the same verified bytes into the private stage when one exists and, when explicitly requested, into an independently bounded exact-member retention buffer.
6. Audit the stage against the admitted IR with streaming size and SHA-256 verification plus an exact path-set comparison.
7. Publish the complete stage without replacement only after every member and the audit pass. Abort and report cleanup on any member, audit, or publication failure.
8. After complete verification, retain the exact snapshot and IR behind an opaque `VerifiedArchive`. Selected exact-path content captured in step 5 can be borrowed directly. Other bounded reads use recorded ranges and recheck measured content without reopening or reparsing.
9. Emit the versioned view and deterministic unsigned receipt for the actual final outcome.

Current support is seekable ZIP32 with Store and Deflate members plus validated data descriptors. Encryption, ZIP64, spanned archives, recovery parsing, recursive nested extraction, links, devices, and unsupported structures fail closed. The [README](../README.md) is authoritative for the complete support and limitation list.

Safe Rust is the default. The shipped crate's current `unsafe` blocks are isolated in the macOS descriptor-ACL module and the Windows native storage, security-descriptor, stage, and publication module. Those modules are the explicit platform FFI audit boundary. Test-only bounded-allocation probes wrap the system allocator with documented `unsafe`. Their source is included in the source package, but they are not compiled or linked into normal library and CLI runtime artifacts.

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

The bounded source is a named `SourceSnapshot`: path inputs become Sealr-owned private files, caller byte inputs remain borrowed, and the recorded digest is SHA-256 of the complete object. Current main routes parsing, codec-free covering checks, initial payload verification, and later verified-member reads through checked exact reads or range-limited readers. Private-file and borrowed-memory variants have semantic-parity coverage. Receipt v2 reports `source_snapshot` as `private-file`, `memory-owned`, `memory-borrowed`, or `unavailable`. `memory-owned` remains a stable compatibility variant for process-owned memory; current public path and byte calls report `private-file` and `memory-borrowed`, respectively. It does not yet:

- freeze preview `sealrTreeV1` roots as a stable lock or authenticated subject; committed cross-platform golden fixtures now pin the preview encoding;
- add alternate snapshot backends, broader native race stress, or open-handle peak evidence;
- run parsing in a reduced-authority worker;
- expose a read-only projection or content-addressed store;
- sign or independently verify evidence.

Current main also implements the non-published [worker protocol v1](worker-protocol.md) codec. Its start frame binds one operation to a source digest, selected profile, policy, resource limits, and out-of-band capability slots. Its reduced result is correlated and canonical, and the request-bound validator enforces the returned profile, member count, file sizes, aggregate size, and path depth against the accepted start request. The result does not echo the source or policy digest and cannot reconstruct `ArchiveIR` or `VerifiedArchive`, so it is not complete invocation or public-capability binding. No process boundary calls it yet, and it does not alter the current in-process trust boundary.

Current main also contains a separate repository-only Linux authority-bootstrap lab. It proves a private same-binary process boundary with `SOCK_SEQPACKET`, `SCM_RIGHTS`, inherited-descriptor closure, fixed Landlock ABI 3 enforcement before source transfer, procfs descriptor observation, and pidfd-backed reap. It has no archive-parser dependency, does not use operation protocol v1, is absent from release archives, and does not alter the in-process product trust boundary.

Current main now routes ordinary `apply()` and the in-crate conformance harness through one production-compiled, crate-private owning planner. After successful policy compilation it acquires the immutable snapshot, interprets and admits the archive, constructs pending IR, completes the covering audit, and returns either terminal planning evidence or a non-cloneable Ready value. Public continuation consumes the original snapshot and IR directly, without reopening, cloning, record serialization, reconstruction, or structural reparse.

Current main also compiles and tests a dormant crate-private [semantic-record experiment](semantic-record.md). Its independent bounded format carries an exact invocation-bound pending IR in planning order and a plan-digest-bound full verification vector in completion order. The in-crate adapter consumes a separate invocation of the shared planner, while its hostile decoder independently reconstructs ready IR only after structural, range, path, parser-equivalent quota, profile, finding, phase, and correlation checks, plus covering, LFH and CDH variable-length geometry, name, and extra-header reproduction against the exact supervisor-owned snapshot. A source-owning inspect executor can consume an accepted Ready record through the same bounded payload verifier as the public path without invoking the structural parser. No production call path invokes the record codec or executor, and neither constructs public outcomes or verified capabilities.

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

Bounded random access preserves the property first supplied by the in-memory source. The current path implementation opens the source once, copies and hashes through a fixed 64 KiB buffer, checks the copied length plus a native before-and-after source fingerprint, closes its writer, reopens only the Sealr-owned file read-only, and removes its filename before returning. Windows denies write sharing for the source handle during the copy. Unix compares device, inode, mode, length, mtime, and ctime; an observed change fails closed. Later reads use positional I/O against the unnamed handle and never reopen the caller path. The private directory uses the same native mode, ownership, ACL, parent-filesystem, and reparse-point checks as extraction staging. It remains empty until the snapshot is dropped, then cleanup runs after the read handle closes. Abrupt termination during construction can leave a protected partial spool; termination after successful ingest or later cleanup failure can leave the empty random directory. Privileged actors and same-principal access to private construction artifacts remain outside the in-process privacy claim.

Reflink or content-addressed variants require an equally strong mutation contract. Remote metadata such as an ETag or content length does not replace possession of the exact bytes. The file-backed implementation is now available for worker IPC so the protocol need not embed a whole archive buffer. Required heap and peak-resident-memory checks plus a monthly native 3 GiB sparse gate now protect the file-backed path. Alternate backends, open-handle peak evidence, and broader hostile native stress remain later assurance work.

### Canonical intermediate representation

The versioned `ArchiveIR` preserves raw name bytes, decoded and canonical names, source ranges, flags, extra-field dispositions, declared and actual sizes, content commitments, and verification state. It is the source of preview layout and content-tree identities. The encoding, committed cross-platform vectors, and [independent identity verifier](identity-conformance.md) now exist. Strict ASCII v2 closes the flag and extra-field interpretation gap; the roots remain preview identities until the broader semantic surface and release stability bar freeze.

### Separated policy layers

Interpretation profile, deterministic resource budget, target filesystem model, consumer profile, and effect policy are separate compiled inputs. Unknown or unsupported controls fail before source ingestion. Publication atomicity and durability are different effect properties.

### Reduced-authority worker

Alpha.6 first proves a nonsemantic Linux authority bootstrap: a trusted supervisor creates the private stage and immutable snapshot, passes a same-binary child only bounded source and optional stage capabilities, installs restrictions, observes readiness, then exits and reaps the child without archive interpretation. This tests descriptor transfer, closure, `no_new_privs`, and runtime-probed Landlock before an incomplete result format shapes the public API. The first [semantic-record](semantic-record.md) slice now makes the split-phase representation, hostile decoder, and plan-native inspect execution executable in-process while separating retained-content transfer, isolated non-retained reads, effect ownership, sealed transport, process isolation, runtime activation, and helper packaging. Equivalent credible packaging boundaries for macOS and Windows require separate work.

The supervisor treats worker output as untrusted. Before validation or audit, it must terminate and reap the worker boundary and prove that no descendant retains writable stage authority. It then audits the quiescent staged tree against the selected complete semantic evidence before publication. Equality with a worker record is not independent agreement with archive semantics. A complete, canonical, internally coherent IR is not automatically a certificate that proves the source has one meaning, so the isolated worker remains in the semantic trusted computing base for every claim the supervisor does not independently recompute. Process isolation strengthens containment and must not introduce a second archive parser.

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

Avoided parsing, inflation, and writes are the strategic optimization. Cores are not wasted by keeping interpretation on one thread. The covering is a chain: EOCD selection, central-directory walk, local-record abutment, and path injectivity are data-dependent. Running two of those walks is a second parser. Independent work starts after one IR exists. ZIP discovery and `audit_covering` share one pure checked interval and exact-partition kernel, while the audit rechecks the claimed ranges and signatures without searching or inflating. Materialization audits the staged tree against that IR before the no-replace rename.

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
