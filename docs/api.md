# API contract

This page distinguishes the implemented Alpha.6 contract from the target semantic API. Current callers must pin to the implemented section. The target is specified further in [semantic-model.md](semantic-model.md).

## Implemented surface

```
UntrustedArchive x Policy
  -> (Allowed { wrote } | Rejected) x Receipt x View
```

Policy: [policy.md](policy.md). Findings: [findings.md](findings.md). Evidence: [attestations.md](attestations.md). Usage: [usage.md](usage.md).

---

### Rust

```rust
/// One function. Do not add inspect/extract that return different trees.
pub fn apply(req: Request<'_>) -> Outcome { ... }

pub struct Request<'a> {
    pub source: Source<'a>,          // file path or borrowed bytes
    pub policy: &'a Policy,          // sealr.policy.v1
    pub dest: Option<&'a Path>,      // Some => request Materialization
}

pub struct Outcome {
    pub interpretation: InterpretationStatus,
    pub admission: AdmissionStatus,
    pub verification: VerificationStatus,
    pub effect: EffectStatus,
    pub view_completeness: ViewCompleteness,
    pub verdict: Verdict,            // alpha.2 compatibility adapter
    pub receipt: Receipt,            // always; schema sealr.receipt.v2
    pub view: View,                  // always; schema sealr.view.v1
}

impl Outcome {
    /// Read-only interpretation evidence when structure planning completed.
    pub fn archive_ir(&self) -> Option<&ArchiveIR>;
}

pub enum Verdict {
    /// Policy passed. `wrote` is true only after a requested destination commits.
    Allowed { wrote: bool },
    /// Compatibility reject: admission denied, not evaluated, or effect failed.
    Rejected,
}
```

Invariants:

- `apply` with `dest: None` never creates member files. Inspect-only success is `Allowed { wrote: false }`.
- `wrote == true` only if `dest.is_some()` and the complete staged member tree committed at the requested destination.
- Every outcome contains both a view and a receipt, including source, parse, policy, quota, and materialization failures.
- `verdict` is derived: `Admitted + Committed` → `Allowed { wrote: true }`; `Admitted + NotRequested` → `Allowed { wrote: false }`; every other combination, including `Admitted + Failed`, → `Rejected`. The receipt axes are the precise record.

- `receipt.view_digest` is currently SHA-256 of deterministic `serde_json` bytes for the versioned Rust struct. RFC 8785 JCS is a Phase 0.1 gate.
- `receipt.policy.digest` uses the same current deterministic struct serialization. It is not yet a cross-encoder canonical JSON promise.
- After the complete source bytes are available, `receipt.source` is `{ "sha256": "..." }`. A source open, metadata, copy, stability-check, or cap failure before exact EOF uses `{ "status": "unavailable" }` and omits `sha256`. An over-cap `Source::Bytes` input is complete caller-owned data, so it is hashed. The inspectable view keeps the same digest object so `receipt.source` equals `view.source.digest`.
- `receipt.source_snapshot` is `private-file` for successful path ingest and `memory-borrowed` for caller byte slices, including an over-cap slice rejected before parsing. It is `unavailable` when no complete snapshot was retained. `memory-owned` remains a stable variant for process-owned in-memory snapshots. Parse and payload reads use the recorded snapshot; they do not reopen the caller path.
- The same source bytes, source metadata, and policy produce the same interpreted member tree and findings. Materialization may add an I/O finding, but it must not reinterpret archive bytes. **This is the LibreOffice bug we refuse:** inspect and materialize cannot disagree about the archive tree.

`ArchiveIR` is constructed only by Sealr. Its fields cannot be mutated outside the crate, and evolving IR records and enums are non-exhaustive. `Outcome::archive_ir()` provides a read-only serializable evidence view after planning. It does not retain verified member bytes and is not the planned `AdmittedArchive` capability. A consumer cannot use it as permission to reopen the source through another ZIP parser.

Evolving output enums and records are non-exhaustive so the preview API can add evidence without forcing downstream exhaustive matches or permitting caller-constructed receipts. Every public field type in `View` and `Receipt`, including `SourceMeta`, `PolicyMeta`, `ToolMeta`, `EnvMeta`, and `SnapshotKind`, is exported from the crate root and exercised by an external-crate compile fixture. `Request` remains directly constructible for the current compatibility facade.

`ZipInterpretationProfile::WheelUtf8V1` is a selectable prerelease research profile, not the default and not a supported wheel consumer API. It admits only its separately identified strict UTF-8 NFC container language. `IrMember::container_facts()` returns immutable `MemberContainerFacts` for ZIP creator-system and external-attribute evidence. Those facts are deliberately excluded from `sealrTreeV1` identities, which bind paths, kinds, methods, sizes, and verified content rather than installer-specific mode interpretation. The downstream compile fixture names both the profile and facts so accidental visibility drift fails CI.

No second function that “recovers” a broken zip.

---

### InspectableView JSON

One document. The current CLI emits pretty JSON; JSONL is planned. The current digest covers deterministic Rust-struct JSON bytes. JCS canonicalization is a Phase 0.1 gate.

```json
{
  "schema": "sealr.view.v1",
  "source": { "path": "foo.zip", "digest": { "sha256": "..." }, "magic": "zip" },
  "policy": { "id": "sealr:policy/default/v1", "digest": { "sha256": "..." } },
  "interpretation": { "status": "interpreted" },
  "admission": { "status": "admitted" },
  "verification": { "status": "complete" },
  "effect": { "status": "not-requested" },
  "view_completeness": { "status": "complete" },
  "verdict": "allowed",
  "wrote": false,
  "findings": [],
  "members": [
    {
      "path": "bundle/hello.txt",
      "kind": "file",
      "comp_bytes": 17,
      "uncomp_bytes": 17,
      "method": "store",
      "crc32": "21e8836b",
      "sha256": "a02804962d3beb2db9929fa6b128329795c7c076d96bb51f63d6afe626bd691e"
    }
  ]
}
```

`verdict`: `allowed` or `rejected` compatibility adapter. `wrote` is Boolean. The axes are the precise record: an admitted archive whose destination fails is `admission: admitted`, `effect: failed`, and still `verdict: rejected`. A rejection before member processing has an empty member list. A later payload or materialization rejection retains every member completed before the failure. The finding that caused rejection is always present. Callers must use `view_completeness` plus the axes rather than assuming a rejected view is a complete member inventory.

Projection and hydration on read are target surfaces. They are not part of Alpha.6.

---

### Receipt

The current receipt is versioned unsigned JSON (`signed: false`). DSSE and in-toto wrapping are future work.

```json
{
  "schema": "sealr.receipt.v2",
  "verdict": "allowed",
  "wrote": false,
  "interpretation": { "status": "interpreted" },
  "admission": { "status": "admitted" },
  "verification": { "status": "complete" },
  "effect": { "status": "not-requested" },
  "view_completeness": { "status": "complete" },
  "source": { "sha256": "..." },
  "source_snapshot": "private-file",
  "policy": { "id": "sealr:policy/default/v1", "digest": { "sha256": "..." } },
  "identities": {
    "source": { "sha256": "..." },
    "interpretation": {
      "id": "sealr.profile.zip.strict-ascii.v1",
      "digest": { "sha256": "..." }
    },
    "layout": { "sealrTreeV1": "..." },
    "content": { "sealrTreeV1": "..." }
  },
  "view_digest": { "sha256": "..." },
  "tool": { "name": "sealr", "version": "0.1.0-alpha.7" },
  "environment": { "os": "windows", "arch": "x86_64", "kernel_jail": "unavailable" },
  "materialization": {
    "schema": "sealr.materialization.v2",
    "requested": false,
    "backend": "none",
    "stage_mode": "none",
    "stage_creation_primitive": "none",
    "member_resolution": "none",
    "durability": "none",
    "publication_primitive": "none",
    "outcome": "not-requested",
    "cleanup": "not-applicable"
  },
  "signed": false,
  "findings": []
}
```

When materialization is requested, the materialization object reports the component-bound backend, stage protection, exact stage-creation primitive, durability mode, exact platform publication primitive, lifecycle outcome, and cleanup result. Windows reports `ntcreatefile-parent-handle-create-directory-explicit-dacl-nofollow` for creation and `ntsetinformationfile-retained-source-parent-noreplace` for publication. Its optional `windows` object records the `windows-local-ntfs-v1` storage policy, observed filesystem and device scope, persistent-ACL and read-only flags, the `windows-protected-token-user-v1` ACL policy, and whether both the stage object owner and exact protected DACL were verified. No SID, volume serial, label, or path is serialized.

On reject, `members` in the view may be partial; `view_digest` still covers exactly that invocation-specific view. It is not a canonical tree identity.

`receipt.identities` is separate from `view_digest`:

- `source` is the archive SHA-256, or `{ "status": "unavailable" }`.
- `interpretation` binds the selected profile identifier and the SHA-256 of its canonical method, flag, extra-field, and name rules. `apply()` selects `sealr.profile.zip.strict-ascii.v1`; `ApplyOptions::with_interpretation_profile(StrictAsciiV2)` selects the [closed v2 contract](profiles/zip-strict-ascii-v2.md); `WheelUtf8V1` selects the separately named repository-only wheel research language. Profile selection affects admission and interpretation identity but not the resource-policy digest.
- `layout` is `sealrTreeV1` over canonical paths, kinds, raw names, flags, methods, declared sizes, complete local-header, payload, optional-descriptor, and central-header ranges, extra-field dispositions, and normalization actions. It is present once an `ArchiveIR` exists. It is `{ "status": "unavailable" }` when planning never produced a tree.
- `content` is `sealrTreeV1` over canonical paths, kinds, actual sizes, and member SHA-256 digests. It is present only when verification is complete. An admitted archive whose destination fails keeps its layout root and does not claim a content root until members are verified.
- Layout and content encodings are Git-style domain-separated preimages (`sealr.tree.layout.v1` and `sealr.tree.content.v1`) over little-endian length-prefixed covering ranges and member records. They do not use JSON, so they are independent of `view_digest` and of later RFC 8785 work. The interpretation profile is a sibling identity, not mixed into the tree bytes. The production golden test and a standalone no-Sealr-dependency verifier consume the same [identity-conformance bundle](identity-conformance.md), independently reproducing both published profile digests plus three layout and three content roots. Layout identity includes the source covering (local prefix, central directory, EOCD, comment). Content identity does not. The standalone checker and internal codec-free audit follow claimed ranges without searching or inflating; materialization audits the staged tree against the same IR before publication.

## Target semantic API

The long-term API separates interpretation, admission, verification, filesystem effects, and view completeness:

```rust
pub struct SemanticOutcome {
    pub interpretation: InterpretationStatus,
    pub admission: AdmissionStatus,
    pub verification: VerificationStatus,
    pub effect: EffectStatus,
    pub view_completeness: ViewCompleteness,
    pub evidence: EvidenceRecord,
}
```

This target decomposition supports results that the current `Verdict` cannot express precisely:

- source I/O failure is `Indeterminate`, not a policy denial;
- a safe archive with a failed destination commit remains admitted and records an effect failure;
- a structure-only result does not claim content verification;
- a future read-only projection reports a partial verification frontier;
- a partial rejected view names the phase and cause at which construction stopped.

These axes now exist as Rust types on `Outcome` and as JSON fields on `sealr.receipt.v2`. The inspectable `View` and CLI exit codes still use the compatibility `Verdict`. `SourceSnapshot` exists internally and `ArchiveIR` is available as a read-only evidence view on the library outcome. A completely verified admitted outcome also exposes `VerifiedArchive`; the broader type-state methods remain design notation.

### Verified member capability

`Outcome::verified_archive()` returns `Some(&VerifiedArchive)` only when admission succeeded and every member was verified. Structure-only and partially verified outcomes never receive the capability. `Outcome::into_verified_archive()` lets a consumer discard the larger outcome after it has persisted whatever evidence it needs.

The capability is opaque and cheap to clone. Clones share one immutable snapshot and IR. Its public operations are intentionally narrow:

- `archive_ir()`, `members()`, and `member(path)` inspect Sealr-produced evidence;
- `source_digest()` binds the capability to the exact ingested bytes;
- `retention_status(path)` reports the result of an exact-path retention request;
- `retained_member(path)` borrows bytes captured during the original verification pass without reopening, parsing, inflating, allocating, or hashing;
- `retained_bytes()` reports the logical aggregate successfully retained content;
- `read_member(canonical_path, max_bytes)` reads only regular files and checks the caller's limit before reserving memory;
- a non-retained read streams only the IR's recorded compressed payload range and rechecks actual size, CRC32, and SHA-256 before returning bytes;
- a retained read through `read_member` still checks the caller limit, validates the retained length, and returns an owned copy;
- absent paths, directories, caller-limit failures, platform or allocation limits, later snapshot I/O failure, and internal integrity disagreement have distinct `MemberReadErrorKind` values.

```rust
let outcome = sealr::apply(request);
let archive = outcome
    .verified_archive()
    .ok_or("archive was not completely verified")?;
let metadata = archive.read_member("package.dist-info/METADATA", 256 * 1024)?;
```

This path does not reopen the caller path or parse ZIP structure again. Without an explicit retention request, the current implementation opens a range-limited reader over the recorded payload, re-inflates a selected Deflate member, and revalidates it for each call. A path outcome reads from its retained private file; a byte outcome reads from the process-owned copy created when the capability outlives the caller borrow. The next section describes the opt-in path that avoids this repeated work for a small, known member set.

The first worker integration preserves these observable contracts through explicit Linux-only entry points. `LinuxWorker::load` authenticates one exact helper artifact from an absolute path, length, and SHA-256. `LinuxWorker::load_from_manifest` applies the fixed package manifest contract and then uses that same authenticator. `apply_supervised` accepts the ordinary `Request` and supports both inspect and materialize; `inspect_supervised` is the inspect-only convenience. They use the same planner, policy controls, outcome axes, retention plan, materialization core, and `VerifiedArchive` surface as in-process execution while returning typed infrastructure errors when they cannot establish or complete isolation. They never fall back to in-process verification. The semantic worker consumes the actual plan profile, policy, budget, target, consumer, effect, target identity, and retention and does not structurally reparse the ZIP. The supervisor reconstructs complete or stopped outcome state only after worker exit, reap, and exact source-derived agreement. For materialization, it also retains the destination parent and final name, audits the exact stage after reap, and alone publishes with no replacement. The CLI, wheel analyzer, and extracted-package fixture select this same boundary through the manifest-backed loader.

### Explicit supervised Linux execution

```rust,no_run
use std::path::Path;
use sealr::{apply_supervised, ApplyOptions, LinuxWorker, Policy, Request, Source};

let worker = LinuxWorker::load_from_manifest(Path::new(
    "/opt/sealr/libexec/sealr/sealr-worker.manifest",
))?;
let bytes = std::fs::read("input.zip")?;
let policy = Policy::default_v1();
let destination = Path::new("verified-tree");
let outcome = apply_supervised(
    Request {
        source: Source::Bytes { path: Some("input.zip"), data: &bytes },
        policy: &policy,
        dest: Some(destination),
    },
    &ApplyOptions::new(),
    &worker,
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The helper path is never discovered through `PATH`. Manifest loading requires an absolute path named `sealr-worker.manifest`, reads at most 4 KiB, rejects a BOM, CR line endings, a missing final LF, unknown JSON fields, release, target, ABI, length, or digest drift, and selects only `sealr-worker` beside that manifest. Callers that already possess separately authenticated identity metadata may use `LinuxWorker::load` directly. Successful worker execution records `kernel_jail: landlock-abi3+seccomp-v1`. Structural rejection or destination setup failure before worker entry records `not-entered`. On non-Linux targets, worker loading and supervised execution return `IsolationUnavailable`.

Archive denial, malformed input, quota stops, destination setup or publication failure, and canonically stopped payload verification remain ordinary `Outcome` values. `SupervisionErrorKind` is reserved for helper identity, spawn, authentication, restriction, protocol, timeout, worker-exit, reap, final cleanup, source-authority, integrity-boundary, and internal failures. This separation prevents an isolation failure from being mistaken for an archive finding or compatibility verdict.

A complete supervised outcome holds the exact private-file snapshot, accepted plan, authorized completion, and authenticated helper inside its opaque `VerifiedArchive`. Retained bytes are borrowed locally. A non-retained `read_member` call uses a new restricted process, returns no partial output, and succeeds only after exact output length, CRC and SHA-256 agreement, clean exit, reap, and source-derived validation. Clones share one serialized read authority, so dropping the original does not invalidate the clone.

For a materialize request, planning completes before destination setup. A setup failure therefore returns an admitted, effect-failed outcome with pending `ArchiveIR`, no `VerifiedArchive`, and no worker entry. After setup, the worker receives a read-only descriptor for only the private stage root. It cannot name the destination parent or final component. A complete worker result is still insufficient to publish: the supervisor requires clean exit and reap, reproduces completion and retained content from its exact source, audits every staged object against the authorized IR, and performs native no-replace publication through its retained parent capability. Audit or publication failure preserves a complete `VerifiedArchive` while reporting a failed effect.

### Bounded one-pass retention

Callers that know the small semantic members they will need can request them before verification:

```rust
use sealr::{
    apply_with_options, ApplyOptions, RetentionPlan, RetentionStatus,
    ZipInterpretationProfile,
};

let retention = RetentionPlan::new(256 * 1024, 1024 * 1024)
    .with_path("package.dist-info/WHEEL")?
    .with_path("package.dist-info/METADATA")?
    .with_path("package.dist-info/RECORD")?;
let options = ApplyOptions::new()
    .with_interpretation_profile(ZipInterpretationProfile::StrictAsciiV2)
    .with_retention(retention);
let outcome = apply_with_options(request, &options);
let archive = outcome
    .verified_archive()
    .ok_or("archive was not completely verified")?;

if archive.retention_status("package.dist-info/METADATA")
    != RetentionStatus::Retained
{
    return Err("required metadata was not retained".into());
}
let metadata = archive
    .retained_member("package.dist-info/METADATA")
    .ok_or("required metadata is unavailable")?;
```

`RetentionPlan` is deliberately not a general cache:

- paths are exact, already-canonical archive paths, with no glob or fallback normalization;
- the plan accepts at most 64 paths, each path is at most 4,096 bytes, and all path strings together are at most 16,384 bytes;
- the caller sets both a maximum retained size for one member and a maximum aggregate retained size;
- aggregate selection is deterministic in canonical-path order, independent of archive record order;
- a duplicate request is idempotent and does not consume another path slot;
- only regular files can be retained;
- content storage is reserved fallibly before inflation and never grows beyond the verified declared size;
- `NotFound`, `NotFile`, `MemberLimitExceeded`, `TotalLimitExceeded`, `PlatformLimit`, `AllocationFailed`, and defensive `IntegrityMismatch` results are observable without changing the archive verdict;
- bytes become available only on a `VerifiedArchive`, after every archive member has passed verification.

The retention limits are operation capabilities, not archive-admission policy. They do not change policy identity, receipt bytes, view bytes, tree identities, or the allow or reject result. Interpretation-profile selection is different: it changes the accepted container language and the recorded interpretation identity while remaining separate from resource-policy identity. A consumer that requires a retained member must inspect its `RetentionStatus` and fail its own higher-level evaluation when the status is not `Retained`. `apply(request)` is exactly the v1, no-retention compatibility path.

During inspect-only verification, selected bytes are the verification writer. During materialization, a bounded tee sends the same checked chunks to the staged file and selected buffer. There is no second codec invocation. Unselected or unsuccessfully retained members still support the ordinary caller-bounded `read_member` fallback, which re-inflates and revalidates from the immutable snapshot.

### Type-state flow

The target flow is:

```rust
let snapshot = sealr::ingest(source)?;
let interpreted = snapshot.interpret(ZipStrictV1)?;
let admitted = interpreted.evaluate(policy, consumer_profile)?;
let verified = admitted.verify_all()?;

verified.materialize(destination)?;
verified.write_evidence(output)?;
```

`SourceSnapshot` and `ArchiveIR` landed in Alpha.3 as the ingest object and the inspect/materialize member plan. Alpha.4 added `VerifiedArchive` as the first concrete verified type-state result. Alpha.5 moves path input to a private file-backed snapshot while preserving `apply()` as the compatibility facade. The split-phase semantic record remains crate-private, but the supported Linux `apply_supervised` path now uses it to isolate inspect, materialize, and later non-retained reads. Worker protocol v1 remains a separate public codec contract, and the record's hidden unsupported fuzz driver exists only under the nondefault fuzz feature. `AdmittedArchive` and the earlier transition methods remain design notation. Their required property is that every operation consumes one immutable interpretation and no operation reparses the original archive through another parser.

### Rust compatibility

The current MSRV is Rust 1.98, declared by the package `rust-version` and exercised as exact Rust 1.98.0 in CI. Preview releases may raise it only with a changelog entry and corresponding metadata update. Once a stable 1.x line exists, patch releases will not raise the MSRV.

### Semantic identities

Receipts now return separate source, interpretation, layout, and content-tree identities. `view_digest` remains invocation evidence. The first independent identity verifier and vectors have landed, but a future `sealr.lock` still waits for the profile and encodings to freeze and for the broader evidence verifier and consumer identity to exist.

---

## C ABI sketch, future

```c
typedef struct sealr_outcome sealr_outcome;
sealr_outcome *sealr_apply(const char *archive, const char *policy_json,
                           const char *dest /* nullable */);
const char *sealr_view_json(const sealr_outcome *);
const char *sealr_receipt_json(const sealr_outcome *);
int sealr_wrote(const sealr_outcome *);
int sealr_rejected(const sealr_outcome *);
void sealr_outcome_free(sealr_outcome *);
```

Same tree as Rust. No separate “list” API that uses a different parser.

---

## Python sketch, future

```python
outcome = sealr.apply("foo.zip", policy=sealr.Policy.default())
outcome.rejected      # bool
outcome.wrote
outcome.view          # dict
outcome.receipt       # dict
```

Not Mojo. Not `extract_all()` that returns `None`.

---

## Compatibility

Current `schema` fields are versioned. Adding a finding code is compatible. Changing default policy bytes requires a new policy `id`. Changing view member fields requires a new `sealr.view.vN`.

Future interpretation profiles are semantic versions, not loose presets. A stable profile must not silently change the meaning of accepted bytes. A security correction that changes interpretation requires a new profile version or explicit revocation of the affected profile.
