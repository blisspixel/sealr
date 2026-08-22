# API contract

This page distinguishes the published alpha.3 contract plus compatible hardening on current main from the target semantic API. Current callers must pin to the implemented section. The target is specified further in [semantic-model.md](semantic-model.md).

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
- After the complete source bytes are available, `receipt.source` is `{ "sha256": "..." }`. A source open, read, pre-read path-size rejection, or path growth beyond the bounded read uses `{ "status": "unavailable" }` and omits `sha256`. An over-cap `Source::Bytes` input is complete caller-owned data, so it is hashed. The inspectable view keeps the same digest object so `receipt.source` equals `view.source.digest`.
- `receipt.source_snapshot` is `memory-owned` for accepted path inputs and `memory-borrowed` for caller byte slices, including an over-cap slice rejected before parsing. It is `unavailable` when no complete snapshot was retained. Parse and payload reads use that snapshot; they do not reopen the caller path.
- The same source bytes, source metadata, and policy produce the same interpreted member tree and findings. Materialization may add an I/O finding, but it must not reinterpret archive bytes. **This is the LibreOffice bug we refuse:** inspect and materialize cannot disagree about the archive tree.

`ArchiveIR` is constructed only by Sealr. Its fields cannot be mutated outside the crate, and evolving IR records and enums are non-exhaustive. `Outcome::archive_ir()` provides a read-only serializable evidence view after planning. It does not retain verified member bytes and is not the planned `AdmittedArchive` capability. A consumer cannot use it as permission to reopen the source through another ZIP parser.

Evolving output enums and records are non-exhaustive so the preview API can add evidence without forcing downstream exhaustive matches or permitting caller-constructed receipts. Every public field type in `View` and `Receipt`, including `SourceMeta`, `PolicyMeta`, `ToolMeta`, `EnvMeta`, and `SnapshotKind`, is exported from the crate root and exercised by an external-crate compile fixture. `Request` remains directly constructible for the current compatibility facade.

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

Projection and hydration on read are target surfaces. They are not part of alpha.3.

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
  "source_snapshot": "memory-owned",
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
  "tool": { "name": "sealr", "version": "0.1.0-alpha.3" },
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
- `interpretation` binds `sealr.profile.zip.strict-ascii.v1` and the SHA-256 of that profile's method, flag, extra-field, and name rules.
- `layout` is `sealrTreeV1` over canonical paths, kinds, raw names, flags, methods, declared sizes, complete local-header, payload, optional-descriptor, and central-header ranges, extra-field dispositions, and normalization actions. It is present once an `ArchiveIR` exists. It is `{ "status": "unavailable" }` when planning never produced a tree.
- `content` is `sealrTreeV1` over canonical paths, kinds, actual sizes, and member SHA-256 digests. It is present only when verification is complete. An admitted archive whose destination fails keeps its layout root and does not claim a content root until members are verified.
- Layout and content encodings are Git-style domain-separated preimages (`sealr.tree.layout.v1` and `sealr.tree.content.v1`) over little-endian length-prefixed covering ranges and member records. They do not use JSON, so they are independent of `view_digest` and of later RFC 8785 work. The interpretation profile is a sibling identity, not mixed into the tree bytes. The production golden test and a standalone no-Sealr-dependency verifier consume the same [identity-conformance bundle](identity-conformance.md), independently reproducing the current profile digest plus three layout and three content roots. Layout identity includes the source covering (local prefix, central directory, EOCD, comment). Content identity does not. The standalone checker and internal codec-free audit follow claimed ranges without searching or inflating; materialization audits the staged tree against the same IR before publication.

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
- `read_member(canonical_path, max_bytes)` reads only regular files and checks the caller's limit before reserving memory;
- every returned read uses the IR's recorded payload range and rechecks actual size, CRC32, and SHA-256 before returning bytes;
- absent paths, directories, caller-limit failures, platform or allocation limits, and internal integrity disagreement have distinct `MemberReadErrorKind` values.

```rust
let outcome = sealr::apply(request);
let archive = outcome
    .verified_archive()
    .ok_or("archive was not completely verified")?;
let metadata = archive.read_member("package.dist-info/METADATA", 256 * 1024)?;
```

This path does not reopen the caller path or parse ZIP structure again. The current in-memory implementation re-inflates a selected Deflate member and revalidates it for each call. Bounded retention or content-addressed reuse is required before a wheel consumer may claim that repeated semantic reads avoid reinflation.

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

`SourceSnapshot` and `ArchiveIR` landed in alpha.3 as the ingest object and the inspect/materialize member plan. Current main adds `VerifiedArchive` as the first concrete verified type-state result while preserving `apply()` as the compatibility facade. `AdmittedArchive` and the earlier transition methods remain design notation. Their required property is that every operation consumes one immutable interpretation and no operation reparses the original archive through another parser.

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
