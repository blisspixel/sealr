# API contract

This page distinguishes the implemented alpha.2 contract from the target semantic API. Current callers must pin to the implemented section. The target is specified further in [semantic-model.md](semantic-model.md).

## Implemented in alpha.2

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
    pub verdict: Verdict,
    pub receipt: Receipt,            // always
    pub view: View,                  // always
}

pub enum Verdict {
    /// Policy passed. `wrote` is true only after a requested destination commits.
    Allowed { wrote: bool },
    /// Policy or materialization failed. View and receipt explain why.
    Rejected,
}
```

Invariants:

- `apply` with `dest: None` never creates member files. Inspect-only success is `Allowed { wrote: false }`.
- `wrote == true` only if `dest.is_some()` and the complete staged member tree committed at the requested destination.
- Every outcome contains both a view and a receipt, including source, parse, policy, quota, and materialization failures.

- `receipt.view_digest` is currently SHA-256 of deterministic `serde_json` bytes for the versioned Rust struct. RFC 8785 JCS is a Phase 0.1 gate.
- `receipt.policy.digest` uses the same current deterministic struct serialization. It is not yet a cross-encoder canonical JSON promise.
- After the source bytes are available, `receipt.source.sha256` is SHA-256 of the archive blob. A source open, read, or pre-read size rejection currently uses 64 zero hex characters as an explicit unavailable sentinel. A dedicated digest-availability field is a receipt-schema gate.
- The same source bytes, source metadata, and policy produce the same interpreted member tree and findings. Materialization may add an I/O finding, but it must not reinterpret archive bytes. **This is the LibreOffice bug we refuse:** inspect and materialize cannot disagree about the archive tree.

No second function that “recovers” a broken zip.

---

### InspectableView JSON

One document. The current CLI emits pretty JSON; JSONL is planned. The current digest covers deterministic Rust-struct JSON bytes. JCS canonicalization is a Phase 0.1 gate.

```json
{
  "schema": "sealr.view.v1",
  "source": { "path": "foo.zip", "digest": { "sha256": "..." }, "magic": "zip" },
  "policy": { "id": "sealr:policy/default/v1", "digest": { "sha256": "..." } },
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

`verdict`: `allowed` or `rejected`. `wrote` is Boolean. A rejection before member processing has an empty member list. A later payload or materialization rejection retains every member completed before the failure. The finding that caused rejection is always present. The current schema does not mark that member list as partial, so callers must use the verdict and findings rather than assuming a rejected view is complete.

Projection and hydration on read are target surfaces. They are not part of alpha.2.

---

### Receipt

The current receipt is versioned unsigned JSON (`signed: false`). DSSE and in-toto wrapping are future work.

```json
{
  "schema": "sealr.receipt.v1",
  "verdict": "allowed",
  "wrote": false,
  "source": { "sha256": "..." },
  "policy": { "id": "sealr:policy/default/v1", "digest": { "sha256": "..." } },
  "view_digest": { "sha256": "..." },
  "tool": { "name": "sealr", "version": "0.1.0-alpha.2" },
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

When materialization is requested, the materialization object reports the component-bound backend, stage protection, exact stage-creation primitive, durability mode, exact platform publication primitive, lifecycle outcome, and cleanup result. Windows reports `ntcreatefile-parent-handle-create-directory-explicit-dacl-nofollow` for creation and `ntsetinformationfile-retained-source-parent-noreplace` for publication. Its optional `windows` object records the `windows-local-ntfs-v1` storage policy, observed filesystem and device scope, persistent-ACL and read-only flags, the `windows-protected-token-user-v1` ACL policy, and whether the stage ACL was verified. No SID, volume serial, label, or path is serialized.

On reject, `members` in the view may be partial; `view_digest` still covers exactly that invocation-specific view. It is not a canonical tree identity. The strongest current statement is: source digest D under policy P produced serialized view V in this invocation.

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

These are target types, not current Rust symbols or JSON fields.

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

`SourceSnapshot`, `ArchiveIR`, `AdmittedArchive`, and the methods above are design notation. They do not exist in alpha.2. Their required property is that every operation consumes one immutable interpretation and no operation reparses the original archive through another parser.

### Semantic identities

The target API returns separate source, interpretation, layout, content-tree, and effect identities. Alpha.2 returns source, policy, and invocation-specific view digests only. A future `sealr.lock` depends on the canonical `ArchiveIR` and `sealrTreeV1` specifications and must not precede them.

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
