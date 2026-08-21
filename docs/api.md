# API (the type, as a crate)

This is the contract other systems pin to. CLI, PyO3, C ABI, and MCP are façades.

```
UntrustedArchive × Policy
  → (Materialization | Rejection) × AttestedReceipt × InspectableView
```

Policy: [policy.md](policy.md). Findings: [findings.md](findings.md). Receipt envelope: [attestations.md](attestations.md). Usage: [usage.md](usage.md).

---

## Rust (Phase 0)

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
- `receipt.source.sha256` is SHA-256 of the archive blob.
- The same source bytes, source metadata, and policy produce the same interpreted member tree and findings. Materialization may add an I/O finding, but it must not reinterpret archive bytes. **This is the LibreOffice bug we refuse:** inspect and materialize cannot disagree about the archive tree.

No second function that “recovers” a broken zip.

---

## InspectableView (JSON)

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

`verdict`: `allowed` | `rejected`. `wrote`: bool. Members listed even on reject **up to the failure point**; do not skip the finding that caused reject.

Mount: same `members[].path` namespace. Hydrate on `read` uses the same inflate+CRC as materialize.

---

## Receipt

The current receipt is versioned unsigned JSON (`signed: false`). DSSE and in-toto wrapping are future work.

```json
{
  "schema": "sealr.receipt.v1",
  "verdict": "allowed",
  "wrote": false,
  "source": { "sha256": "..." },
  "policy": { "id": "sealr:policy/default/v1", "digest": { "sha256": "..." } },
  "view_digest": { "sha256": "..." },
  "tool": { "name": "sealr", "version": "0.1.0-alpha.1" },
  "environment": { "os": "windows", "arch": "x86_64", "kernel_jail": "unavailable" },
  "materialization": {
    "schema": "sealr.materialization.v1",
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

When materialization is requested, the materialization object reports the component-bound backend, stage protection, exact stage-creation primitive, durability mode, exact platform publication primitive, lifecycle outcome, and cleanup result. Windows reports `ntcreatefile-parent-handle-create-directory-nofollow` for atomic stage creation and `ntsetinformationfile-retained-source-parent-noreplace` for publication through retained handles.

On reject, `members` in the view may be partial; `view_digest` still covers exactly that view. Downstream: “digest D under policy P produced view V.”

---

## C ABI (sketch, Phase 1)

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

## Python (PyO3, after the crate is boring)

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

`schema` fields are versioned. Adding a finding code is compatible. Changing default policy bytes is a new `id`. Changing view member fields is a new `sealr.view.vN`.
