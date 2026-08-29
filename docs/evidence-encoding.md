# Evidence encoding contract

> Status: normative statement of the encoding behind every shipped policy digest and the receipt's `view_digest`. An external verifier can reproduce these digests from this page alone, without running sealr or serde. The machine-checked half lives in `crates/sealr/tests/evidence_encoding.rs`.

## Sealr canonical JSON, declaration-order lineage (v1)

The digests of the `sealr.view.v1` and `sealr.receipt.v2` schemas and of every policy schema through `sealr:policy/default/v11` are SHA-256 over **compact declaration-order JSON**:

1. **No whitespace** between any tokens.
2. **Object keys appear in struct declaration order**, not sorted. The order for each schema is fixed by that schema's published shape and never changes; a schema's key order is part of its digest preimage.
3. **Strings** escape `"` and `\`, use the two-character escapes `\b`, `\t`, `\n`, `\f`, `\r` for their control characters, lowercase `\u00hh` for other control characters below U+0020, and emit every other character — including non-ASCII — as literal UTF-8.
4. **Numbers are integers only.** The evidence domain contains no floats anywhere, and every emitted integer is at most 2^53 − 1, so each value is exactly representable as an IEEE-754 double. Integers serialize as their exact minimal decimal form. `max_ratio` may be JSON `null`.
5. **Object keys are fixed ASCII names.** Member paths and other untrusted text appear only as values, never as keys.
6. **One conditional field exists**: a policy's `max_derived_archive_bytes` is present exactly when the policy sets it and absent otherwise. No other field is conditional.

Digest definitions:

- **Policy digest** = lowercase-hex SHA-256 over the compact declaration-order bytes of the policy object. The exact serialized bytes and digests of all eleven default policies are byte-pinned in `crates/sealr/src/policy.rs` tests.
- **`view_digest`** (inside the receipt) = lowercase-hex SHA-256 over the compact declaration-order bytes of the view object.

## The presentation split, stated honestly

The CLI prints views and receipts — and writes `--view`/`--receipt` files — as **pretty-printed** JSON for human readability. Pretty bytes are a presentation of the same document, not the digested bytes: hashing an emitted file does not reproduce `view_digest`, and the receipt carries no digest of itself. A verifier that wants the covered bytes today must re-serialize the parsed document compactly in declaration order per this page.

This split is a known limitation of the declaration-order lineage, not an accident. A planned RFC 8785 (JCS) lineage — new schema identifiers, never a mutation of the shipped ones — will make the emitted file bytes exactly the canonical digested bytes.

## Frozen invariants

These are immutable for the life of the shipped schemas, and tests assert them:

1. `Policy` field names, declaration order, and the single conditional field are the v1-v11 digest preimage shape and never change.
2. Compact serde_json-compatible encoding (the escape table and integer formatting above) remains the digest encoder for the existing schemas.
3. Every pinned schema id, policy serialization, and policy digest is an immutable historical contract.
4. `sealr.view.v1` and `sealr.receipt.v2` shapes are frozen; canonicalization changes arrive only as new versioned schemas alongside them.

## Environment-variant receipt fields

Receipts bind the producing environment on purpose: the `env` object's `os` and `arch` come from the running platform, so the same archive and policy produce receipts that differ in exactly those fields across platforms. Verifiers comparing receipts across platforms must treat them as environment facts, not evidence drift. Source, policy, view, findings, and identity fields are environment-independent for the same bytes and policy.

## Out of scope

The wheel consumer identities (`consumer_profile_digest`, artifact, plan, and realization identities) use bespoke length-prefixed binary preimages documented in the [wheel profile](profiles/python-wheel-v1.md), not JSON, and are unaffected by this page.
