# Usefulness test

> This is the quality bar for whether Sealr is actually useful. Alpha.8 exposes the first supported-preview non-reopening consumer, while the stable product bar remains open. Current executable behavior is the [README](../README.md). Sequencing is the [roadmap](../ROADMAP.md).

Treat Sealr as an **admission boundary other software calls**, not as an unzip.

The test is:

```text
same bytes + same policy
    -> one tree, or no tree
    on Linux, macOS, and Windows

the next tool consumes that admitted tree
    and does not open the ZIP again
```

If something still reparses the archive, the receipt is just a receipt and the category has not been proven. Wheel admission is the first consumer that would prove it.

Current main supplies the generic `VerifiedArchive` capability, the supported portable UTF-8 profile, and the public `sealr::wheel` evaluator for filenames, metadata, `RECORD`, relocation, generated targets, and distinct identities. A downstream contract deletes the original Unicode wheel before evaluation and proves deterministic output through the capability alone, and the runnable `wheel_admission` example demonstrates the same loop end to end — admission, source deletion, plan materialization, and realization identity — alongside a hostile container refused at admission and a lying `RECORD` denied by the consumer. The Alpha.7 laboratory separately preserves the hash-pinned external PyPA installer proof. This passes the supported mechanism test. Stable usefulness remains open because no external adopter treats the public representation as authority and the public same-digest, different-tree demonstration remains open.

Until then, keep every admitted language strict and fail closed. Format work counts only when it strengthens the shared admission boundary with a concrete profile, dependency budget, conformance evidence, and downstream capability path. Raw portable ustar is the zero-dependency proof; adding 7z or a desktop CLI without equivalent semantics would not substitute for a dependent.

## Checklist

- Inspect and materialize share one interpretation. No recovery parser, no second opinion on the same bytes.
- Policy is data in the receipt. No `--insecure`, no “just this once.”
- Unknown structure, ZIP64 outside the explicit policy-v3 profile, gzip-wrapped TAR outside the explicit policy-v4 profile, encryption, rich TAR extensions, additional compressed wrappers, and unsupported methods fail closed. The ZIP compatibility default requires explicit strict UTF-8 flagging for non-ASCII paths, strict ASCII v2 rejects them, portable UTF-8 v1 admits only its pinned Unicode 16.0 repertoire in NFC, and raw plus gzip-wrapped portable ustar use that same closed path contract. Authenticated worker ZIP64 and gzip-TAR selections also fail closed until later semantic records bind their evidence.
- Rejection still returns a view and a receipt. Silence is a bug.
- A digest of the archive is not a digest of the tree. Semantic identity (layout root, content root, versioned IR) has to land before anyone should reuse the result.
- Cross-platform sameness is the product. If Windows writes a different tree, that is a fail, not a port quirk.
- Materialize only after every member passes, no-replace, no follow. The staged tree is audited against the admitted IR before publication. Same-user attackers and leftover staging directories are still outside the claim; do not pretend otherwise.
- Do not claim production security. ZipDiff coverage is a pinned corpus, not a proof.
- Do not optimize for format count, throughput, or bindings until one real consumer (wheels first) imports the crate and stops unzipping.
- CI should protect the boundary (corpus, lockfile, cargo-deny, native materialize). Screenshots and walkthrough PNGs are not the usefulness gate.

## What would count as passing

1. Preview semantic identity is frozen enough that layout and content roots are the same on every supported release platform for the same source bytes and policy. The walkthrough allowed fixture roots are pinned in `crates/sealr/tests/golden_identity.rs`.
2. A `python-wheel.v1` consumer validates the exact artifact filename, wheel metadata, `RECORD`, and relocation plan against verified members without reopening the ZIP or invoking a second ZIP parser.
3. One external publisher, registry, build backend, or installer takes Sealr's admitted representation as authoritative. In the decisive test, access to the original wheel is removed after admission and the consumer still completes through the admitted capability.
4. An open-hook or process trace confirms that no ZIP parser opens the source after admission, and mutation of any admitted member is detected before consumption.
5. A public same-digest, different-tree wheel demonstration uses that path and distinguishes source, archive-tree, wheel-artifact, and installation-plan identities.

Alpha.8 demonstrates items 1 and 2 through the public prerelease API and preserves the external research proof for items 3 and 4. Item 5, a real external adopter, stable API review, targeted compatibility breadth, and the remaining trust gates still prevent a stable product-level passing claim.

See [semantic-model.md](semantic-model.md#the-consumption-rule), the [wheel profile](profiles/python-wheel-v1.md), [theory.md](theory.md), and [ROADMAP.md](../ROADMAP.md#phase-02-one-canonical-consumer).
