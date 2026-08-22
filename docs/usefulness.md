# Usefulness test

> This is the quality bar for whether Sealr is actually useful. It is not a claim that the bar is met. Current executable behavior is the [README](../README.md). Sequencing is the [roadmap](../ROADMAP.md).

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

Current main now supplies the first generic `VerifiedArchive` capability and proves through a packaged consumer that member bytes remain available after the caller's original slice is changed. That closes the reopen and second-parser gap for this API path. It does not yet pass the usefulness test: no wheel evaluator or external installer consumes it, and current reads re-inflate the selected member instead of retaining bounded semantic bytes.

Until then, keep the ZIP32 path strict, fail closed, and do not add TAR, 7z, or a desktop CLI as a substitute for a dependent.

## Checklist

- Inspect and materialize share one interpretation. No recovery parser, no second opinion on the same bytes.
- Policy is data in the receipt. No `--insecure`, no “just this once.”
- Unknown structure, ZIP64, encryption, non-ASCII paths, and unsupported methods fail closed until the Unicode and canonical-path design exists.
- Rejection still returns a view and a receipt. Silence is a bug.
- A digest of the archive is not a digest of the tree. Semantic identity (layout root, content root, versioned IR) has to land before anyone should reuse the result.
- Cross-platform sameness is the product. If Windows writes a different tree, that is a fail, not a port quirk.
- Materialize only after every member passes, no-replace, no follow. The staged tree is audited against the admitted IR before publication. Same-user attackers and leftover staging directories are still outside the claim; do not pretend otherwise.
- Do not claim production security. ZipDiff coverage is a pinned corpus, not a proof.
- Do not optimize for format count, throughput, or bindings until one real consumer (wheels first) imports the crate and stops unzipping.
- CI should protect the boundary (corpus, lockfile, cargo-deny, native materialize). Screenshots and walkthrough PNGs are not the usefulness gate.

## What would count as passing

1. Preview semantic identity is frozen enough that layout and content roots are the same on every supported release platform for the same source bytes and policy. The walkthrough allowed fixture roots are pinned in `crates/sealr/tests/golden_identity.rs`.
2. A `python-wheel.v1` consumer validates the exact artifact filename, wheel metadata, `RECORD`, and relocation plan against verified members without reopening or reinflating the ZIP.
3. One external publisher, registry, build backend, or installer takes Sealr's admitted representation as authoritative. In the decisive test, access to the original wheel is removed after admission and the consumer still completes through the admitted capability.
4. An open-hook or process trace confirms that no ZIP parser opens the source after admission, and mutation of any admitted member is detected before consumption.
5. A public same-digest, different-tree wheel demonstration uses that path and distinguishes source, archive-tree, wheel-artifact, and installation-plan identities.

Until those hold, Sealr is a strict ZIP32 evaluation boundary with evidence. That is worth building. It is not yet proof of the category.

See [semantic-model.md](semantic-model.md#the-consumption-rule), the [wheel profile draft](profiles/python-wheel-v1.md), [theory.md](theory.md), and [ROADMAP.md](../ROADMAP.md#phase-02-one-canonical-consumer).
