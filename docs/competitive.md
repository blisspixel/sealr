# Adjacent tools and research

> Research snapshot reviewed 2026-08-21. This page supports product decisions but is not a live market database or a source of security guarantees. Recheck upstream behavior before relying on a comparison.

Sealr overlaps several established categories but should not claim to replace them.

## Landscape

| Category | Representative work | What it does well | What Sealr should learn |
|---|---|---|---|
| General archive tools | [7-Zip](https://7-zip.org/), [PeaZip](https://peazip.github.io/), platform archive utilities | Broad formats, mature user workflows, strong compatibility | Do not compete on format count or desktop extraction convenience |
| Unified extraction | [ouch](https://github.com/ouch-org/ouch), [HashiCorp go-extract](https://github.com/hashicorp/go-extract), [exarch](https://github.com/bug-ops/exarch) | Practical APIs, multiple formats, path and resource controls | Clear configuration and safe defaults matter, but breadth alone is not Sealr's goal |
| Parallel ZIP extraction | [ripunzip](https://github.com/GoogleChrome/ripunzip), [ripzip](https://github.com/velopack/ripzip-rs) | Efficient member-level work on suitable archives | Performance depends on corpus and destination; measure with all verification enabled |
| Read-only archive access | [ratarmount](https://github.com/mxmlnkn/ratarmount), [archivemount](https://github.com/cybernoid/archivemount) | Avoids eager extraction for some workloads | Any future projection must consume the admitted IR and expose verification completeness |
| Supply-chain evidence | [in-toto](https://in-toto.io/), [Sigstore](https://www.sigstore.dev/), [GitHub artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) | Standard envelopes, identities, and verification workflows | Use established authenticated envelopes after Sealr's claim bytes are canonical |
| Parser differential research | [ZipDiff](https://github.com/ouuan/ZipDiff) and its [USENIX Security 2025 paper](https://www.usenix.org/conference/usenixsecurity25/presentation/you) | Reproducible ambiguity taxonomy across many ZIP parsers | Treat one byte sequence having multiple consumer meanings as a first-class admission problem |

## Narrow differentiation to test

The working hypothesis is modest:

1. one strict interpretation is shared by inspection and every Sealr effect;
2. known ambiguous structure receives stable, machine-readable refusal evidence;
3. accepted content receives explicit verification completeness;
4. downstream consumers use the admitted representation instead of reparsing the source;
5. Linux, macOS, and Windows produce the same semantic tree evidence for the same profile.

Alpha.3 establishes the first preview interpretation and tree identities for a narrow ZIP32 subset. It does not yet establish stable lock semantics, reusable admission, a stable consumer profile, or the complete cross-platform semantic contract.

## What not to optimize for first

- the largest format list;
- a desktop archive GUI;
- one synthetic unzip throughput result;
- GPU or hardware checkboxes;
- a custom signature system;
- many language bindings without one dependent consumer;
- permissive recovery for rejected archives.

The next test of differentiation is not a marketing comparison. It is whether the Phase 0.1 semantic identity, corpus, worker, and verifier gates can be implemented without weakening compatibility or platform support.

See [who-else.md](who-else.md) for project-specific notes and [ROADMAP.md](../ROADMAP.md#active-execution-queue) for the implementation order.
