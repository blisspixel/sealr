# Testing, fuzzing, and assurance

> This is the assurance target. The deterministic Rust unit suite, strict CI, cargo-deny policy, and pinned 5,927-file ZipDiff construction gate exist today. Property testing, cargo-fuzz targets, Kani harnesses, public fuzzing, and external audit remain Phase 0.1 or later work.

Trust is the scarce resource. Performance and format breadth come after the invariants are boring.

## Layers

| Layer | Current evidence | Remaining work |
|---|---|---|
| Unit | ZIP path jail, topology, overlap and layout, quotas, rollback, destination preservation, ZipDiff-driven cases, and deterministic truncation/mutation/noise no-panic coverage | Expand each invariant as the implementation grows |
| Property | None yet | I1-I8 over generated names, topology, and quota counters |
| Corpus | All 5,927 pinned ZipDiff constructions plus local generated adversarial fixtures | Fifield quoted-overlap artifacts and package-manifest cases |
| Fuzz | None yet | `cargo fuzz` targets for ZIP parse, canonical names, and inspect-only `apply()`; oracle checks no panic, no escape, and bounded allocation |
| Differential | The ZipDiff expectation gate binds strict rejection and documented valid controls | Optional scheduled comparison against independent parsers on well-formed archives only |
| Audit | `SECURITY.md` reporting process and automated dependency checks | Public external report after the core freezes |

## ZipDiff as a gate

The CI gate regenerates the [ZipDiff](https://github.com/ouuan/ZipDiff) `construction` output at a pinned revision. After revision verification, a committed patch replaces the generator's current-time DOS timestamp defaults with zero. The [manifest](../tests/corpus/zipdiff/expectations.txt) then binds the deterministic fixture bytes through one aggregate digest, exact finding counts, and the valid-control allowlist. The 50-parser Docker farm is not part of CI or the product runtime.

If ZipDiff adds a 15th type, its changed count and digest fail the gate before the manifest can be updated deliberately.

## Formal / semi-formal - tiny TCB, not the zoo

Do **not** try to verify inflate, 7z, or “the ZIP parser.” That is a career. Verify the **boundary**:

| Property | Tooling (2026) | Why this one |
|---|---|---|
| I1 path containment after normalize | **Kani** on the pure jail function; **Verus** if we keep that module in a Verus-friendly subset | Highest-value, smallest surface |
| I2/I3 quota monotonicity (never trust headers) | Kani on the counters; proptest as the daily driver | Easy to state, easy to get wrong under concurrency |
| Fail-closed policy (no implicit allow) | Exhaustive match tests + Kani on the policy enum | The `--insecure` class of bug |

The rest of the system can be messy. The arrow itself should not be. Do not claim “formally verified unzip.” Claim “the containment and quota core has machine-checked proofs; the codecs are fuzzed.”

## Continuous

- oss-fuzz once the crate is public.
- `cargo deny`, `cargo geiger` (the unsafe allowlist is empty by default; every platform exception requires a documented invariant and focused tests).
- Living threat model: this docs set. Record dated decisions in curated documentation and executable tests.

## Unsafe policy

The jail, central-directory parser, and limit counters contain no `unsafe`. The current Apple descriptor-ACL and Windows native stage/publication adapters are isolated exceptions with documented pointer, layout, handle, and error-conversion invariants. Archive mmap may require a future `sealr-io` exception; isolate it, document the truncation invariant, and never use mmap for outputs.
