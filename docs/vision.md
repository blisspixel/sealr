# Vision: the safe-unarchive primitive

**sealr.** Public positioning: [../README.md](../README.md). The CLI is the reference implementation and the demo.

The product is not “files appear in a directory.” It is not a safer unzip. It is the **arrow**:

```
UntrustedArchive × Policy
  →  (Materialization | Rejection)
    × AttestedReceipt
    × InspectableView
```

That is a **product**, not a menu. Every call returns paperwork and a view. The only fork is whether the host also gets files.

| Factor | Always? | What it is |
|---|---|---|
| **Materialization \| Rejection** | yes (sum) | Files on disk **or** a fail-closed no. Never both. Never silent. |
| **AttestedReceipt** | always | Signed (or explicitly `signed: false`) record of archive digest, policy, findings, dest, tool. Exists **on reject**. |
| **InspectableView** | always | Structured tree + findings (JSONL). Mount is one *representation* of this view, not a third dest. |

Findings live in the view and are summarized on the receipt. Inspect-only is `Rejection` of disk writes (or empty materialization) plus a full view - agents reason from that. `materialize` is the same function with writes enabled *if* policy said yes.

You never get files without a receipt and a view. You never get a reject without a receipt and a view. That is what makes this a boundary other systems can depend on, instead of `extract() -> ()`.

Why this type is newly *shippable* in 2026: [now.md](now.md).

ZIP is not an input format. It is an **attack surface that sometimes contains files** - a non-deterministic language whose meaning depends on which parser you feed. Path traversal, size caps, and ratio limits are mitigations. They are not the problem. The problem is treating parser disagreement as an edge case. The 2025 ZipDiff paper already showed almost every pair of major implementations diverges. Shipping another crate that blocks `../` is cosplay.

Safety properties are the **type of the operation**. Files are a side effect of `Materialization`. The view and the receipt are the actual return values. Everything else (codecs, rayon, Mojo, GPU) is implementation detail.

The trusted computing base is tiny: path containment after full normalize, monotonic quotas that never believe headers, fail-closed policy, one interpretation. Point Verus/Kani at *those*, not at the format zoo. Throw away ambient authority **before** the first header (Landlock / AppContainer). Rust owns the part that has to be right. Mojo owns the part that is allowed to be hot and boring.

If the receipt, the policy, and the differential resistance are not first-class, this is just another unzip with better marketing. Other systems (package managers, CI, agents) should depend on the **boundary**, not on our CLI.

This is infrastructure. A Mojo+Rust unzip is a learning project.

sealr does not claim to make ZIP/TAR/7z well-specified. It claims a **precise place to stand** while the formats remain hostile - so the choice is no longer “risk the host,” “pay for heavy isolation every time,” or “operate on vibes.”

Doc map (this is the ambition; the rest is how):

| Doc | Job |
|---|---|
| [threat-model.md](threat-model.md) | Adversary + ZipDiff 14 types (USENIX Security 2025) |
| [invariants.md](invariants.md) | I1–I8, testable properties |
| [differentials.md](differentials.md) | Single interpretation, corpus, normalize |
| [safety.md](safety.md) | Path grammar, caps, szips parity |
| [sandbox.md](sandbox.md) | Landlock-first / mount as view |
| [attestations.md](attestations.md) | CycloneDX + in-toto extraction receipt |
| [assurance.md](assurance.md) | Fuzz, ZipDiff constructions, unsafe policy |
| [architecture.md](architecture.md) | Rust core, Mojo secondary, crates |
| [backends.md](backends.md) | When GPU/Mojo exist |
| [bigger.md](bigger.md) | Mount as a dest |
| [now.md](now.md) | What Rust/Mojo made practical in Aug 2026 |
| [api.md](api.md) | `apply()` contract |
| [policy.md](policy.md) | Policy object |
| [findings.md](findings.md) | Code registry |

If they fight: this file wins on “what we are”; [invariants.md](invariants.md) wins on safety; [backends.md](backends.md) wins on GPU.

---

## The claim

Untrusted archives are a decades-old, still-burning primitive. Path traversal, zip bombs, polyglots, parser disagreement, and symlink/junction escapes keep producing CVEs in the tools that *already know better*:

- Python `zipfile` / `tarfile` (CVE-2025-8291, CVE-2025-4517, CVE-2024-0450, …)
- pip tar fallback (CVE-2025-8869)
- uv wheel/ZIP confusion (CVE-2025-54368)
- PyPI wheel RECORD vs ZIP disagreement (2025–2026 policy)
- 7-Zip MOTW / symlink (2025–2026)
- libarchive, the `zip` crate (CVE-2025-29787), Go `archive/zip`, every language’s DIY `extract()`

The HTML analog is real: once `DOMPurify` / `bleach` existed, “roll your own sanitizer” became malpractice. There is **no DOMPurify for archives**. There is HashiCorp `go-extract` (caps + Zip-Slip, sequential, Go, telemetry, one-archive). There are `safezip` / `safe_unzip` (slow, library-shaped). There is PEP 706 (Python-only, opt-in filters). There is not a fast, fuzzed, C-ABI, structured-findings, receipt-emitting engine that agents and `uv` and CI can all call.

Agentic systems made this urgent instead of merely correct. In 2026 an agent downloads a repo zip, a wheel, a dataset, model weights, a “here’s the dump.” Options today: `unzip` (malpractice) or a VM (too heavy). A primitive that **always** returns `AttestedReceipt × InspectableView`, and only sometimes files, is what those runtimes actually need.

---

## Product shape (library first)

```
                    ┌─────────────────────────────────────────┐
                    │  sealr engine (Rust)                   │
                    │  parse → policy → locate → hydrate      │
                    │  findings + receipts                    │
                    └───────────────┬─────────────────────────┘
                                    │ C ABI (the penetration layer)
          ┌─────────────┬───────────┼────────────┬─────────────┐
          ▼             ▼           ▼            ▼             ▼
        CLI           Python      WASM/JS       Go/cgo       MCP/skill
      (reference)    (agents)    (later)       (later)      (agents)
```

Return-type factors (see [bigger.md](bigger.md) for mount as a *view representation*):

| Factor | When |
|---|---|
| **InspectableView** | Always. JSONL tree; `--mount` (ProjFS/FUSE) is a representation. Policy at `open()`. |
| **AttestedReceipt** | Always. Policy, digests, environment. |
| **Materialization** | Only if policy said yes *and* caller passed `--dest`. |
| **Rejection** | Policy fail, or inspect-only (no dest). Still view+receipt. |

Hydrate into a GPU/process buffer is an optional dest for *members after* the boundary said yes. Never the default. Never a fourth factor of the type.

Ironclad defaults: the only way to use the engine is the safe way. Policy can *name* a relaxation (Unix-tarball symlinks inside the jail, larger caps for a trusted dataset) and that name goes on the receipt. There is no `--insecure`. There is `policy: datasets/huggingface-v1` that an auditor can read.

---

## Architecture (hybrid, 2026)

**Rust core is the security boundary.** Memory safety, FFI, the trust story package managers need. Jail, ZipDiff checks, limit counters, dest open: **no `unsafe`**. Near-zero elsewhere; mmap of the archive is isolated in `sealr-io` and documented.

**Mojo is secondary, high-leverage, not the critical path.** 1.0 + Apache compiler (August 2026) is real. Use it for bulk hash/CRC on multi-GB–TB inspect, high-throughput validation, GPU-accelerable stages when dest is a buffer or mount page cache, later content-addressed select. **Do not** put path containment or limit enforcement in Mojo until its path/I/O story is audited. If Mojo never ships, the primitive still exists. Details: [backends.md](backends.md).

**Surfaces, in order:** crate + CLI JSONL → Python (**PyO3 on this crate**) → C ABI → MCP skill → napi-rs / WASM component. Not four languages on day one. Mojo’s Python interop is for kernel bring-up, not the agent API. JSONL is the agent default. The receipt always carries policy, digests, and environment.

## What is load-bearing vs what is costume

| Piece | Load-bearing? | Notes |
|---|---|---|
| Rust core, memory safety, C ABI | **Yes** | This is how you get into `uv`, npm, a container runtime, a WASM agent. |
| Non-optional jail + bombs + overlap + no-symlink default | **Yes** | The product. [safety.md](safety.md). |
| Streaming inflate + CRC in one pass | **Yes** | Integrity without a second read. |
| Structured **findings** (not a 0–100 “risk score”) | **Yes** | Compiler diagnostics. Agents can switch on codes. |
| InspectableView always (even on reject) | **Yes** | The agent-native return value. |
| Policy as data, copied onto the receipt | **Yes** | Enterprises and agents. Receipt is a return-type factor. |
| Python bindings | **Yes** (wave 1) | PyO3 on this crate. |
| CLI | **Yes**, as reference | Not the business. |
| Mount | **Yes**, as view representation | Not a third dest. [bigger.md](bigger.md). |
| Receipts in **in-toto / DSSE / Sigstore**, SBOM as **CycloneDX/SPDX of members** | **Yes**, don’t invent a format | Syft already SBOMs *packages*. We attest *this unpack under this policy*. Different predicate. |
| JS/TS, WASM, Go | Wave 2 | C ABI makes them cheap. Don’t start there. |
| Mojo / GPU / nvCOMP | **Backend, not the pitch** | Earn on multi-TB inspect/hash or dest=device. CRC32 is already GB/s on CPU (`crc32fast`). Selling “Mojo safe-unzip” is a learning-project headline. |
| Next-gen archive format | Later | Become the migration path after the engine is trusted. Cram is already in that graveyard-adjacent lane. |
| Formal proofs of the jail | After fuzz | oss-fuzz + a million hostile zips first. Coq later if a consumer demands it. |

### Findings, not scores

A 0–100 “risk score” will be bike-shed and gamed. Emit **structured findings**, like a compiler:

```
code: zip.overlap_bomb
severity: error          # error | deny | warn | info
member: payload.bin
detail: compressed ranges [0x1a00,0x4fff) and [0x1c00,0x5000) overlap
policy: default
```

Structural facts (path `..`, overlap, ratio, polyglot ZIP+PDF, local vs CD name mismatch, RECORD vs payload, symlink, ADS `:`) are the engine. “Looks malware” is YARA/EDR’s job; we MAY attach an optional classifier later, labeled as such. Distillr’s rule applies: don’t fake a judgment with a heuristic.

Polyglot / parser-disagreement is a **real differentiator** go-extract does not own. “This is a ZIP to us, a PDF to `file(1)`, and a tar to libarchive” is exactly the class PyPI spent 2025 killing in wheels.

### Mojo, honestly

The language exploration that started this repo is real. It is not co-equal to the primitive.

- Rust is the product because of *trust and penetration*, not because of Deflate GB/s.
- Mojo is allowed as a hydrate/hash backend for huge scientific/AI archives when dest is a buffer or a mount page cache, and when it beats CPU after copies. Same gate as nvCOMP: [backends.md](backends.md).
- Do not put Mojo on the user install path. Do not delay the C ABI for MAX.

If Mojo never ships, the product is intact. If Rust never ships, there is no product.

---

## Dual audience (without the network-effects slide)

Same engine, two façades.

**Classic:** `uv` / pip / npm / cargo installers, GitHub Actions artifact unzip, container layer unpack, OS extract, EDR “what did this zip contain.” They need: C ABI or language-native, no telemetry surprise, stable findings codes, boring performance, an audit story (fuzz corpus, advisory process).

**Agents:** MCP tool + Python. `inspect(archive) → tree + findings`. `extract(..., policy=)`. `mount(...)`. Receipt path for the session log. They need: JSONL, no TTY assumptions, inspect-without-write as the default.

Adoption is not magic. It is **one canonical dependent**. Until `uv` or a major agent runtime or Actions vendors us, we are a crate. Plan the first dependent explicitly; do not list six ecosystems as launch customers.

Closest existing thing to beat, not clone: **go-extract** (safety, sequential, Go) + **ripunzip** (speed, trusts the archive) + **Syft attest** (receipts for SBOMs, not unpacks) + **ratarmount** (mount, not policy). The hole is the composition plus inspect-as-API plus findings plus a C ABI.

---

## Expansion (in order, not a pile)

1. ZIP inspect + materialize, findings, Python, CLI JSONL. Fuzz the jail.
2. tar / gz / zst. Policy files. Receipts (unsigned first, Sigstore second).
3. C ABI. One classic dependent (even if it’s us, inside another of our tools).
4. Mount (ProjFS, then FUSE).
5. 7z native, jailed. MCP skill.
6. Optional nvCOMP/QAT/Mojo on fat inspect/hash. Content-addressed selective extract (`--only-hash`).
7. oss-fuzz continuous. Maybe formal jail.
8. Native tiled format only if hydrate of stock ZIP is maxed and we have users.

---

## What would make this *not* infrastructure

- Shipping a CLI that happens to have `--json` and calling it a platform.
- `--insecure` because a Unix tarball has a symlink.
- A risk score dashboard.
- Four language bindings before one consumer.
- Leading the README with Mojo or GPU.
- Inventing an attestation format.
- Competing with Syft on package graphs, or 7-Zip on RAR, or Cram on a new container.

Infrastructure looks like: **a crate + a `.so` + a findings spec + a policy schema + a receipt predicate + a public hostile-archive corpus**, and then someone who is not us calls it from a package manager.

## Open problems worth owning

- Maintainable defenses against the full ZipDiff set (and new types as the artifact grows).
- Overlapping-entry bombs at scale without a second full pass.
- Verified path-containment across POSIX + Windows prefix/8.3/ADS semantics.
- Standardizing an **extraction** in-toto predicate the industry can adopt (we may be first).
- Agent tool-calling + sandboxed/mount views that do not destroy performance.
- Mojo (or any accelerator) on integrity-heavy paths without putting the jail in an unaudited runtime.

Study: ZipDiff paper + artifact, `exarch` / `safe_unzip` / `openpack` SecurityConfigs, Landlock/seccomp, in-toto/SLSA/CISA 2026 SBOM elements. Then build the hybrid that closes the gaps none of those libraries fully close.
