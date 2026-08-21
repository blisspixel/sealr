# Why this is practical now

Reviewed 2026-08-20.

The problem is old: archives encode content and filesystem topology, and extraction bugs repeatedly cross trust boundaries. What changed is that several pieces needed for a measurable boundary now exist together.

## Parser ambiguity has a reproducible taxonomy

The [USENIX Security 2025 ZipDiff paper](https://www.usenix.org/conference/usenixsecurity25/presentation/you) compared 50 ZIP parsers across 19 languages and classified 14 ambiguity types. The [public artifact](https://github.com/ouuan/ZipDiff) includes construction code for those types.

That gives sealr a concrete regression gate. The library does not need to run 50 parsers during extraction. It needs one documented interpretation and a fixture-backed rejection for known ambiguous structures.

## Reduced authority is available without a virtual machine

The Linux kernel's [Landlock interface](https://docs.kernel.org/userspace-api/landlock.html) lets an unprivileged process restrict its own ambient filesystem and network rights. It is stackable with existing access control and exposes a runtime ABI so software can report exactly which controls are available.

This makes a small worker process practical: open only the archive and destination capabilities, restrict the process, then read the first header. Landlock limits blast radius, while userspace path and quota invariants remain mandatory.

## Capability-oriented filesystem APIs are mature enough to use

[cap-std](https://github.com/bytecodealliance/cap-std) exposes filesystem operations relative to an open directory capability on Linux, macOS, FreeBSD, and Windows. Its [cap-fs-ext](https://docs.rs/cap-fs-ext/latest/cap_fs_ext/) companion adds portable no-follow directory and file opens.

That portable baseline is now in the materialization path: archive-derived names are accepted only as validated relative components, and each component is opened no-follow from a retained directory handle. Linux and Apple publication is handle-relative and exclusive. Windows uses isolated native adapters to atomically create and retain the stage, then publish it without replacement through the retained source and parent handles. Hostile concurrent mutation stress and reduced-authority process isolation remain open work.

## Small Rust properties can be machine checked

[Kani](https://model-checking.github.io/kani/) uses proof harnesses to check Rust safety and correctness properties, including panics, arithmetic overflow, and assertions. It is suited to the pure path and quota core, not to verifying an entire archive format or Deflate implementation.

This supports a precise claim: bounded path-containment and counter properties can be machine checked while codecs remain covered by tests, corpora, and fuzzing.

## Fuzzing a byte-oriented parser is routine

The [Rust Fuzz Book](https://rust-fuzz.github.io/book/) documents cargo-fuzz and libFuzzer targets that accept arbitrary byte slices. ZIP parsing, canonical names, and inspect-only application are natural targets, and the ZipDiff constructions provide high-value seeds.

## Receipts fit modern supply-chain workflows

Source digests, policy digests, structured findings, and a view digest can be returned for both allow and reject. in-toto, DSSE, Sigstore, SBOM formats, and GitHub artifact attestations provide established envelopes and signing workflows once sealr's unsigned receipt bytes are stable.

The immediate task is canonical, deterministic evidence. Signing comes after that.

## Acceleration is optional

Rust CPU processing is the product path. Mojo, GPU codecs, QAT, and specialized kernels are research options only after a correct performance baseline identifies a bottleneck. None may own path, policy, quota, verdict, or receipt decisions.

The [Modular repository](https://github.com/modular/modular) is public and uses Apache 2.0 with LLVM exceptions for repository contributions, but sealr does not depend on Mojo or MAX and makes no release decision based on their roadmap.

## The practical opportunity

The pieces now line up:

| Need | Available mechanism |
|---|---|
| Known differential classes | ZipDiff paper and constructions |
| Small trusted core | Safe Rust parser and jail plus isolated reviewed platform adapters |
| Reduced ambient authority | Landlock worker, later AppContainer |
| Path-relative output | Directory-capability filesystem API |
| Unknown-input discovery | cargo-fuzz with corpus seeds |
| Bounded proofs | Kani on path and quota properties |
| Auditable result | Versioned view and receipt |

The roadmap therefore prioritizes justified trust in one ZIP interpretation before format breadth or acceleration. See [ROADMAP.md](../ROADMAP.md).
