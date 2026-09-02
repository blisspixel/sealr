# Why this is practical now

Reviewed 2026-08-30.

The problem is old: archives encode content and filesystem topology, and extraction bugs repeatedly cross trust boundaries. What changed is that several pieces needed for a measurable boundary now exist together.

## Parser ambiguity has a reproducible taxonomy

The [USENIX Security 2025 ZipDiff paper](https://www.usenix.org/conference/usenixsecurity25/presentation/you) compared 50 ZIP parsers across 19 languages and classified 14 ambiguity types. The [public artifact](https://github.com/ouuan/ZipDiff) includes construction code for those types.

That gives sealr a concrete regression gate. The library does not need to run 50 parsers during extraction. It needs one documented interpretation and a fixture-backed rejection for known ambiguous structures.

## Reduced authority is available without a virtual machine

The Linux kernel's [Landlock interface](https://docs.kernel.org/userspace-api/landlock.html) lets an unprivileged process restrict its own ambient filesystem rights and, on newer ABIs, selected network rights. It is stackable with existing access control and exposes a runtime ABI so software can report exactly which controls are available.

This makes a small worker process practical. The current explicit x86_64 Linux path has a trusted supervisor create and retain the immutable archive snapshot, open the destination parent, and create the private stage, then give the worker only bounded source and stage capabilities. The worker closes unrelated inherited descriptors, installs Landlock ABI 3 and measured seccomp restrictions before source transfer, and never receives publication authority. This reduces authority for supported ZIP32 payload verification, stage writes, and later reads; structural planning remains in the supervisor. It is not a general process, network, IPC, same-user, or production-containment claim.

## Capability-oriented filesystem APIs are mature enough to use

[cap-std](https://github.com/bytecodealliance/cap-std) exposes filesystem operations relative to an open directory capability on Linux, macOS, FreeBSD, and Windows. Its [cap-fs-ext](https://docs.rs/cap-fs-ext/latest/cap_fs_ext/) companion adds portable no-follow directory and file opens.

That portable baseline is now in the materialization path: archive-derived names are accepted only as validated relative components, and each component is opened no-follow from a retained directory handle. Linux and macOS publication is handle-relative and exclusive. Windows uses isolated native adapters to admit local NTFS, apply and verify an owner-private stage security descriptor during atomic creation, then publish without replacement through the retained source and parent handles. Hostile concurrent mutation stress and reduced-authority process isolation remain open work.

## Small Rust properties can be machine checked

[Kani](https://model-checking.github.io/kani/) uses proof harnesses to check Rust safety and correctness properties, including panics, arithmetic overflow, and assertions. It is suited to the pure path and quota core, not to verifying an entire archive format or Deflate implementation.

This supports a precise claim: bounded path-containment and counter properties can be machine checked while codecs remain covered by tests, corpora, and fuzzing.

## Fuzzing a byte-oriented parser is routine

The [Rust Fuzz Book](https://rust-fuzz.github.io/book/) documents cargo-fuzz and libFuzzer targets that accept arbitrary byte slices. ZIP parsing, canonical names, and inspect-only application are natural targets, and the ZipDiff constructions provide high-value seeds.

## Receipts fit modern supply-chain workflows

Source digests, policy digests, structured findings, and a view digest can be returned for both allow and reject. in-toto, DSSE, Sigstore, SBOM formats, and GitHub artifact attestations provide established envelopes and signing workflows once sealr's unsigned receipt bytes are stable.

Separate outcome axes, named immutable snapshot domains, typed policy compilation, format-specific IRs, and preview tree identities now exist. Alpha.11 added `sealr.archive-ir.tar-pax.v1` and `sealrTreeV5` for restricted raw POSIX PAX while preserving the format-neutral content identity. Alpha.12 released the additional profile and tree families through Copy-only 7z. Inspect and materialize consume one IR. The current API wraps a completely verified IR and its exact snapshot in an opaque `VerifiedArchive`, allowing bounded canonical-member reads without reopening the source or running another structural parser. Explicit exact paths can be retained under independent bounds during the original verification stream. A separate identity verifier checks every committed profile and tree family through Copy-only 7z without depending on Sealr or executing codecs. It also verifies live RFC 8785 view v2 and receipt v3 pairs against an observed source, every registered interpretation profile, known default-policy identities, outcome consistency, and an independently reconstructed format-neutral content root. External adoption, stable lock semantics, and authenticated-envelope verification follow. The supervised worker consumes the ZIP32 tree contract and refuses unsupported selections without fallback.

## Acceleration is optional

Rust CPU processing is the product path. Mojo, GPU codecs, QAT, and specialized kernels are research options only after a correct performance baseline identifies a bottleneck. None may own path, policy, quota, verdict, or receipt decisions.

The [Modular repository](https://github.com/modular/modular) is public and uses Apache 2.0 with LLVM exceptions for repository contributions, but sealr does not depend on Mojo or MAX and makes no release decision based on their roadmap.

## The practical opportunity

The pieces now line up:

| Need | Available mechanism |
|---|---|
| Known differential classes | ZipDiff paper and constructions |
| Small trusted core | Safe Rust parser and jail plus isolated reviewed platform adapters |
| Reduced ambient authority | Explicit x86_64 Linux Landlock ABI 3 plus seccomp worker for supported ZIP32 operations; other selections fail closed |
| Path-relative output | Directory-capability filesystem API |
| Unknown-input discovery | cargo-fuzz with corpus seeds |
| Bounded proofs | Kani on path and quota properties |
| Auditable result | Versioned view and receipt |

The roadmap expands format breadth only through narrow profiles on the same boundary. Alpha.12 completed the planned GNU long-name, gzip-composition, promoted-codec, and Copy-only 7z steps, so parser breadth is now frozen. Alpha.13 released supervised prefix parity, which lets the wheel evaluator run through the strongest Linux backend without fallback. It also released the [copyable public-API-only `WheelSource` handoff](../crates/sealr/examples/pypa_installer_handoff/README.md) and exact [Poetry 2.4.2 repository fixture](../tests/poetry-consumer/README.md). The next sequence is an independently maintained dependent that consumes the admitted capability and does not reopen the archive. Measured compatibility, stable API and identity review, and independent security review continue alongside it. See [usefulness.md](usefulness.md) and [ROADMAP.md](../ROADMAP.md).
