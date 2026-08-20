# sealr

[![CI](https://github.com/blisspixel/sealr/actions/workflows/ci.yml/badge.svg)](https://github.com/blisspixel/sealr/actions/workflows/ci.yml)

```text
Untrusted archive x policy -> materialization | rejection
                                           x receipt
                                           x inspectable view
```

sealr is a high-assurance boundary between an untrusted archive and anything that is allowed to become a filesystem capability.

It is not a safer unzip. The product is the decision, evidence, and constrained view around extraction.

> Status: pre-alpha Phase 0. The ZIP inspection core is useful for development and adversarial testing. It is not ready to protect a production host from arbitrary hostile archives. The limitations below are security boundaries, not fine print.

## Why this exists

Agents, package systems, upload handlers, and data pipelines routinely receive archives from outside their trust boundary. Archive formats encode filesystem topology as well as content, and different parsers can assign different meanings to the same bytes.

The 2025 ZipDiff study compared 50 ZIP parsers across 19 languages, found that almost every parser pair disagreed somewhere, and classified 14 ambiguity types. Its public artifact includes constructors for those cases. That makes parser agreement a testable security property instead of an assumption.

sealr therefore has one operation:

```rust
pub fn apply(request: Request<'_>) -> Outcome
```

Every outcome contains:

- an allow or reject verdict;
- a structured view of the interpretation;
- a receipt binding the source, policy, view, tool, and environment;
- materialized files only after the entire archive has passed.

## What works today

The current Rust implementation supports classic ZIP32 archives with stored or Deflate members.

- CD-first parsing with exact EOCD, central-directory, local-header, and data-descriptor agreement.
- Rejection of hidden stream records, unreferenced layout bytes, overlapping records, spanned archives, ZIP64, encryption, unsupported methods, and mismatched flags or metadata.
- Pure lexical path jailing for absolute paths, parent traversal, ADS colons, reserved Windows names, trailing dots and spaces, control characters, empty components, depth, duplicates, case-fold collisions, and file/directory topology conflicts.
- Strict filename handling. Invalid UTF-8 and non-ASCII CP437 names are rejected until the canonical Unicode path design is complete.
- Bounded source reads, metadata, file count, declared and actual member size, total expanded size, and declared and actual compression ratio.
- Streaming Deflate, CRC32, and SHA-256 calculation without buffering an expanded member in memory.
- Capability-relative, same-volume staging with 128-bit random names. Members use create-new handles, and the requested destination is published with native no-replace semantics only after every member passes.
- Deterministic JSON view and unsigned receipt on allow and reject paths.
- A pinned 5,927-file, 14-class ZipDiff construction gate with an aggregate corpus digest, exact finding-count expectations, and an explicit 73-file control allowlist.
- An adversarial unit suite, strict Clippy, rustfmt, documentation checks, cross-platform tests, and cargo-deny policy in CI.

## Security limitations

The following work must land before a production-readiness claim:

- The ZipDiff gate covers its pinned known constructions. It does not prove that future or previously unknown parser ambiguities cannot exist.
- The archive itself is currently buffered in memory, with a default 512 MiB input cap. Expanded members stream.
- Unicode normalization and CP437 decoding are not implemented, so non-ASCII member paths fail closed.
- Destination member operations are contained beneath a `cap-std` directory handle. Per-component no-follow enforcement and hostile concurrent stage-mutation stress tests, especially Windows reparse points, still need dedicated closure.
- A killed process can leave a hidden staging directory. Normal error returns clean it up.
- Landlock, seccomp, AppContainer, and other process sandboxes are not implemented. Receipts report `kernel_jail: unavailable`.
- Receipts are unsigned, and their JSON digest is deterministic for the current Rust structs but is not yet RFC 8785 JCS.
- ZIP64, TAR, compressed TAR, gzip, zstd, and 7z are not implemented.
- There is no external security audit or supported release.

See [SECURITY.md](SECURITY.md), [the threat model](docs/threat-model.md), and [the invariants](docs/invariants.md) before integrating the crate.

## Try it

The repository pins Rust 1.98.0 in `rust-toolchain.toml`; rustup selects it automatically.

```powershell
git clone https://github.com/blisspixel/sealr.git
cd sealr
cargo test --locked --workspace

# Inspect only. View goes to stdout; receipt goes to stderr.
cargo run --locked -p sealr-cli -- path\to\archive.zip

# Materialize into a destination that does not already exist.
cargo run --locked -p sealr-cli -- path\to\archive.zip --dest D:\out
```

The CLI exits `0` when policy allows the archive and `2` when it rejects it. Operational command-line errors use the normal Clap exit behavior.

## Design rules

- One interpretation serves inspect and materialize. There is no recovery parser.
- Policy is data and its digest is part of the receipt. There is no `--insecure` mode.
- Unknown or unsupported structure fails closed.
- Declared sizes never authorize allocation or output. Actual bytes are counted as they arrive.
- Rejection is evidence-bearing. It still returns a view and receipt.
- Format breadth and acceleration come after the boundary is measurable.

## What comes next

The next milestone remains the Phase 0.1 trust gate, not another archive format. Its ZipDiff construction gate and portable capability materializer are now executable. The highest-risk remaining materialization work is per-component no-follow enforcement, reparse and symlink race stress, crash recovery, and receipt reporting. Portable Unicode collision semantics, bounded random-access input, fuzz and property suites, small-core proofs, and a reduced-authority worker follow before TAR begins.

The order and exit criteria are in [ROADMAP.md](ROADMAP.md).

## Research basis

- [My ZIP isn't your ZIP, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [ZipDiff artifact and construction generator](https://github.com/ouuan/ZipDiff)
- [Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
- [cap-std capability-oriented filesystem API](https://github.com/bytecodealliance/cap-std)
- [Kani Rust Verifier](https://model-checking.github.io/kani/)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)

## Documentation

| Document | Purpose |
|---|---|
| [ROADMAP.md](ROADMAP.md) | Ordered work, gates, and rationale |
| [docs/vision.md](docs/vision.md) | Product contract |
| [docs/api.md](docs/api.md) | Rust and JSON contract |
| [docs/policy.md](docs/policy.md) | Policy schema and defaults |
| [docs/findings.md](docs/findings.md) | Stable finding-code registry |
| [docs/threat-model.md](docs/threat-model.md) | Adversary and ZipDiff classes |
| [docs/invariants.md](docs/invariants.md) | Non-negotiable safety properties |
| [docs/differentials.md](docs/differentials.md) | Single-interpretation rules and corpus |
| [docs/sandbox.md](docs/sandbox.md) | Reduced-authority process design |
| [docs/attestations.md](docs/attestations.md) | Receipt and signing design |
| [docs/assurance.md](docs/assurance.md) | Tests, fuzzing, proofs, and audits |
| [docs/architecture.md](docs/architecture.md) | Target crate and runtime architecture |
| [docs/usage.md](docs/usage.md) | Intended CLI surface |

## License

[MIT](LICENSE)
