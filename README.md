# sealr

[![CI](https://github.com/blisspixel/sealr/actions/workflows/ci.yml/badge.svg)](https://github.com/blisspixel/sealr/actions/workflows/ci.yml)

**One archive. One meaning. One verified tree.**

Sealr turns an untrusted archive into a verified, reusable tree capability.
It chooses one explicit interpretation, verifies every member, and returns
an evidence receipt. If verification fails, no tree is published.

Downstream tools consume the `VerifiedArchive` capability or materialized tree.
The original archive can be deleted after admission, so another parser cannot
silently give the same bytes a different meaning.

[Get started](docs/getting-started.md) · [Documentation](docs/index.md) · [Roadmap](ROADMAP.md) · [Releases](https://github.com/blisspixel/sealr/releases)

## Try it

Download the native Linux, macOS, or Windows archive from
[`v0.1.0-alpha.14`](https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.14)
and [verify the release](docs/release-verification.md) before running it.

```sh
# Inspect. View JSON goes to stdout; receipt JSON goes to stderr.
./sealr path/to/archive.zip

# Publish the verified tree into a new destination.
./sealr path/to/archive.zip --dest ./out
```

ZIP32 is the default. Select ZIP64 explicitly with `--format zip64`.
The destination must be new and its parent must already exist.
Exit `0` means verified, `2` means not admitted, and `3` means a failed destination effect.

To build from source, the repository pins Rust 1.98.0:

```sh
git clone https://github.com/blisspixel/sealr.git
cd sealr
cargo run --locked -p sealr-cli -- path/to/archive.zip
```

The [getting started guide](docs/getting-started.md) covers source builds,
canonical evidence verification, and a Rust example that deletes the source
before evaluating a wheel.

## See it work

Inspecting a two-member ZIP verifies both members without writing a destination:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/readme-walkthrough/sealr-inspect-allowed-terminal-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/readme-walkthrough/sealr-inspect-allowed-terminal-light.png">
  <img alt="Linux terminal summary of Alpha.14 verifying two ZIP members with no destination written." src="docs/assets/readme-walkthrough/sealr-inspect-allowed-terminal-light.png" width="1000">
</picture>

This is a rendered summary of verified CLI output. The
[full walkthrough](docs/walkthrough.md) includes parent-path rejection,
materialization, both themes, and reproduction instructions.

## Current status

Alpha.14 fixes incomplete Deflate stream admission and adds 24 reproducible
Unicode and streaming wheel fixtures. Native CI covers Linux, macOS, and Windows.
See the [release notes](docs/releases/v0.1.0-alpha.14.md) for the measured changes.

Sealr is a development preview for integration and adversarial testing. It has
no independent security audit or stable production release. Receipts are unsigned,
and admission does not establish that a program is safe to execute.
Alpha.14 is published on GitHub; it is not available on crates.io.

The [implementation and security boundary](docs/implementation.md) describes
supported formats, the explicit Linux worker, resource limits, and open gaps.

## What comes next

Make a real downstream acceptance decision depend on the verified capability.
The [separate validation project](https://github.com/blisspixel/sealr-validation)
exercises released Deepr, Primr, and Recon wheels. Deepr's existing wheel-content
check is the clearest next integration seam.

That work tests API, acquisition, compatibility, and failure handling before
more format breadth. The [roadmap](ROADMAP.md) and
[pilot contract](docs/adopter-pilot.md) define the remaining adoption, lifecycle,
stability, and independent-review gates.

## Go deeper

- [CLI usage and formats](docs/usage.md)
- [Rust API and evidence](docs/api.md)
- [Complete Python wheel installation handoff](crates/sealr/examples/pypa_installer_handoff/README.md)
- [Compatibility evidence](docs/wheel-producer-compatibility.md)
- [Security policy](SECURITY.md) and [threat model](docs/threat-model.md)
- [Contributing](CONTRIBUTING.md) and [documentation index](docs/index.md)

[Apache-2.0](LICENSE). Native archives include dependency license notices.
