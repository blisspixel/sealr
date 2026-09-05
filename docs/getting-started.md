# Getting started

Sealr verifies one archive under an explicitly selected interpretation. After admission, consume the materialized tree or the library capability.

## Install and run

The repository pins Rust 1.98.0 in `rust-toolchain.toml`; rustup selects it automatically.

The crate's current minimum supported Rust version is 1.98, declared through `rust-version`. CI selects exactly 1.98.0. Preview releases may raise this minimum only as a documented compatibility change; patch releases within a stable 1.x line will not.

Download the native preview archives, `SHA256SUMS`, and provenance from the [`v0.1.0-alpha.14` release](https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.14). Runnable checksum and provenance commands are in [release verification](https://github.com/blisspixel/sealr/blob/main/docs/release-verification.md). Every archive extracts the `sealr` CLI and independent `sealr-identity-verifier` companion.

```text
# After checksumming and extracting the native archive:
./sealr path/to/archive.zip
# View JSON goes to stdout; receipt JSON to stderr. Exit 0 means admitted.

# Materialize into a new destination below an existing parent.
./sealr path/to/archive.zip --dest ./out

# Alpha.14 can emit and independently check exact evidence.
./sealr path/to/archive.zip --view view.json --receipt receipt.json --canonical
./sealr-identity-verifier evidence \
  --view view.json --receipt receipt.json --source path/to/archive.zip
```

Authenticate the downloaded native archive before trusting either executable. Verifier exit `0` means the unsigned evidence is internally coherent and, when `--source` is present, bound to those observed source bytes. Coherent rejection evidence also verifies successfully. The companion does not reinterpret the archive, execute codecs, reconstruct the live layout root, authenticate a signer, or authenticate the release archive that contains it.

**After admission, do not reopen the archive.** Consume the materialized `--dest` tree, or a `VerifiedArchive` from the library, and never parse the original bytes again. The original archive is not an authority; a second parser is exactly where two tools' interpretations of the same bytes can diverge, which is the failure this project exists to prevent. Materializing to `--dest` and then reading that tree is the contract; materializing and continuing to trust the original ZIP is just unzip with extra steps.

To build from source instead of using the native binary:

```text
git clone https://github.com/blisspixel/sealr.git
cd sealr
cargo test --locked --workspace

# Inspect only. View goes to stdout; receipt goes to stderr.
cargo run --locked -p sealr-cli -- path/to/archive.zip

# Materialize into a new destination below an existing parent.
cargo run --locked -p sealr-cli -- path/to/archive.zip --dest ./out
```

The library and shipped CLI are Rust. CI runs native tests and release builds on Ubuntu, macOS, and Windows; the platform-specific materializers are release gates, not secondary ports. Some repository maintenance and release scripts are currently PowerShell because the same scripts run on all three GitHub-hosted runner families and the local release operator uses Windows. PowerShell is not a runtime dependency of `sealr`, but this is more scripting surface than the project should keep. Shared deterministic repository tasks are scheduled to move into a small Rust `xtask`, leaving only thin host-specific wrappers where an operating-system or operator boundary requires one.

The CLI exits `0` only when the archive is admitted and completely verified without an effect failure, `2` when admission or verification does not complete successfully, and `3` when admission succeeds but a requested destination effect fails. The inspectable view now includes the same interpretation, admission, verification, effect, and completeness axes as the receipt. The compatibility `verdict` maps incomplete verification and an admitted archive with a failed destination to `rejected`. Operational command-line errors use the normal Clap exit behavior.

## Use the Rust capability

This example evaluates a wheel from the capability alone. The source file is gone before evaluation begins:

```rust
use sealr::wheel::{evaluate_wheel, WheelEvaluation, WheelLimits};
use sealr::{apply_with_options, ApplyOptions, Policy, Request, Source, ZipInterpretationProfile};

fn main() {
    let policy = Policy::default_v1();
    let options = ApplyOptions::new()
        .with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
    let request = Request {
        source: Source::Path("demo-1.0-py3-none-any.whl".as_ref()),
        policy: &policy,
        dest: None,
    };
    let outcome = apply_with_options(request, &options);
    let archive = outcome.verified_archive().expect("admitted").clone();
    std::fs::remove_file("demo-1.0-py3-none-any.whl").expect("capability outlives the file");
    match evaluate_wheel("demo-1.0-py3-none-any.whl", &archive, WheelLimits::default()) {
        WheelEvaluation::Admitted { plan, identities, .. } => {
            println!("{} planned entries, artifact {}", plan.entries().len(), identities.artifact_sha256);
        }
        other => println!("refused: {other:?}"),
    }
}
```

The complete runnable version, including a hostile `..` container refused before any capability exists and an admitted container whose lying `RECORD` is denied with an exact finding, is `cargo run --locked -p sealr --example wheel_admission`. A second example, `cargo run --locked -p sealr --example same_digest_different_tree`, turns the archive-confusion research into a capability-path artifact: one archive digest, an identical archive tree under two filenames, distinct filename-bound identities, and a typed refusal for a third. [The write-up](same-digest-different-tree.md) explains why same digest is not same tree. The packaged [copyable PyPA `WheelSource` handoff](../crates/sealr/examples/pypa_installer_handoff/README.md) shows the complete supervised installer boundary using only public Sealr APIs.

## Choose a format

ZIP32 is the compatibility default. ZIP64 requires `--format zip64`; there is no automatic fallback. The [usage guide](usage.md) lists every explicit selection and its current limitations.

Continue with the [illustrated walkthrough](walkthrough.md), [API contract](api.md), or [complete wheel handoff](../crates/sealr/examples/pypa_installer_handoff/README.md).
