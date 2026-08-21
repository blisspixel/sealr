# Usage

The current CLI is a thin facade over `sealr::apply()`.

## Inspect

```text
cargo run --locked -p sealr-cli -- path/to/archive.zip
```

The inspectable view is printed as pretty JSON on stdout. The unsigned receipt is printed as pretty JSON on stderr. No member files are created.

## Materialize

```text
cargo run --locked -p sealr-cli -- path/to/archive.zip --dest ./new-output
```

The destination must not exist, and its parent must already exist. On Linux and macOS, the parent must have a trusted owner and either deny group and other writes or use trusted sticky-directory semantics. macOS extended ACLs fail closed. Windows requires a non-remote, writable NTFS parent with persistent ACLs and creates the stage with a protected effective-TokenUser-only DACL. sealr creates a random hidden stage beside the destination, retains it as a directory capability, and resolves every validated member component through no-follow directory handles. It publishes with the platform's native no-replace operation only after every member passes policy, expansion limits, CRC32 verification, and SHA-256 calculation.

On a normal rejection, the final destination does not appear. sealr attempts cleanup and retries once after failure, then records the final result. Setup failure after stage creation uses retained-handle cleanup first and a parent-relative retry. A killed process or two failed attempts can leave a hidden `.sealr-stage-*` directory; authenticated crash recovery is planned.

## Output contract

The view contains:

- source path, detected magic, and either the archive digest or the documented unavailable sentinel when source bytes could not be read;
- policy id and digest;
- verdict and whether materialization committed;
- structured findings;
- canonical member paths, kinds, sizes, methods, CRC32, and SHA-256.

The receipt binds:

- source digest, or the documented unavailable sentinel on a pre-read failure;
- policy id and digest;
- view digest;
- tool name and version;
- operating system, architecture, and actual kernel-jail status;
- whether materialization was requested, the component-resolution guarantee, staging and durability modes, stage-creation and publication primitives, and cleanup outcome;
- on Windows, non-sensitive storage-policy observations and stage-ACL verification;
- verdict, write status, signature status, and findings.

Receipts are currently unsigned and the kernel jail is unavailable.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Policy allowed the archive. `wrote` says whether a destination was committed. |
| `2` | The archive or materialization request was rejected. View and receipt are still emitted. |
| Clap default | Command-line syntax or argument error. |

Source open and read failures currently become a structured rejection and therefore exit `2`.

## Current CLI surface

```text
Usage: sealr [OPTIONS] <ARCHIVE>

Arguments:
  <ARCHIVE>  Archive file

Options:
      --dest <DEST>  Materialize into a new directory below an existing parent
  -h, --help         Print help
  -V, --version      Print version
```

Policy files, JSONL output, receipt paths, mounts, folder scans, force replacement, backend selection, and signing are roadmap items. They are not accepted flags today.

## Target CLI experience

Alpha.2 intentionally exposes the underlying JSON contract. It is useful for validation but is not the finished human interface.

After the semantic outcome model stabilizes, the default terminal experience should be concise and task-oriented:

```text
$ sealr gate package.zip

ADMITTED  package.zip
Verified: complete
Files:    47
Expanded: 812 KiB
Evidence: package.zip.sealr.json
```

This is design notation, not current output. The exact fields depend on the versioned interpretation, admission, verification, effect, and completeness types.

The target CLI follows these rules:

- human output is short, scannable, and explains the next action;
- `--json` emits one versioned machine envelope on stdout;
- progress and diagnostics never corrupt machine stdout;
- color defaults to terminal-aware `auto`, honors `NO_COLOR`, and is never required to understand a result;
- redirected output has no animation or control sequences;
- exit classes distinguish denial, indeterminate input, failed effects, and command misuse;
- no telemetry, implicit network request, update check, or hidden write occurs;
- Linux, macOS, and Windows help and output receive equal golden coverage;
- UI formatting remains a thin layer over the Rust library and adds no second parser or policy path.

Job-oriented verbs such as `gate`, `verify`, `materialize`, and `explain` follow the semantic types. They must not freeze the current combined verdict under a more polished surface.

## README capture policy

The committed images are rendered terminal-style summaries derived from the current alpha.2 JSON view and receipt streams. They remain paired with copyable commands and expected text. They were first captured for alpha.1; the visible walkthrough output did not change in alpha.2. Whenever visible output changes, the walkthrough fixtures and transcripts must be regenerated from the locally built release-profile binary, semantic assertions must run first, and both light and dark screenshots must be recaptured.

Current CI regenerates fixture and transcript inputs, checks their SHA-256 values against the committed manifest, and verifies the exact PNG hashes, asset set, format, dimensions, density, and metadata policy. A future pixel-level renderer comparison is deliberately not claimed.

Screenshots demonstrate released behavior. They are never the only instructions and are not updated to show planned commands before those commands exist.

## Design references

- [Command Line Interface Guidelines](https://clig.dev/) for human-first output, composable streams, useful help, and actionable errors.
- [`clap::ColorChoice`](https://docs.rs/clap/latest/clap/enum.ColorChoice.html) for the existing parser's terminal-aware `auto`, `always`, and `never` behavior.
- [`NO_COLOR`](https://no-color.org/) for the cross-tool environment convention.
