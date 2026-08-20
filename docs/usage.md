# Usage

The current CLI is a thin facade over `sealr::apply()`.

## Inspect

```powershell
cargo run --locked -p sealr-cli -- path\to\archive.zip
```

The inspectable view is printed as pretty JSON on stdout. The unsigned receipt is printed as pretty JSON on stderr. No member files are created.

## Materialize

```powershell
cargo run --locked -p sealr-cli -- path\to\archive.zip --dest D:\new-output
```

The destination must not exist. sealr creates a random hidden stage beside it, opens that stage as a directory capability, and performs member operations relative to that handle. It publishes with the platform's native no-replace move only after every member passes policy, expansion, CRC32, and digest checks.

On a normal rejection, the final destination does not appear. A killed process can leave a hidden `.sealr-stage-*` directory; automatic crash recovery is planned.

## Output contract

The view contains:

- source path, digest, and detected magic;
- policy id and digest;
- verdict and whether materialization committed;
- structured findings;
- canonical member paths, kinds, sizes, methods, CRC32, and SHA-256.

The receipt binds:

- source digest;
- policy id and digest;
- view digest;
- tool name and version;
- operating system, architecture, and actual kernel-jail status;
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
Usage: sealr.exe [OPTIONS] <ARCHIVE>

Arguments:
  <ARCHIVE>  Archive file

Options:
      --dest <DEST>  Request materialization into this directory
  -h, --help         Print help
  -V, --version      Print version
```

Policy files, JSONL output, receipt paths, mounts, folder scans, force replacement, backend selection, and signing are roadmap items. They are not accepted flags today.
