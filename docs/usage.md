# Usage

The current CLI is a thin facade over the ordinary in-process API or the
explicit fail-closed Linux supervisor.

## Inspect

```text
cargo run --locked -p sealr-cli -- path/to/archive.zip
```

The inspectable view is printed as pretty JSON on stdout. The unsigned receipt is printed as pretty JSON on stderr. No member files are created.

Both documents can be captured as files instead:

```text
cargo run --locked -p sealr-cli -- path/to/archive.zip --view evidence.view.json --receipt evidence.receipt.json
```

`--view` and `--receipt` each name a file that must not yet exist; the redirected stream stays silent and the bytes written are identical to the stream output. Both destinations are claimed before any evaluation or materialization effect, an existing file is never overwritten, and a refused claim exits `1` leaving the filesystem unchanged. Semantic exit codes are unaffected by redirection.

The same two operations are also explicit subcommands. Each subcommand resolves to the identical pipeline as the flag form, so streams, files, findings, and exit codes are byte-for-byte the same:

```text
cargo run --locked -p sealr-cli -- inspect path/to/archive.zip
cargo run --locked -p sealr-cli -- materialize path/to/archive.zip --dest ./out
```

`inspect` accepts no `--dest`; `materialize` requires one.

A caller-authored policy replaces the format's default policy:

```text
cargo run --locked -p sealr-cli -- path/to/archive.zip --policy my-policy.json
```

`--policy` names a JSON policy document. It is deserialized strictly — unknown fields are refused — then validated into a proven policy: string fields must match the exact supported vocabulary, the schema must be a known version, every cap must sit within the 2^53-1 double-safe ceiling, and the policy must compile. A refused policy never reaches evaluation: the CLI prints the exact typed reason on stderr and exits `2` with no JSON documents, matching the argument-error class. A validated policy that does not authorize the selected `--format` produces the ordinary evidence-bearing policy rejection. The receipt binds the caller policy's own id and digest.
 Top-level flags cannot be mixed with a subcommand, and the compatibility form (`sealr <ARCHIVE> [--dest ...]`) remains unchanged. One consequence of subcommand parsing: an archive file literally named `inspect` or `materialize` in the working directory must be passed with a path prefix (`./inspect`).

Portable raw ustar is selected explicitly and requires no filename-extension inference:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar --format tar-ustar
```

ZIP remains the compatibility default. Every `--format` value invokes exactly one parser and uses a policy that authorizes that selection.

Strict single-member gzip-wrapped portable ustar is a separate current-main in-process preview under policy v4:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar.gz --format tar-gzip-ustar
```

The suffix is illustrative only. `--format tar-gzip-ustar` performs the selection; the gzip FNAME field and source filename never select the parser or supply a member path.

Restricted raw POSIX PAX is a separate Alpha.11 in-process preview under policy v5:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar --format tar-pax
```

`--format tar-pax` accepts only `sealr.profile.tar.pax-portable.v1`: exact portable-ustar physical headers plus bounded local or global extensions containing only canonical `path` and `size` records. It is not automatic PAX detection or general TAR compatibility. Unknown keywords, links, sparse files, GNU records, base-256 numbers, mixed dialects, and recovery behavior fail closed.

Restricted raw old-GNU long-name TAR is a separate current-main in-process preview under policy v6:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar --format tar-gnu-longname
```

`--format tar-gnu-longname` accepts only exact old-GNU magic with at most one bounded pathname-only `L` carrier per member. `K` long links, sparse records, base-256 numbers, PAX records, mixed state, and orphan carriers fail closed.

The gzip-wrapped restricted PAX and GNU long-name compositions are separate current-main in-process previews under policy v7:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar.gz --format tar-gzip-pax
cargo run --locked -p sealr-cli -- path/to/archive.tar.gz --format tar-gzip-gnu-longname
```

Each composition accepts exactly one strict RFC 1952 gzip member whose bounded decoded output satisfies the complete frozen raw dialect. No composition detects, retries, or aliases another selection, and the gzip FNAME field never selects the parser or supplies a member path.

The zstd-wrapped portable ustar profile is a separate current-main in-process preview under policy v8, and the first promoted codec beyond Deflate:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar.zst --format tar-zstd-ustar
```

`--format tar-zstd-ustar` accepts exactly one strict RFC 8878 frame whose bounded decoded output is exact portable ustar. Skippable frames, dictionaries, windows beyond 8 MiB, concatenation, and trailing bytes fail closed.

The xz-wrapped portable ustar profile is a separate current-main in-process preview under policy v9, and the second promoted codec:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar.xz --format tar-xz-ustar
```

`--format tar-xz-ustar` accepts exactly one restricted XZ stream — one to 4096 LZMA2-only blocks, dictionaries at most 8 MiB, CRC32/CRC64/SHA-256 checks verified twice with check `None` denied — whose bounded decoded output is exact portable ustar. Other filter chains, stream padding, concatenation, and trailing bytes fail closed.

The bzip2-wrapped portable ustar profile is a separate current-main in-process preview under policy v10, and the third promoted codec:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar.bz2 --format tar-bzip2-ustar
```

`--format tar-bzip2-ustar` accepts exactly one restricted bzip2 stream — levels 1 to 9, one to 65,536 blocks, the bit-aligned container independently replayed with a footer shift-scan and a block-CRC chain fold — whose bounded decoded output is exact portable ustar. Bzip1, randomized blocks, empty streams, concatenated streams, and trailing bytes fail closed.

The Copy-only 7z container is a separate current-main in-process preview under policy v11, and the first Gate C structure step:

```text
cargo run --locked -p sealr-cli -- path/to/archive.7z --format 7z-copy
```

`--format 7z-copy` accepts exactly one raw-header, single-volume 7z whose every coder is Copy. Stock `7z a` output compresses the header itself and is rejected as unsupported — produce admissible archives with `7z a -m0=Copy -mhc=off` (or py7zr's `set_encoded_header_mode(False)`). Non-Copy coders, packed headers, external records, anti-items, and trailing bytes fail closed.

Strict ZIP64 is a separate current-main in-process preview under policy v3:

```text
cargo run --locked -p sealr-cli -- path/to/archive.zip --format zip64
```

`--format zip` never detects, retries, or aliases to ZIP64.

## Materialize

```text
cargo run --locked -p sealr-cli -- path/to/archive.zip --dest ./new-output
```

For portable ustar:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar --format tar-ustar --dest ./new-output
```

For gzip-wrapped portable ustar:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar.gz --format tar-gzip-ustar --dest ./new-output
```

For restricted raw PAX:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar --format tar-pax --dest ./new-output
```

For restricted GNU long-name TAR, the gzip compositions, and the promoted codec wrappers:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar --format tar-gnu-longname --dest ./new-output
cargo run --locked -p sealr-cli -- path/to/archive.tar.gz --format tar-gzip-pax --dest ./new-output
cargo run --locked -p sealr-cli -- path/to/archive.tar.gz --format tar-gzip-gnu-longname --dest ./new-output
cargo run --locked -p sealr-cli -- path/to/archive.tar.zst --format tar-zstd-ustar --dest ./new-output
cargo run --locked -p sealr-cli -- path/to/archive.tar.xz --format tar-xz-ustar --dest ./new-output
cargo run --locked -p sealr-cli -- path/to/archive.tar.bz2 --format tar-bzip2-ustar --dest ./new-output
```

For the Copy-only 7z container:

```text
cargo run --locked -p sealr-cli -- path/to/archive.7z --format 7z-copy --dest ./new-output
```

For strict ZIP64 in process:

```text
cargo run --locked -p sealr-cli -- path/to/archive.zip --format zip64 --dest ./new-output
```

The destination must not exist, and its parent must already exist. On Linux and macOS, the parent must have a trusted owner and either deny group and other writes or use trusted sticky-directory semantics. macOS extended ACLs fail closed. Windows requires a non-remote, writable NTFS parent with persistent ACLs and creates the stage with a protected effective-TokenUser-only DACL. sealr creates a random hidden stage beside the destination, retains it as a directory capability, and resolves every validated member component through no-follow directory handles. It publishes with the platform's native no-replace operation only after every member passes policy, expansion limits, CRC32 verification, and SHA-256 calculation.

On a normal rejection, the final destination does not appear. sealr attempts cleanup and retries once after failure, then records the final result. Setup failure after stage creation uses retained-handle cleanup first and a parent-relative retry. A killed process or two failed attempts can leave a hidden `.sealr-stage-*` directory; authenticated crash recovery is planned.

## Supervised Linux execution

The Linux native archive includes one authenticated helper and exact manifest.
Select it explicitly with an absolute path:

```text
sealr path/to/archive.zip \
  --worker-manifest /opt/sealr/libexec/sealr/sealr-worker.manifest
```

The CLI bounds and validates the fixed-name manifest, release version, helper
target, bootstrap ABI, byte length, and lowercase SHA-256, then selects only
the sibling `sealr-worker`. It does not search `PATH`. A selected worker must
establish the complete supervised boundary or the command exits unsuccessfully
without invoking the in-process payload path. macOS and Windows return
isolation unavailable if this option is selected.

The authenticated worker currently carries semantic-record v2 ZIP32 plans only. Combining `--format tar-ustar`, `--format tar-gzip-ustar`, `--format tar-pax`, `--format tar-gnu-longname`, `--format tar-gzip-pax`, `--format tar-gzip-gnu-longname`, `--format tar-zstd-ustar`, `--format tar-xz-ustar`, `--format tar-bzip2-ustar`, `--format 7z-copy`, or `--format zip64` with `--worker-manifest` returns a typed isolation-unavailable supervision error and exits `1`; it refuses before source access, never creates a destination effect, and never falls back to in-process verification. Worker support waits for later semantic records that bind each format-specific evidence model.

## Output contract

The view contains:

- source path, detected magic, and either `{ "sha256": "..." }` or `{ "status": "unavailable" }` when source bytes could not be read;
- policy id and digest;
- interpretation, admission, verification, effect, and view-completeness axes;
- the compatibility `verdict` adapter and whether materialization committed;
- structured findings;
- canonical member paths, kinds, sizes, the format-appropriate payload method, integrity fields, and SHA-256.

The axes are the precise record. `verdict: rejected` still covers denial, indeterminate source, and an admitted archive whose destination failed. Use `admission` and `effect` to tell those apart.

The receipt binds:

- source digest `{ "sha256": "..." }`, or `{ "status": "unavailable" }` on a pre-read failure;
- source snapshot kind (`private-file`, `memory-owned`, `memory-borrowed`, or `unavailable`);
- interpretation, admission, verification, effect, and view-completeness axes (`sealr.receipt.v2`);
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
| `0` | The archive was admitted. `wrote` says whether a destination was committed. |
| `2` | The archive was not admitted (denied, malformed, unsupported, or indeterminate). View and receipt are still emitted. |
| `3` | The archive was admitted but the requested destination effect failed. View and receipt still record `admission: admitted`. |
| `1` | The selected supervised boundary failed, a `--view` or `--receipt` output file could not be claimed, or a view or receipt stream could not be written. |
| Clap default | Command-line syntax or argument error. |

Source open and read failures currently become a structured rejection and therefore exit `2`. Receipts mark those failures as `interpretation: indeterminate` with an unavailable source digest. An admitted archive whose destination cannot be published exits `3`. The compatibility `verdict` remains `rejected` on that path so older adapters keep working.

## Current CLI surface

```text
Usage: sealr [OPTIONS] [ARCHIVE]
       sealr <COMMAND>

Commands:
  inspect      Interpret and verify without writing any member file
  materialize  Interpret, verify, and publish the tree into a new destination
  help         Print this message or the help of the given subcommand(s)

Arguments:
  [ARCHIVE]  Archive file

Options:
      --format <FORMAT>                  Exact container interpretation [default: zip] [possible values: zip, zip64, tar-ustar, tar-gzip-ustar, tar-pax, tar-gnu-longname, tar-gzip-pax, tar-gzip-gnu-longname, tar-zstd-ustar, tar-xz-ustar, tar-bzip2-ustar, 7z-copy]
      --dest <DEST>                      Materialize into a new directory below an existing parent
      --worker-manifest <ABSOLUTE_PATH>  Use the exact packaged Linux worker bound by this manifest
      --view <NEW_FILE>                  Write the view JSON to this exact new file instead of stdout
      --receipt <NEW_FILE>               Write the receipt JSON to this exact new file instead of stderr
      --policy <FILE>                    Validate and use this exact JSON policy document instead of the format's default policy
  -h, --help                             Print help
  -V, --version                          Print version
```

JSONL output, mounts, folder scans, force replacement, other isolation backends, and signing are roadmap items. They are not accepted flags today.

## Target CLI experience

Alpha.6 intentionally exposes the underlying JSON contract. It is useful for validation but is not the finished human interface.

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

The committed images are rendered terminal-style summaries derived from the current Alpha.6 JSON view and receipt streams. They remain paired with copyable commands and expected text. The visible summary uses a stable subset even though Alpha.6 includes outcome axes and identities in the underlying JSON. Whenever visible output changes, the walkthrough fixtures and transcripts must be regenerated from the locally built release-profile binary, semantic assertions must run first, and both light and dark screenshots must be recaptured.

Current CI regenerates fixture and native transcript inputs, checks their SHA-256 values against the manifest's Unix or Windows variant, and verifies the exact PNG hashes, asset set, format, dimensions, density, and metadata policy. A future pixel-level renderer comparison is deliberately not claimed.

Screenshots demonstrate released behavior. They are never the only instructions and are not updated to show planned commands before those commands exist.

## Design references

- [Command Line Interface Guidelines](https://clig.dev/) for human-first output, composable streams, useful help, and actionable errors.
- [`clap::ColorChoice`](https://docs.rs/clap/latest/clap/enum.ColorChoice.html) for the existing parser's terminal-aware `auto`, `always`, and `never` behavior.
- [`NO_COLOR`](https://no-color.org/) for the cross-tool environment convention.
