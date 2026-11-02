# Usage

The current CLI is a thin facade over the ordinary in-process API or the
explicit fail-closed Linux supervisor.

## Inspect

```text
cargo run --locked -p sealr-cli -- path/to/archive.zip
```

When stdout and stderr are both terminals, and the command sets neither `--view`, `--receipt`, nor `--json`, sealr prints one summary line on stderr and leaves stdout empty. A pipe, a redirect, or `--json` prints the view as pretty JSON on stdout and the unsigned receipt as pretty JSON on stderr. `--json` forces those two documents on a terminal. It is not the future one-envelope machine output described under Target CLI. No member files are created.

Both documents can be captured as files instead:

```text
cargo run --locked -p sealr-cli -- path/to/archive.zip --view evidence.view.json --receipt evidence.receipt.json
```

`--view` and `--receipt` each name a file that must not yet exist; the redirected stream stays silent and the bytes written are identical to the stream output. Adding `--canonical` (valid only together with both file flags) switches the files to the canonical RFC 8785 lineage — `sealr.view.v2` and `sealr.receipt.v3` — where the file bytes are exactly the digested bytes with no trailing newline: `sha256sum` of the view file reproduces the receipt's `view_digest`, and `sha256sum` of the receipt file is the receipt's externally nameable digest. Semantic exit codes are unchanged, and a canonicalization failure discards both files and exits `1`, never silently falling back to the default lineage. See the [evidence encoding contract](evidence-encoding.md). Both destinations are claimed before any evaluation or materialization effect, an existing file is never overwritten, and a refused claim exits `1` leaving the filesystem unchanged. Semantic exit codes are unaffected by redirection.

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

Strict single-member gzip-wrapped portable ustar is a separate Alpha.10 in-process preview under policy v4:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar.gz --format tar-gzip-ustar
```

The suffix is illustrative only. `--format tar-gzip-ustar` performs the selection; the gzip FNAME field and source filename never select the parser or supply a member path.

Restricted raw POSIX PAX is a separate Alpha.11 in-process preview under policy v5:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar --format tar-pax
```

`--format tar-pax` accepts only `sealr.profile.tar.pax-portable.v1`: exact portable-ustar physical headers plus bounded local or global extensions containing only canonical `path` and `size` records. It is not automatic PAX detection or general TAR compatibility. Unknown keywords, links, sparse files, GNU records, base-256 numbers, mixed dialects, and recovery behavior fail closed.

Restricted raw old-GNU long-name TAR is a separate Alpha.12 in-process preview under policy v6:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar --format tar-gnu-longname
```

`--format tar-gnu-longname` accepts only exact old-GNU magic with at most one bounded pathname-only `L` carrier per member. `K` long links, sparse records, base-256 numbers, PAX records, mixed state, and orphan carriers fail closed.

The gzip-wrapped restricted PAX and GNU long-name compositions are separate Alpha.12 in-process previews under policy v7:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar.gz --format tar-gzip-pax
cargo run --locked -p sealr-cli -- path/to/archive.tar.gz --format tar-gzip-gnu-longname
```

Each composition accepts exactly one strict RFC 1952 gzip member whose bounded decoded output satisfies the complete frozen raw dialect. No composition detects, retries, or aliases another selection, and the gzip FNAME field never selects the parser or supplies a member path.

The zstd-wrapped portable ustar profile is a separate Alpha.12 in-process preview under policy v8, and the first promoted codec beyond Deflate:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar.zst --format tar-zstd-ustar
```

`--format tar-zstd-ustar` accepts exactly one strict RFC 8878 frame whose bounded decoded output is exact portable ustar. Skippable frames, dictionaries, windows beyond 8 MiB, concatenation, and trailing bytes fail closed.

The xz-wrapped portable ustar profile is a separate Alpha.12 in-process preview under policy v9, and the second promoted codec:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar.xz --format tar-xz-ustar
```

`--format tar-xz-ustar` accepts exactly one restricted XZ stream — one to 4096 LZMA2-only blocks, dictionaries at most 8 MiB, CRC32/CRC64/SHA-256 checks verified twice with check `None` denied — whose bounded decoded output is exact portable ustar. Other filter chains, stream padding, concatenation, and trailing bytes fail closed.

The bzip2-wrapped portable ustar profile is a separate Alpha.12 in-process preview under policy v10, and the third promoted codec:

```text
cargo run --locked -p sealr-cli -- path/to/archive.tar.bz2 --format tar-bzip2-ustar
```

`--format tar-bzip2-ustar` accepts exactly one restricted bzip2 stream — levels 1 to 9, one to 65,536 blocks, the bit-aligned container independently replayed with a footer shift-scan and a block-CRC chain fold — whose bounded decoded output is exact portable ustar. Bzip1, randomized blocks, empty streams, concatenated streams, and trailing bytes fail closed.

The Copy-only 7z container is a separate Alpha.12 in-process preview under policy v11, and the first Gate C structure step:

```text
cargo run --locked -p sealr-cli -- path/to/archive.7z --format 7z-copy
```

`--format 7z-copy` accepts exactly one raw-header, single-volume 7z whose every coder is Copy. Stock `7z a` output compresses the header itself and is rejected as unsupported — produce admissible archives with `7z a -m0=Copy -mhc=off` (or py7zr's `set_encoded_header_mode(False)`). Non-Copy coders, packed headers, external records, anti-items, and trailing bytes fail closed.

Strict ZIP64 is a separate Alpha.10 in-process preview under policy v3:

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

On a normal rejection, the final destination does not appear. sealr attempts cleanup and retries once after failure, then records the final result. Setup failure after stage creation uses retained-handle cleanup first and a parent-relative retry. A killed process or two failed attempts can leave a hidden `.sealr-stage-*` directory. [Abandoned-stage ownership](abandoned-stage.md) says that name is not authority. This command does not store a retention record. A library caller can pass `ApplyOptions::with_stage_retention_path` and later read that file with `read_stage_retention`, or keep `Outcome::stage_retention` from a returned outcome. `recover_abandoned_stage` removes that one directory. A process killed before the file is written still has nothing to present.

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

Source open and read failures currently become a structured rejection and therefore exit `2`. Receipts mark those failures as `interpretation: indeterminate` with an unavailable source digest. An admitted archive whose destination cannot be published exits `3`. The compatibility `verdict` remains `rejected` on that path so older adapters keep working. The terminal summary follows the exit class, so that same case says `not written`.

When stderr is a terminal and neither `--json` nor `--receipt` is set, the summary is printed on stderr even if stdout is piped. The view JSON still goes to stdout, and no receipt is written to stderr. Both terminals print only the summary. Non-terminal stderr keeps the view on stdout and the receipt on stderr. `--color always` also selects the summary when stderr is redirected. `--json` forces the view and receipt JSON. `--machine` is a separate stdout document and is not colored.

## Current CLI surface

`sealr --help` is the source of the flag list. Help wraps on word boundaries, and hyphenated format names stay intact. The purpose line is `Admit an untrusted archive into a new directory, or refuse it, with a receipt.` Formats are listed once, in groups, after the flags. Invalid `--format tar-gz` exits 2 and lists `tar-gzip-ustar`, `tar-gzip-pax`, and `tar-gzip-gnu-longname`.

JSONL output, mounts, folder scans, force replacement, other isolation backends, and signing are roadmap items. They are not accepted flags today.

## Summary, color, and machine output

The summary is one line. `allowed` covers exit 0. `rejected` covers exit 2. `not written` covers exit 3. A destination that already exists uses this fixed sentence rather than the library detail:

```text
not written: materialize.exists (destination already exists; sealr never replaces). Choose a new --dest path.
```

A hinted refusal without a member looks like `rejected: format.magic (observed xz stream). Try: --format tar-xz-ustar`. A hinted refusal with a member looks like `rejected: tar.feature_unsupported member PaxHeader (PAX extended header). Try: --format tar-gzip-pax`. Extra findings use `(+3 more; --json for all)` when three findings remain beyond the first. Plurals are `1 member` and `1 finding`. Displayed member names and details replace control characters with `?` and cap the member at 120 characters. JSON stays exact.

Color paints the verdict word, the finding code, the detail, and `Try`. Green is allowed, red is rejected, and yellow is not written. The code is bold and the detail is dim. There is no truecolor and no brand teal. Only stderr summary text is colored.

After a written admitted tree, and only when stderr is a terminal, one dim line follows:

```text
content tree 850eb7fb25938114 (preview identity, unsigned)
```

Those 16 characters are the start of `identities.content.sealrTreeV1`. The line is absent for inspect-only runs, refusals, exit 3, redirected stderr, and `--json`.

`--machine` writes `sealr.command-result.v1` to stdout. `category` is `semantic` when an outcome exists, and otherwise `policy`, `worker`, `output`, or `usage`. `evaluated` is false and `semantic` is null when evaluation never happened. Process exit codes stay as they are today. `semantic_exit` preserves 0, 2, or 3 when a later output write fails. Consumers branch on `schema`, `category`, and the typed axes. An unknown schema or category is not an admission. The known extra category `usage` is not an admission either. Clap's own parse errors do not emit the envelope. Missing source is a semantic outcome with finding code `source.io`.

The multi-line `gate` layout below is design notation, not current output:

```text
$ sealr gate package.zip

ADMITTED  package.zip
Verified: complete
Files:    47
Expanded: 812 KiB
Evidence: package.zip.sealr.json
```

Job-oriented verbs such as `gate`, `verify`, `materialize`, and `explain` remain future names. They must not freeze the current combined verdict under a more polished surface. Progress and diagnostics never corrupt machine stdout. There is no telemetry, implicit network request, update check, or hidden write. UI formatting remains a thin layer over the Rust library and adds no second parser or policy path.

## Documentation capture policy

The [walkthrough](walkthrough.md) owns the screenshots and reproduction commands.
The images are rendered terminal summaries of a measured view and receipt,
captured from a Linux run with shell notation. Their displayed version matches
the receipt of this source tree. They remain
paired with copyable commands and expected text. The README shows one overview
image; detailed scenarios belong in the walkthrough.

Regenerate fixtures and transcripts from the release-profile binary, run the
semantic assertions, and recapture both themes whenever visible output changes.
The renderer binds the displayed version to the measured receipt. CI checks
fixture and native transcript hashes and every PNG's hash, format, dimensions,
density, size, and metadata policy. A pixel comparison is not claimed.

Screenshots demonstrate released behavior and never replace text instructions
or show planned commands as though they already exist.

## Design references

- [Command Line Interface Guidelines](https://clig.dev/) for human-first output, composable streams, useful help, and actionable errors.
- [`clap::ColorChoice`](https://docs.rs/clap/latest/clap/enum.ColorChoice.html) for the existing parser's terminal-aware `auto`, `always`, and `never` behavior.
- [`NO_COLOR`](https://no-color.org/) for the cross-tool environment convention.
