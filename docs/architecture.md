# Architecture

> This document describes the target architecture. The current two-crate implementation and its limitations are listed in [README.md](../README.md). Items such as `rawzip`, mmap, rayon, the expanded crate graph, hardware backends, and six-target distribution are not implemented yet.

Rust core is the security boundary for the jail, ZipDiff checks, limits, and materialization. Safe Rust is the default. The only current `unsafe` blocks are isolated in the Apple descriptor-ACL module and Windows native stage/publication module. Those small modules are the explicit platform-FFI audit boundary. Mojo is a later hydrate/hash module, never the path logic ([vision.md](vision.md), [backends.md](backends.md)).

Phase 0/1 is a Rust CPU **inspect + materialize** engine. Optional hardware backends plug into the same scheduler later. If well-formed ZIP materialize does not match `ripunzip` / Cram / Bandizip with the jail on, stop.

## Crate graph

```
sealr/                          # workspace root (this folder)
  crates/
    sealr-cli/                  # clap façade of the type
    sealr/                      # lib: Archive × Policy → tuple
    sealr-formats/              # ZIP via rawzip; later tar/gz/7z
    sealr-safety/               # jail, bomb limits, overlap, ZipDiff A1–C5, policy
    sealr-cpu/                  # deflate / crc / later zstd
    sealr-io/                   # mmap, prealloc, long paths, write bound
    sealr-bench/                # corpus hashes + harness vs 7z/ripunzip
```

`sealr` (lib) is one function with that type: always `AttestedReceipt × InspectableView`; `Materialization | Rejection` is the fork. `inspect` / `materialize` / `mount` are façades (view-only, write files, view-as-FS). Same interpretation for all three - do not grow a recovery/streaming parser (LibreOffice class of bug). The current CLI emits one pretty JSON view on stdout and one pretty JSON receipt on stderr. JSONL is a later surface.

`sealr-cli` is thin so benches call the lib without spawning. The process path stays for apples-to-apples vs `7z`.

Do **not** take `ripunzip` or the batteries-included `zip` crate on the hot path. `zip` 8.x is an interop/fuzz oracle. `rawzip` 0.5 is the structure parser: ZIP64, `Copy + Send` wayfinders, consumer supplies inflate and CRC.

Default features stay pure Rust (`flate2` + `zlib-rs`, `crc32fast`, `rawzip`) so `cargo dist` does not need nasm/cmake. `libdeflate` / ISA-L / C zstd are extra features.

Empty stubs `nvidia` and `mojo` exist so the feature names are real. They must not break the default build.

## Pipeline (one archive)

```
0. Drop ambient authority (Landlock/seccomp / AppContainer); pin archive + dest fds
1. Open + mmap (or cloned File if too big)
2. Parse central directory (CD-first; ZipDiff C2–C5)
3. Differential + safety pre-pass (A1–A5, B1–B4, overlap, jail, caps)
   → always: InspectableView + AttestedReceipt
   → if policy fail: Rejection (stop)
   → if no --dest: Rejection of writes (inspect); still return the tuple
4. Sequential mkdir of unique parents, sorted
5. rayon over file members, bounded write concurrency
6. Per member: inflate → bound uncompressed bytes → CRC → write
7. On CRC mismatch: delete the partial file, fail the member; receipt records it
```

## Hardened materialization path

The implemented materializer has one admission and publication sequence:

1. Require the destination parent to exist, canonicalize it once, and retain an opened directory capability. Do not create missing parents.
2. Refuse an existing destination. On Unix, require parent ownership by the effective user or root and reject group/other write unless the trusted owner has set sticky. On macOS, reject any extended ACL or descriptor ACL query failure.
3. Create a random 128-bit same-volume stage. Linux and macOS use mode `0700`, then verify effective-user ownership, mode, and the macOS descriptor ACL. Windows uses parent-rooted `NtCreateFile` with exclusive creation and reparse-point-open semantics, retains the handle, and omits delete sharing.
4. Create each canonical member with component-by-component no-follow directory capabilities and exclusive file creation. Windows additionally checks opened handles for the reparse-point attribute.
5. Publish without replacement. Linux uses `renameat2(RENAME_NOREPLACE)`, macOS uses `renameatx_np(RENAME_EXCL)`, and Windows calls `NtSetInformationFile` on the retained stage handle with the retained parent as `RootDirectory` and replacement disabled.
6. On ordinary rejection, attempt cleanup twice before constructing the receipt. Record setup, staging, publication, abort, and final cleanup outcomes. Two cleanup failures leave the stage for explicit recovery and report `cleanup: failed`.

Linux, macOS, and Windows are the supported materialization platforms. Other targets fail closed. The Windows stage inherits the parent ACL, so handle-bound publication prevents stage-name substitution but does not make a broadly writable parent private. Root, administrators, same-principal processes, filesystem-override capabilities, and debugging or handle-duplication rights remain outside the in-process boundary.

The receipt's `materialization` object records `backend`, `stage_mode`, `stage_creation_primitive`, `member_resolution`, `durability`, `publication_primitive`, `outcome`, and `cleanup`. These fields make the active control path inspectable. They do not authenticate an unsigned preview receipt.

Mount hydrates step 6 on `read` (view representation). Same interpretation everywhere.

Folder of archives: one global rayon pool after a global safety + mkdir pass if they share a dest. Non-recursive scan, like szips.

## Parallelism

| Layer | Granularity | Phase 1 |
|---|---|---|
| Outer | archives in a folder | rayon, or one pool of members across archives |
| Middle | ZIP members | rayon over pre-validated work items |
| Inner | Deflate blocks inside one member | **not v0** |
| Write | files into one dest dir | **bounded** (default 8 on Windows, 32 elsewhere) |

No tokio in Phase 1. `tokio::fs` is a blocking pool. Completion I/O (`compio`: io_uring + IOCP) is Phase 2 if writing a few huge files is the limiter.

NTFS serializes MFT updates. Unbounded `CreateFile` into one folder can be slower than modest concurrency. Sequential mkdir, then parallel files.

## ZIP surface

Current support: in-memory seekable ZIP32, EOCD + CD, methods Store (0) and Deflate (8), and validated data descriptors.

Phase 0.1 changes the source to bounded random-access I/O and keeps the same interpretation. ZIP64 remains rejected until its locator, EOCD, extra-field, offset, count, and corpus rules are implemented together.

Reject: encryption, spanned, overlapping compressed ranges, streamed zip (no CD), nested-archive recursion.

Deflate64, ZIP zstd (method 93), SFX prefixes: later, do not silently skip-as-success.

## Codecs (CPU)

1. Deflate + known uncompressed size + under a RAM gate (e.g. 64 MiB) + `libdeflate` feature: whole-buffer inflate.
2. Else: `flate2` + `zlib-rs`, streaming into the file.
3. Never ship `miniz_oxide` as the release default.

CRC with `crc32fast` **during** write. Do not re-read from disk. SHA-256 is calculated for every expanded member in the same streaming pass. Hash selection is a later policy surface.

libdeflate is not a streaming library. A 4 GiB member must not try to allocate 4 GiB.

## I/O

Phase 1, all three OSes:

- `memmap2` the archive up to a cap (default 4 GiB or 50% RAM); else per-worker `File`.
- Preallocate outputs ≥ 64 KiB (`fs4`).
- 256 KiB buffered writes. No per-file `fsync` unless `--fsync`.
- Windows: `\\?\` long paths, longPathAware manifest, `FILE_FLAG_SEQUENTIAL_SCAN` on large outputs.
- Do not mmap 50k output files.

Later: `compio` if benches show syscall overhead on fat members. DirectStorage is **not** a filesystem extractor (dest is D3D12; GPU path is GDeflate). See [backends](backends.md).

## Scheduler (the actual product, Phase 4)

Per member, after safety:

```
if dest is device memory:
    prefer nvCOMP (DE if present) for {lz4, snappy, deflate, gzip, zstd, gdeflate}
elif QAT live and codec in {deflate, gzip} and size >= S_qat:
    QAT
elif nvidia live and member >= S_gpu and codec in {lz4, snappy, zstd} and chunked:
    nvCOMP, overlap D2H with writer
else:
    CPU SIMD
never:
    GPU for lzma, tiny members, first-run CUDA on a small zip
```

Thresholds `S_*` are measured on *this* machine. Hard-coding 64 MiB is less wrong than “always GPU.” Print the decision.

## Ship

`cargo-dist`. Six targets: Windows / macOS / Linux × x86_64 / aarch64. Default binary: no C compiler. Optional `sealr-fast` artifact with libdeflate.

## Footguns

- `zip` crate `extract()` is sequential and not the parallel foundation.
- `testzip()` doubles CPU; CRC-on-write replaces it.
- Two archives, one dest, same `readme.txt`: define overwrite policy (default refuse; szips silently overwrote - we are stricter).
- Archive mmap is `unsafe` if another process truncates the file. Keep the `File` handle alive on Windows.
- Defender can dwarf inflate. Measure with it on.
- 7z solid archives are one decoder. Rayon over members is a lie.

Dependency versions are pinned in `Cargo.lock`; this document records the intended boundaries rather than a second dependency manifest.
