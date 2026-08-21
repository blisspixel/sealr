# Who else already does this?

Second research pass, 2026-08-19. First pass: [competitive.md](competitive.md).

**Short answer:** pieces exist. Nobody ships the whole thing. Phase 1 by itself is not worth shipping as a product.

**Library competitor to study first, not to fear:** [exarch](https://github.com/bug-ops/exarch) (`exarch-core` 0.6.0). TAR/ZIP/7z, fluent `SecurityConfig`, Python/Node, `deny(unsafe_code)` (not `forbid`; graph still pulls C codecs). Caps on; README vs docs.rs disagree on the total default (10 GiB vs 500 MB). **Adoption is vapor** (~5 stars, hundreds of crates.io downloads). **Does not** implement ZipDiff 14-type deny, overlap bombs, inspect-as-API, receipts, or mount. Steal the typestate config; do not vendor it.

The other 2026 “secure extract” crates (`safe_unzip`, `openpack`, `archmeld`, `pulith-archive`, `archive-core`) exist and almost none have reverse dependencies. **go-extract** is still the only safety library with a real organization behind it.

## The test

“Basically this” means all of:

1. Fast extract (CPU parallel where the format allows)
2. Folder of mixed archives, one command (szips UX)
3. Path jail + zip-bomb caps **on by default**
4. Optional hardware (GPU / QAT) only when it wins, and it **says so**
5. Windows, as a binary people actually run

Anything that only hits (1) is a weekend clone.

## Closest living tools

| Tool | What they actually are | Hits | Misses |
|---|---|---|---|
| **[Cram](https://github.com/lukr54/cram)** 1.1.0 (16 Aug 2026) | Rust multi-format archiver. Real extract scheduler: rayon ZIP, 7z over LZMA2 resets, sequential tar/RAR. Drive-aware worker counts (SSD vs HDD). Zip-Slip in one place. Declared-size bomb checks. Their kernel-tree zip: 1.89 s vs 7-Zip 7.21 s. | 1, some 2, some 3 | No GPU. No `--why`. CRC not universal. Folder-of-archives is not the verb. Energy is `.cram` format + Studio GUI. Author notes an LLM wrote most of it - judge the benches, not the origin. |
| **[Bandizip](https://en.bandisoft.com/bandizip/)** 7.45 | The Windows GUI people install when 7-Zip feels slow. **Parallel ZIP extract**, 2–6× on SSD. Explicitly **off** on HDD, encrypt, split, symlink. Batch GUI + CLI. | 1 (ZIP), 2 (GUI), Windows | Proprietary, ads. No bomb product. “Hardware acceleration” is CPU cores. ZIP-only parallelism. |
| **[NanaZip](https://github.com/M2Team/NanaZip)** 6.5 / 7.0 | 7-Zip for Windows 11 (Store). Smart extract, MOTW, extra codecs (zstd/brotli/lz4). Same speed as 7-Zip. | 2 (context menu), Windows | No rayon ZIP. No GPU. Hardening ≠ zip-bomb policy. Still had 2026 CVEs. |
| **[ripunzip](https://github.com/GoogleChrome/ripunzip)** | Google Chrome team. Rayon unzip of **one** zip. Chromium ASAN: 9 s vs unzip 94 s. URI/range unzip-while-download. | 1 (ZIP) | One archive. No bombs. No folder. No GPU. |
| **[ripzip](https://github.com/velopack/ripzip-rs)** | Velopack. mmap + rayon + zlib-rs, CRC on every file, path jail, ZIP64, zstd method 93. Extract 1.2–3.8× vs `zip` crate. | 1, CRC, jail | ZIP only. Tiny adoption. No bombs. No folder. |
| **[ouch](https://github.com/ouch-org/ouch)** | Unified `ouch d a.zip b.tar.gz`. Path jail in 0.8.1. Optional `OUCH_MAX_DECOMPRESSED_BYTES` **env, off**. | 2 (multi-file, not dir scan) | Not the speed king (own benches lose to `tar`). Bombs off. |
| **[ExtractNow](https://extractnow.com/)** | Dedicated Windows “extract every archive in this folder.” Recursive. | 2 | No speed story. No safety product. Sketchy installer history. |
| **[go-extract](https://github.com/hashicorp/go-extract)** | HashiCorp. Caps: 100k files, 1 GiB, 60 s. Zip-Slip. Library + `goextract`. | 3 | Sequential. One archive. Not fast. |
| **[exarch](https://github.com/bug-ops/exarch)** | Closest *API shape* (TAR/ZIP/7z, Py/Node, SecurityConfig). Sequential. Tiny adoption. | 3, some bindings | No ZipDiff, no receipts, no mount, no overlap deny; `unsafe` slogan is crate-local |
| **[openpack](https://github.com/santhreal/openpack)** | ZIP/JAR/APK/IPA/CRX reader, BOM-safe limits. | 3 (ZIP-family) | Reader, not a general engine |
| **szips** | Private predecessor prototype. Folder + jail + caps. | 2, 3 (ZIP only) | Sequential Python. 7z shell-out **has no jail**. |
| **dtrx / atool / patool** | Unix “do the right extraction” wrappers. | 2 | Shell out to unzip/7z. Not fast. |

7-Zip, WinRAR, PeaZip, Keka, The Unarchiver, Windows Explorer, `tar.exe` (libarchive): format Swiss army or OS default. Not this thesis.

## Hardware / GPU - is there an ffmpeg for zip?

**No.** Closest analogs, none are unzip-to-folder:

| Thing | What it is |
|---|---|
| **nvlzcat** | NVIDIA’s GPU gzip CLI. Linux, **one stream**, not ZIP. |
| **qzip** | Intel QAT `gzip` stand-in. Linux servers with QAT silicon. |
| **DirectStorage + GDeflate** | Games → VRAM. Dest = RAM → **CPU on purpose**. |
| **nvCOMP** | Library. 600 GB/s is device buffers. |
| **zlib-accel** | `LD_PRELOAD` so existing gzip hits QAT. Not a product. |
| **Compressonator `-PackageBRLG`** | GPU unpack of a **custom** `.brlg`, not zip. |

7-Zip does not use the GPU. hipCOMP has no CLI. Intel IAA cannot inflate stock ZIP (4 KiB window vs 32 KiB).

## What would make Phase 1 pointless

Shipping `zip` + rayon + a hyperfine on a 200 MB zip. That cell is taken by ripunzip, Bandizip, Cram’s ZIP path, ripzip, and Go `fastzip` (GitLab Runner).

Phase 1 is only justified as **the CPU backend inside the real product**, with jail+caps on, benches vs **Bandizip + Cram + ripunzip + 7-Zip** on named corpora, Defender on.

## What would still be worth doing exceptionally well

The hole after this pass is the **type**, not a faster `x`:

```
UntrustedArchive x Policy
  -> (Allowed { wrote } | Rejected) x Receipt x View
```

exarch/go-extract do not return that tuple. Cram/Bandizip do not. ZipDiff is the paper nobody in that table implements.

exarch is the library to absorb, not clone. Cram/Bandizip eat a vague fast unzip. go-extract is the safety floor we have to match *and then be strict about differentials*. ZipDiff is the paper nobody in that table implements.

## Bar to bother

Do it only if we are willing to:

1. Beat or tie **Cram and Bandizip** on many-member ZIP to NVMe, CRC on, Defender on.
2. Keep szips caps **on** in those benches (and still win, or print the cost of safety).
3. Make `x ./folder` the headline, not `x one.zip`.
4. Ship `--why` before a GPU checkbox.
5. Treat GPU as a backend that is allowed to lose in public.

If that list feels like too much, don’t start. A “Rust unzip” is a crate, not a project.
