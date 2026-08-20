# Competitive landscape

Fast extract is already split by workload. A rayon unzip is crowded. A scheduler that picks CPU SIMD vs GPU *per member*, with szips-grade safety and honest benches, is not.

Snapshot: 2026-08-19. Numbers are upper bounds on *that* machine, not extract-to-NTFS promises.

**Second pass (same day):** more of the market exists than the first scan listed. **Cram**, **Bandizip parallel ZIP**, **NanaZip**, **ripzip**, **go-extract**, **ExtractNow**, **qzip**, **dtrx**. The full thesis is still unoccupied. Phase 1 as a standalone product is not. See [who-else.md](who-else.md).

## Who already wins which row

| Workload | Who wins | Notes |
|---|---|---|
| Many independent ZIP members | **ripunzip** (Rust + rayon) | Chromium ASAN zip ~3.85 GB: 9 s vs unzip 94 s (Linux); 52 s vs 7z 165 s (Windows). Author: not universal. HDD/AV dominate. |
| One huge `.gz` | **rapidgzip** | Paper: 5.6–8.7 GB/s @ 128 cores. README later: 12–24 GB/s with index. `pigz` does **not** parallel-decompress. |
| Single-core Deflate | **igzip / libdeflate** | ~1 GB/s in-memory Silesia. Codec numbers, not unzip. |
| Solid `.7z` | **7-Zip** | Only if the compressor wrote multiple LZMA2 chunks. 1-thread-created archive stays 1-thread. LZMA decode ~30–100 MB/s/thread. |
| Ordinary `.zst` | `zstd` ~0.8 GB/s/core | `pzstd` only helps `pzstd`-framed files. |
| Unified CLI (zip+tar+7z) | **ouch** | Their own benches: sometimes *slower* than `tar`. Not the speed bar. |
| Game assets → VRAM | DirectStorage + GDeflate | Dest MEMORY → CPU on purpose. |
| GPU gzip CLI | **nvlzcat** | Linux, one stream, NVIDIA, nvCOMP 5.2+. |
| Safe unzip | safezip / safe_unzip / **szips** | Slow-and-safe corner. |
| Windows default | Explorer Compressed Folders | Single-thread, the floor. PeaZip corpus: Explorer 17.2 s vs 7-Zip ZIP 8.9 s. |

**7-Zip does not use the GPU.** [ip7z/7zip#129](https://github.com/ip7z/7zip/issues/129) is Windows graphics-preference confusion.

## Tool matrix (extract CLIs)

| Tool | Parallel | GPU | Safety story |
|---|---|---|---|
| ripunzip | Per ZIP member | No | `enclosed_name`; no bomb product |
| ouch | Across archives; not a rayon unzip | No | Optional landlock; not bombs |
| 7-Zip | LZMA2 chunks if encoder cooperated | **No** | Mature path/symlink hardening; not bomb caps |
| unzip / bsdtar | Sequential | No | Some slip hardening; streaming ≠ bombs |
| rapidgzip | Speculative Deflate blocks | No | `--verify` CRC is opt-in and slower |
| nvlzcat | One gzip on GPU | NVIDIA | Not Zip Slip relevant |
| szips | Sequential Python | No | Jail + caps + CRC - the DNA to keep |

Rust libraries: `zip` crate is sequential `extract()` and had CVE-2025-29787 (symlink slip, patched 2.3.0). `sevenz-rust` is unmaintained; **sevenz-rust2** is what ouch uses. `rawzip` is the structure parser we want.

## Empty niche

1. **Scheduler + `--why`**, not another codec.
2. **Honest benches** as a first-class artifact: named workload rows, dest = `/dev/null` *and* NVMe *and* NTFS-many-files, CRC on vs off, AV on vs off. Compare 7z, unzip, ripunzip, ouch, rapidgzip, nvlzcat. If GPU loses, print that.
3. **szips safety on the fast path** (jail, overlap, caps, CRC default-on).
4. **Folder-of-archives** with the right algorithm per archive (ZIP members, gzip stream, 7z chunks) in one binary.
5. **Windows extract that is not Explorer and not “install 7-Zip.”** A `sealr --dest` that is safe-by-default and faster on many-member ZIP is a *wedge*, not the product. The product is the tuple. A GPU checkbox is not.

## Do not bother

- `zip` + rayon clone of ripunzip
- ouch-style unified UX as the differentiator
- Replacing 7-Zip as the format Swiss army knife (RAR/ISO/NSIS)
- Parallel gzip that isn’t as good as rapidgzip
- GPU Deflate for 50k tiny files to NTFS
- GPU LZMA / solid 7z
- nvlzcat-but-Windows as the whole product
- Safety-only Python wrapper (szips already was)
- Mojo-only CLI
- Beating memcpy charts of stored data

## What “new” looks like

Not interesting: `ZipArchive` + rayon + libdeflate, one hyperfine on a 200 MB zip.

Interesting:

```
sealr --source ./folder --dest ./out
  inspect: 8 zips (12k small deflate), 1 4 GB .gz, 1 solid 7z (2 chunks), 1 pzstd .zst
  schedule the right backend per shape
  safety: jail, caps, CRC on
  print: backend, GB/s, why-not-GPU
  same corpus vs 7z / unzip / ripunzip / ouch / rapidgzip
```

## Primary sources

- [ripunzip benchmark and design notes](https://github.com/GoogleChrome/ripunzip)
- [Rapidgzip paper](https://doi.org/10.1145/3588195.3592992)
- [7-Zip release history](https://7-zip.org/)
- [pzstd framing and benchmarks](https://github.com/facebook/zstd/blob/dev/contrib/pzstd/README.md)
- [DirectStorage 1.1 architecture](https://devblogs.microsoft.com/directx/directstorage-1-1-now-available/)
- [nvCOMP nvlzcat documentation](https://docs.nvidia.com/cuda/nvcomp/nvlzcat.html)
- [PeaZip compression and extraction benchmark](https://peazip.github.io/peazip-compression-benchmark.html)
