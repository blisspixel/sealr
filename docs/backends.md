# Backends

Runtime priority is not implementation order. **Default is always CPU.** Everything else is optional, dynamically loaded, and allowed to return `Unavailable`.

## 0. CPU SIMD (always)

The product. If this does not beat `7z` / `unzip` / `ripunzip` on the published corpus, GPU work is theater.

| Codec | Library | Notes |
|---|---|---|
| Deflate / gzip / ZIP method 8 | `zlib-rs` (default, pure Rust streaming); `libdeflate` (optional, whole-buffer); ISA-L later | Never miniz_oxide in release |
| Store | memcpy | Never GPU |
| Zstd | C libzstd behind a feature; `ruzstd` only for no-C builds | One ZIP member = one frame; member rayon is enough |
| LZ4 | `lz4_flex` until a corpus needs C lz4 | First GPU-comparison codec |
| CRC32 | `crc32fast` | Same pass as write |
| Apple | Compression.framework / LZFSE on Darwin, plus the ZIP walker | No Metal inflate |
| AMD CPU | AOCL-Compression worth probing on Zen | CPU, not hipCOMP |

Parallel gzip of one stream (`rapidgzip`-style) is a later experiment, not Phase 1. `pigz` does not parallel-decompress.

## 1. Intel QAT (optional, Linux servers)

The only hardware inflate that speaks **stock** gzip/ZIP Deflate into **host** memory. No PCIe round-trip.

Probe, use for large Deflate/Gzip members, fall back to ISA-L. Operationally heavier than SIMD (firmware, huge pages). Do not require it.

**Intel IAA is not a ZIP backend.** Decompress rejects distances > 4 KiB. RFC 1951 windows are 32 KiB. Easy to misuse; don’t silently send stock ZIP there.

## 2. NVIDIA nvCOMP (optional)

C API from Rust, dynamically loaded `nvcomp.dll` / `libnvcomp.so`. NVIDIA GPUs only (SDK EULA). The CLI must still have material functionality without it.

| Path | Codecs | When |
|---|---|---|
| **DE** (fixed-function copy engine) | Snappy, LZ4, Deflate, Gzip | **B200 / B300 / GB200 / GB300 only.** Not GeForce RTX 50. Chunks ≤ 4 MiB on B200. Special alloc flags or it silently uses SMs. |
| **SM** | Those plus Zstd, GDeflate, Cascaded, … | Consumer NVIDIA, including RTX 50 |

`nvlzcat` (nvCOMP 5.2+) is Linux, one gzip stream, the honest GPU gzip demo. It is not ZIP-to-folder.

Several nvCOMP decompressors assume **valid input** from the same compressor. Untrusted ZIP still CRCs on the host. Do not disable OOB checks to chase GB/s on untrusted members.

License: redistribute the blob inside a larger app, NVIDIA GPUs only, no copyleft-infection of the SDK. Offer a build without the blob.

## 3. Mojo (research, not a product backend in 2026)

Verdict: **later.**

Mojo 1.0 shipped 11 Aug 2026; compiler went Apache 2.0 on 18 Aug. GPU host APIs (`DeviceContext`) moved into **MAX** (Community License). Windows is **WSL-only**. Shared libs work on Linux/macOS (`@export` + `abi("C")` + `initialize_runtime()`), with undocumented Modular runtime rpath. Apple unified-memory zero-copy can be silently wrong. You cannot target Blackwell DE from a Mojo kernel.

**12-month bet:** (1) independently-chunked **LZ4** kernel vs CPU vs nvCOMP, after H2D+D2H; (2) optional **comptime-specialized** CRC/BLAKE3 for a *fixed* member-size class. Success is beating CPU SIMD on fat buffers, byte-identical. If that loses, publish it and stop.

Agent Python is **PyO3 on Rust**, not Mojo’s Python interop. Comptime does **not** move policy into Mojo.

Do not put `pixi` / MAX on the user install path. Do not block Windows. Do not promise NVIDIA+AMD+Apple in a feature table.

If portable GPU must live in the crate graph, **CubeCL** (Rust `#[cube]` → CUDA/HIP/Metal/SPIR-V, MIT/Apache) is the more honest product candidate. wgpu is a later fallback, a bad first bitstream.

## 4. Not backends for extract-to-folder

| Thing | Why not |
|---|---|
| DirectStorage + GDeflate | Dest MEMORY → CPU by design. Dest BUFFER → D3D12. Format is not ZIP method 8. |
| hipCOMP | Preview, nvCOMP 2.2-era, not production, no DE |
| Metal “lossless” | Texture bandwidth, not Deflate |
| Home-grown LZMA-on-GPU | Serial dictionary, no DE, 7-Zip already owns the chunked case |
| GPU as default | Cold CUDA context ruins a 200 ms unzip |

## Decision rules (copy onto the scheduler)

**May offload**

1. Destination is device memory.
2. Datacenter DE present, codec in {LZ4, Snappy, Deflate, Gzip}, DE-capable buffers, chunks ≤ 4 MiB.
3. One or few members, each ≳ 64–256 MiB uncompressed, independently chunked, CPU inflate is the bottleneck.
4. QAT present, large Deflate/Gzip, Linux.

**Must not offload**

1. Filesystem tree of many small files.
2. Stock ZIP with thousands of members < ~1–4 MiB.
3. LZMA / xz / 7z / bzip2.
4. Need strict validation of untrusted bitstreams (nvCOMP valid-input-only).
5. No NVIDIA GPU, or CUDA would be loaded just for this.
6. Already saturating disk with CPU inflate.
7. macOS / AMD GPU / iGPU-only as of 2026.

When `--gpu` is on, print what you actually got: `nvcomp-sm` vs `nvcomp-de (B200)` vs `unavailable`. Do not advertise RTX 50 hardware unzip.

Primary references: [nvCOMP](https://docs.nvidia.com/cuda/nvcomp/), [Intel QATzip](https://github.com/intel/QATzip), [Intel Query Processing Library](https://github.com/intel/qpl), [DirectStorage 1.1](https://devblogs.microsoft.com/directx/directstorage-1-1-now-available/), and [Mojo GPU fundamentals](https://docs.modular.com/mojo/manual/gpu/fundamentals/).
