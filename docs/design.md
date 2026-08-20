# Design: what sealr believes

The **product** is a high-assurance unarchive *engine* other systems depend on. The CLI is the reference implementation. Ambition: [vision.md](vision.md). Mount/project dest: [bigger.md](bigger.md). Jail: [safety.md](safety.md).

This file is the physics and the engineering beliefs. It is not “we are a nicer unzip.”

The beliefs do not depend on the name, but the name is **sealr**.

## 1. “Fast extract” is several products sharing a verb

A ZIP of 50,000 tiny Deflate members, one 8 GB `.gz`, a solid `.7z`, and a GDeflate pack headed for VRAM are different bottlenecks. A bench that does not name the row is advertising.

The rows that matter:

| Workload | Real bottleneck | GPU? |
|---|---|---|
| Many independent ZIP members | CPU across members, then filesystem create | Almost never |
| One huge gzip/zstd stream | Serial codec, or speculative/indexed parallel decode | Only as a fat buffer, not unzip-to-folder |
| Solid 7z / LZMA2 | Dictionary + whether the encoder emitted chunks | No |
| 50k tiny files to NTFS | Metadata + AV minifilters | Theater |
| Dest = GPU memory | PCIe carrying compressed bytes | Yes, by design |

If we only ever beat `unzip` on a 200 MB zip in `/tmp`, we built a weekend clone of `ripunzip`.

## 2. The product is the boundary, not a codec (and not a scheduler)

The type is `UntrustedArchive × Policy → (Materialization | Rejection) × AttestedReceipt × InspectableView`. Codecs, rayon, and GPU are how *hydrate* happens after the boundary said yes. A scheduler that prints `--why` is an implementation detail of hydrate, not the product. [vision.md](vision.md), [now.md](now.md).

CPU SIMD is the default hydrate because it already saturates consumer NVMe on the workloads people actually extract. GPU, QAT, and Mojo earn a dispatch per member. They do not get a README checkbox until `--why` exists.

## 3. Safety is on the fast path, or it never lands

szips already has the part most fast unzip tools skip: path jail, zip-bomb limits, CRC, chunked I/O, no nested recursion. Fast CLIs (`ripunzip`, `rapidgzip`) trust the archive. Safe CLIs (`safezip`) are slow. The hole is both.

Jail, overlap reject, reserved names, and CRC-during-write are not `--strict`. Caps may be raised by flags. The jail may not.

szips’ `testzip()` then extract then SHA-256-from-disk is three passes. One inflate → bound bytes → CRC → write is stricter per byte and faster. Do not port the pre-pass.

## 4. Hardware decompress is real, and it is not GeForce unzip

True in 2026:

- NVIDIA **datacenter** Blackwell Decompression Engine (B200 / B300 / GB200 / GB300) for Snappy, LZ4, Deflate, Gzip - fused with the copy engine, destination typically device memory.
- Intel **QAT** for stock gzip/ZIP Deflate into **host** RAM on Linux servers.
- DirectStorage + GDeflate into **D3D12 resources**. When dest is system memory, Microsoft decompresses on the CPU on purpose.

False as a product claim:

- RTX 50 “hardware unzip.” Consumer Blackwell does not expose the DE.
- AMD RDNA lossless DE. hipCOMP is an unoptimized nvCOMP 2.2 preview.
- Apple GPU lossless inflate. Compression.framework is CPU. Metal “lossless” is textures.
- nvCOMP “600 GB/s” as extract-to-NTFS. That number is batched device buffers.

Video decode had a standard bitstream and a dest that *is* the GPU. Archives have a hostile bitstream and a dest that *is* the disk.

## 5. Rust is the product. Mojo is a lab.

Rust owns CLI, formats, jail, I/O, shipping a Windows/macOS/Linux binary. Mojo 1.0 (August 2026) is a real portable-SIMT language. It is also WSL-only on Windows, GPU APIs live in MAX (not Apache stdlib), and you will not beat nvCOMP+DE on NVIDIA by writing LZ4 in Mojo.

CubeCL is the more honest *in-crate* portable GPU bet if we ever need one kernel in the product graph. DirectStorage is not an unzip-to-folder API.

## 6. Honesty is a feature

Every public number names: corpus, dest (`/dev/null` vs NVMe vs NTFS-many-files), CRC on/off, backend actually used (`cpu`, `nvcomp-sm`, `nvcomp-de`, `qat`, `unavailable`). If GPU loses, print that.

Do not disable Defender as a “optimization.” Measure with it on.

## Sources

The curated research record is split across [architecture](architecture.md), [backends](backends.md), [formats](formats.md), [safety](safety.md), [competitive](competitive.md), and [usage](usage.md). The [roadmap](../ROADMAP.md#primary-research-behind-the-order) links the primary sources that determine implementation order.
