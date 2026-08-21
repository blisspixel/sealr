# Think bigger

Read-only projection is **not a competing product**. It is a future representation of the admitted tree described in [semantic-model.md](semantic-model.md), not a current alpha.2 feature.

The current public outcome remains:

`UntrustedArchive x Policy -> (Allowed { wrote } | Rejected) x Receipt x View`

Cram and Bandizip own “fast files on disk.” GPU unzip-to-NTFS is physics-wrong. The view factor is how we change the destination without abandoning the type.

The research kept repeating one sentence. Treat it as the product constraint:

> Creating 50,000 files is slower than decompressing them. GPU inflate only wins if the destination is not the filesystem.

So the bigger move is **change the destination.** Unzip is a materialize button on a data plane whose default is *don’t materialize*.

---

## Why “exceptionally well unzip” still isn’t big

Video got hardware decode because:

- there was a standard bitstream (H.264)
- the dest **was the GPU/display**
- nobody wanted a folder of frames

Lossless archives got the opposite: hostile bitstreams (Deflate window, solid 7z) and a dest that is **CreateFile × N**, then Defender, then you delete the zip. A scheduler that picks libdeflate vs nvCOMP is still serving that dest. You will spend a year beating Bandizip by 15% on a named zip and the world will not move.

Bigger means one of these, not a faster inner loop:

1. The bytes never become files.
2. You control a bitstream hardware wants.
3. You sit in front of a consumer that isn’t Explorer (GPU training, agents, restore).

---

## Swing 1 (the one I’d build): the archive *is* the working tree

**Do not extract. Project.**

Point at a zip / tar.zst / 7z / OCI layer / dataset dump. User (and every process) sees a directory. Directory listing is metadata from the central directory. `open`/`read` hydrates that member - SIMD, QAT, nvCOMP, or memcpy - into the process that asked, or into a page cache you own. Writes go to an overlay. `export` / `materialize` is the old unzip, for the cases that actually need files.

Windows-first via **ProjFS** (what VFS-for-Git uses). Linux FUSE / macOS FSKit later. This is the native Win11 version of ratarmount, which is excellent and Python/FUSE/Linux-shaped. Archive-mount GUIs (Pismo, WinArchiver, 7-Zip “open as folder”) exist and are slow, sequential, and unsafe.

Now the sealr scheduler has a dest that can win:

| Hydrate dest | GPU interesting? |
|---|---|
| 50k tiny files to NTFS | Never (today’s trap) |
| One 2 GB member into a process | Maybe |
| Fat member into a CUDA/Direct3D buffer | Yes (this is DirectStorage, generalized) |
| Many small reads from a build/`node_modules` zip | CPU + metadata, still no GPU, but you skipped CreateFile |

Safety moves from “pre-pass then explode” to **policy at open()**: jail, caps, no symlinks, overlap reject, CRC on first hydrate. An agent can see the tree without detonating a zip bomb. That is strictly more interesting than szips.

Honest measurement (fitr DNA): `doctor` prints, on *this* box, hydrate GB/s vs extract-all GB/s vs Defender-on extract. If extract-all is faster for a 12-file zip, say so and offer `--materialize`.

**Not new as a sentence** (ratarmount, squashfuse, archivemount, Cram ProjFS). New as a *Windows-native, SIMD/GPU hydrate, policy-at-open, measured* data plane whose CLI is `mount`, not `x`.

Working shape:

```
sealr mount downloads/thing.zip  D:\work\thing     # ProjFS projection
sealr mount ./folder_of_archives D:\work\pool      # union
sealr open  thing.zip --file payload.bin --to gpu  # no FS
sealr materialize D:\work\thing  D:\out            # old unzip, still jailed
sealr doctor thing.zip                             # why GPU/CPU/mount
```

Phase-1 CPU ZIP decoder still has to exist. It just isn’t the product.

## Swing 2: dest = the consumer (training / analytics plane)

NVIDIA already did the money version: **DALI** (images/video to GPU), **KvikIO / GPUDirect Storage**, nvCOMP, WebDataset tars. ZipFlow (2026) is a compiler for “compressed over PCIe, inflate on GPU, query on GPU.”

The unoccupied slice is **not** “DALI for jpeg.” It’s a general **archive → consumer** runtime that doesn’t care if the consumer is PyTorch, a game, DuckDB, or a process mmap:

- NVMe read compressed
- optional DE/QAT/CPU inflate
- deliver into GPU buffer, Arrow batch, or anonymous mmap
- never a tree of files unless asked

This is Magnum IO as an independent product. Hard: you are in NVIDIA’s house, competing with DALI on the path they care about. Worth it only if the *source* side is the world’s actual dumps (random ZIP/tar.zst of mixed shit, not WebDataset-by-construction) and the *dest* side is more than CUDA.

Mojo kernels finally have a dest that matches ORNL’s memory-bound result: independent LZ4 blocks into device memory, no D2H.

## Swing 3: own the bitstream (the historically big one)

Hardware unzip of RFC 1951 is a trick. Hardware **video** worked because the format was designed for it.

The 10-year play: a container that is

- independently chunked (LZ4 / GDeflate-class tiles / zstd seek table)
- CPU-readable with a fallback
- DE- and DirectStorage-friendly when those exist
- has a **writer people will use** (that’s the actual product)

Then you are HandBrake, not VLC. DirectStorage tried this for games (GDeflate). nvCOMP tries it for HPC. Nobody won “the zip of 2030.” Cram is attempting a new container (`.cram`) for dedup, not for hardware inflate.

Do **not** start here. Format adoption is a graveyard. Design Swing 1 so a native tiled method is a backend, and only invent the format when hydrate of stock ZIP is maxed out and you have users.

## Swing 4 (distribution, not physics): agent ingress

Every coding agent and MCP tool now unpacks untrusted zips (repos, datasets, “here’s the dump”). They all reinvent Zip Slip badly. go-extract is the library; nobody is the **plane**.

`sealr mount` / `sealr open` as the thing an agent calls: policy, hydrate, no 50k-file workspace, SBOM of what was opened, hashes. Fits distillr/fitr-shaped tools. Smaller physics than 1–2, maybe bigger 2026 distribution.

Build this *on* Swing 1, not instead of it.

---

## What I would not do

- **Cram, but safer.** They shipped a scheduler last week. Competing on “also jail” is a rounding error unless mount+policy is the product.
- **GPU unzip CLI.** nvlzcat exists. Physics says no for folders.
- **Mojo as the app.** Still a kernel language. In Swing 1/2 it can be a hydrate backend. That’s the right size.
- **New format in month one.**
- **FUSE-on-Windows via WinFsp as the headline.** It works; it feels like a port. ProjFS is the interesting Windows-native bet (and the hard one).
- **Replace 7-Zip’s format list.** Let 7-Zip open RAR. You own the data plane.

---

## If the repo stays `sealr`

Keep the name as a scratch folder. The *program* is a compressed namespace:

| Layer | Job | Old sealr doc |
|---|---|---|
| Policy | jail, bombs, CRC, no recurse | safety.md |
| Locate | CD / tar index / seek table | formats.md |
| Hydrate | CPU SIMD / QAT / nvCOMP / later Mojo | backends.md |
| Dest | ProjFS / mmap / GPU buffer / materialize | **new** |
| Probe | this machine, this dest, this archive | fitr instinct |

Phase 1 CPU ZIP still ships - as the hydrate codec and as `materialize`. The README headline stops being `x` and becomes `mount` / `open`.

That’s the interesting project. Unzip was the tutorial.
