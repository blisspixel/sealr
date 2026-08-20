# Formats

> Current implementation: classic ZIP32 with Store and Deflate only. Every other row is planned or deliberately refused.

ZIP is a container. Each member is independently compressed. That is why ZIP is v0. gzip is one stream. 7z is often one solid folder. Treat them as different products.

## Matrix

**Par.** = independent extract work. **GPU** = realistic win on DE or nvCOMP SM for typical members, dest = disk.

| Format | Par. | GPU | Ship | Notes |
|---|---|---|---|---|
| ZIP32 stored + deflate | Per member | Fat Deflate only | **current pre-alpha** | CD-first. Exact layout. Data descriptors. |
| ZIP64 | Per member | same | Phase 0.2 candidate | Currently rejected with `zip.diff.c5_zip64` |
| ZIP method 93 zstd | Per member | SM, not DE | v1 | |
| ZIP lzma / xz / deflate64 | Per member | No | v1 decode | |
| ZIP encrypt / span | n/a | n/a | refuse | |
| gzip `.gz` | Serial; optional later rapidgzip | Only if chunked/concat | v1 serial | ISIZE is 32-bit; count actual bytes |
| tar | Scan serial, writes can fan out | No | v1 | Same jail; no symlinks |
| tar.gz | Serial gzip + tar | Same as gzip | v1 | Pipeline |
| zstd `.zst` | Per frame if many | SM if fat frames | v1 | Seek table magic `0x184D2A5E` |
| tar.zst | If seekable | SM | v1 serial first | |
| xz / tar.xz | Serial unless block index | No | v1 | |
| 7z non-solid | Per folder | No (LZMA) | v1 native | **Same jail.** Do not shell out to `7z x` |
| 7z solid | Almost none | No | v1 correct-and-slow | One decoder; do not fake rayon |
| LZ4 frame | Per independent block | **Best GPU** | v1 / Mojo experiment | |
| RAR | Weak | No | **never default** | License + CVE history |
| WIM / CAB | Reparse / folder compress | No | later or never | |
| GDeflate packs | Tiles | Best on-GPU | later | Not internet ZIP |

## ZIP rules that matter

- **CD-first.** Local headers are not the index. Streaming local-to-local cannot see quoted-overlap bombs (Fifield): `zbsm.zip` 42 kB → 5.5 GB.
- After CD parse, compute compressed-data ranges. Reject overlap with each other, with the CD, or past EOCD. szips does not do this; sealr must.
- Data descriptors (bit 3): sizes live in the CD. Local nonzero values and the descriptor must agree with the CD. Stored payloads containing alternate record signatures are rejected as C1 ambiguity.
- Methods v0: 0 (store), 8 (deflate). Refuse Shrink/Reduce/Implode (1–6).
- Encryption: refuse. ZipCrypto is not a security boundary.
- Names target: `/` is the only separator. Backslash is rejected rather than rewritten. Bit 11 means strict UTF-8; legacy CP437 and canonical Unicode remain planned, so current non-ASCII names fail closed. Never hand raw archive bytes to `CreateFileW`.
- No nested-archive recursion. Zip quines are harmless unless you recurse.
- SFX / trailing ZIP: later. Do not mmap a 2 GB PE to extract 10 MB without using `directory_offset`.

## What not to promise

- GPU for random internet `.tar.gz`. One Deflate stream, 32 KiB window.
- Parallel decode of ordinary `.zst` (one frame). `pzstd` only parallelizes `pzstd`-framed files. MT *compress* still emits one frame.
- Parallel extract of default 7-Zip solid archives. Pavlov: a 1-thread-created 7z stays 1-thread on extract.
- RAR on day one (or in the default binary).

szips only did `.zip` native and shelled `.7z` with **no jail**. sealr ZIP is native. 7z waits until the jail wraps the unpacker.

The normative path jail and quota rules are in [safety](safety.md).
