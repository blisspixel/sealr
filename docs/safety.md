# Safety spec

Threat model: **untrusted archives**, including parser-differential attacks (USENIX Security 2025 ZipDiff). Full adversary: [threat-model.md](threat-model.md). Testable properties: [invariants.md](invariants.md).

Goals: no path escape, no disk/RAM bomb, no silent corruption, no extra files (ADS, junctions), **no second interpretation** between inspect and materialize. Non-goals: antivirus, package-graph SBOMs, treating CRC as a signature.

Language: MUST / SHOULD / MAY.

This is the target safety specification. [README.md](../README.md#security-limitations) and [ROADMAP.md](../ROADMAP.md) record current implementation status. Options described as future policy surfaces are not accepted by the Phase 0 CLI.

## Path jail (hard, not a flag)

Applies to every format. szips only applied this to ZIP.

Let `dest` be the user destination after `abspath`. Let `raw` be the member name.

1. Reject NUL in `raw`.
2. Reject `\`; `/` is the only accepted archive separator.
3. Split on `/`. Reject a component that is empty, `..`, contains `:`, contains `<>"|?*` or a char `< 0x20`, is a Windows reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, any extension, case-insensitive), or ends with `.` or space.
4. `.` MAY be dropped.
5. Reject absolute: leading `/`, `//server/share`, or `^[A-Za-z]:`.
6. Join `dest` + components. Reject unless the result is `dest` or a strict child. Canonicalize **dest root** once; do not `canonicalize` children that do not exist yet.
7. Decode according to the format, then jail one canonical Unicode string. Phase 0 requires valid UTF-8 when ZIP bit 11 is set, accepts only ASCII when it is clear, and rejects every non-ASCII result until CP437 transcoding and Unicode normalization are implemented.

Do the jail in a pure function on strings **before** any `open`. Re-check after join.

szips did not check reserved names or trailing dot/space. sealr MUST.

## Symlinks and reparse points

Current Phase 0 behavior: **do not create them.** ZIP external attributes that describe a special file type are rejected, and file/directory attribute disagreements are rejected.

A future named policy may allow constrained links only after the target passes the jail relative to the link parent and is proven non-absolute. Such links must be created only after regular files. Member creation must never open through a symlink or reparse point. Phase 0 has no link-enabling CLI option, and per-component no-follow race closure remains a release gate.

## Overlap (ZIP)

After CD parse, compressed-data ranges MUST NOT overlap each other, the CD, or extend past EOCD. Quoted-overlap bombs look like valid CD-first archives. This is not a flag.

## Resource limits

szips defaults, kept:

```
MAX_ARCHIVE_BYTES  = 512 MiB
MAX_FILES          = 10_000
MAX_MEMBER_BYTES   = 1 GiB
MAX_TOTAL_BYTES    = 5 GiB
MAX_COMPRESSION_RATIO = 100
CURRENT_CHUNK      = 64 KiB
```

| Control | Phase 0 default | Future named policy surface |
|---|---|---|
| Jail, ADS `:`, reserved names, no `..`, no overlap | on | none |
| No symlink creation | on | constrained links may be considered later |
| No nested-archive recursion | on | none |
| Encrypted members | refuse | password support may be considered later; ZipCrypto may stay refused |
| File, member, and total caps | values above | may raise caps, but never default to unlimited |
| Ratio 100 | on | `null` may disable it for a named trusted-input policy |
| Dictionary window | reserved at 64 MiB | format-specific limits when zstd or LZMA exists |

Count **actual** uncompressed bytes, not just headers. Lying sizes are a known bomb (Pellegrino, Fifield). Abort the member if the stream exceeds `min(declared, MAX_MEMBER)`. Global counter aborts at `MAX_TOTAL`.

Ratio 100 is stricter than DEFLATE’s theoretical max (~1032:1) and will reject some legitimate all-zero archives. That is szips. Size caps still stop Fifield bombs if someone raises ratio.

## Integrity

| Check | szips | sealr |
|---|---|---|
| `testzip()` full pre-pass | yes | **Do not default.** Inspection already inflates to a sink in Phase 0. |
| CRC | re-read from disk | **During write**, one pass |
| SHA-256 | log every file | Current receipt path hashes every member during the same pass. Hash selection is a later policy surface. |
| Other checksums | ZIP CRC only | Always verify when present (gzip CRC, zstd xxHash, 7z CRC) |

CRC is not authentication. Caps stop bombs. Fail-closed: delete the partial file on mismatch.

## Overwrite and modes

Current behavior: refuse if the destination exists. Replacement is not implemented, even if a caller mutates the reserved policy field. szips silently overwrote; sealr is stricter.

Do not preserve setuid/setgid. Mask to `0777` minus umask, or `0755`/`0644`.

The Rust policy field `atomic` defaults to false. When true, completed member files are synced before publication. Directory durability and crash recovery are not yet guaranteed. There is no Phase 0 CLI switch for this field.

## 7z

szips ran `7z x -y -o{dest}` with **no jail**. sealr MUST NOT. Native parse + the same jail, or do not ship 7z.

## szips parity

MUST keep or strengthen: path jail (reject backslash, absolute, `..`, empty, and `:`), containment checks, the four caps, skip ratio when `compress_size == 0`, chunked I/O, CRC verification, no nested recursion, and non-recursive folder scan.

MUST drop: a redundant `testzip()` pre-pass, a second SHA-256 read pass, silent overwrite, and shell-out 7z. Phase 0 computes CRC32 and SHA-256 together while streaming each expanded member.

MUST add: reserved names, trailing dot/space, ZIP overlap reject, no symlink extract, actual-byte caps, ZipDiff A1–C5 deny-or-finding, TAR PAX/GNU metadata size cap, inspect ≡ materialize.

Tests from szips (`../outside.txt`, colon ADS) plus overlap, reserved names, ratio bomb, lying sizes.

The executable adversarial catalog lives in the unit tests and the pinned ZipDiff corpus gate.
