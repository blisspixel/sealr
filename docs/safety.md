# Safety spec

Threat model: **untrusted archives**, including parser-differential attacks (USENIX Security 2025 ZipDiff). Full adversary: [threat-model.md](threat-model.md). Testable properties: [invariants.md](invariants.md).

Goals: no path escape, no disk/RAM bomb, no silent corruption, no extra files (ADS, junctions), **no second interpretation** between inspect and materialize. Non-goals: antivirus, package-graph SBOMs, treating CRC as a signature.

Language: MUST / SHOULD / MAY.

This is the target safety specification. The [README](../README.md#security-limitations), [API contract](api.md), and [security policy](../SECURITY.md) record current implementation status; the [roadmap](../ROADMAP.md) defines sequencing and stable gates. Options described as future policy surfaces are not accepted by the current CLI.

## Path jail (hard, not a flag)

Applies to every format. szips only applied this to ZIP.

Let `dest` be the user destination after `abspath`. Let `raw` be the member name.

1. Reject NUL in `raw`.
2. Reject `\`; `/` is the only accepted archive separator.
3. Split on `/`. Reject a component that is empty, `..`, contains `:`, contains `<>"|?*` or a control character, is a Windows reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1` through `COM9`, `LPT1` through `LPT9`, `COM¹` through `COM³`, `LPT¹` through `LPT³`, any extension, case-insensitive), or ends with `.` or space.
4. `.` MAY be dropped.
5. Reject absolute: leading `/`, `//server/share`, or `^[A-Za-z]:`.
6. Join `dest` + components. Reject unless the result is `dest` or a strict child. Canonicalize **dest root** once; do not `canonicalize` children that do not exist yet.
7. Decode according to the selected format profile, then jail one canonical string. Compatibility v1 requires valid UTF-8 when ZIP bit 11 is set and accepts only ASCII when it is clear. Strict ASCII v2 denies bit 11 and every non-ASCII member name. Portable UTF-8 v1 requires strict UTF-8, bit 11 for non-ASCII, NFC, no dot normalization, and fixed UTF-8 and UTF-16 component ceilings. Portable ustar composes its fixed prefix and name bytes once, requires strict UTF-8 and NFC under the same portable repertoire, and carries no ZIP flag semantics. CP437 transcoding remains unimplemented and is never an implicit fallback.

Do the jail in a pure function on strings **before** any `open`. Re-check after join.

szips did not check reserved names or trailing dot/space. sealr MUST.

## Destination namespace admission

The destination parent must already exist. sealr canonicalizes and opens that parent as a retained directory capability; it does not create a missing parent. The final destination must be absent both at admission and at no-replace publication.

On Linux and macOS, the opened parent must be owned by the effective user or root. A parent with group or other write permission is rejected unless it has the sticky bit and a trusted owner. Sticky does not protect entries from the directory owner, so a sticky directory owned by another user is rejected. A root-owned sticky directory is accepted only because root is outside the in-process threat boundary. The created stage is checked for effective-user ownership and mode `0700` semantics.

On macOS, sealr queries the already-open parent and stage descriptors for extended ACLs. Any extended ACL is rejected because it can grant namespace rights that mode bits do not show. Failure to prove an ACL absent also rejects materialization.

On Windows, sealr supports only a retained parent handle that reports non-remote, writable NTFS with persistent ACLs. ReFS, FAT32, exFAT, UDF, CDFS, remote redirectors and shares, read-only volumes, and query ambiguity fail closed with `materialize.unsupported_filesystem`. The stage is created atomically with a security descriptor whose object owner is the effective token user and whose protected DACL contains one inheritable `FILE_ALL_ACCESS` allow ACE for that SID. The descriptor is verified through the returned handle before any member write. Descendant DACLs retain that sole effective principal. Windows assigns each descendant its creating token's default owner, which can be an owner-enabled group for an administrative token. A principal matching that default-owner SID can change the descendant DACL and is outside the in-process containment promise.

## Symlinks and reparse points

Current preview behavior: **do not create them.** ZIP external attributes that describe a special file type are rejected, file/directory attribute disagreements are rejected, and portable ustar admits only regular files plus zero-size directories while denying all link and special-file typeflags.

A future named policy may allow constrained links only after the target passes the jail relative to the link parent and is proven non-absolute. Such links must be created only after regular files. Member creation never opens through a symlink or reparse point: each canonical component is opened separately with no-follow semantics from a retained directory handle. Windows also rejects a reparse-point attribute on each opened directory or file handle. Alpha.13 has no link-enabling CLI option. Repeated hostile race stress remains a stable-release gate.

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

| Control | Alpha.6 default | Future named policy surface |
|---|---|---|
| Jail, ADS `:`, reserved names, no `..`, no overlap | on | none |
| No symlink creation | on | constrained links may be considered later |
| No nested-archive recursion | on | none |
| Encrypted members | refuse | password support may be considered later; ZipCrypto may stay refused |
| File, member, and total caps | values above | may raise caps, but never default to unlimited |
| Ratio 100 | on | `null` may disable it for a named trusted-input policy |
| Dictionary window | reserved at 64 MiB | format-specific limits when zstd or LZMA exists |

Count **actual** uncompressed bytes, not just headers. Lying sizes are a known bomb (Pellegrino, Fifield). Abort the member if the stream exceeds `min(declared, MAX_MEMBER)`. Global counter aborts at `MAX_TOTAL`.

Ratio 100 is stricter than DEFLATE’s theoretical max (~1032:1) and will reject some legitimate all-zero archives. That is strict by design. Size caps still stop Fifield bombs if someone raises the ratio.

## Integrity

| Check | szips | sealr |
|---|---|---|
| `testzip()` full pre-pass | yes | **Do not default.** Inspection already inflates to a sink in Alpha.6. |
| CRC | re-read from disk | **During write**, one pass |
| SHA-256 | log every file | Current receipt path hashes every member during the same pass. Hash selection is a later policy surface. |
| Other checksums | ZIP CRC only | Always verify when present (gzip CRC, zstd xxHash, 7z CRC) |

CRC is not authentication. Caps stop bombs. Fail-closed: delete the partial file on mismatch.

## Overwrite and modes

Current behavior: refuse if the destination exists. Replacement is not implemented, even if a caller mutates the reserved policy field. szips silently overwrote; sealr is stricter.

Do not preserve setuid/setgid. Mask to `0777` minus umask, or `0755`/`0644`.

The Rust policy field `atomic` defaults to false. When true, completed member files are synced before publication. Directory durability and crash recovery are not yet guaranteed. There is no Alpha.6 CLI switch for this field.

Publication is native and no-replace on the three release platforms. Linux uses `renameat2` with `RENAME_NOREPLACE`; macOS uses `renameatx_np` with `RENAME_EXCL`. Windows creates the stage relative to the retained parent handle with `NtCreateFile`, `FILE_CREATE`, reparse-point-open semantics, and the explicit protected DACL. It withholds delete sharing, retains the returned stage handle for the full write, and publishes that same object with `NtSetInformationFile`, the retained parent as `RootDirectory`, and replacement disabled.

Linux, macOS, and Windows are the supported materialization platforms. Every other target fails closed with `materialize.unsupported`; Windows storage outside the matrix below fails with `materialize.unsupported_filesystem`.

| Windows parent observed through the retained handle | Alpha.6 status | Reason |
|---|---|---|
| Non-remote, writable NTFS with `FILE_PERSISTENT_ACLS` | Supported | Creation-time descriptor and descendant inheritance are natively tested. |
| ReFS, including Dev Drive | Rejected | ACL support is documented but the complete stage, inheritance, reparse, cleanup, and publication path is not natively qualified. |
| FAT32, exFAT, UDF, CDFS, or unknown | Rejected | The required persistent protected sole-principal DACL semantics cannot be established. |
| SMB, UNC, mapped remote drives, DFS, WebDAV, NFS redirectors, or any `FILE_REMOTE_DEVICE` handle | Rejected | Remote ACL, sharing, and rename semantics are outside the qualified support boundary. |
| Read-only volume or any volume-query failure | Rejected | Required stage creation or the support decision cannot be established. |

## Receipt evidence

The receipt records the materialization backend, stage mode, stage-creation primitive, member-resolution primitive, durability mode, publication primitive, outcome, and cleanup result. `sealr.materialization.v2` adds Windows storage-policy observations and stage-ACL verification without recording a SID, volume serial, label, or path. Setup failure, successful commit, publication failure, explicit abort, and failed cleanup are distinguishable. These fields are evidence of the selected control path, but the preview receipt is unsigned and is not authentication.

The current receipt strings are an auditable map to the implemented native controls:

| Platform | `stage_mode` | `stage_creation_primitive` | `publication_primitive` |
|---|---|---|---|
| Linux | `same-volume-random-128-mode-0700` | `mkdirat-mode-0700-openat-nofollow-safe-parent` | `renameat2-noreplace` |
| macOS | `same-volume-random-128-mode-0700` | `mkdirat-mode-0700-openat-nofollow-safe-parent` | `renameatx-np-excl` |
| Windows | `same-volume-random-128-protected-token-user-dacl` | `ntcreatefile-parent-handle-create-directory-explicit-dacl-nofollow` | `ntsetinformationfile-retained-source-parent-noreplace` |

All three report `component-handles-nofollow` for member resolution. Durability reports `member-sync` when `atomic` is true and `flush-only` otherwise.

Windows evidence reports `storage_policy: windows-local-ntfs-v1` and `stage_acl_policy: windows-protected-token-user-v1`, plus the observed filesystem, device scope, persistent-ACL flag, read-only flag, and stage-ACL state.

The current core keeps platform `unsafe` code in two narrow FFI modules: descriptor-based extended-ACL inspection on macOS and native volume, token, security-descriptor, stage-creation, and publication operations on Windows. This is the explicit audit boundary for pointer lifetime, layout, handle ownership, share flags, and error conversion.

Root, administrators, SYSTEM, principals matching the effective token's default-owner SID, same-principal processes, filesystem-override or backup/restore privileges, filter drivers, and debugging or handle-duplication rights can act with or override the library's authority. They are outside this in-process containment claim. A reduced-authority worker narrows parser ambient authority, but a distinct service identity or equivalent mandatory-access-control boundary is required to contain another process running as the same user.

## 7z

Sealr implements only the explicitly selected restricted Copy-only 7z profile:
one raw-header, single-volume container whose coders are all Copy. General 7z,
packed headers, LZMA-family coders, encryption, and the rest of the format are
not implemented. Sealr MUST NOT shell out to another extractor and then imply
that its own interpretation, jail, quotas, or evidence covered the result. Any
additional 7z profile requires a maintained native parser strategy and the
same semantic, capability, worker, corpus, and evidence gates, or it does not
ship.

## szips parity

MUST keep or strengthen: path jail (reject backslash, absolute, `..`, empty, and `:`), containment checks, the four caps, skip ratio when `compress_size == 0`, chunked I/O, CRC verification, no nested recursion, and non-recursive folder scan.

MUST drop: a redundant `testzip()` pre-pass, silent overwrite, and shell-out 7z. Alpha.6 computes CRC32 and SHA-256 together while streaming each expanded member, then independently streams the staged file hash before publication when materializing.

MUST add: reserved names, trailing dot/space, ZIP overlap reject, no symlink extract, actual-byte caps, ZipDiff A1–C5 deny-or-finding, TAR PAX/GNU metadata size cap, inspect ≡ materialize.

Tests from szips (`../outside.txt`, colon ADS) plus overlap, reserved names, ratio bomb, lying sizes.

The executable adversarial catalog lives in the unit tests and the pinned ZipDiff corpus gate.
