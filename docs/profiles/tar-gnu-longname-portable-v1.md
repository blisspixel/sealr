# Restricted raw GNU long-name TAR profile v1

> Status: supported in-process preview released in Alpha.12. This is a restricted GNU TAR long-name language, not a claim of general GNU TAR compatibility. Authenticated worker execution fails closed until a later semantic record can represent GNU carrier evidence.

Profile ID: `sealr.profile.tar.gnu-longname-portable.v1`

Profile SHA-256: `08fe2698806da997bc42e7e13a45cbf412a4a7056dec39c62456202680b91fa4`

Canonical profile bytes: [`tar-gnu-longname-profile-v1.json`](../../crates/sealr/tests/conformance/tar-gnu-longname-profile-v1.json)

This profile interprets one uncompressed old-GNU TAR source. It accepts standard regular files and directories, plus bounded `L` long-name carrier blocks that override the effective pathname of the single immediately following physical file or directory entry. It does not widen, detect, retry, or alias portable ustar, PAX, or ZIP selections.

## Underlying TAR language

Every 512-byte header satisfies the old-GNU magic (`ustar  \0`), numeric octal, checksum, owner-name, and zero-tail requirements.

The accepted typeflags are strictly:
- `b'0'` or `0`: regular file.
- `b'5'`: directory (underlying size must be zero).
- `b'L'`: long-name carrier block.

All other typeflags (`1` hard link, `2` symlink, `3`/`4` device/FIFO, `6` FIFO, `7` contiguous file, `K` long link, `S` sparse, `D` directory dump, `M` multi-volume, `N` rename/symlink, `V` volume header, `x`/`g` PAX headers) are denied.

## Long-name carrier contract

- **Carrier Name**: The raw name field of an `L` header (typically `././@LongLink` or similar) is validated for structural old-GNU text grammar and retained as raw evidence, but is never destination-path validated or materialized.
- **Payload**: The payload must contain between 1 and 8,191 strict UTF-8 path bytes followed by exactly one terminating NUL (`\0`). Embedded NUL bytes are forbidden.
- **Immediate Consumption**: A carrier sets a pending long name that must be consumed by the very next member header. Consecutive `L` carriers, trailing carriers at EOF, or carriers followed by non-file/non-directory entries fail closed with `tar.gnu.state`.
- **Bounds**: At most 1,024 carrier headers are permitted per archive. Maximum payload size is 8,192 bytes.
- **Accounting**: Carrier headers, payloads, and 512-byte block padding count against `max_metadata_bytes`. Carriers do not increment `max_files`.

## Effective member path contract

Effective member paths (whether from the standard 100-byte name field or an `L` carrier) must satisfy the complete portable path contract:
- Strict UTF-8 and NFC normalization.
- Portable component limit (≤ 255 UTF-8 bytes and ≤ 255 UTF-16 code units).
- Pure lexical jailing: no parent traversal (`..`), no leading slash, no Windows reserved names (CON, PRN, AUX, NUL, COM1-9, LPT1-9), no ADS colons, no trailing dots or spaces.
- Unique canonical paths without collision under the pinned Unicode 16 case-fold relation.

## Denied features

- Long links (`K`)
- GNU sparse files and incremental dumps
- GNU base-256 binary numeric encodings
- Mixed GNU and PAX states
- Multi-volume and concatenated archives
- Device files, FIFOs, and links

## Evidence and identities

The IR schema is `sealr.archive-ir.tar-gnu-longname.v1`. Archive evidence records the complete source covering plus every ordered `L` carrier: its raw name bytes, header, payload, path, and padding ranges, mode, modification time, checksum, header SHA-256, exact path bytes, and payload SHA-256. Every member records its underlying header name and an exact header-or-carrier path provenance.

An independent covering audit reparses every header from the source, replays the single-depth carrier state without the structural parser, and requires exact agreement with the claimed evidence before readiness. Layout identity is `sealrTreeV6` under label `sealr.tree.layout.tar-gnu-longname.v1`; it binds the covering, ordered carriers, member geometry, effective names, and provenance. Content identity remains the format-neutral `sealrTreeV1` over verified paths and bytes. The standalone identity verifier reconstructs the canonical profile bytes, the covering, the carrier replay, and both roots without linking Sealr.

Policy v6 (`sealr:policy/default/v6`, digest `aefc8a1baa113d7face30857ef64fe8f47c647fae863a72810b80380f8fd4178`) authorizes the separate `tar-gnu-longname` format. Selection is explicit through `TarGnuLongNameInterpretationProfile::PortableV1` or `--format tar-gnu-longname`; no other selection aliases to it.
