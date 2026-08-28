# Restricted POSIX PAX profile v1

> Status: supported Alpha.11 in-process preview. This is a restricted PAX language, not a claim of general PAX compatibility. Authenticated worker execution fails closed until a later semantic record can represent PAX extension and precedence evidence.

Profile ID: `sealr.profile.tar.pax-portable.v1`

Profile SHA-256: `db951f620acf54e67845144e138f9f16994439847a97601e20a424dfea7f4445`

Canonical profile bytes: [`tar-pax-profile-v1.json`](../../crates/sealr/tests/conformance/tar-pax-profile-v1.json)

This profile interprets one uncompressed POSIX PAX source. It extends the pinned portable ustar profile only with bounded `x` and `g` extension headers carrying the exact keywords `path` and `size`. It does not widen, detect, retry, or alias the portable ustar selection. Selection by filename suffix is forbidden.

## Underlying TAR language

Every 512-byte header, including an extension carrier, satisfies the checksum, magic, version, fixed-field, numeric, owner-name, reserved-byte, and zero-padding rules of `sealr.profile.tar.ustar-portable.v1`. GNU base-256 numbers remain denied.

The following differences are the complete extension to that base profile:

- Typeflag `x` is a local PAX extension carrier.
- Typeflag `g` is a global PAX extension carrier.
- Typeflag NUL or `0` remains a regular file. Typeflag `5` remains a directory whose underlying and effective sizes are both zero.
- An ordinary member's effective path and size are resolved from PAX state. Its underlying ustar name remains structurally valid and is preserved as raw evidence, but it is not required to be UTF-8 or destination-safe when an effective PAX `path` record overrides it. Without an effective `path` override, that underlying name is the effective path and must pass the complete destination path contract.

An extension carrier's ustar name and optional prefix satisfy the structural ustar text-field grammar, but they are not destination-path validated. Those raw bytes are evidence only. They are not inserted into destination topology, do not consume the file-count budget, and can never be retained, read as a member, or materialized. Global or local overrides never change an extension carrier's own name or payload size.

Extension carrier payload padding through the next 512-byte boundary is all zero. Two consecutive zero blocks terminate the archive, every remaining complete block is zero, and a pending local extension at termination is denied.

## Exact record grammar

Each extension payload contains one or two adjacent records and no other byte:

```text
record = length SP keyword "=" value LF
```

The following rules are normative:

- `length` is one through twenty ASCII decimal digits. It has no leading zero and its parsed value fits `u64`.
- The parsed length equals the complete record byte count, including the length digits, space, keyword, equals sign, value, and final newline.
- The declared record length is no greater than the unconsumed extension payload. Parsing consumes exactly that range before the next record begins.
- The records consume the complete declared extension payload. A gap, trailing NUL, partial record, extra newline, or unconsumed byte is denied.
- The keyword terminator `=` must be found within a 16-byte keyword scan bound. The only accepted byte-exact, case-sensitive keywords are `path` and `size`.
- Each keyword appears at most once in one extension header. Unknown keywords, duplicate keywords, empty values, and a zero-record extension are denied.
- An extension payload is at most 65,536 bytes. The payload cap, remaining source range, remaining metadata budget, record count, record length, keyword length, and derived value length are checked before allocation.

A `path` value is the exact nonempty byte sequence between `=` and LF. It must be strict UTF-8 and satisfy the portable Unicode 16 repertoire, NFC, component, reserved-name, separator, traversal, and case-fold collision contract inherited from the base profile.

A `size` value is canonical ASCII decimal `u64`: `0`, or a nonzero digit followed by zero or more digits. Leading zero, sign, whitespace, non-digit, and overflow are denied.

## Fixed state machine

The parser maintains only four optional semantic values: global path, global size, local path, and local size. Each stored value carries the source extension index and record index that established it. There is no map of arbitrary keywords and no recursive or backtracking interpretation.

State transitions are exact:

1. A completely validated `g` payload replaces each global field named by that header. An omitted field retains its prior global value. Empty-value deletion is unavailable because empty values are denied. Global state persists through later ordinary members and global headers.
2. A completely validated `x` payload sets the pending local fields. No local header may be pending already.
3. The record immediately after an `x` carrier must be one ordinary regular-file or directory header. Another `x`, a `g`, an unsupported type, or the archive terminator while local state is pending is denied.
4. For that ordinary member, each effective field is selected independently using local value, then global value, then underlying ustar value.
5. Both local fields are cleared after exactly that one ordinary member. Global fields are unchanged.

The archive admits at most 1,024 extension headers total across `x` and `g`. This is independent of `max_files`. Consecutive global headers are accepted within that cap because their field-by-field replacement is deterministic.

## Effective member contract

The effective path is checked only after precedence is resolved and before it enters topology. Its UTF-8 byte length cannot exceed:

```text
min(8191, 256 * policy.max_path_depth - 1)
```

The calculation uses checked widened arithmetic. If `max_path_depth` is zero, no member path is admissible. The existing 255 UTF-8 byte and 255 UTF-16 code-unit component ceilings still apply, so the formula is an aggregate bound rather than permission for an oversized component.

The effective size determines regular-file payload geometry and every declared and actual output quota. It must fit the exact remaining source range after checked 512-byte rounding. A directory's underlying size and effective size are both zero. `max_member_bytes`, `max_total_bytes`, member verification, retained reads, and materialization operate on the effective size. A base header size that is overridden remains canonical octal evidence and does not create an alternate payload boundary.

Path normalization and topology checks run on effective paths in source order. Duplicate paths, case-fold collisions, and file or directory ancestor conflicts are denied exactly as in the base portable path profile.

## Resource and metadata accounting

The PAX caps are cumulative and independent:

- `max_archive_bytes` bounds the complete source snapshot.
- `max_metadata_bytes` includes every ordinary and extension 512-byte header, every PAX payload byte, every PAX payload-padding byte, and the two-block terminator. As in the base profile, ordinary member padding and trailing complete zero blocks are checked but are not metadata.
- A fixed 65,536-byte cap applies to each extension payload.
- A fixed 1,024-header cap applies to all extension carriers.
- A fixed two-record cap applies to each extension payload.
- A fixed 16-byte scan cap applies while locating the keyword terminator.
- `max_files` counts only ordinary files and directories.
- Effective path depth, per-member output, aggregate output, and destination-effect limits retain their policy bounds.

Every count, offset, range end, block rounding operation, and cumulative byte total uses checked integer arithmetic. Limit equality passes. Failure leaves no partially updated global or local state and no admitted member.

## Denied language

The profile denies all PAX keywords except exact `path` and `size`, including `linkpath`, `uid`, `gid`, `uname`, `gname`, `mtime`, `atime`, `ctime`, `charset`, `hdrcharset`, vendor namespaces, and sparse-map fields.

It also denies GNU `L` and `K` carriers, mixed PAX and GNU extension state, links, sparse files, devices, FIFOs, multi-volume records, concatenated archives, recovery parsing, nonzero hidden padding, base-256 numbers, orphan or chained local headers, and any unrecognized member type. Destination owner, group, timestamp, permission, set-ID, link, and special-file effects are never restored.

## Evidence and identities

Source identity is SHA-256 of the complete caller-supplied TAR bytes. Interpretation identity is the SHA-256 of the exact canonical profile artifact linked above.

The IR schema is `sealr.archive-ir.tar-pax.v1`. Its source covering records all member and extension records, the exact two-block terminator, and all trailing zero blocks. Each extension evidence record binds:

- source-order extension index and global or local kind;
- raw carrier name, header, payload, and padding ranges;
- carrier mode, modification time, checksum, header SHA-256, and payload SHA-256;
- every record and value range in payload order;
- the admitted keyword, raw value bytes, and parsed decimal size where applicable.

Each ordinary member retains its base ustar header evidence, effective path and size, and separate path and size provenance. Provenance is exactly one of underlying ustar, global extension plus record index, or local extension plus record index.

Layout identity uses `sealrTreeV5` with label `sealr.tree.layout.tar-pax.v1`. Its canonical preimage binds the complete covering, ordered extension evidence, underlying member evidence, effective values, and both provenance selections. Distinct PAX state, carrier geometry, redundant overrides, or underlying placeholder headers therefore produce distinct layout identities even when verified output is identical.

Content identity remains format-neutral `sealrTreeV1` over verified effective paths, kinds, and bytes. A PAX archive and a portable ustar archive may share a content identity only after complete verification, while their source, interpretation, and layout identities remain distinct.

An independent verifier must reconstruct the canonical profile digest, source covering, PAX state transitions, effective-field provenance, `sealrTreeV5`, and `sealrTreeV1` without linking Sealr. No identity is available from an incomplete extension payload or a partially verified content tree.

## Controlled producer guidance

Producer names and version numbers are fixture provenance, not permission to admit every archive they can emit. Every fixture must be checked against this exact language.

- GNU tar 1.35 `--format=posix` commonly emits `mtime`, `atime`, and `ctime` records, which this profile denies. Controlled fixtures must delete those keywords, for example with `--pax-option=delete=atime,delete=ctime,delete=mtime`, use only regular files and directories, avoid sparse handling, and verify that the remaining PAX records are only `path` or `size`.
- libarchive 3.8.4 restricted PAX output, named `paxr` where the producer exposes that format, is eligible only when exact fixture inspection proves canonical record lengths, portable carrier fields, and the two-key allowlist. Libarchive version compatibility alone is not sufficient.
- CPython 3.12.10 `tarfile.PAX_FORMAT` fixtures must use explicit `TarInfo` values representable by the base ustar fields and restrict `pax_headers` to `path` and `size`. Any automatically emitted timestamp, ownership, link, sparse, or vendor keyword makes the source unsupported by this profile.

These controls intentionally trade broad producer acceptance for one deterministic interpretation. General PAX support, timestamp extensions, ownership extensions, links, sparse layouts, and vendor namespaces require separately identified future profiles.

The committed conformance suite contains byte-exact controlled fixtures from GNU tar 1.35, libarchive 3.8.4 `paxr`, and CPython 3.12.10. Each fixture pins its generation command, sparse source reconstruction, source hash, ordered records, effective-field provenance, layout root, content root, and verified payload. These fixtures demonstrate the documented recipes, not unrestricted compatibility with other producer settings or versions.

## Authorities

- [POSIX pax extended header records](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) defines the record framing, global and local header roles, and keyword model.
- [GNU tar archive formats](https://www.gnu.org/software/tar/manual/html_chapter/Formats.html) documents GNU tar PAX output and the separate GNU extension families denied here.
- [Python 3.12 tarfile](https://docs.python.org/3.12/library/tarfile.html) documents `PAX_FORMAT` and explicit `TarInfo` construction used for controlled fixtures.
