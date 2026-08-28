# Finding codes

Agents switch on `code`. Humans read `detail`. There is no numeric risk score.

```json
{
  "code": "zip.diff.a3_name",
  "severity": "error",
  "member": "word/document.xml",
  "detail": "CDH name != LFH name"
}
```

The enclosing view and receipt bind the policy. Individual finding objects do not repeat it.

## Severity

| Value | Meaning |
|---|---|
| `error` | Reject the archive. This is the only severity emitted by the current implementation. |
| `deny` | Reserved for a future policy that can deny one member without weakening archive-level invariants. |
| `warn` | Reserved for policy-dependent continuation. |
| `info` | Reserved for recorded transformations such as permission stripping. |

Unknown error codes must be treated as rejection by consumers.

## Implemented registry

### Source and format

| Code | Meaning |
|---|---|
| `source.io` | The archive source could not be inspected, opened, or read. |
| `format.unsupported` | Magic or format is unsupported or disallowed by policy. |
| `format.magic` | Reserved for explicit magic-versus-extension policy. |
| `method.unsupported` | ZIP compression method is not Store or Deflate. |

### Path and topology

| Code | Meaning |
|---|---|
| `path.absolute` | Absolute, UNC-like, or drive-qualified member path. |
| `path.dotdot` | Parent component. |
| `path.empty` | Empty component or empty normalized name. |
| `path.ads` | Colon that could address an NTFS alternate data stream. |
| `path.reserved` | Windows reserved device name. |
| `path.trailing` | Component ending in dot or space. |
| `path.escape` | Internal containment join failed. |
| `path.depth` | Normalized depth exceeds policy. |
| `path.nul` | NUL byte in a decoded name. |
| `path.invalid_char` | Character denied by the selected profile, including controls, backslash, portable Windows-illegal characters, and Portable v1's pinned non-ASCII whitespace, bidi-control, assigned-repertoire, and private-use rules. |
| `path.unicode` | Path is not in the selected profile's canonical Unicode form, including a non-NFC path under portable UTF-8 v1. |
| `path.case_fold` | Collision or topology conflict under the selected profile's case-fold relation. |
| `path.conflict` | A path is both a file and a directory ancestor or descendant. |

### Materialization

| Code | Meaning |
|---|---|
| `materialize.exists` | Destination exists or appeared before publication. |
| `materialize.io` | The destination parent is missing or staging, member write, flush, sync, or other materialization I/O failed. |
| `materialize.commit` | Final same-volume no-replace publication failed. |
| `materialize.unsafe_parent` | The destination parent or stage failed trusted ownership, Unix mode, or macOS extended-ACL admission checks. |
| `materialize.unsafe_component` | A canonical member component could not be opened through the required no-follow boundary, including a link, reparse point, non-directory parent, or invalid component. |
| `materialize.cleanup` | Explicit removal of a staged tree failed. The receipt reports `cleanup: failed`. |
| `materialize.unsupported` | The platform has no supported atomic no-replace publication primitive, so materialization failed closed. |
| `materialize.unsupported_filesystem` | The opened Windows parent is remote, read-only, lacks persistent ACLs, is not NTFS, or could not be classified safely. |
| `materialize.unsafe_stage` | A created Windows stage did not retain the required effective-TokenUser object owner or exact protected effective-TokenUser-only DACL before member writes. |
| `materialize.audit` | The staged tree diverged from the admitted IR before publication: size, content digest, path set, or a reparse point. The destination is not published. |

### Quotas

| Code | Meaning |
|---|---|
| `quota.archive` | Compressed input exceeds `max_archive_bytes`. |
| `quota.derived` | A wrapper's immutable decoded archive would exceed `max_derived_archive_bytes`. |
| `quota.files` | Entry count exceeds `max_files`. |
| `quota.member` | Declared or actual member size exceeds its cap. |
| `quota.total` | Declared or actual running total exceeds its cap. |
| `quota.ratio` | Declared or actual compression ratio exceeds policy. |
| `quota.overflow` | A checked security counter could not be represented in `u64`. |
| `quota.metadata` | Structural archive metadata exceeds its cap. |
| `quota.declared_lie` | Actual expanded size disagrees with the declared size. |
| `policy.unsupported` | The constructor policy names an unimplemented or reserved control. Compilation fails before source ingestion. |

### ZIP structure and differentials

| Code | Meaning |
|---|---|
| `zip.diff.a1_method` | CDH and LFH methods disagree. |
| `zip.diff.a2_size` | CDH, LFH, CRC, size, or data descriptor fields disagree. |
| `zip.diff.a3_name` | Raw CDH and LFH names disagree, or an alternate Unicode Path extra field is present. |
| `zip.diff.a4_dir` | Filename, size, host, or external attributes disagree on entry type. |
| `zip.diff.a5_crypt` | Encryption-related flags disagree. |
| `zip.diff.b1_dup` | Duplicate canonical destination path. |
| `zip.diff.b2_chars` | Reserved for the upstream character ambiguity class. Current paths use the more specific `path.*` codes. |
| `zip.diff.c1_stream` | Hidden, prefixed, gapped, or otherwise unreferenced local-record bytes. |
| `zip.diff.c2_eocd` | Ambiguous or additional EOCD structure. |
| `zip.diff.c3_count` | Disk, entry-count, CDH, or central-directory structure disagreement. |
| `zip.diff.c4_offset` | Invalid central, local, payload, or descriptor offset. |
| `zip.diff.c5_zip64` | A ZIP64 marker appeared outside the explicitly selected strict ZIP64 profile, or ZIP64 and legacy structure disagreed within that profile. |
| `zip.overlap` | Referenced local records overlap each other or the central directory. |
| `covering.inconsistent` | The IR covering is not a labeled partition of the snapshot, or a claimed LFH/CDH/EOCD offset does not hold the recorded signature. The checker does not search for an EOCD or inflate. |
| `zip.encrypted` | Traditional, strong-encryption, or masked-header flag is present on a member. |
| `zip.encoding` | Invalid UTF-8 name or unsupported non-ASCII CP437 decoding. |
| `zip.extra` | Extra-field sequence is malformed, repeats an identifier, or violates the selected profile's closed table. ZIP32 v1 may record permitted well-formed extras as ignored occupancy; strict ZIP64 permits only its exact semantic ZIP64 field shapes. |
| `zip.flags` | Non-encryption CDH and LFH flags disagree. |
| `codec.deflate.invalid_stream` | The declared DEFLATE payload is not one valid raw DEFLATE stream, or decoder accounting is inconsistent. |
| `codec.deflate.trailing_input` | One valid DEFLATE stream ended before the declared compressed payload ended. Trailing bytes and concatenated streams are rejected. |
| `codec.zstd.invalid_frame` | The declared Zstandard payload is not one valid RFC 8878 frame within the restricted language, the frame is truncated, or decoder accounting is inconsistent. |
| `codec.zstd.trailing_input` | One valid Zstandard frame ended before the source ended. Concatenated frames, skippable frames, and every other trailing byte are rejected. |
| `codec.xz.invalid_stream` | The declared XZ payload is not one valid stream within the restricted language, a structural CRC32 or index relation fails, the stream is truncated, or decoder accounting is inconsistent. |
| `codec.xz.trailing_input` | One valid XZ stream ended before the source ended. Concatenated streams, stream padding, and every other trailing byte are rejected. |
| `codec.bzip2.invalid_stream` | The declared bzip2 payload is not one valid stream within the restricted language, the footer or block-CRC chain fold fails, the stream is truncated, or decoder accounting is inconsistent. |
| `codec.bzip2.trailing_input` | One valid bzip2 stream ended before the source ended. Concatenated streams and every other trailing byte are rejected. |
| `crc.mismatch` | Expanded member CRC32 disagrees with the archive. |

### Gzip wrapper

| Code | Meaning |
|---|---|
| `gzip.extra` | The strict gzip wrapper encountered malformed `FEXTRA` subfield framing, a declared subfield length that exceeds `XLEN`, trailing remainder bytes, the reserved SI2 value zero, or a duplicate SI1/SI2 identifier. |

### TAR structure

| Code | Meaning |
|---|---|
| `tar.checksum` | A ustar header checksum field is malformed, overflows, or disagrees with the unsigned header-byte sum. |
| `tar.dialect` | The selected portable ustar language does not recognize the required magic, version, fixed text fields, or reserved-byte form. |
| `tar.numeric` | An octal numeric field is malformed or overflows. GNU base-256 numeric fields are reported as unsupported instead. |
| `tar.padding` | Member padding or trailing record padding contains a nonzero byte. |
| `tar.terminator` | The archive lacks exactly observable two-block zero termination or contains an incomplete trailing block. |
| `tar.truncated` | A complete header, payload, padding region, or checked offset is unavailable. |
| `tar.type` | A record type is invalid for the portable profile, or a regular-file or directory invariant is violated. |
| `tar.feature_unsupported` | A recognized PAX, GNU, link, special-file, or base-256 extension is outside the selected portable ustar profile. |
| `tar.pax.record` | A PAX record violates the restricted profile's canonical length, delimiter, keyword, value, or complete-consumption grammar. |
| `tar.pax.state` | Local or global PAX state violates the restricted profile's ordering, lifetime, or precedence contract. |
| `tar.gnu.long_name` | A GNU long-name carrier violates the portable profile's canonical length, delimiter, single NUL terminator, or payload grammar. |
| `tar.gnu.state` | GNU long-name carrier state violates the portable profile's immediate-consumption, single-carrier, or ordering contract. |

## Reserved registry work

The pinned 5,927-file upstream construction corpus is already enforced. B3 canonicalization and B4 case constructions map to the specific implemented `path.*` codes for the selected ASCII or portable UTF-8 profile. A future CP437 profile must decide whether its additional collision model needs aliases or dedicated `zip.diff.b3_canon` and `zip.diff.b4_case` codes.

Additional link, permission, wrapper, dictionary, polyglot, signing, and sandbox findings will be added only with their implementations and tests.

## Stability

Finding strings become compatibility commitments at the first stable supported release. During the preview line, registry changes must update this document, receipt tests, and fixture expectations in the same change and must be called out in the changelog.
