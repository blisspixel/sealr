# Policy

Policy is an input to `apply()` and is bound into every receipt by id and SHA-256 digest. Caps and behavioral choices must not live only in command-line state.

The implemented pre-release schemas are `sealr.policy.v1` through
`sealr.policy.v11`. Rust callers may use the versioned `Policy` constructors or
deserialize the closed `PolicyDocument` shape and call `validate()`.
`PolicyDocument` rejects unknown fields, unsupported schemas and vocabulary,
noncanonical format sets, and caps above the double-safe integer ceiling before
producing a `ValidatedPolicy`. The CLI `--policy` path applies that same
validation before archive access. The validated policy retains the caller's
explicit id and memoizes the digest of Sealr's deterministic declaration-order
serialization. That digest is not yet an RFC 8785 cross-encoder policy promise,
and a broader external policy language beyond this exact public shape is not
implemented.

There is no insecure mode.

## Operation options are not policy

`apply_with_options` accepts two kinds of operation-scoped input outside the policy object: explicit archive/profile selection and capabilities such as a bounded `RetentionPlan`. Selection changes the container language and interpretation identity. The policy separately authorizes that selected format, so selection cannot widen `formats`. A retention plan does not change interpretation, archive admission, receipt or tree identity, or whether a destination is requested.

`apply()` selects the immutable compatibility profile `sealr.profile.zip.strict-ascii.v1` and requires the ZIP32-only `Policy::default_v1()` contract. Callers can explicitly select the [closed strict ASCII v2 profile](profiles/zip-strict-ascii-v2.md), the [strict ZIP64 profile](profiles/zip64-strict-ascii-v1.md), the [portable ustar profile](profiles/tar-ustar-portable-v1.md), the [gzip-wrapped portable ustar profile](profiles/tar-gzip-ustar-portable-v1.md), the [restricted POSIX PAX profile](profiles/tar-pax-portable-v1.md), the [restricted GNU long-name profile](profiles/tar-gnu-longname-portable-v1.md), the [gzip-wrapped restricted PAX profile](profiles/tar-gzip-pax-portable-v1.md), the [gzip-wrapped GNU long-name profile](profiles/tar-gzip-gnu-longname-portable-v1.md), the [zstd-wrapped portable ustar profile](profiles/tar-zstd-ustar-portable-v1.md), the [xz-wrapped portable ustar profile](profiles/tar-xz-ustar-portable-v1.md), the [bzip2-wrapped portable ustar profile](profiles/tar-bzip2-ustar-portable-v1.md), or the [Copy-only 7z container profile](profiles/7z-copy-portable-v1.md) through `ApplyOptions`. ZIP64 selection requires policy v3, raw ustar requires authorization for `tar-ustar`, gzip-wrapped ustar requires policy v4 authorization for `tar-gzip-ustar`, raw PAX requires policy v5 authorization for `tar-pax`, raw GNU long-name requires policy v6 authorization for `tar-gnu-longname`, the gzip-wrapped PAX and GNU compositions require policy v7 authorization for `tar-gzip-pax` and `tar-gzip-gnu-longname`, the zstd-wrapped ustar profile requires policy v8 authorization for `tar-zstd-ustar`, the xz-wrapped ustar profile requires policy v9 authorization for `tar-xz-ustar`, the bzip2-wrapped ustar profile requires policy v10 authorization for `tar-bzip2-ustar`, and the Copy-only 7z container requires policy v11 authorization for `7z-copy`. Selection never aliases or retries through another format. The same prerelease enum exposes the separately named `sealr.profile.zip.wheel-utf8.v1` repository-research language without changing either supported ASCII ZIP32 profile. A retention plan names only exact canonical paths and supplies independent per-member and aggregate retained-byte ceilings. Failure to retain a requested path is reported through `VerifiedArchive::retention_status`; it does not relax an archive rule or convert a rejection into an admission. A higher-level consumer that requires those bytes must fail its own evaluation unless every required status is `Retained`. The full contract and limits are in [bounded one-pass retention](api.md#bounded-one-pass-retention).

## Compatibility default v1

The serialized default object is equivalent to:

```json
{
  "schema": "sealr.policy.v1",
  "id": "sealr:policy/default/v1",
  "formats": ["zip"],
  "max_archive_bytes": 536870912,
  "max_files": 10000,
  "max_member_bytes": 1073741824,
  "max_total_bytes": 5368709120,
  "max_ratio": 100,
  "max_path_depth": 32,
  "max_metadata_bytes": 4194304,
  "max_dict_bytes": 67108864,
  "symlinks": "deny",
  "hardlinks": "deny",
  "overwrite": "refuse",
  "setuid": "strip",
  "nested_depth": 1,
  "ambiguity": "deny",
  "case_fold_collision": "deny",
  "magic_vs_extension": "deny",
  "encrypted": "deny",
  "atomic": false
}
```

Rust struct field order is deterministic, so the current implementation produces a stable digest for a given build and object. It does not yet claim cross-encoder JSON canonicalization.

The exact `Policy::default_v1()` digest remains `8298b205c981ed140a52ba555c0499712436969faf4ebc28d88d8d9e7024c340`.

## Multi-format default v2

`Policy::default_v2()` preserves every resource and effect control above, changes the schema and id to `sealr.policy.v2` and `sealr:policy/default/v2`, and authorizes the canonical format list:

```json
"formats": ["zip", "tar-ustar"]
```

Its exact digest is `a02984fd88cb3fed1d60a339485eb0742da418681427dadcf699b4303f17d14a`. A v2 caller may narrow `formats` to exactly `["zip"]` or `["tar-ustar"]`. The two-format list must remain in the canonical order shown. Empty, duplicate, reversed, unknown, and three-or-more-element lists fail before source ingestion.

## ZIP64-capable default v3

`Policy::default_v3()` preserves the resource and effect controls, changes the schema and id to `sealr.policy.v3` and `sealr:policy/default/v3`, and authorizes the canonical format list:

```json
"formats": ["zip", "zip64", "tar-ustar"]
```

Its exact digest is `2cc96c7a2dd83617b3c80df7ec5ae7e4b92f74b0b391d70aa73f54f3f82068bd`. A v3 caller may use any nonempty canonical subset of that list. Authorization does not select a parser: the caller must still select `Zip64StrictAsciiV1` explicitly, and the ZIP32 default remains unchanged.

## Gzip-TAR-capable default v4

`Policy::default_v4()` preserves all earlier resource and effect controls, changes the schema and id to `sealr.policy.v4` and `sealr:policy/default/v4`, adds the mandatory derived-archive cap, and authorizes the canonical format list:

```json
"formats": ["zip", "zip64", "tar-ustar", "tar-gzip-ustar"],
"max_derived_archive_bytes": 536870912
```

Its exact digest is `ecfca685a8f05c63fd12b7fd1c183a90a3fa705f801493fa4cb003cd57f1d601`. A v4 caller may use any nonempty canonical subset of the format list. The derived cap is serialized only in policy v4 and v5; setting it under v1 through v3 or omitting it under v4 or v5 fails compilation. `TarGzipInterpretationProfile::UstarPortableV1` must still be selected explicitly.

## Restricted-PAX-capable default v5

`Policy::default_v5()` preserves the v4 resource and effect controls, including the mandatory derived-archive cap, changes the schema and id to `sealr.policy.v5` and `sealr:policy/default/v5`, and authorizes the canonical format list:

```json
"formats": ["zip", "zip64", "tar-ustar", "tar-gzip-ustar", "tar-pax"],
"max_derived_archive_bytes": 536870912
```

Its exact digest is `d1268c72f284f8f1b7ce5e06ada17ef7cbbbc5768a876ee93d103ad21e77d019`. A v5 caller may use any nonempty canonical subset of the format list. Authorization does not detect PAX or widen ustar: `TarPaxInterpretationProfile::PortableV1` must still be selected explicitly. Policy v5 retains the derived cap so its compiled controls remain exactly equal to v4 even when the selected raw PAX path has no derived snapshot.

## GNU-long-name-capable default v6

`Policy::default_v6()` preserves the v5 resource and effect controls, including the mandatory derived-archive cap, changes the schema and id to `sealr.policy.v6` and `sealr:policy/default/v6`, and authorizes the canonical format list:

```json
"formats": ["zip", "zip64", "tar-ustar", "tar-gzip-ustar", "tar-pax", "tar-gnu-longname"],
"max_derived_archive_bytes": 536870912
```

Its exact digest is `aefc8a1baa113d7face30857ef64fe8f47c647fae863a72810b80380f8fd4178`. A v6 caller may use any nonempty canonical subset of the format list. Authorization does not detect GNU state or widen ustar or PAX: `TarGnuLongNameInterpretationProfile::PortableV1` must still be selected explicitly.

## Gzip-composition-capable default v7

`Policy::default_v7()` preserves the v6 resource and effect controls, including the mandatory derived-archive cap, changes the schema and id to `sealr.policy.v7` and `sealr:policy/default/v7`, and authorizes the canonical format list:

```json
"formats": ["zip", "zip64", "tar-ustar", "tar-gzip-ustar", "tar-pax", "tar-gnu-longname", "tar-gzip-pax", "tar-gzip-gnu-longname"],
"max_derived_archive_bytes": 536870912
```

Its exact digest is `92d576984b718e8a02bc6044090f8e2b335dbd1abd136d53e5b02d0ffbd978ef`. A v7 caller may use any nonempty canonical subset of the format list. Authorization does not compose formats implicitly: `TarGzipInterpretationProfile::PaxPortableV1` and `TarGzipInterpretationProfile::GnuLongNamePortableV1` must still be selected explicitly, and each composition authorizes only its own format string.

## Zstd-capable default v8

`Policy::default_v8()` preserves the v7 resource and effect controls, including the mandatory derived-archive cap, changes the schema and id to `sealr.policy.v8` and `sealr:policy/default/v8`, and authorizes the canonical format list:

```json
"formats": ["zip", "zip64", "tar-ustar", "tar-gzip-ustar", "tar-pax", "tar-gnu-longname", "tar-gzip-pax", "tar-gzip-gnu-longname", "tar-zstd-ustar"],
"max_derived_archive_bytes": 536870912
```

Its exact digest is `d0cfdf4d40e3a88c8e80170494b23e91761802304265e41ce19cb616fa8a1c42`. A v8 caller may use any nonempty canonical subset of the format list. `TarZstdInterpretationProfile::UstarPortableV1` must still be selected explicitly. The 8 MiB zstd window ceiling is a profile constant; the reserved `max_dict_bytes` field remains reserved and compiles only at its default.

## Xz-capable default v9

`Policy::default_v9()` preserves the v8 resource and effect controls, including the mandatory derived-archive cap, changes the schema and id to `sealr.policy.v9` and `sealr:policy/default/v9`, and authorizes the canonical format list:

```json
"formats": ["zip", "zip64", "tar-ustar", "tar-gzip-ustar", "tar-pax", "tar-gnu-longname", "tar-gzip-pax", "tar-gzip-gnu-longname", "tar-zstd-ustar", "tar-xz-ustar"],
"max_derived_archive_bytes": 536870912
```

Its exact digest is `c512895c09453f16c07ebeae94712099191b197ba9edaae384dba0fe7bb8b39e`. A v9 caller may use any nonempty canonical subset of the format list. `TarXzInterpretationProfile::UstarPortableV1` must still be selected explicitly. The 8 MiB xz dictionary ceiling is a profile constant; the reserved `max_dict_bytes` field remains reserved and compiles only at its default.

## Bzip2-capable default v10

`Policy::default_v10()` preserves the v9 resource and effect controls, including the mandatory derived-archive cap, changes the schema and id to `sealr.policy.v10` and `sealr:policy/default/v10`, and authorizes the canonical format list:

```json
"formats": ["zip", "zip64", "tar-ustar", "tar-gzip-ustar", "tar-pax", "tar-gnu-longname", "tar-gzip-pax", "tar-gzip-gnu-longname", "tar-zstd-ustar", "tar-xz-ustar", "tar-bzip2-ustar"],
"max_derived_archive_bytes": 536870912
```

Its exact digest is `eada8150e14c0f05dcb25b6c9a90b87d3821fbb5f754192aceaea6d942e9f374`. A v10 caller may use any nonempty canonical subset of the format list. `TarBzip2InterpretationProfile::UstarPortableV1` must still be selected explicitly. Bzip2 decoder memory is capped by the format's own level digit — nothing attacker-declared exists — and the reserved `max_dict_bytes` field remains reserved and compiles only at its default.

## 7z-capable default v11

`Policy::default_v11()` preserves the v10 resource and effect controls, changes the schema and id to `sealr.policy.v11` and `sealr:policy/default/v11`, and authorizes the canonical format list:

```json
"formats": ["zip", "zip64", "tar-ustar", "tar-gzip-ustar", "tar-pax", "tar-gnu-longname", "tar-gzip-pax", "tar-gzip-gnu-longname", "tar-zstd-ustar", "tar-xz-ustar", "tar-bzip2-ustar", "7z-copy"],
"max_derived_archive_bytes": 536870912
```

Its exact digest is `afa0aeb04ceca00706b31dfd250216a87f2af0ada6e98d3815873de0d15172fc`. A v11 caller may use any nonempty canonical subset of the format list. `SevenZInterpretationProfile::CopyPortableV1` must still be selected explicitly. The Copy-only container decodes nothing, so no derived-archive or ratio consideration applies to it; the field requirements are preserved unchanged for the wrapped formats.

## Enforced fields

| Field | Current behavior |
|---|---|
| `formats` | Policy v1 must equal `["zip"]`. Policy v2 accepts canonical nonempty subsets of `["zip", "tar-ustar"]`. Policy v3 accepts canonical nonempty subsets of `["zip", "zip64", "tar-ustar"]`. Policy v4 accepts canonical nonempty subsets of `["zip", "zip64", "tar-ustar", "tar-gzip-ustar"]`. Policy v5 adds `"tar-pax"`, policy v6 adds `"tar-gnu-longname"`, policy v7 adds `"tar-gzip-pax"` and `"tar-gzip-gnu-longname"`, policy v8 adds `"tar-zstd-ustar"`, policy v9 adds `"tar-xz-ustar"`, policy v10 adds `"tar-bzip2-ustar"`, and policy v11 adds `"7z-copy"`, each accepting canonical nonempty subsets of its list. The explicitly selected format must be present; authorization never implies format detection or fallback. |
| `max_archive_bytes` | Bounds path reads and borrowed byte inputs before parsing. Path reads use a capped reader so file growth cannot exceed the cap. |
| `max_derived_archive_bytes` | Policy v4 through v11 only. Bounds the immutable decoded TAR while a gzip, zstd, xz, or bzip2 wrapper is consumed. It is separate from the original source, member, and total extracted-byte caps. Policies v5 through v11 preserve the field even when a raw dialect or container is selected so compiled controls do not drift. |
| `max_files` | Checked against both format-declared counts where present and the number of members actually parsed. A false low ZIP EOCD count cannot authorize member-vector growth beyond the cap. Policy v2 through v11 cap the configured value at `u32::MAX` because their multi-format identity encodings bind the count as `u32`. Policy v1 preserves the Alpha.8 constructor language; ZIP32 itself bounds actual member counts below that encoding limit. |
| `max_member_bytes` | Checked against declared size and actual bytes while expanding. |
| `max_total_bytes` | Checked against declared total and actual running total. |
| `max_ratio` | Integer uncompressed:compressed bound, compared with widened `u128` arithmetic. The default `100` rejects when uncompressed bytes strictly exceed `100 ×` compressed bytes. `null` disables the ratio check. `0` is not “off”: any positive expansion with a positive compressed size fails. A member with uncompressed size `> 0` and compressed size `0` is an infinite ratio. |
| `max_path_depth` | Checked after rejecting backslashes and removing dot components. |
| `max_metadata_bytes` | Bounds format-specific structural metadata. For ZIP this includes the central directory, EOCD comment, and referenced local name and extra bytes. For raw ustar it bounds admitted headers before trailing zero record padding is scanned. For every gzip-, zstd-, xz-, or bzip2-wrapped selection it cumulatively bounds the wrapper's structural bytes (headers, trailers, for xz the block headers, padding, checks, index, and footer, and for bzip2 the bit-granular block frames and padded footer rounded up to whole bytes) plus the inner dialect's structural metadata. For the 7z container it bounds the signature plus next header before the header is read. For raw PAX it additionally includes every extension payload and its zero padding; for raw GNU long-name it includes every carrier header and payload. |
| `overwrite` | Existing destinations are refused. Replacement is not implemented even if a caller mutates this field. |
| `encrypted` | Only `"deny"` compiles. Admission rejects traditional encryption bit 0, strong-encryption bit 6, and masked-header bit 13 even when LFH and CDH flags agree. |
| `atomic` | Despite its name, this field selects durability, not atomicity. Materialization always stages members privately and publishes with a native no-replace operation regardless of this value; that all-or-nothing publication is unconditional. When `atomic` is true, each completed member file is additionally synced before commit (durability `member-sync` in the receipt instead of the default `flush-only`). Directory syncing, crash recovery, and power-loss durability are not implemented in either mode. The field keeps its historical name because the policy schema and digest are an immutable contract; a clearer name would change every published policy digest. |

## Reserved fields

The following constructor fields exist so the receipt-hashed `Policy` object keeps a stable shape. They are **not** copied into compiled controls. Mutating any of them away from the default is `policy.unsupported` and fails before source ingestion:

- `max_dict_bytes`: reserved for future dictionary and window policy. The shipped zstd profile uses a fixed 8 MiB window ceiling and denies dictionaries outright; the shipped xz profile uses a fixed 8 MiB LZMA2 dictionary ceiling; the shipped bzip2 profile's memory is capped by the format's own level digit.
- `symlinks` and `hardlinks`: archive links are not created. ZIP external attributes are checked for file/directory agreement, and entries described as special file types are rejected. Mode bits and link targets are not preserved.
- `overwrite`: only `"refuse"` compiles. Replacement is not implemented.
- `setuid`: new files do not preserve archive mode bits.
- `nested_depth`: nested archives are never recursively opened.
- `ambiguity`: known structural ambiguity is always rejected by the interpretation profile.
- `case_fold_collision`: collisions under the interpretation profile's exact case-fold relation are always rejected by the path grammar.
- `magic_vs_extension`: the parser uses magic and does not interpret filename extensions.
- `encrypted`: encrypted ZIP members are always denied. The admission check covers the traditional, strong-encryption, and masked-header indicators defined by the ZIP general-purpose flags.

Callers must not treat mutating a reserved field as enabling the corresponding behavior. Compilation fails closed instead of silently ignoring the mutation.

## Evaluation order

1. Compile the constructor `Policy` into typed supported controls. Unknown or reserved combinations fail closed without reading the archive.
2. Bound and read the archive source.
3. Require the explicitly selected format to be authorized, then record observed magic independently from that selection.
4. Invoke exactly one selected parser and apply file-count and metadata caps. No parser race or extension-based fallback occurs.
5. Validate member method, declared sizes, declared ratio, path, duplicates, and topology.
6. Create a private staging directory only when materialization was requested.
7. Stream each member through actual size, total, ratio, CRC32, and SHA-256 checks.
8. Audit the staged tree against the admitted IR when materialization was requested.
9. Publish the staged tree only after every member and the audit pass.
10. Build the view, receipt, and tree identities for both allow and reject.

## Compatibility rule

Once a policy id is published in a stable supported release, changing its serialized bytes requires a new id. During the preview line, schema and defaults may change, and such changes must be called out in the changelog and receipt tests.

Normative safety properties are in [invariants.md](invariants.md). Current implementation limitations are in [README.md](../README.md).
