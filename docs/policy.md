# Policy

Policy is an input to `apply()` and is bound into every receipt by id and SHA-256 digest. Caps and behavioral choices must not live only in command-line state.

The implemented pre-release schemas are `sealr.policy.v1` and `sealr.policy.v2`. The Rust API constructs `Policy` directly. `apply()` compiles that constructor into typed supported controls before reading archive bytes. Loading arbitrary JSON policy documents, rejecting unknown serde fields, derived policy ids, and RFC 8785 canonical hashing are planned but not implemented.

There is no insecure mode.

## Operation options are not policy

`apply_with_options` accepts two kinds of operation-scoped input outside the policy object: explicit archive/profile selection and capabilities such as a bounded `RetentionPlan`. Selection changes the container language and interpretation identity. The policy separately authorizes that selected format, so selection cannot widen `formats`. A retention plan does not change interpretation, archive admission, receipt or tree identity, or whether a destination is requested.

`apply()` selects the immutable compatibility profile `sealr.profile.zip.strict-ascii.v1` and requires the ZIP-only `Policy::default_v1()` contract. Callers can explicitly select the [closed strict ASCII v2 profile](profiles/zip-strict-ascii-v2.md) or the [portable ustar profile](profiles/tar-ustar-portable-v1.md) through `ApplyOptions`. TAR selection requires a policy that authorizes `tar-ustar`, normally `Policy::default_v2()`. The same prerelease enum exposes the separately named `sealr.profile.zip.wheel-utf8.v1` repository-research language without changing either supported ASCII profile. A retention plan names only exact canonical paths and supplies independent per-member and aggregate retained-byte ceilings. Failure to retain a requested path is reported through `VerifiedArchive::retention_status`; it does not relax an archive rule or convert a rejection into an admission. A higher-level consumer that requires those bytes must fail its own evaluation unless every required status is `Retained`. The full contract and limits are in [bounded one-pass retention](api.md#bounded-one-pass-retention).

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

## Enforced fields

| Field | Current behavior |
|---|---|
| `formats` | Policy v1 must equal `["zip"]`. Policy v2 accepts the canonical nonempty subsets `["zip"]`, `["tar-ustar"]`, or `["zip", "tar-ustar"]`. The explicitly selected format must be present. |
| `max_archive_bytes` | Bounds path reads and borrowed byte inputs before parsing. Path reads use a capped reader so file growth cannot exceed the cap. |
| `max_files` | Checked against both format-declared counts where present and the number of members actually parsed. A false low ZIP EOCD count cannot authorize member-vector growth beyond the cap. Policy v2 caps the configured value at `u32::MAX` because its multi-format identity encodings bind the count as `u32`. Policy v1 preserves the Alpha.8 constructor language; ZIP32 itself bounds actual member counts below that encoding limit. |
| `max_member_bytes` | Checked against declared size and actual bytes while expanding. |
| `max_total_bytes` | Checked against declared total and actual running total. |
| `max_ratio` | Integer uncompressed:compressed bound, compared with widened `u128` arithmetic. The default `100` rejects when uncompressed bytes strictly exceed `100 ×` compressed bytes. `null` disables the ratio check. `0` is not “off”: any positive expansion with a positive compressed size fails. A member with uncompressed size `> 0` and compressed size `0` is an infinite ratio. |
| `max_path_depth` | Checked after rejecting backslashes and removing dot components. |
| `max_metadata_bytes` | Bounds format-specific structural metadata. For ZIP this includes the central directory, EOCD comment, and referenced local name and extra bytes. For ustar it bounds admitted headers before trailing zero record padding is scanned. |
| `overwrite` | Existing destinations are refused. Replacement is not implemented even if a caller mutates this field. |
| `encrypted` | Only `"deny"` compiles. Admission rejects traditional encryption bit 0, strong-encryption bit 6, and masked-header bit 13 even when LFH and CDH flags agree. |
| `atomic` | Materialization always stages before publication. When true, each completed member file is also synced before commit. Directory durability is not yet guaranteed. |

## Reserved fields

The following constructor fields exist so the receipt-hashed `Policy` object keeps a stable shape. They are **not** copied into compiled controls. Mutating any of them away from the default is `policy.unsupported` and fails before source ingestion:

- `max_dict_bytes`: reserved for zstd and LZMA windows.
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
