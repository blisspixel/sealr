# Policy

Policy is an input to `apply()` and is bound into every receipt by id and SHA-256 digest. Caps and behavioral choices must not live only in command-line state.

The current schema is pre-release `sealr.policy.v1`. The Rust API constructs `Policy` directly. Loading arbitrary JSON policy documents, rejecting unknown fields, derived policy ids, and RFC 8785 canonical hashing are planned but not implemented.

There is no insecure mode.

## Current default

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

## Enforced fields

| Field | Current behavior |
|---|---|
| `formats` | ZIP must be present. ZIP is the only implemented format. |
| `max_archive_bytes` | Bounds path reads and borrowed byte inputs before parsing. Path reads use a capped reader so file growth cannot exceed the cap. |
| `max_files` | Checked from EOCD before member-vector growth. |
| `max_member_bytes` | Checked against declared size and actual bytes while expanding. |
| `max_total_bytes` | Checked against declared total and actual running total. |
| `max_ratio` | Checked against declared and actual expanded bytes when compressed size is nonzero. `null` disables the ratio check. |
| `max_path_depth` | Checked after rejecting backslashes and removing dot components. |
| `max_metadata_bytes` | Bounds the central directory, EOCD comment, and referenced local name and extra bytes during parsing. |
| `overwrite` | Existing destinations are refused. Replacement is not implemented even if a caller mutates this field. |
| `atomic` | Materialization always stages before publication. When true, each completed member file is also synced before commit. Directory durability is not yet guaranteed. |

## Reserved fields

The following fields are present so the receipt describes the intended policy shape, but the current ZIP32 subset either denies the feature unconditionally or has no relevant implementation yet:

- `max_dict_bytes`: reserved for zstd and LZMA windows.
- `symlinks` and `hardlinks`: archive links are not created. ZIP external attributes are checked for file/directory agreement, and entries described as special file types are rejected. Mode bits and link targets are not preserved.
- `setuid`: new files do not preserve archive mode bits.
- `nested_depth`: nested archives are never recursively opened.
- `ambiguity`: known structural ambiguity is always rejected.
- `case_fold_collision`: ASCII case-fold collisions are always rejected.
- `magic_vs_extension`: the parser uses magic and does not interpret filename extensions.
- `encrypted`: encrypted ZIP members are always rejected.

Callers must not treat mutating a reserved field as enabling the corresponding behavior.

## Evaluation order

1. Bound and read the archive source.
2. Detect format magic and check the allow-list.
3. Parse one exact ZIP layout and apply file-count and metadata caps.
4. Validate member method, declared sizes, declared ratio, path, duplicates, and topology.
5. Create a private staging directory only when materialization was requested.
6. Stream each member through actual size, total, ratio, CRC32, and SHA-256 checks.
7. Publish the staged tree only after every member passes.
8. Build the view and receipt for both allow and reject.

## Compatibility rule

Once a policy id is published in a supported release, changing its serialized bytes requires a new id. Before the first supported release, schema and defaults may change, and such changes must be called out in the changelog and golden receipt tests.

Normative safety properties are in [invariants.md](invariants.md). Current implementation limitations are in [README.md](../README.md).
