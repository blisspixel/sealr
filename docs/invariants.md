# Core safety invariants (non-negotiable)

These are **properties**, not features. They are the *type* of `inspect` / `materialize` / `mount`. Files on disk are a side effect that is only allowed if this boundary returns yes.

This document is the target safety contract. [README.md](../README.md#security-limitations) and [ROADMAP.md](../ROADMAP.md) are authoritative for current implementation status. Alpha.4 intentionally fails closed where canonical Unicode handling is unfinished, and it does not yet satisfy every filesystem-race, fuzzing, proof, isolation, or bounded-input obligation below.

Each invariant MUST appear in the assurance claim ledger and receive evidence appropriate to its kind. Pure input properties require deterministic tests and generated properties; byte parsers require finite hostile corpora and coverage-guided fuzzing; bounded arithmetic and finite state machines are model-checking candidates; filesystem and authority properties require native fault and race tests. A finding code is required when an invocation can report the violation. CI infrastructure failures and excluded-adversary assumptions are recorded as evidence or limitations rather than invented archive findings.

Safety is the only default. Permissive behavior is a **named policy document**, loud in logs and on the receipt. There is no `--insecure`.

Detail for ZIP differentials: [threat-model.md](threat-model.md). Path grammar: [safety.md](safety.md).

---

## I1 - Path containment

Every extracted (or hydrated) path, with `/` as the only accepted archive separator, canonical Unicode normalization, case-fold where the destination filesystem is case-insensitive, and rejection of backslashes, reserved names, ADS names, and trailing-dot names, MUST be `dest` or a strict child. Alpha.4 strict ASCII v2 rejects non-ASCII paths until that canonical Unicode representation exists.

- No symlink or hardlink is followed when computing the dest (`O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`).
- Pre-existing reparse points inside the private stage are hostile and are never traversed for member creation.
- Windows 8.3 short names, `\\?\`, and prefix attacks require retained directory handles for member creation. Windows stage creation and final publication are rooted at retained parent and stage handles, not a re-resolved source pathname.
- Recent GHSA issues in “safe extract” crates show this is still easy to get wrong. Property test: for all member names in a hostile corpus, `open` never yields a path outside dest.

## I2 - Resource limits (streaming)

Hard caps, enforced **as bytes arrive**, not after the fact:

| Cap | Default | Notes |
|---|---|---|
| Entry count | 10_000 | Includes dirs and skipped links |
| Uncompressed per member | 1 GiB | Actual AND declared |
| Uncompressed total | 5 GiB | Global atomic |
| Compression ratio | 100 | Declared and actual; stored = 1 |
| Path depth | 32 | After normalize |
| Metadata (TAR PAX / GNU long-name, ZIP extra, comment) | 4 MiB | exarch’s TAR bomb bound; keep |
| Dictionary / window | 64 MiB LZMA; 8 MiB zstd rec | Reject insane frames |

Flags may **raise** caps. They may not default unlimited. `max_ratio: null` disables the ratio check. `max_ratio: 0` is not off.

## I3 - Never trust declared sizes

Always count actual decompressed bytes. If the stream exceeds `min(declared, MAX_MEMBER)`, abort the member, delete the partial file. Allocation from headers uses `try_reserve` and MUST be bounded by I2 **before** the alloc. ZipDiff A2 is this invariant.

## I4 - Symlink / hardlink policy

Default **deny**. When a named policy allows them: the **target** MUST pass I1 relative to the link’s parent; not absolute; created only after regular files; never `open` through a link.

## I5 - Permission sanitization

Strip setuid/setgid/sticky by default. Mask to `0777` minus umask, or `0644`/`0755`. Finding `perm.setuid` if we stripped.

## I6 - Parser differential resistance

A single, documented interpretation (CD-first ZIP, magic over extension, deny the 14 ZipDiff classes). Anomalies are findings. Ambiguous archives are **errors** under default policy, not “best effort extract.” See [differentials.md](differentials.md).

The inspect API and the materialize API MUST NOT diverge (LibreOffice recovery-mode class of bug).

## I7 - Streaming + bounded allocation

Target state: no whole-archive load. Header-driven allocations go through `try_reserve` and I2. Expanded bytes stream in bounded chunks. A future whole-buffer codec is allowed only under a RAM gate. Alpha.4 still reads the archive into one input buffer capped at 512 MiB; removing that buffer is the Alpha.5 gate.

## I8 - Staged publication and optional durability

Publishing a final destination is all-or-reject. Materialization stages into a same-volume directory, audits that staged tree against the admitted IR (sizes, content digests, and the exact path set, including implicit parent directories), and renames it to a previously absent destination only after every member passes and that audit succeeds. Unix stages are private by verified mode and ownership. Windows stages on supported local NTFS parents are created with the effective token user as object owner and one protected allow ACE for that SID, with DACL inheritance to descendants. Descendants receive the creating token's default owner, which is independent of the inherited sole-TokenUser DACL. A normal failure never publishes the requested destination, attempts cleanup and one retry, and records whether the stage was removed or remains after both attempts fail.

The destination parent MUST already exist; materialization MUST NOT create it. On Linux and macOS, the opened parent MUST be owned by the effective user or root. Group/other write is safe only with sticky and a trusted owner. A sticky parent owned by any other user MUST be rejected. The stage MUST be owned by the effective user and MUST deny group and other permissions. On macOS, descriptor inspection MUST prove that both parent and stage have no extended ACL; an ACL or query failure MUST reject before publication.

Durability is a separate policy choice. When `atomic` is true, completed member files are synced before commit. Member creation uses retained per-component no-follow directory capabilities. Linux uses `renameat2` no-replace and macOS uses `renameatx_np` exclusive publication. Windows MUST admit only a non-remote, writable NTFS parent with persistent ACLs, create the stage exclusively with parent-rooted `NtCreateFile` and a protected effective-TokenUser-only inheritable DACL, verify that DACL through the retained handle, retain the handle without delete sharing, and publish that same object with parent-rooted `NtSetInformationFile` and replacement disabled.

Linux, macOS, and Windows are the supported materialization platforms; every other platform MUST fail closed. The receipt MUST record the selected stage-creation, member-resolution, durability, publication, outcome, and cleanup evidence, plus Windows storage and ACL observations when applicable. Root, administrators, principals matching the effective token's default-owner SID, same-principal processes, filesystem-override capabilities, and debugging or handle-duplication rights remain outside the in-process containment claim. The planned worker narrows its own ambient authority but does not contain another same-user process. Directory syncing, crash recovery, repeated hostile race testing, and that reduced-authority worker remain Phase 0.1 gates. Do not describe normal rollback as crash durability or an unsigned receipt as authentication.

## I9 - Verified consumption authority

Serializable evidence is not authority. A consumer may receive `VerifiedArchive` only after archive admission and complete member verification. Denied, structure-only, and partially verified outcomes MUST NOT expose it. An effect failure after complete verification may preserve the capability because archive admission and destination publication are separate axes.

Member lookup consumes the canonical paths in the existing `ArchiveIR`. It MUST NOT reopen the caller path, run another structural parser, or trust a caller-constructed IR. Before allocating, each read enforces a caller-supplied byte ceiling against the measured member size. A non-retained read rechecks actual size, CRC32, and SHA-256 against the verified evidence. An explicitly retained member is captured from that original checked stream and becomes visible only on the fully verified capability. The retention plan MUST use exact canonical paths, independent per-member and aggregate byte ceilings, bounded path metadata, deterministic selection, and fallible allocation. Retention failure MUST NOT admit an archive that would otherwise reject or expose partially verified bytes. Directory, absent-member, and retention statuses remain distinct.

---

## Mapping to findings

Every invariant break is a structured finding (`code`, `severity: error|deny|warn|info`, `member`, `detail`, `policy`). Errors abort that archive. Denies skip a member. Warns are policy-dependent.

No 0–100 “risk score.” Agents switch on `code`.
