# Threat model (as of 22 August 2026)

Archive extraction is a **security boundary**, same class as HTML sanitizers, memory-safe parsers, and supply-chain attestations. Folklore (“just reject `..`”) is not enough. This file is the living adversary model. Invariants: [invariants.md](invariants.md). Differentials: [differentials.md](differentials.md).

**Mandatory paper:** Yufan You, Jianjun Chen, Qi Wang, Haixin Duan. *My ZIP isn’t your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers.* USENIX Security 2025.

- PDF: https://www.usenix.org/system/files/usenixsecurity25-you.pdf
- Talk: https://www.usenix.org/conference/usenixsecurity25/presentation/you
- Artifact (Results Reproduced): https://github.com/ouuan/ZipDiff - Zenodo `10.5281/zenodo.15526863`

They built ZipDiff, tested **50 parsers / 19 languages**. **1221 / 1225 parser pairs** were inconsistent. They systematized **14 ambiguity types** (10 new or substantially extended) in three categories. Real exploits: Gmail/Coremail/Zoho email-gateway bypass, Office content spoofing, LibreOffice signature forgery (CVE-2024-7788), Spring Boot nested JAR (CVE-2024-38807), VS Code extension ID impersonation, Go `archive/zip` (CVE-2024-24789).

Any serious engine must treat **parser disagreement** as a first-class threat, not an edge case.

---

## Adversary

The attacker crafts bytes (not necessarily a legal ZIP from Info-ZIP) and delivers them to a victim pipeline that **parses the same blob more than once**: scanner then extractor, marketplace then client, verifier then loader, agent then host.

They win if two components in that pipeline **both succeed** and **disagree** about the tree. ZipDiff explicitly does not count “one parser errors, one succeeds” as exploitable.

For materialization, a concurrent local actor may also race names inside the destination parent or a discovered stage. The destination parent must already exist and is opened as a retained capability. A missing parent is rejected rather than created, and a destination that exists or appears during staging is preserved.

On Linux and macOS, cross-principal namespace mutation is in scope. The opened parent is accepted only when its owner is the effective user or root and either its group/other write bits are clear or its sticky bit is set. Sticky does not make an untrusted directory owner safe, so a sticky directory owned by another user is rejected. Root-owned `/tmp` is trusted only because root is outside this in-process adversary boundary. The stage must be owned by the effective user with no group or other permissions. On macOS, any descriptor-reported extended ACL on the parent or stage is rejected, and an ACL query error fails closed, because an extended ACL can grant mutation rights beyond the mode bits.

On Windows, the retained parent must report non-remote, writable NTFS with persistent ACLs. Stage creation is an exclusive `NtCreateFile` operation rooted at that handle and receives a security descriptor whose object owner is the effective token user and whose protected DACL contains one inheritable allow ACE for that SID. The descriptor is verified through the returned handle before member writes. Descendants inherit that sole-principal DACL but receive the creating token's default owner under Windows semantics. A principal matching that default-owner SID can change a descendant DACL and is outside the in-process containment promise. The stage handle is retained without delete sharing. Publication uses `NtSetInformationFile` on that retained source handle, names the opened parent handle as the target root, and disables replacement. This closes inherited-DACL mutation by other principals, stage-name substitution, and destination clobber within the stated filesystem boundary.

Member operations must not follow a substituted link or reparse point. Root, an administrator, a principal matching the effective token's default-owner SID, a process running as the same security principal, a process with take-ownership, restore, or filesystem-override capabilities, or a process with debugging or handle-duplication rights is outside the containment promise of an in-process library. The planned worker contains its own parser authority but does not constrain another same-user process; bringing that actor into scope requires a distinct service identity or equivalent mandatory-access-control boundary. Receipts expose the selected storage, stage ACL, member-resolution, publication, outcome, and cleanup controls, but remain unsigned and therefore are evidence rather than authenticated attestations.

Pipelines that matter for us:

| Pipeline | Why it exists |
|---|---|
| AV / email gateway → user unarchiver | Classic ZipDiff scenario |
| Signature verifier → runtime loader | Android master key, Spring Boot JAR, LibreOffice |
| Marketplace / PyPI / npm → installer | VS Code, uv/pip wheels, RECORD vs ZIP |
| Agent `inspect` → host `materialize` | **Our** dual API; we must not be two parsers |
| Scanner (libarchive) → sealr | We must not be the second interpretation |

**Invariant for this engine:** current inspect, materialize, and verified-member reads share one interpretation. `VerifiedArchive` retains the exact snapshot and IR, and its path-input regression deletes the original archive before reading. Any future projection or mount MUST consume that same interpretation. A recovery or streaming parser MUST NOT provide a second display or effect meaning.

---

## ZipDiff taxonomy (the 14 types)

IDs are from the paper §5.2. `#` = new or newly extended by You et al.

### A - Redundant metadata (LFH vs CDH vs extra vs descriptor)

| ID | Name | What disagrees | Engine rule |
|---|---|---|---|
| A1 | Compression method confusion | CDH method ≠ LFH method (often one is “stored”) | **Deny** if CDH and LFH methods differ. Finding `zip.diff.a1_method`. |
| A2 | File size confusion `#` | Compressed/uncompressed size in CDH, LFH, data descriptor, one or more ZIP64 extras | **Never trust declared size.** Measure actual bytes. Deny if any declared size used for allocation disagrees with actual, or if CDH/LFH/descriptor/ZIP64 sizes disagree. Finding `zip.diff.a2_size`. |
| A3 | Filename confusion `#` | CDH name vs LFH name vs Info-ZIP Unicode Path extra (UP), version/CRC32/flag 11 games | **CD-first.** Raw LFH and CDH names must match. Alternate Unicode Path extras are rejected until one canonical Unicode representation exists. Finding `zip.diff.a3_name`. |
| A4 | Fake directory `#` | Trailing `/` vs `\`, external attributes (DOS vs Unix), `version made by` | `/` and zero sizes define a directory, and external type attributes must not contradict it. Backslash and non-regular external types are rejected. Finding `zip.diff.a4_dir`. |
| A5 | Fake encryption `#` | Encryption-related flags in CDH vs LFH; “first member encrypted ⇒ skip archive”; strong-encryption or masked-header bits without the traditional bit | CDH/LFH flags MUST agree. Admission refuses traditional bit 0, strong-encryption bit 6, and masked-header bit 13. Findings `zip.diff.a5_crypt` and `zip.encrypted`. |

CRC32 is **not** authentication (paper: easy to pad while preserving CRC). We still verify it. We do not treat it as a signature. SHA-256 is the current cryptographic content digest. BLAKE3 is not implemented.

### B - File-path processing

| ID | Name | Issue | Engine rule |
|---|---|---|---|
| B1 | Duplicate files | Same path, first vs last wins | **Deny** duplicate dest paths after normalization. Finding `zip.diff.b1_dup`. |
| B2 | Invalid characters `#` | Control chars, `"*:<>?\|`, NUL truncation, host-system charset | Jail already rejects these. Do **not** rewrite to `_`. NUL → deny (do not C-string truncate). Finding `zip.diff.b2_chars`. |
| B3 | Path canonicalization `#` (new type) | `//`, `./`, `content.xml` vs `./content.xml`, `\` vs `/` | Jail with `/` as the only separator. Reject backslash and empty components. Two names that canonicalize to one destination are duplicates. |
| B4 | Case sensitivity | `WORD/DOCUMENT.XML` vs `word/document.xml` | On Windows/macOS dest: treat case-fold collisions as B1. On Linux: preserve case but **report** `zip.diff.b4_case` if two members fold-equal. Default **deny** fold collisions everywhere so an agent on Linux doesn’t ship a tree that explodes on Windows. |

### C - ZIP structure positioning

| ID | Name | Issue | Engine rule |
|---|---|---|---|
| C1 | Streaming vs CD-first `#` (many constructions) | LFH without CDH; LFH after EOCD; LFH in comment; descriptor hunt; holes/overlaps | **CD-first only.** Ignore unreferenced LFHs. Deny overlapping compressed ranges (also Fifield bombs). Deny LFH data that doesn’t match CD offsets. No streaming extract API in v0. Finding `zip.diff.c1_stream`. |
| C2 | EOCDR selection `#` | Multiple EOCD signatures; comment-length skip; libzip “consistency score” | Scan backward; **one** EOCD whose comment length **exactly** matches remaining bytes. Extra EOCD signatures in the comment → finding, default **deny**. Finding `zip.diff.c2_eocd`. |
| C3 | CDH count confusion `#` | Total vs this-disk count; 16-bit wrap; size vs count | ZIP32 counts must agree with each other and the actual CDH count. ZIP64 sentinels and records fail closed. Finding `zip.diff.c3_count`. |
| C4 | CD & LFH offset confusion | Gap before EOCD; prepended SFX; parsers add δ to offsets | Default **deny** prepended junk (SFX later, explicit). CD offset + CD size MUST land exactly on EOCD. LFH offsets MUST land inside the file and not overlap. Finding `zip.diff.c4_offset`. |
| C5 | ZIP64 EOCD processing `#` (new type) | Locator vs signature search; mix ZIP64 and classic fields | Alpha.4 rejects every ZIP64 locator, EOCD record, sentinel, and semantic extra. A future ZIP64 profile must bind the locator and record and must never mix classic and ZIP64 interpretations. Finding `zip.diff.c5_zip64`. |

---

## Classical attacks (still live)

| Attack | Status 2025–2026 | Control |
|---|---|---|
| Zip Slip / path traversal | zip crate CVE-2025-29787; GuardDog; pip CVE-2025-8869 | Jail ([safety.md](safety.md)) |
| Overlapping-entry bombs (Fifield / Bamsoftware) | Not ZipDiff; still the quadratic bomb | Range overlap + actual-byte caps |
| Recursive 42.zip | Classic | No nested recurse; depth limit when nested *is* allowed |
| Declared vs actual size | ZipDiff A2 + bombs | Measure actual |
| TAR GNU long-name / PAX metadata bombs | exarch already bounds 4 MiB | Metadata size cap |
| setuid/setgid | Still default-on in tar extractors | Strip |
| Polyglot / magic vs extension | Jana/Shmatikov chameleon; Panakkal mixed containers | Magic authority; report conflict |
| Wheel `RECORD` vs ZIP | PyPI 2025–2026; uv CVE-2025-54368 | Dedicated wheel container and consumer profiles |
| Parser differential (this file) | USENIX 2025 | Strict single interpretation + findings |

### Wheel consumer threats

Wheel admission adds a second semantic layer above the ZIP container. The proposed controls below are design targets, not Alpha.4 behavior. Their full contract is in [Python wheel consumer profile v1](profiles/python-wheel-v1.md).

| Attack | Ambiguity or effect | Planned control |
|---|---|---|
| Missing, duplicate, or phantom `RECORD` rows | ZIP members and the hashed inventory disagree | Require one canonical `RECORD`, one row per admitted member, no unknown rows, and verified hashes and sizes except for specification-defined self and signature-file exemptions |
| Traversing or colliding `RECORD` paths | The metadata inventory names a different target from the archive member | Parse every row through the same wheel path grammar and reject normalized, case-folded, and Unicode collisions |
| `.data` relocation collision | Two archive paths become one installed path after scheme relocation | Build and validate the complete install plan before any target effect |
| Generated entry-point target collision | A launcher or wrapper overwrites an admitted file or another generated target | Treat generated entries as first-class install-plan nodes and run the same collision checks over the combined plan |
| Reserved interpreter or platform name | A valid-looking member becomes unsafe on a target filesystem | Apply target-aware reserved-name and portability rules before realization |
| Executable mode or script rewrite disagreement | Installers disagree about shebang rewriting or executable permission | Make transformations explicit, deterministic install-plan operations and bind their rules into the consumer-profile identity |

---

## Paper mitigations → our choice

You et al. §7.2, seven strategies:

| Mitigation | We do? |
|---|---|
| Use the same parser everywhere in a workflow | **Yes for current inspect and materialize.** Any future projection or mount must consume the same IR. We cannot control consumers that reopen the source elsewhere. |
| On-access / consume the other component’s parse | A future admitted-tree projection is the analog. It is not implemented. |
| **Normalize** (extract + repack to an unambiguous ZIP) | Phase 3. Powerful; must not become a second parser. Normalize **with this engine**, then the output is the artifact. |
| Identify ambiguous patterns | **Current strict default.** Known ambiguous or malformed structure is denied. A future compatibility profile must be separately versioned rather than acting as an insecure fallback. |
| Incorporate multiple parsers | Research/CI only (ZipDiff corpus). Not in the hot path. |
| Fix unique/outlier behaviors | A versioned interpretation specification and executable behavior must agree. Alpha.4 has two preview profile identities, but neither is yet stable. |
| Better format design | Later (next-gen container). |

Default posture: **reject ambiguity**. Future SFX or APK support would require separate named interpretation and consumer profiles recorded in evidence, never an `--insecure` fallback.

---

## What we are not

Sealr is not an antivirus or package inventory system. It does not claim CRC is a signature and does not run 50 parsers during an invocation. Alpha.4 is one strict parser with selectable versioned rules that returns a structured finding at the deterministic refusal point. A rejected view may be partial and must not be treated as a complete inventory.

Property tests, fuzzing, model checking, native race stress, and release provenance support different claims. None alone establishes unique interpretation, complete filesystem race freedom, or a formally verified extractor. Every assurance result is scoped to its input domain, model, platform, tool version, and stated assumptions.
