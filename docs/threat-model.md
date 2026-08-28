# Threat model (as of 27 August 2026)

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

For path ingest, replacement of the caller pathname after open is in scope. Sealr opens once, copies under the input cap into a random native-private directory, hashes exact copied bytes, checks opened-source length and observable modification state, reopens its own file read-only, removes that filename, and performs all interpretation and verification against the retained unnamed handle. Truncation, cap growth, path replacement, short reads, and interruption have deterministic regressions. A same-principal actor that can modify the already opened caller file during construction without a detectable length or timestamp change remains outside the current in-process containment claim and needs broader native stress plus a reduced-identity boundary.

On Linux and macOS, cross-principal namespace mutation is in scope. The opened parent is accepted only when its owner is the effective user or root and either its group/other write bits are clear or its sticky bit is set. Sticky does not make an untrusted directory owner safe, so a sticky directory owned by another user is rejected. Root-owned `/tmp` is trusted only because root is outside this in-process adversary boundary. The stage must be owned by the effective user with no group or other permissions. On macOS, any descriptor-reported extended ACL on the parent or stage is rejected, and an ACL query error fails closed, because an extended ACL can grant mutation rights beyond the mode bits.

On Windows, the retained parent must report non-remote, writable NTFS with persistent ACLs. Stage creation is an exclusive `NtCreateFile` operation rooted at that handle and receives a security descriptor whose object owner is the effective token user and whose protected DACL contains one inheritable allow ACE for that SID. The descriptor is verified through the returned handle before member writes. Descendants inherit that sole-principal DACL but receive the creating token's default owner under Windows semantics. A principal matching that default-owner SID can change a descendant DACL and is outside the in-process containment promise. The stage handle is retained without delete sharing. Publication uses `NtSetInformationFile` on that retained source handle, names the opened parent handle as the target root, and disables replacement. This closes inherited-DACL mutation by other principals, stage-name substitution, and destination clobber within the stated filesystem boundary.

Member operations must not follow a substituted link or reparse point. Root, an administrator, a principal matching the effective token's default-owner SID, a process running as the same security principal, a process with take-ownership, restore, or filesystem-override capabilities, or a process with debugging or handle-duplication rights is outside the containment promise of an in-process library. The planned worker contains its own parser authority but does not constrain another same-user process; bringing that actor into scope requires a distinct service identity or equivalent mandatory-access-control boundary. Receipts expose the selected storage, stage ACL, member-resolution, publication, outcome, and cleanup controls, but remain unsigned and therefore are evidence rather than authenticated attestations.

The future worker response is hostile input to the supervisor. [Worker protocol v1](worker-protocol.md) bounds frames, counts, strings, canonical paths and topology, state combinations, capability slots, operation correlation, and representable request resource claims before effect. It does not return a complete `ArchiveIR`, source or policy binding, or later verified-read authority, so it cannot become a public outcome format by itself. A future supervisor must validate the selected complete semantic contract, prove that the worker boundary and every descendant have released writable stage authority, audit the quiescent stage through retained capabilities, and retain publication authority. The codec does not prove that a transport attached the intended handles or that their operating-system rights are minimal.

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
| A3 | Filename confusion `#` | CDH name vs LFH name vs Info-ZIP Unicode Path extra (UP), version/CRC32/flag 11 games | **CD-first.** Raw LFH and CDH names must match. All current closed profiles deny Unicode Path extras. Portable UTF-8 v1 gives member-name bytes one strict UTF-8 NFC meaning. Finding `zip.diff.a3_name`. |
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
| C3 | CDH count confusion `#` | Total vs this-disk count; 16-bit wrap; size vs count | ZIP32 counts must agree with each other and the actual CDH count, and every ZIP32 profile rejects ZIP64 sentinels. The explicit ZIP64 profile resolves sentinel values once and requires legacy, ZIP64, and actual counts to agree. Finding `zip.diff.c3_count`. |
| C4 | CD & LFH offset confusion | Gap before EOCD; prepended SFX; parsers add δ to offsets | Default **deny** prepended junk (SFX later, explicit). CD offset + CD size MUST land exactly on EOCD. LFH offsets MUST land inside the file and not overlap. Finding `zip.diff.c4_offset`. |
| C5 | ZIP64 EOCD processing `#` (new type) | Locator vs signature search; mix ZIP64 and classic fields | ZIP32 profiles reject every ZIP64 locator, EOCD record, sentinel, and semantic extra. The explicit current-main strict ZIP64 profile binds fixed end-record and adjacent locator geometry when present, resolves each sentinel once, requires exact redundant-field agreement, and emits separate ZIP64-native evidence. It is authorized only by policy v3 and is not a ZIP32 fallback. Finding `zip.diff.c5_zip64`. |

---

## Classical attacks (still live)

| Attack | Status 2025–2026 | Control |
|---|---|---|
| Zip Slip / path traversal | zip crate CVE-2025-29787; GuardDog; pip CVE-2025-8869 | Jail ([safety.md](safety.md)) |
| Overlapping-entry bombs (Fifield / Bamsoftware) | Not ZipDiff; still the quadratic bomb | Range overlap + actual-byte caps |
| Recursive 42.zip | Classic | No nested recurse; depth limit when nested *is* allowed |
| Declared vs actual size | ZipDiff A2 + bombs | Measure actual |
| TAR GNU long-name / PAX metadata bombs | Extension payloads can drive allocation and state | Policy metadata cap plus profile-specific extension, record, keyword, and count caps |
| setuid/setgid | Still default-on in tar extractors | Strip |
| Polyglot / magic vs extension | Jana/Shmatikov chameleon; Panakkal mixed containers | Magic authority; report conflict |
| Wheel `RECORD` vs ZIP | PyPI 2025–2026; uv CVE-2025-54368 | Dedicated wheel container and consumer profiles |
| Parser differential (this file) | USENIX 2025 | Strict single interpretation + findings |

### Portable ustar threats

Raw ustar adds a second explicitly selected parser, not a parser race. `Policy::default_v1()` cannot authorize it; policy v2 plus `ArchiveSelection::TarUstar` must agree before source ingestion. Selection and observed magic are separate evidence, and no filename suffix triggers fallback.

| Attack | Portable ustar control |
|---|---|
| Header checksum confusion | Require exact six-octal-digit, NUL, space syntax and the unsigned byte sum with the checksum field treated as spaces. |
| Octal and GNU base-256 confusion | Accept a closed terminated ASCII-octal grammar with checked arithmetic; classify base-256 as a recognized unsupported feature. |
| Link or special-file effects | Admit only regular files and zero-size directories; reject links, devices, FIFOs, sparse, PAX, GNU long-name, and unknown types. |
| Prefix and name disagreement | Compose the fixed ustar prefix and name once, require strict UTF-8, and pass the result through the same portable path and topology contract. |
| Hidden bytes and concatenation | Require zero member padding, two zero terminator blocks, and only complete zero record-padding blocks through exact source end. |
| Metadata or count exhaustion | Charge every admitted header and terminator against the metadata cap before growing member state; bind the member-count ceiling to the identity encoding width. |
| Parser-produced range drift | Run an independent codec-free covering audit before payload execution and independently reconstruct the published layout vector. |

### Restricted POSIX PAX threats

Raw PAX is a third explicitly selected TAR parser path, not a wider ustar mode or parser race. `Policy::default_v5()` must authorize `tar-pax`, and `ArchiveSelection::TarPax(TarPaxInterpretationProfile::PortableV1)` must select it before source ingestion. Its profile digest is `db951f620acf54e67845144e138f9f16994439847a97601e20a424dfea7f4445`. Filename suffixes, carrier names, and observed magic never trigger a retry.

| Attack | Restricted PAX control |
|---|---|
| Record-length disagreement | Require one through twenty canonical decimal digits, exact full-record byte count including the newline, complete payload consumption, and checked arithmetic. |
| Unknown or security-sensitive metadata | Admit only exact `path` and `size`; deny timestamps, ownership, link, charset, sparse, vendor, unknown, duplicate, and empty-value records. |
| Local or global precedence confusion | Use a fixed four-field state, resolve local then global then underlying ustar independently for path and size, and retain exact extension and record provenance. |
| Orphan or chained local state | Require each local `x` header to be followed immediately by exactly one ordinary member, then clear local state. Deny another extension or terminator while local state is pending. |
| Extension metadata bomb | Cap one extension payload at 65,536 bytes, one extension at two records, keyword discovery at 16 bytes, and one archive at 1,024 extensions, in addition to `max_metadata_bytes`. |
| Hidden alternate path or size | Preserve the checksum-covered underlying ustar name and size as evidence, apply only the resolved effective values to topology and payload geometry, and bind both plus provenance into `sealrTreeV5`. |
| Carrier path effect | Treat extension carrier names as structural evidence only. They never enter destination topology, file count, retention, later reads, or materialization. |
| Mixed TAR dialect interpretation | Deny GNU carriers, links, sparse files, devices, FIFOs, base-256 numbers, concatenation, recovery behavior, and every unknown type. |
| Parser and audit shared mistake | Independently reparse physical headers, canonical records, exact covering, padding, state transitions, effective values, and provenance before readiness. |

### Restricted GNU long-name threats

Raw GNU long-name TAR is a fourth explicitly selected TAR parser path with exact old-GNU magic. `Policy::default_v6()` must authorize `tar-gnu-longname`, and selection is explicit. Its profile digest is `08fe2698806da997bc42e7e13a45cbf412a4a7056dec39c62456202680b91fa4`.

| Attack | Restricted GNU control |
|---|---|
| Carrier state confusion | One bounded `L` carrier must be consumed by exactly the next ordinary member; chained, orphan, or trailing carriers fail closed. |
| Carrier payload effects | The carrier payload requires strict UTF-8 with exactly one terminating NUL and passes the complete portable path contract; the carrier's own name is structural evidence only. |
| Hidden alternate path | The checksum-covered underlying header name is preserved as evidence, exact header-or-carrier provenance is recorded, and both are bound into `sealrTreeV6`. |
| Mixed dialect interpretation | `K` long links, sparse maps, base-256 numbers, PAX records, devices, links, concatenation, and recovery behavior are denied before any carrier state exists. |
| Carrier metadata bomb | Carrier payloads are capped at 8,192 bytes and archives at 1,024 carriers, in addition to `max_metadata_bytes`. |
| Parser and audit shared mistake | An independent audit reparses every header and replays the single-depth carrier state before readiness. |

### Gzip composition threats

The gzip-wrapped PAX and GNU compositions reuse the exact Alpha.10 wrapper threat model over a frozen inner dialect. `Policy::default_v7()` must authorize `tar-gzip-pax` or `tar-gzip-gnu-longname`, and each composition is selected explicitly.

| Attack | Composition control |
|---|---|
| Wrapper hiding an unsettled inner language | Compositions exist only for raw dialects whose conformance is frozen; the inner language is byte-for-byte the raw profile. |
| Inner-dialect aliasing through the wrapper | Each composition invokes exactly one inner parser against the derived domain; no detection, retry, or fallback between ustar, PAX, and GNU exists. |
| Derived-domain substitution | The ready boundary requires exactly two snapshots and one full-source transform whose recorded output length and SHA-256 match the derived snapshot and the wrapper evidence, then replays wrapper CRC32 and ISIZE against the derived bytes. |
| Identity collapse across encodings | Source identity names the compressed bytes, layout identity (`sealrTreeV7`/`sealrTreeV8`) binds wrapper fields plus the complete inner layout, and only content identity is shared with the raw dialect. |
| Decompression resource abuse | `max_derived_archive_bytes` bounds the decoded TAR, `max_ratio` bounds expansion against the recorded Deflate payload, and the wrapper metadata is charged against `max_metadata_bytes` before the inner parse. |

### Zstd wrapper threats

The zstd-wrapped ustar profile is the first codec promotion, so its threat model adds decoder-trust concerns beyond the composition pattern. `Policy::default_v8()` must authorize `tar-zstd-ustar`, and selection is explicit. Its profile digest is `c7d2e708f2f5258eddfb99fbf13661bd2f671a2daa4a45bc1d9603d30d472ae7`.

| Attack | Zstd wrapper control |
|---|---|
| Window-driven allocation abuse | The effective window — descriptor formula or single-segment content size — is capped at 8 MiB before decoder allocation, and `--long`-style frames are rejected exactly as the reference decompressor requires opt-in. |
| Dictionary or skippable-frame smuggling | Any `Dictionary_ID` and every skippable frame fail closed; no dictionary is ever registered with the decoder. |
| Header interpretation divergence | Sealr parses the frame header byte-exactly for evidence, then cross-checks the decoder's consumed length, content size, and checksum state; any disagreement is an integrity failure, never a silent preference. |
| Checksum or size lies | The XXH64 checksum and `Frame_Content_Size` are verified when present, Sealr owns the comparisons, and the ready boundary independently re-hashes the derived snapshot before any destination stage exists. |
| Concatenation and trailing bytes | Exactly one frame must consume the complete source; magic-prefixed trailing bytes are unsupported concatenation and everything else is malformed. |
| Decoder implementation faults | The reviewed `ruzstd` 0.9.0 floor postdates RUSTSEC-2024-0400 and the first-frame window-cap fix; its remaining `unsafe` ring buffer is a named review item, bounded incremental decoding avoids the crate's multi-frame conveniences, and a dedicated fuzz campaign exercises the wrapper. |

### Wheel consumer threats

Wheel evaluation adds a second semantic layer above the ZIP container. The controls below are supported Alpha.8 preview behavior in `sealr::wheel`; the Alpha.7 laboratory preserves the external installer proof. Their full contract is in [Python wheel consumer profile v1](profiles/python-wheel-v1.md).

| Attack | Ambiguity or effect | Supported-preview control |
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
| Fix unique/outlier behaviors | A versioned interpretation specification and executable behavior must agree. Current main has eight preview profile identities: four ZIP32 profiles, one explicit strict ZIP64 profile, raw portable ustar, strict gzip-wrapped portable ustar, and restricted raw POSIX PAX. None is yet stable. |
| Better format design | Later (next-gen container). |

Default posture: **reject ambiguity**. Future SFX or APK support would require separate named interpretation and consumer profiles recorded in evidence, never an `--insecure` fallback.

---

## What we are not

Sealr is not an antivirus or package inventory system. It does not claim CRC is a signature and does not run competing parsers during an invocation. Current main explicitly selects exactly one ZIP32, strict ZIP64, raw portable ustar, strict gzip-wrapped portable ustar, or restricted raw PAX path with versioned rules and returns a structured finding at the deterministic refusal point. ZIP64 and every TAR selection are in process only under their exact policy versions; supervised selection fails closed before source access and without fallback until later semantic records can bind their evidence. A rejected view may be partial and must not be treated as a complete inventory.

Property tests, fuzzing, model checking, native race stress, and release provenance support different claims. None alone establishes unique interpretation, complete filesystem race freedom, or a formally verified extractor. Every assurance result is scoped to its input domain, model, platform, tool version, and stated assumptions.
