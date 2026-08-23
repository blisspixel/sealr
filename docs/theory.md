# Interpretation theory

> Status: research notes. This page names the mathematical object Sealr is aiming at. It is not a proof, not a qualification claim, and not a description of capabilities that Alpha.4 already has. Implemented predicates and the ideal function are distinguished throughout. The current executable contract is the [README](../README.md), [invariants](invariants.md), and [semantic model](semantic-model.md).

Sealr is trying to give untrusted archive bytes a denotation: **at most one canonical IR per versioned profile, or no IR.** Git, Nix, and in-toto already know how to hash a tree you have. ZipDiff showed that ZIP, as deployed, does not uniquely produce one. The work is the missing compiler in the middle.

The tone of this page is intentional. The goal is high-consequence ingest. The method is to restrict the language until interpretation is a partial function of size at most one, then to hash that function’s output with domain separation, and to keep realization from choosing a second meaning. That is an engineering program. It is not “we proved ZIP unique,” and it is not “NASA uses this.”

## The inversion

Other extractors ask: *what tree can we recover from these bytes?*

That is the HTML5 move: specify recovery so every consumer shares one generous meaning. Archives are the opposite problem. ZipDiff compared 50 ZIP parsers across 19 languages, found 1221 of 1225 pairs inconsistent, and classified 14 ambiguity types. Almost every parser already has a meaning. They disagree.

The inverted primitive is not a list of files. A file list is a forgetful projection of a parse. The primary object is a **Π-covering**: a labeled partition of the source interval `[0, |S|)` into local records, central directory, EOCD, and comment, together with equations that force redundant labels on those intervals to coincide. A logical tree is a theorem of that covering, not an input to sanitization.

Central directory walking backward and local records walking forward must meet with empty remainder. If some byte has two roles or none, there is no archive. There is only an attack.

That is the middle-out inversion. The object in the middle is the unique covering, not the extracted files.

```text
untrusted bytes × profile
    ⇀  covering certificate
    ⇀  ArchiveIR
    →  layout root          (always, once IR exists)
    ⇀  content root         (only after complete verification)
    →  effect               (inspect / materialize / later project)
```

Effect is a different morphism. A failed destination does not retract the covering.

## Notation

| Symbol | Meaning |
|---|---|
| \(\mathbb{B} = \{0,\ldots,255\}\) | Bytes. |
| \(b \in \mathbb{B}^n\) | A source snapshot, identified with the half-open interval \([0,n)\). |
| \([i,j)\) | Byte range. Empty iff \(i=j\). Adjacent ranges meet: \([i,j) \cup [j,k) = [i,k)\). |
| \(\pi\) | Versioned interpretation profile. Executable profiles: compatibility-default `sealr.profile.zip.strict-ascii.v1` and opt-in closed `sealr.profile.zip.strict-ascii.v2`. |
| \(I_\pi : \mathbb{B}^* \rightharpoonup \mathsf{IR}\) | Partial interpretation. Undefined means no admitted tree. |
| \(L(\pi) = \mathrm{dom}(I_\pi)\) | The unique-parse language of the profile: a **strict subset** of APPNOTE. |
| \(\mathsf{H}\) | SHA-256, treated as a collision-resistant hash **assumption**, not a theorem. |
| \(\mathsf{pre}(\ell, x)\) | Git-style preimage \(\ell \,\Vert\, \mathtt{SP} \,\Vert\, \mathrm{dec}(\lvert x\rvert) \,\Vert\, \mathtt{NUL} \,\Vert\, x\). |
| \(R_\ell(x) = \mathsf{H}(\mathsf{pre}(\ell, x))\) | Domain-separated root. |
| \(E\) | Effect morphism: inspect, materialize, later project. |

Partial function means: for each \(b\), \(I_\pi(b)\) is undefined or a single IR. Uniqueness is \(\lvert I_\pi(b)\rvert \le 1\). It is never “ZIP has a unique parse.”

## Definitions

### Source as an interval

A `SourceSnapshot` is an immutable \(b \in \mathbb{B}^n\). Alpha.4 realizes this as owned or borrowed whole-buffer bytes. Current main also realizes path input as a bounded copy into a Sealr-owned private file whose exact length and digest are fixed before interpretation. A caller path, mutable file descriptor, ETag, or content length alone is not a snapshot: another writer can change the bytes under the parse.

Source identity \(S(b) = \mathsf{H}(b)\), or explicit unavailability if bytes were never held.

### Covering

For ZIP32 under `strict-ascii.v1`, an admitted covering of \([0,n)\) is, in order:

\[
[0,n) \;=\; \bigsqcup_m \mathrm{Local}(m) \;\sqcup\; [C,\,E) \;\sqcup\; [E,\,n)
\]

where \(C\) is the EOCD-stated central-directory offset, \(E = C + \lvert\mathrm{CD}\rvert\), and the EOCD comment length is exactly the suffix. Each local record is

\[
\mathrm{Local}(m) = \mathrm{LFH}(m) \;\sqcup\; \mathrm{Payload}(m) \;\sqcup\; \mathrm{Desc}(m)
\]

with \(\mathrm{Desc}(m)\) empty unless general-purpose bit 3 is set.

`check_layout` in `crates/sealr/src/zip.rs` already asks whether the local ranges are a partition of \([0,C)\): first start \(0\), nonempty, no overlap, no gap, last end \(C\). `find_eocd` selects the rightmost offset whose stored comment length makes the suffix exact. That **choice function** is unique. It does not prove that every other ZIP parser would pick the same record.

Extra fields live inside LFH/CDH intervals. They do not get a fifth top-level role. Denied IDs (`0x0001` ZIP64, `0x7075` Unicode Path) make \(I_\pi\) undefined. Other well-formed extras are recorded as ignored occupancy: they change layout identity and must not become a name channel.

### Interpretation

\[
I_\pi : \mathbb{B}^* \rightharpoonup \mathsf{IR}
\]

Defined only when the covering exists, CDH/LFH/descriptor agreement holds, names jail, and codecs consume their payload intervals exactly. Undefined is classified:

- `Malformed`: in-profile syntax, cover, or agreement failure;
- `Unsupported`: ZIP64, encryption, methods other than Store/Deflate, spanned, non-ASCII names;
- `Indeterminate`: bytes never held, I/O, cancellation.

Ideal \(I_\pi\) depends only on \((b,\pi)\). Alpha.4 still folds resource budget into `parse_zip` (`max_files`, `max_metadata_bytes`). That interference is named below.

`ArchiveIR` is an effect-independent term: profile id and digest, source digest, members with raw names, canonical paths, kinds, flags, methods, declared sizes, source ranges, extra dispositions, normalization actions, and after verification, actual sizes and content SHA-256. Inspect and materialize walk that object. They do not search for a second EOCD.

### Layout and content

\[
\begin{align*}
\mathrm{layout}(\mathit{ir}) &= R_{\mathtt{sealr.tree.layout.v1}}(\mathrm{enc}_L(\mathit{ir})) \\
\mathrm{content}(\mathit{ir}) &= R_{\mathtt{sealr.tree.content.v1}}(\mathrm{enc}_C(\mathit{ir}))
\end{align*}
\]

Layout commits to canonical paths, kinds, raw names, methods, flags, declared sizes, source ranges, extra occupancy, and jail actions. Content commits to canonical paths, kinds, actual sizes, and member SHA-256, and is **undefined** until verification is complete. The profile digest is a sibling identity, not mixed into tree bytes. `view_digest` is invocation JSON. It is not a tree root.

Store versus Deflate of the same files: different layout, same content. That is a feature. Hermetic reuse keys on content. Anti-confusion keys on layout. Mixing them is how “one digest, two trees” returns.

### Verification as a poset

```text
StructureOnly  ⊑  Partial{verified, pending}  ⊑  Complete
```

Content identity lives only at the top element. Layout identity lives as soon as IR exists.

### Effect is not interpretation

\[
E : \mathsf{IR} \times \text{target} \times \text{effect policy}
    \longrightarrow \{\mathsf{NotRequested},\;\mathsf{Committed},\;\mathsf{Failed}\}
\]

A failed rename is `Interpreted + Admitted + Complete + Failed`, not a different tree. Alpha.4 axes represent this. The compatibility `Verdict` still maps it to `rejected`.

## Implemented versus ideal

| Object | Ideal | Alpha.4 |
|---|---|---|
| \(I_\pi\) | Partial function of \((b,\pi)\) only | Parser also sees budget; Unicode absent |
| Unique covering | At most one admitted partition of \([0,n)\) | Local-prefix partition + CD land + last exact-suffix EOCD |
| Unique ZIP parse | False for ZIP-the-format | The ambiguous remainder is refused |
| EOCD | Unique covering certificate | Unique *selected* EOCD under exact-suffix scan |
| Extras | Every ID semantic or denied | ZIP64 and Unicode Path denied; others ignored occupancy |
| Codec | Exact consumption as part of \(I_\pi\) | Deflate `total_in == payload.len()`; Store copies the slice |
| Snapshot | Immutable for the job | Whole-buffer; no worker; no spool |
| Tree roots | Frozen encoding + golden ZIP vectors | Preview `sealrTreeV1`; empty-tree and walkthrough vectors |
| Covering certificate | Independently checkable interval list including EOCD | Top-level and per-member ranges on IR plus codec-free `audit_covering` |
| Formal proofs | Lemmas below | None yet |

## Named conjectures

None of these is “ZIP is unambiguous.” Collision resistance of SHA-256 is an assumption used by some claims, not a conjecture.

### Unique Covering

Fix \(\pi\). For every \(b \in \mathbb{B}^n\) there is at most one labeled partition of \([0,n)\) that satisfies the profile’s covering rules, CD/LFH agreement, extra policy, and EOCD exact-suffix rule, and at most one IR derived from that partition.

**Refutation.** Two distinct member lists or range assignments both accepted by \(\pi\).

**Not a refutation.** ZipDiff pairs where Info-ZIP and Python disagree: those parsers are not \(\pi\). Bytes outside \(L(\pi)\).

**Code.** `check_layout`, CD land, last exact-suffix EOCD, extra denylist. `ArchiveIR.covering` records the local prefix, central directory, EOCD, and comment ranges, `sealrTreeV1` layout hashes them, and `audit_covering` rechecks the certificate without a second parse. Discovery and audit use one checked half-open interval and exact-partition kernel. Its arithmetic is exhaustively compared with a wide-integer oracle over 4,624 boundary pairs, and its partition predicate is exhaustively compared with a per-byte bitmap oracle over 1,055,758 bounded interval lists. These are finite executable checks, not an unbounded proof. Extra-field allowlist still waits on a new profile id.

### Redundant-Metadata Agreement

If `parse_π(S)` succeeds, then for every member, CDH and LFH agree on method, flags, and raw name, and sizes/CRC agree with the data-descriptor rule the profile binds. Directory-ness from a trailing `/` does not contradict external attributes.

**Code.** ZipDiff A1–A5 and descriptor parse. ZIP64 size extras are denied, not interpreted. CRC32 is a declared-field check, not authentication.

### Path-Projection Injectivity

The ASCII jail is a partial function. On an admitted IR, `canonical_path` is injective, the prefix relation is a forest, and ASCII case-fold is injective on the same set. Distinct raw names that jail identifies (`a/./b` versus `a/b`) are duplicates, not two files.

**Code.** Approximate for ASCII. Unicode NFC/NFKC, CP437, and host case tables are not in the domain.

### CD/LFH Confluence

On a unique covering with agreement, the CD-indexed reading and the LFH-stream reading of `[0, C)` induce the same map from canonical path to declared metadata. Hidden local records, prepended junk, and CD/LFH disagreement are divergence witnesses, hence rejects.

This is the ZIP analogue of Church–Rosser: two evaluation orders agree on the unique-covering language. It is the reason `check_layout` exists. It is not yet a theorem.

### Consumer Confluence (no second parser)

Consumers may read the IR and may read `S` only at ranges recorded in the IR. They do not call another ZIP parser. Then layout roots agree, and content roots agree whenever both verifications are complete. Inspect and materialize may disagree on `view_digest` and effect.

**Code.** One `apply()` path, tests pin inspect = materialize trees and roots. Not a proof that a future binding, wheel consumer, or worker will keep the signature.

### Effect Independence

Source, interpretation, layout, and content identities do not depend on destination, `wrote`, platform, or receipt environment.

**Code.** Axes and CLI exit `3` exist. The compatibility verdict still maps effect failure to `rejected`. Golden ZIP vectors run on every native platform job.

### Profile Non-Interference

Configuration factors as interpretation × budget × target × consumer × effect. \(I\) depends only on \((b, P)\). Admission depends on IR, budget, target, and consumer, not on whether an effect was requested. Overlays are monotone: a narrower overlay cannot enlarge \(L(P)\).

**Code.** `Policy::compile()` exists. `parse_zip` still takes budget caps. Target and consumer are not yet separate compiled objects.

### Codec Exact Consumption

For an admitted member with compressed range \([p, p+\ell)\): Store’s unique output is that slice; Deflate has a unique raw stream whose input cursor ends at \(p+\ell\). Concatenated streams and trailing bytes are not in the language.

If the codec may leave unread compressed bytes, those bytes can be a second ZIP record. Exact consumption is how payload intervals stay a partition.

**Code.** `DeflateDecoder::total_in() == payload.len()`. Not a proof of `zlib-rs`. Future Zstd/XZ/BZip2 adapters clone this predicate, they do not grow a second archive parser. Codecs never see an archive: they see a slice the covering already named.

### Parallel morphisms, sequential covering

Covering is a chain: each local record’s end is the next record’s start, and the last end is the central-directory offset. That chain is not data-parallel. Member verification after \(I_\pi(b)\) is defined *is* data-parallel: payload intervals are disjoint, the snapshot is immutable, and the content root sorts by canonical path, so thread schedule cannot change the root. Realization is a tree morphism: parents before children, then independent files, then one publish.

Using one core for \(I_\pi\) is not leaving performance on the table. Using sixteen cores to search for two EOCDs is. The first honest speedup is \(T_{\mathrm{verify}}\) over independent members, with quota combining and CD-order stop identity preserved. That cut must not introduce a task runtime into the TCB.

### Unique-Parse Admission

Let \(\mathcal{P}\) be ZIP parsers that choose an EOCD, read a central directory or a local stream, and bind names and payloads. Two parsers disagree on \(S\) if both succeed and the maps `canonical_path ↦ content` differ.

**Conjecture.** If extras are classified as semantic or denied (not ignored-and-used-elsewhere), jail is injective on the admitted name set, and Unique Covering, Agreement, and Exact Consumption hold, then \(L(\pi) \subseteq \mathrm{Unique}(\mathcal{P})\): if Sealr admits \(S\), no pair in \(\mathcal{P}\) both-succeed-and-disagree, and the unique map equals the content of the IR.

**Status.** Not yet. What exists is pattern detection of ZipDiff’s 14 classes plus a pinned 5,927-file gate. That is a finite set of divergence witnesses, not a proof of inclusion in \(\mathrm{Unique}(\mathcal{P})\). Unknown future ambiguity types are outside the corpus. `Ignored` extras are a hole in this conjecture.

## A lemma for this year

Not a Coq of Deflate. Not “all ZIP parses unique.” The covering checker is already a pure function on integer ranges.

### Lemma (Adjacent Covering of a Prefix)

Let \(R = ((s_i, e_i))_{i=1}^{k}\) with \(s_i, e_i \in \mathbb{N}\) and let \(C \in \mathbb{N}\). Write `check_layout` as in `crates/sealr/src/zip.rs`: empty-range reject, sort by start, first start \(= 0\), adjacent windows neither overlapping nor gapped, last end \(= C\), each end \(\le C\).

Then `check_layout(R, C)` succeeds if and only if:

1. \(k = 0\) and \(C = 0\), or
2. \(k \ge 1\) and the start-sorted intervals are a partition of \([0, C)\) into nonempty half-open intervals:

\[
s_{\sigma(1)} = 0,\quad
s_{\sigma(i)} < e_{\sigma(i)},\quad
e_{\sigma(i)} = s_{\sigma(i+1)},\quad
e_{\sigma(k)} = C.
\]

**Proof.** Sort is total on starts. `start ≥ end` is rejected, so intervals are nonempty. `end > next.start` is rejected, so they are disjoint. `end < next.start` is rejected, so there is no gap. First start \(= 0\) and last end \(= C\) means the union is \([0, C)\). The empty list is the unique partition of \([0, 0)\), and the code requires \(C = 0\). Conversely, any such partition satisfies each branch.

Independent of ZIP signatures, Deflate, Unicode, Windows, and SHA-256. This is the honest “we actually meant the partition predicate” lemma. Unique Covering uses it as the local-prefix part of the admitted covering. It does not say those ranges are the only ZIP-grammar reading of \(b\).

Kani target: extract the predicate on a bounded array of pairs and state the maximum array length and loop unwind bound explicitly. A successful harness is exhaustive only for that domain. It is machine-checked evidence for the adjacent-covering implementation, not an unbounded proof of ZIP interpretation.

**Runner-up.** If `jail_name(raw, d)` succeeds and `join_under_dest(dest, P, raw)` succeeds, then the result is dest plus the jailed components, and \(P\) contains none of \(\{\varepsilon, \mathtt{..}\}\). Kani on bounded ASCII. Still no Unicode.

## Why this is stronger than safe unzip, and where it is not

Safe unzip is mostly path containment plus quotas. Necessary. Already in the jail and streaming counters. It does not make interpretation a function. A sanitizer after a recovery parser is the non-confluent pipeline. LibreOffice-class bugs are two successful parses of one blob.

Git trees, Nix NAR, in-toto `dirHash1`, and OCI DiffID hash a tree you **already have**:

| Object | What it hashes | What it forgets |
|---|---|---|
| Git tree | Mode, name, child digest of an FSO | ZIP ranges, extras, methods, profile, verification completeness |
| Nix NAR | Unique serialization of an FSO | Same; NAR exists *because* ZIP/TAR hashes are not unique |
| in-toto `dirHash1` | Sorted `sha256  path` lines over **files only** | Empty directories, kinds, ranges, extras. Defined as extract-then-hash |
| OCI DiffID | SHA-256 of an uncompressed tar stream | Tar header non-canonicity, whiteouts, layer apply |
| Wheel `RECORD` | CSV of path, hash, size | Extra ZIP members, path aliases. Two parsers: ZIP and RECORD |
| cap-std / Landlock | Authority of a handle | Meaning. They constrain effect, not denotation |
| PEG / LangSec | Unique parse for languages that *are* PEGs or DCFLs | APPNOTE is not that language |
| PCC / TAL | Checkable safety of machine code | Not unique denotation of an archive |

Sealr’s pair \((\mathrm{layout}, \mathrm{content})\) is Git-style domain separation applied to an IR that still remembers ZIP intervals. Layout is not a Git tree. Content is not `dirHash1`. Content is not NAR: it is a root over members, not a dump of a realized directory. If Sealr ever *emits* a Git tree or NAR, that is a projection of an admitted IR, recorded as such.

What prior systems already have: containment of effect; content-addressed FSO identity once you have an FSO; measurement that ZIP is not unique; unique parse for languages that are PEGs; checkable certificates for code.

What they do not have, and Sealr is aiming at:

> A profile-indexed partial compilation \(I_\pi\) from untrusted archive bytes to a canonical IR, such that (i) \(I_\pi(b)\) is unique when defined, (ii) definition is witnessed by a covering certificate of source-interval facts checkable without re-executing codecs, (iii) layout and content identity do not depend on realization, and (iv) downstream consumption is a function of IR, not of a second ZIP parser.

That is not safer extract. It is “this profile is a unique-parse language, and consumers must use that denotation.”

## Three ways the aim is mathematically stricter

1. **Covering certificate over source intervals.** Git, NAR, DiffID, `dirHash1`, and RECORD commit to names and file bytes. None commit to “these CDH/LFH/payload ranges are pairwise disjoint, contained in \(b\), and exhaust the referenced structure” as a checkable object. Proof-carrying compilation applied to parse coverage, not to memory safety.
2. **Partial function, not total best effort.** PEG’s theorem is \(\lvert\mathrm{parses}\rvert \le 1\), which includes failure. A profile whose domain is the ZipDiff-closed subset, with \(I_\pi\) undefined outside it, is a **stricter language** (smaller domain), not a better unzip.
3. **Effect-independent identity plus a consumption morphism.** Layout from structure, content only after complete verification, neither depending on dest or OS. Then every admitted use is \(f(\mathsf{IR})\), never \(\mathrm{Parse}'(b)\).

## Three ways “better than all approaches before” would be dishonest

1. **Stealing FSO-hash theorems and calling them archive-compilation theorems.** NAR exists because ZIP hashes are not unique. Git already has domain-separated Merkle preimages; `sealrTreeV1` copies that construction with different labels. Claiming a new uniqueness theorem because Sealr hashes a tree is claiming Nix’s theorem about FSOs as if it were a theorem about ZIP bytes. Sealr still has to *choose* the FSO. That choice is the ZipDiff problem.
2. **Calling fail-closed subset uniqueness a proof of parser uniqueness.** APPNOTE is context-sensitive, search-based, and redundant. Pattern-detecting 14 classes is McKeeman-style testing plus a deny-list. ZipDiff itself says that cannot see unknown types. Shipping evidence JSON is not Necula.
3. **Collapsing effect confinement with interpretation.** cap-std and Landlock already separate effect from meaning; they do not make two parsers agree. If consumers still open the original archive with another ZIP parser, Sealr has Git-like identity plus ZipDiff’s original bug.

Shorter: uniqueness modulo a profile that rejects most of APPNOTE is a **smaller language**, not a stronger result than NAR-on-already-unzipped-trees. Until \(I_\pi\) is a specified language, the covering certificate exists, and some consumer is forbidden to reparse, this page is a research program, not a theorem Sealr possesses.

## Ideas that increase trust per unit of trusted code

Ranked. Trusted code means production TCB, not tests.

1. **Serialize the covering onto the IR and into the layout preimage.** `ArchiveIR.covering` records the local prefix, central directory, EOCD, and comment. `sealrTreeV1` layout hashes those ranges. A nonempty remainder is already a parse error via `check_layout`.
2. **A codec-free range-oracle checker.** `audit_covering` is the production checker: snapshot digest, signatures at claimed offsets, local and central partitions, and header/payload abutment. It shares checked interval and partition arithmetic with ZIP discovery, does not search for an EOCD, and does not inflate. A bounded bitmap oracle independently checks the partition predicate, while the separate identity verifier independently repeats the covering certificate check for committed vectors and recomputes their roots without depending on Sealr. Neither checker interprets ZIP again or executes codecs.
3. **Abolish ignored extras in a later profile.** Every extra ID is semantic (bound into layout) or denied. “Ignored” looks conservative and is how unique parse dies.
4. **Treat codecs as slice morphisms.** They see a payload interval the covering already named. Exact input consumption is the empty-remainder obligation one level down. They cannot re-enter discovery, jail, or publish.
5. **Worker as untrusted inhabitant-finder; supervisor as covering auditor.** Two coverings: source bytes and staged tree. Publish iff both check and the content root matches. The supervisor must not reparse ZIP.
6. **Machine-check bounded kernels; test the morphisms.** Use bit-precise model checking for stated jail, covering-arithmetic, and quota domains. Use property tests and hostile corpora for larger strings, parsers, codecs, and systems behavior. Do not claim a verified extractor.

Refuse even when they sound clever: consensus of N parsers in the hot path; a proof extra inside the ZIP (new A3); recovery-normalize as a second meaning of the old bytes; `--insecure`; libarchive; proving flate2.

## Proof obligations, three kinds

Do not mix these. A Kani harness on ranges is not a SHA-256 proof. A corpus gate is not Unique Covering.

**Combinatorial, this year.** Adjacent covering lemma; CD exact consumption; exact-suffix EOCD choice as the max of a finite set; ASCII jail dest-prefix; path injectivity; length-delimited tree encodings are uniquely decodable; extra denylist; quota monotonicity. The current pure quota transition is compared with `u128` over 159,528 finite states and increments and preserves the previous state on overflow or cap failure. That is executable bounded evidence, not a proof over all transition traces.

**Cryptographic assumptions.** SHA-256 collision and second-preimage resistance. Domain-separated labels so layout and content cannot share a preimage even if bodies collided across labels. CRC32 is not a CRHF. Hygiene: never hash unlabelled concatenations of variable-length fields; never mix profile bytes into tree bytes.

**Systems, adversarial.** Inspect/materialize stay one parser after a worker exists; snapshot immutability under concurrent writers; no-replace publication; host does not select Unicode; ZipDiff gate covers known constructions, not \(\mathbb{B}^*\).

The current independent identity verifier checks committed covering certificates without inflating and reproduces their profile and tree digests. That establishes combinatorial and encoding agreement for those finite vectors, not codec execution, parser correctness outside the vectors, or a cryptographic proof. The broader signed-evidence verifier in the [roadmap](../ROADMAP.md) remains future work.

## What this page must not become

- A claim that ZipDiff’s 14 classes exhaust ZIP ambiguity.
- A claim that 5,927 fixtures prove Unique-Parse Admission.
- “Formally verified extractor,” “flight-proven,” or “safe for Mars.”
- A claim that `source` digest implies a tree. That is the identity Sealr exists to refuse.
- A claim that `view_digest` is a tree root, or that an unsigned receipt is an attestation.
- A claim that inspect = materialize is a theorem about all future consumers. It is one code path plus tests.
- Completeness with respect to APPNOTE. \(L(\pi)\) is an intentional unique-parse subset: APPNOTE-legal but ambiguous is undefined.

**What the math is, unproven:** compilation of untrusted container bytes under a versioned unique-parse grammar, with the covering as witness and the tree as a projection of that witness.

**What is implemented:** a recognizer for a ZIP32 Store/Deflate fragment of that language, one IR, preview roots, and a corpus of known divergence witnesses.

The work is to make \(L(\pi)\) actually unique-parse, then to check certificates without parsing again.

## References

- Yufan You, Jianjun Chen, Qi Wang, Haixin Duan. *My ZIP isn’t your ZIP.* USENIX Security 2025.
- LangSec: parser differentials; unique parse for restricted language classes; equivalence of parsers is undecidable above deterministic context-free.
- Git objects: `type SP decimal_len NUL body` as domain separation.
- Nix NAR: unique serialization of an already-unambiguous filesystem object.
- in-toto digest sets, including `dirHash1`.
- OCI image spec: DiffID as hash of an uncompressed tar stream.
- Necula, proof-carrying code: complex producer, small checker.
- Ford, PEG: at most one parse, including failure.
- McKeeman, differential testing: if two implementations disagree, at least one is wrong.
- EverParse / non-malleable DER: unique binary representation of a value, which is what a profile wants and what APPNOTE is not.
- [Semantic model](semantic-model.md), [invariants](invariants.md), [differentials](differentials.md), [attestations](attestations.md), [roadmap](../ROADMAP.md).
