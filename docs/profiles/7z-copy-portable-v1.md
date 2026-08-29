# Restricted Copy-only 7z container profile v1

> Status: supported in-process preview on current main. This is the first Gate C container profile — 7z structure separated deliberately from decoder complexity — and the first profile to prove cross-container content parity. Authenticated worker execution fails closed until a later semantic record.

Profile ID: `sealr.profile.7z.copy-portable.v1`

Profile SHA-256: `7b6604ad59b5aecf9ebdfa42d7d48d3df663813798992741dd6d74ea56f60b75`

Select this profile explicitly with `SevenZInterpretationProfile::CopyPortableV1` and authorize it with `Policy::default_v11()`. The CLI selection is `--format 7z-copy`. `apply()`, every ZIP and TAR selection, and source suffixes never select or retry this profile.

## Container model

7z is a header-last container: a 32-byte signature header names the next header's offset, size, and CRC32, and the next header's tagged property grammar describes pack streams, folders, substreams, and file records. Unlike the TAR wrappers, this is a single-domain container profile — no derived snapshot, no transform record — with member payloads at exact byte ranges of the original source, the same shape as ZIP and ZIP64. The ready boundary requires exactly one snapshot and an empty transform graph, and independently replays the complete container covering before a destination stage can be created.

## The packed-header carve, stated honestly

Stock producers compress the header itself: 7-Zip's `7z a -m0=Copy` and py7zr's writer default both emit a `kEncodedHeader` whose header stream is LZMA1-coded even when every payload is Copy. This first profile admits exactly one **raw** `kHeader` and classifies `kEncodedHeader` as a named unsupported shape whose finding text carries the producer remedy: `-mhc=off` for the 7-Zip CLI, `set_encoded_header_mode(False)` for py7zr. Both remedies are deterministic and measured (7-Zip 26.02 output is byte-identical across runs with fixed mtimes). Packed-header admission is the named follow-up, bound to the LZMA member review, because it introduces a new architectural shape — a decode step whose output is metadata rather than a member payload domain. This is the same posture as denying pbzip2 concatenation or `xz -9` dictionaries: a real, common producer shape with a named switch, denied with a stable classification.

## Accepted 7z language

- Signature `37 7A BC AF 27 1C` at offset zero, version major 0 minor 4, single volume; a signature elsewhere (SFX, `.001` volumes) is not this profile.
- Exactly one raw `kHeader`; `kEncodedHeader`, `kArchiveProperties`, `kAdditionalStreamsInfo`, `kComment`, `kStartPos`, `kAnti`, and every `External = 1` record (folders, names, times, attributes) are unsupported.
- Every coder is Copy (id `00`): one coder, one in-stream, one out-stream per folder, no bind pairs, no coder attributes, no complex coders; a folder's unpack size must equal its pack size — under Copy anything else is malformed.
- Variable-length integers must use minimal encodings — two encodings of one value are two readings, so non-minimal forms are malformed — and all size and count arithmetic is checked.
- Bit vectors are MSB-first with zero padding bits; digest sets use the `AllAreDefined` shortcut with exact per-item accounting.
- Substreams tile their folder exactly (the last substream's size is the folder remainder, and zero-size substreams are malformed); substream, pack, and folder CRC32s are verified when present — and every CRC in the container is the plain zlib CRC32, so **Sealr verifies every integrity field itself**: the start-header CRC, the next-header CRC, and every declared payload digest, with nothing decoder-owned.
- File records resolve through the kEmptyStream/kEmptyFile matrix: an empty-stream entry without the empty-file bit is a directory; with it, an empty file. The measured reality (the kEmptyFile bit, not the attribute, is the discriminator) corrects the common secondary documentation, and a `FILE_ATTRIBUTE_DIRECTORY` disagreement with the matrix is malformed rather than silently resolved — the exact two-parsers-disagree seam the boundary exists to close.
- Names are non-external, null-terminated UTF-16LE, consumed exactly, decoded strictly (unpaired surrogates are malformed), and pass the existing portable UTF-8 path grammar and jail; `kDummy` alignment padding must be all-zero bytes.
- Times and attributes are validated structurally and recorded as evidence-only container facts — the ZIP external-attribute posture; the unix-mode high bits are never applied.
- The covering is dense: `PackPos` must be zero, pack streams tile `[32, header)` contiguously, the header ends exactly at end-of-file, and there is no unreferenced-bytes category at all — stricter than ZIP32's comment allowance.
- Empty archives are unsupported: an admission boundary that admits nothing is not useful evidence.

## Resource contract

Policy v11 preserves every earlier control. `max_metadata_bytes` bounds the signature plus next header before the header is read; `max_files` bounds the declared file count before allocation, and every claimed count is additionally bounded by the remaining header bytes so hostile counts can never drive allocation; member payloads flow through the normal member, total, and path quotas. Copy is the identity, so there is no expansion-ratio concern and no derived-archive cap in play.

## Dependency boundary

Zero new packages. Raw-header parsing is pure structure over the snapshot; CRC32 uses the existing `crc32fast`, member hashing the existing `sha2`, and UTF-16LE decoding the standard library. The later packed-header step also costs nothing: `lzma-rust2`'s LZMA1 decoder already compiles under the pinned features from the xz promotion. No extractor crate enters, per the standing Gate C refusal of `sevenz-rust2`.

## Evidence and identities

The IR schema is `sealr.archive-ir.7z-copy.v1`. Container evidence records the version minor, the pack region and next-header ranges with the next-header CRC, every folder's pack stream, optional pack and folder CRCs, unpack size, and substream ranges with declared CRCs, and the name-region and dummy-padding geometry. Each member records its Copy payload range, declared CRC, and evidence-only attributes and modification time.

Source identity is SHA-256 of the exact source. Interpretation identity is the canonical profile above. Layout identity is `sealrTreeV12`, labeled `sealr.tree.layout.7z-copy.v1`, binding the profile digest, the dense covering, every folder and substream record, name and dummy geometry, and each member's destination meaning with its container facts. Content identity remains the format-neutral `sealrTreeV1`.

**Cross-container parity, proven for the first time:** a Copy 7z of exactly `mission/plan.txt` = "verify twice, decode once" shares the content root `bc8f6d6f7870aeab647cff08db25471a729bd2a41e095d49d6254c49afc34278` with the raw TAR and all four codec wrappers of the same member set — six structural identities, one content identity, now spanning containers rather than wrappers of one TAR. The conformance manifest pins that equality, and the standalone identity verifier reconstructs the full container grammar, every CRC, `sealrTreeV12`, and the shared `sealrTreeV1` root without linking Sealr.

## Producer coverage

Measured against 7-Zip 26.02: `-m0=Copy -mhc=off` output is admitted and deterministic; stock `-m0=Copy` output (packed header) is rejected as unsupported with the remedy named; the empty matrix, kDummy alignment, sorted UTF-16 names with forward slashes, and per-file Copy folders match the measured fixtures. py7zr's raw-header mode (`set_encoded_header_mode(False)`) is the documented second producer; its default mode is likewise packed-header and rejected.

## API example

```rust
use sealr::{ApplyOptions, Policy, SevenZInterpretationProfile};

let policy = Policy::default_v11();
let options = ApplyOptions::new()
    .with_sevenz_interpretation_profile(SevenZInterpretationProfile::CopyPortableV1);
```

The policy and selection are separate gates. Policies v1 through v10 refuse this selection before source ingestion. Combining the selection with a worker manifest returns typed isolation-unavailable failure and never falls back to in-process execution.

## Authorities

- The official [7z format description](https://github.com/ip7z/7zip/blob/main/DOC/7zFormat.txt) defines the signature, NUMBER encoding, property grammar, folders, and digests, corrected by local producer measurement where secondary documentation disagrees.
- [POSIX portable UTF-8 path rules](zip-portable-utf8-v1.md) govern decoded member names through the existing jail.
