# Portable UTF-8 ZIP32 profile v1

> Status: supported Alpha.8 preview profile. The identifier, canonical bytes, and digest are published for conformance testing. Callers opt in through `ApplyOptions`; `apply()` retains the strict ASCII v1 compatibility default.

`sealr.profile.zip.portable-utf8.v1` is the first general-purpose Unicode interpretation supported by the library. It defines one strict UTF-8 and NFC name language without guessing between UTF-8, CP437, or Unicode Path extra-field meanings.

The profile SHA-256 is `acee86158d481adff96da0277a470ba753d6208ede74bc48586bb0134db5152e`. Its canonical JSON bytes are committed in the [identity conformance bundle](../../crates/sealr/tests/conformance/identity-v1.json) and reproduced by the independent verifier in required CI.

## Container language

- classic single-disk ZIP32 only;
- Store (`0`) and Deflate (`8`) methods only;
- one exact central-directory-first covering with exact LFH, CDH, EOCD, and optional data-descriptor agreement;
- strict UTF-8 member names, with general-purpose bit 11 required whenever a name contains non-ASCII bytes;
- NFC member paths with no dot-component normalization;
- at most 255 UTF-8 bytes and 255 UTF-16 code units in each canonical component;
- directory names ending in `/`, using Store, zero sizes, and the CRC32 of empty content;
- no extra fields, ZIP64, encryption, spanning, links, devices, recovery parsing, hidden records, or uninterpreted layout bytes.

Resource budgets, consumer semantics, target projection beyond the bound collision relation, and effect controls remain separate from this interpretation profile.

## General-purpose flag table

The table is exhaustive over bits 0 through 15. A member is accepted only when its complete flag word is `0x0000`, `0x0008`, `0x0800`, or `0x0808`. Non-ASCII name bytes additionally require bit 11.

| Bit | Mask | Disposition | Bound meaning |
|---:|---:|---|---|
| 0 | `0x0001` | Denied | Traditional encryption |
| 1 | `0x0002` | Denied | Compression-method-dependent option 1 |
| 2 | `0x0004` | Denied | Compression-method-dependent option 2 |
| 3 | `0x0008` | Semantic | CRC32 and sizes follow the payload in an exact data descriptor |
| 4 | `0x0010` | Denied | Enhanced Deflating |
| 5 | `0x0020` | Denied | Compressed patched data |
| 6 | `0x0040` | Denied | Strong encryption |
| 7 | `0x0080` | Denied | Currently unused |
| 8 | `0x0100` | Denied | Currently unused |
| 9 | `0x0200` | Denied | Currently unused |
| 10 | `0x0400` | Denied | Currently unused |
| 11 | `0x0800` | Semantic | Member name bytes are UTF-8 |
| 12 | `0x1000` | Denied | Reserved enhanced compression |
| 13 | `0x2000` | Denied | Masked local-header values |
| 14 | `0x4000` | Denied | Alternate streams |
| 15 | `0x8000` | Denied | Reserved |

Required CI tests all 65,536 flag words against the four-value language.

## Extra-field table

The permitted semantic ID set is empty. The permitted nonsemantic ID set is empty. Every identifier from `0x0000` through `0xffff`, at both local and central sites, is denied. Required CI tests the complete identifier domain.

This includes Unicode Path (`0x7075`). An admitted path has exactly one source of character meaning: the member-name bytes under the UTF-8 flag rule.

## Canonical names

Name decoding is strict UTF-8. An invalid byte sequence is malformed input. ASCII names may omit bit 11; non-ASCII names may not. Unflagged non-ASCII bytes are denied as ambiguous instead of being guessed as UTF-8 or decoded as CP437.

Decoded paths must already be NFC and every scalar must be public-assigned in Unicode 16.0. Unassigned scalars and private-use characters are denied. Unicode 16.0 General Category `Cc`, the exact Unicode 16.0 `White_Space` set outside ASCII, and the complete Unicode 16.0 `Bidi_Control` set are denied through pinned tables and explicit scalar ranges. Sealr does not normalize a different input spelling into admission. The ordinary portable jail also rejects absolute paths, parent traversal, backslashes, colons, trailing dots or spaces, Windows device names, empty components, excessive depth, duplicate paths, case collisions, and file-directory topology conflicts. Dot components are denied in this profile rather than silently removed.

The collision key is Unicode 16.0 full default case folding followed by NFC. The profile pins `caseless` 0.2.2 for the Unicode 16.0 case-fold table, `unicode-general-category` 1.1.0 for the Unicode 16.0 assigned repertoire, and `unicode-normalization` 0.1.25 for Unicode 17.0 normalization tables. UAX #15 normalization stability makes the latter exact for the admitted Unicode 16.0 repertoire. The canonical profile bytes bind each version, table role, and implementation. A future change to any of them requires a new profile identifier and new conformance bytes.

Each admitted component is limited to both 255 UTF-8 bytes and 255 UTF-16 code units. The byte limit is the active upper bound for valid Unicode scalar strings; the UTF-16 check pins the Windows-facing contract independently.

## Legacy names

This profile intentionally does not decode CP437. Accepting an unflagged non-ASCII byte string would require choosing legacy character semantics that are not present in the archive. A future compatibility profile may define a pinned CP437 mapping under a different identifier when byte-addressed corpus evidence justifies it.

## Selection

```rust
use sealr::{ApplyOptions, ZipInterpretationProfile};

let options = ApplyOptions::new()
    .with_interpretation_profile(ZipInterpretationProfile::PortableUtf8V1);
```

The selected identifier and canonical digest are recorded in `ArchiveIR` and receipt interpretation identity. The [supported wheel consumer](python-wheel-v1.md) requires this profile.

## Normative references

- [Unicode 16.0 Normalization Forms, UAX #15 revision 56](https://www.unicode.org/reports/tr15/tr15-56.html) defines NFC and its stability guarantees.
- [Unicode 16.0 CaseFolding.txt](https://www.unicode.org/Public/16.0.0/ucd/CaseFolding.txt) defines the full default case-fold mappings.
- [Unicode 16.0 UnicodeData.txt](https://www.unicode.org/Public/16.0.0/ucd/UnicodeData.txt) defines the assigned general-category repertoire.
- [Unicode 16.0 PropList.txt](https://www.unicode.org/Public/16.0.0/ucd/PropList.txt) defines the `White_Space` and `Bidi_Control` properties.
- [PKWARE APPNOTE 6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) defines the ZIP records, general-purpose bits, methods, descriptors, and extra-field mechanism classified here.
- [Microsoft naming files, paths, and namespaces](https://learn.microsoft.com/windows/win32/fileio/naming-a-file) defines the Windows reserved names and path restrictions included in the portable target model.
- [Unicode CP437 mapping](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP437.TXT) is the mapping authority reserved for a separately identified legacy profile.
