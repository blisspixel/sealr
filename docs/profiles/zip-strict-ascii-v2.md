# Strict ASCII ZIP32 profile v2

> Status: executable Alpha.4 preview profile. Identifier and canonical bytes are published for conformance testing. `apply()` continues to select v1 for compatibility; callers opt into v2 through `ApplyOptions`.

`sealr.profile.zip.strict-ascii.v2` closes the two unspecified parts of the v1 interpretation. It assigns a disposition to every general-purpose flag bit and every extra-field identifier while leaving the immutable v1 profile bytes and digest unchanged.

The profile SHA-256 is `384dceb8623a2b32d430034fefda2a9498439927285952c10a60c9f6caa51d45`. The canonical JSON bytes are committed in the [identity conformance bundle](../../crates/sealr/tests/conformance/identity-v1.json) and independently digest-checked in required CI.

## Container language

- classic single-disk ZIP32 only;
- Store (`0`) and Deflate (`8`) methods only;
- one exact central-directory-first covering with exact LFH, CDH, EOCD, and optional data-descriptor agreement;
- ASCII member-name bytes only;
- directory names end in `/` and use Store, zero sizes, and the CRC32 of empty content;
- no archive or member comments containing ZIP record signatures;
- no prefixed, trailing, overlapping, hidden, recovery-parsed, ZIP64, encrypted, linked, or device structure.

Resource budgets, target collision rules, consumer semantics, and effect controls remain separate from this interpretation profile.

## General-purpose flag table

The table is exhaustive over bits 0 through 15. A member is accepted only when its complete flag word is `0x0000` or `0x0008`.

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
| 11 | `0x0800` | Denied | UTF-8 name indicator |
| 12 | `0x1000` | Denied | Reserved enhanced compression |
| 13 | `0x2000` | Denied | Masked local-header values |
| 14 | `0x4000` | Denied | Alternate streams |
| 15 | `0x8000` | Denied | Reserved |

Bit 3 is semantic because it changes which redundant metadata values are authoritative and adds a source range to the interpreted member. Its signed descriptor must exactly match the CDH. The current implementation also recognizes the unambiguous unsigned descriptor form under the existing exact layout checks.

Bits 1 and 2 are not treated as harmless compression hints. The initial corpus did not exercise them, and accepting a bit whose consumer significance has not been measured would reopen the contract. A later profile can assign a different disposition with a new identifier and new vectors.

## Extra-field table

The permitted semantic ID set is empty. The permitted nonsemantic ID set is empty. Every identifier from `0x0000` through `0xffff`, at both local and central sites, is denied.

This rule is intentionally stricter than v1, which rejects ZIP64 (`0x0001`) and Unicode Path (`0x7075`) but records other well-formed IDs as ignored. No v2 extra-field payload can disappear from consumer meaning because no v2 archive containing an extra field is admitted.

## Name rule

Every raw member-name byte must be ASCII and flag bit 11 must be clear. ASCII is a strict subset of the wheel specification's UTF-8 name language, but this profile is a generic ZIP boundary rather than the future wheel-oriented UTF-8 profile. Non-ASCII wheels need a separately named profile with UTF-8 vectors and compatibility evidence.

## Compatibility evidence

The pinned [20-wheel pilot](../wheel-compatibility-pilot.md) was rerun under v2. It retained the same measured result as v1: 19 of 20 artifacts were admitted, all 4,504 interpreted members used flags `0x0000`, and no extra fields appeared. SciPy remained denied only by the unchanged resource ratio policy.

This result establishes compatibility only for those exact bytes. It does not estimate ecosystem prevalence or justify a UTF-8, timestamp-extra, ZIP64, or additional-codec rule.

## Selection

```rust
use sealr::{ApplyOptions, ZipInterpretationProfile};

let options = ApplyOptions::new()
    .with_interpretation_profile(ZipInterpretationProfile::StrictAsciiV2);
```

The selected profile is recorded in `ArchiveIR` and receipt interpretation identity. Profile selection can change admission and never changes the resource-policy digest.

## Normative references

- [PKWARE APPNOTE 6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) defines the ZIP32 records, general-purpose bits, methods, descriptors, and extra-field mechanism classified by this profile.
- [Python wheel binary distribution format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/) establishes the distinct UTF-8 requirement that the future wheel-oriented container profile must satisfy.
