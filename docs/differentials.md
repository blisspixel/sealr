# Parser differentials and polyglots

This is the research frontier that separates a good library from a definitive one. Paper and 14 types: [threat-model.md](threat-model.md).

## Single interpretation (default)

The rules below are normative. The current ZIP32 subset implements the classic-record path and rejects ZIP64. Corpus coverage is executable through the [pinned expectation manifest](../tests/corpus/zipdiff/expectations.txt).

sealr is **one** ZIP parser:

1. Find the unique EOCD whose comment length exactly matches the suffix (C2).
2. Reject ZIP64 markers until the ZIP64 interpretation and fixtures are implemented (C5).
3. Parse the central directory. Count, size, offset MUST agree (C3, C4).
4. Each CDH: jail the name; LFH at the stated offset MUST agree on method, sizes, name, encryption flag (A1–A5).
5. Referenced local-record ranges, including headers and data descriptors, MUST form one contiguous prefix before the central directory. Gaps, hidden prefixes, overlap, and bytes crossing into the CD are rejected (C1 + Fifield).
6. Duplicate dest paths after canonicalize → deny (B1, B3, B4).
7. No streaming-LFH API in v0.

Anything that would require guessing is a finding and, under default policy, a hard error. “Would Info-ZIP, 7-Zip, and Python zipfile disagree about this blob?” is a **reject condition**, not an afterthought. We detect the known classes; we do not spawn those parsers in the library hot path.

## Detection vs multi-parser

| Mode | When |
|---|---|
| **Pattern detect** (default) | The 14 types as explicit checks. Fast. Incomplete for *unknown* future types. |
| **ZipDiff corpus CI** | Regenerate the pinned `construction` outputs and classify all 5,927 files through the production API. The aggregate digest, finding counts, and 73-file control allowlist must match. |
| **Optional multi-parser** | CI/research only: run Info-ZIP / 7-Zip / Python zipfile / Go archive/zip in Docker and compare. Too slow and too many deps for the library hot path. |
| **Safe normalize** (Phase 3) | Materialize with *this* engine into a staging tree, then write a canonical ZIP (store or deflate, CD=LFH, no extras that carry names, one EOCD, no ZIP64 unless needed). Downstream tools then see one tree. The paper’s “extract and repack” mitigation - **we** must be the extract, or we have reintroduced a second parser. |

## Polyglots and magic

- **Magic-byte authority** over extension. `.zip` that is gzip → treat as gzip or **deny** (default deny + `polyglot.ext_magic`).
- Mixed containers (ZIP that is also PDF, JAR+APK members, Panakkal-style): report `polyglot.container` and default deny unless policy names the role (`policy: ooxml-v1`, `policy: wheel-v1`).
- Nested archives: depth default **1** (no recurse). If policy allows, each layer gets the **same** policy; metadata-size cap still applies.

## Format-specific extras (not ZipDiff, still differentials)

| Format | Extra check |
|---|---|
| `.whl` | ZIP members vs `RECORD` (PyPI 2025–2026, uv CVE-2025-54368) |
| `.jar` / Spring | Do not implement a second streaming parser |
| OOXML / ODF / VSIX / CRX / APK | Path of the “identity” file (`[Content_Types].xml`, `extension.vsixmanifest`, …) after our canonicalize; duplicate identity paths → deny |
| TAR | PAX/GNU long-name size cap; checksum; no parser-pair paper of ZipDiff quality yet - still jail + metadata bombs |

## Corpus

- ZipDiff `construction` binary output is generated in CI from a pinned revision. `tests/corpus/zipdiff/` commits the aggregate digest and expectations, not generated binaries or the 100 GB fuzz output.
- Fifield overlap bombs (`zbsm.zip` class) - generate in tests, do not commit 10 MB → 281 TB payloads.
- szips tests (`../`, colon ADS).
- TAR PAX bomb fixtures (exarch’s class).

CI job: `ZipDiff 14-class gate`. A nightly `cargo fuzz` job on ZIP bytes that must never materialize outside its destination remains planned.
