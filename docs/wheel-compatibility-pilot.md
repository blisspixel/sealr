# Wheel compatibility pilot

> Status: non-shipping compatibility evidence. This is a deliberately small, stratified pilot, not a claim about PyPI-wide acceptance or wheel support.

- Query date: `2026-08-22`
- Artifacts: `20`
- Source bytes: `90417280`
- Analyzer revision: `sealr-wheel-lab.v3`
- Interpretation profile: `sealr.profile.zip.strict-ascii.v2`
- Interpretation profile SHA-256: `384dceb8623a2b32d430034fefda2a9498439927285952c10a60c9f6caa51d45`
- Policy: `sealr:policy/default/v1`
- Policy SHA-256: `8298b205c981ed140a52ba555c0499712436969faf4ebc28d88d8d9e7024c340`
- Admitted by current strict ASCII ZIP profile: `19/20`
- Manifest SHA-256: `71ec8026d04d6fdde9fa58fa9f3b84acd54c3a82b5f0a13bd1aff1b6ab4419a5`
- Selection: Stratified pilot of 20 named projects: eight universal wheels and four artifacts from each of Linux x86_64, Windows x86_64, and macOS. For each project, use the current non-yanked release returned by the PyPI JSON API on the query date and the lexicographically first exact universal or CPython 3.12 platform match; cryptography and psutil use compatible abi3 wheels. Projects were chosen to exercise packaging tools, pure libraries, native extensions, and large scientific artifacts. This is judgmental coverage, not a representative sample.

The [corpus manifest and reproduction instructions](../tests/corpus/wheels/README.md) define acquisition, full re-analysis, and offline report verification.

## Admission

| Result | Count |
|---|---:|
| `admitted` | 19 |
| `denied` | 1 |

## Cohorts

| Cohort | Artifacts | Admitted |
|---|---:|---:|
| `linux-x86_64` | 4 | 4 |
| `macos-arm64` | 3 | 2 |
| `macos-universal2` | 1 | 1 |
| `universal` | 8 | 8 |
| `windows-x86_64` | 4 | 4 |

## Artifacts by finding code

| Finding | Count |
|---|---:|
| `quota.ratio` | 1 |

## Finding occurrences

| Finding | Count |
|---|---:|
| `quota.ratio` | 3 |

## Methods

| Method | Count |
|---|---:|
| `0:store` | 318 |
| `8:deflate` | 4186 |

## General-purpose flags

| Flags | Count |
|---|---:|
| `0x0000` | 4504 |

## Extra fields

No observations.

## Normalization actions

| Action | Count |
|---|---:|
| `strip-directory-trailing-slash` | 318 |

## Top-level .dist-info paths per interpreted artifact

| Path count | Count |
|---|---:|
| `1` | 19 |

## Candidate metadata members under any .dist-info path

| Basename | Count |
|---|---:|
| `METADATA` | 31 |
| `RECORD` | 31 |
| `WHEEL` | 31 |
| `entry_points.txt` | 8 |

## Candidate metadata members under top-level .dist-info paths

| Basename | Count |
|---|---:|
| `METADATA` | 19 |
| `RECORD` | 19 |
| `WHEEL` | 19 |
| `entry_points.txt` | 7 |

## Artifacts

| Project | Cohort | Result | Members | .dist-info top/all | Findings | Filename |
|---|---|---:|---:|---:|---|---|
| cffi 2.1.1 | macos-arm64 | admitted | 34 | 1/1 | none | `cffi-2.1.1-cp312-cp312-macosx_11_0_arm64.whl` |
| cryptography 50.0.0 | linux-x86_64 | admitted | 141 | 1/1 | none | `cryptography-50.0.0-cp311-abi3-manylinux_2_28_x86_64.whl` |
| grpcio 1.83.0 | macos-universal2 | admitted | 66 | 1/1 | none | `grpcio-1.83.0-cp312-cp312-macosx_11_0_universal2.whl` |
| hatchling 1.32.0 | universal | admitted | 73 | 1/1 | none | `hatchling-1.32.0-py3-none-any.whl` |
| lxml 6.1.2 | linux-x86_64 | admitted | 188 | 1/1 | none | `lxml-6.1.2-cp312-cp312-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl` |
| numpy 2.5.2 | linux-x86_64 | admitted | 1044 | 1/1 | none | `numpy-2.5.2-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` |
| orjson 3.12.0 | windows-x86_64 | admitted | 11 | 1/1 | none | `orjson-3.12.0-cp312-cp312-win_amd64.whl` |
| packaging 26.3 | universal | admitted | 29 | 1/1 | none | `packaging-26.3-py3-none-any.whl` |
| pandas 3.0.5 | windows-x86_64 | admitted | 1725 | 1/1 | none | `pandas-3.0.5-cp312-cp312-win_amd64.whl` |
| pillow 12.3.0 | linux-x86_64 | admitted | 145 | 1/1 | none | `pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` |
| pip 26.2.1 | universal | admitted | 476 | 1/1 | none | `pip-26.2.1-py3-none-any.whl` |
| psutil 7.2.2 | windows-x86_64 | admitted | 16 | 1/1 | none | `psutil-7.2.2-cp37-abi3-win_amd64.whl` |
| pydantic-core 2.48.0 | macos-arm64 | admitted | 10 | 1/1 | none | `pydantic_core-2.48.0-cp312-cp312-macosx_11_0_arm64.whl` |
| regex 2026.7.19 | windows-x86_64 | admitted | 10 | 1/1 | none | `regex-2026.7.19-cp312-cp312-win_amd64.whl` |
| requests 2.34.2 | universal | admitted | 26 | 1/1 | none | `requests-2.34.2-py3-none-any.whl` |
| rich 15.0.0 | universal | admitted | 105 | 1/1 | none | `rich-15.0.0-py3-none-any.whl` |
| scipy 1.18.1 | macos-arm64 | denied | unavailable | unavailable | quota.ratio (3) | `scipy-1.18.1-cp312-cp312-macosx_12_0_arm64.whl` |
| setuptools 84.0.0 | universal | admitted | 343 | 1/13 | none | `setuptools-84.0.0-py3-none-any.whl` |
| urllib3 2.7.0 | universal | admitted | 42 | 1/1 | none | `urllib3-2.7.0-py3-none-any.whl` |
| wheel 0.48.0 | universal | admitted | 20 | 1/1 | none | `wheel-0.48.0-py3-none-any.whl` |

## Denial evidence

| Artifact | Finding | Member | Detail |
|---|---|---|---|
| `scipy-1.18.1-cp312-cp312-macosx_12_0_arm64.whl` | `quota.ratio` | scipy/stats/tests/data/nist_anova/SmLs03.dat | declared 451566:2098 exceeds 100:1 |
| `scipy-1.18.1-cp312-cp312-macosx_12_0_arm64.whl` | `quota.ratio` | scipy/stats/tests/data/nist_anova/SmLs06.dat | declared 523605:2310 exceeds 100:1 |
| `scipy-1.18.1-cp312-cp312-macosx_12_0_arm64.whl` | `quota.ratio` | scipy/stats/tests/data/nist_anova/SmLs09.dat | declared 577633:2463 exceeds 100:1 |

## Interpretation

The report is produced only through Sealr's public fail-closed `apply_supervised` outcome and read-only `ArchiveIR`. It does not invoke Python `zipfile`, another ZIP parser, an external extractor, or the in-process fallback. Counts describe the exact byte-addressed artifacts in the manifest. Rejected artifacts can lack an IR, so their container features are not inferred by a fallback parser.

The `.dist-info` and metadata-name counts are structural candidates only. They do not parse metadata or decide which directory matches the outer wheel filename. Distinguishing one top-level artifact directory from nested vendored `.dist-info` trees is a required consumer step.

This pilot does not justify relaxing the default `100:1` per-member expansion-ratio limit. A ratio denial is a bounded-resource policy decision, not a parser incompatibility, and any future change needs a larger corpus plus explicit memory, time, and adversarial-cost analysis.

The pilot can identify candidate flag and extra-field rules for the next profile, but it cannot establish ecosystem prevalence, semantic safety of ignored payloads, wheel metadata correctness, `RECORD` agreement, target compatibility, or install-plan identity. Those remain separate gates.
