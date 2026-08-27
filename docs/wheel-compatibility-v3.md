# Wheel compatibility inventory v3

> Status: Alpha.8 supported-preview baseline over the pinned 20-wheel pilot. This is not a PyPI prevalence estimate or a claim of general wheel compatibility.

- Analyzer: `sealr-wheel-inventory.v3`
- Profile: `sealr.profile.zip.portable-utf8.v1`
- Profile SHA-256: `acee86158d481adff96da0277a470ba753d6208ede74bc48586bb0134db5152e`
- Artifacts: `20`
- Source bytes: `90417280`

## Outcomes

| Value | Count |
|---|---:|
| `admitted` | 16 |
| `denied` | 2 |
| `unsupported` | 2 |

## Metadata versions

| Value | Count |
|---|---:|
| `2.1` | 2 |
| `2.4` | 14 |

## Generators

| Value | Count |
|---|---:|
| `flit 3.12.0` | 2 |
| `hatchling 1.29.0` | 1 |
| `maturin (1.14.1)` | 3 |
| `meson` | 2 |
| `poetry-core 2.3.1` | 1 |
| `setuptools (75.3.3)` | 1 |
| `setuptools (77.0.1)` | 1 |
| `setuptools (82.0.1)` | 2 |
| `setuptools (83.0.0)` | 1 |
| `setuptools (84.0.0)` | 2 |

## .data schemes

| Value | Count |
|---|---:|
| none | 0 |

## Expanded filename tags

| Value | Count |
|---|---:|
| `cp311-abi3-manylinux_2_28_x86_64` | 1 |
| `cp312-cp312-macosx_11_0_arm64` | 1 |
| `cp312-cp312-macosx_11_0_universal2` | 1 |
| `cp312-cp312-manylinux_2_26_x86_64` | 1 |
| `cp312-cp312-manylinux_2_27_x86_64` | 2 |
| `cp312-cp312-manylinux_2_28_x86_64` | 3 |
| `cp312-cp312-win_amd64` | 3 |
| `cp37-abi3-win_amd64` | 1 |
| `py3-none-any` | 6 |

## ZIP creator systems

| Value | Count |
|---|---:|
| `0` | 1762 |
| `3` | 2615 |

## Finding clusters

| Value | Count |
|---|---:|
| `quota.ratio` | 1 |
| `wheel.header-duplicate` | 1 |
| `wheel.metadata-version-unsupported` | 2 |

## Rejection-cluster investigation

- `wheel.header-duplicate`: the cffi artifact contains two `Generator` fields. The supported model denies this because it has not defined ordered or merged generator semantics; this is a consumer-compatibility gap, not a container disagreement.
- `wheel.metadata-version-unsupported`: Hatchling and wheel declare Core Metadata 2.5. The pinned supported snapshot implements 2.1 through 2.4, so both are unsupported rather than denied.
- `quota.ratio`: SciPy reaches the existing default 100:1 expansion ceiling on three test-data members before wheel evaluation. The portable profile does not weaken the adversarial resource policy to improve corpus acceptance.

## Predecessor delta

The supported evaluator preserves the v2 cohort outcome of 16 admitted, two denied, and two unsupported artifacts. Every artifact in this cohort uses a zero general-purpose flag word, so admitting data descriptors in the portable profile does not change these results.

The supported model reports 60 source-executable members instead of 61. The removed case is an orjson member created under ZIP creator system 0 whose external attributes happen to resemble a Unix executable mode. Alpha.8 requires creator system 3 before treating Unix mode bits as executable authority; the immutable v2 report retains the exact PyPA installer 0.7.0 observation.

## Additional observations

- Artifacts with Unicode paths: `0`
- Unix-creator executable regular-file members: `60`

## Artifacts

| Project | Cohort | Outcome | Metadata | Generator | .data | Findings | Filename |
|---|---|---|---|---|---|---|---|
| cffi 2.1.1 | macos-arm64 | denied | unavailable | unavailable | none | wheel.header-duplicate | `cffi-2.1.1-cp312-cp312-macosx_11_0_arm64.whl` |
| cryptography 50.0.0 | linux-x86_64 | admitted | 2.4 | maturin (1.14.1) | none | none | `cryptography-50.0.0-cp311-abi3-manylinux_2_28_x86_64.whl` |
| grpcio 1.83.0 | macos-universal2 | admitted | 2.4 | setuptools (77.0.1) | none | none | `grpcio-1.83.0-cp312-cp312-macosx_11_0_universal2.whl` |
| hatchling 1.32.0 | universal | unsupported | unavailable | unavailable | none | wheel.metadata-version-unsupported | `hatchling-1.32.0-py3-none-any.whl` |
| lxml 6.1.2 | linux-x86_64 | admitted | 2.4 | setuptools (84.0.0) | none | none | `lxml-6.1.2-cp312-cp312-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl` |
| numpy 2.5.2 | linux-x86_64 | admitted | 2.4 | meson | none | none | `numpy-2.5.2-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` |
| orjson 3.12.0 | windows-x86_64 | admitted | 2.4 | maturin (1.14.1) | none | none | `orjson-3.12.0-cp312-cp312-win_amd64.whl` |
| packaging 26.3 | universal | admitted | 2.4 | flit 3.12.0 | none | none | `packaging-26.3-py3-none-any.whl` |
| pandas 3.0.5 | windows-x86_64 | admitted | 2.1 | meson | none | none | `pandas-3.0.5-cp312-cp312-win_amd64.whl` |
| pillow 12.3.0 | linux-x86_64 | admitted | 2.4 | setuptools (82.0.1) | none | none | `pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` |
| pip 26.2.1 | universal | admitted | 2.4 | flit 3.12.0 | none | none | `pip-26.2.1-py3-none-any.whl` |
| psutil 7.2.2 | windows-x86_64 | admitted | 2.1 | setuptools (75.3.3) | none | none | `psutil-7.2.2-cp37-abi3-win_amd64.whl` |
| pydantic-core 2.48.0 | macos-arm64 | admitted | 2.4 | maturin (1.14.1) | none | none | `pydantic_core-2.48.0-cp312-cp312-macosx_11_0_arm64.whl` |
| regex 2026.7.19 | windows-x86_64 | admitted | 2.4 | setuptools (83.0.0) | none | none | `regex-2026.7.19-cp312-cp312-win_amd64.whl` |
| requests 2.34.2 | universal | admitted | 2.4 | setuptools (82.0.1) | none | none | `requests-2.34.2-py3-none-any.whl` |
| rich 15.0.0 | universal | admitted | 2.4 | poetry-core 2.3.1 | none | none | `rich-15.0.0-py3-none-any.whl` |
| scipy 1.18.1 | macos-arm64 | denied | unavailable | unavailable | none | quota.ratio, quota.ratio, quota.ratio | `scipy-1.18.1-cp312-cp312-macosx_12_0_arm64.whl` |
| setuptools 84.0.0 | universal | admitted | 2.4 | setuptools (84.0.0) | none | none | `setuptools-84.0.0-py3-none-any.whl` |
| urllib3 2.7.0 | universal | admitted | 2.4 | hatchling 1.29.0 | none | none | `urllib3-2.7.0-py3-none-any.whl` |
| wheel 0.48.0 | universal | unsupported | unavailable | unavailable | none | wheel.metadata-version-unsupported | `wheel-0.48.0-py3-none-any.whl` |
