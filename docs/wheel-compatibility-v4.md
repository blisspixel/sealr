# Wheel compatibility inventory v4

> Status: supported-preview measurement of the widened Core Metadata 2.1-2.6 snapshot over a 64-artifact stratified corpus. This is not a PyPI prevalence estimate or a claim of general wheel compatibility.

- Analyzer: `sealr-wheel-inventory.v4`
- Profile: `sealr.profile.zip.portable-utf8.v1`
- Profile SHA-256: `acee86158d481adff96da0277a470ba753d6208ede74bc48586bb0134db5152e`
- Specification snapshot: `pypa-wheel-core-metadata-2026-08-28`
- Consumer profile digest: `d8c71f98c25db7e7f22f1a265f718ebaf2c50428a8c11de98c3f014f965125ef`
- Artifacts: `64`
- Source bytes: `275387891`

## Outcomes

| Value | Count |
|---|---:|
| `admitted` | 58 |
| `denied` | 6 |

## Metadata versions

| Value | Count |
|---|---:|
| `2.1` | 8 |
| `2.4` | 41 |
| `2.5` | 9 |

## Generators

| Value | Count |
|---|---:|
| `flit 3.11.0` | 1 |
| `flit 3.12.0` | 5 |
| `flit 4.0.2` | 3 |
| `hatchling 1.29.0` | 2 |
| `hatchling 1.31.0` | 1 |
| `hatchling 1.32.0` | 6 |
| `maturin (1.13.1)` | 1 |
| `maturin (1.13.3)` | 2 |
| `maturin (1.14.1)` | 4 |
| `meson` | 3 |
| `pdm-backend (0.0.0+local)` | 1 |
| `poetry-core 2.3.1` | 1 |
| `poetry-core 2.4.1` | 1 |
| `scikit-build-core 0.11.5` | 1 |
| `scikit-build-core 1.0.3` | 4 |
| `setuptools (75.1.0)` | 2 |
| `setuptools (75.3.3)` | 1 |
| `setuptools (75.6.0)` | 1 |
| `setuptools (77.0.1)` | 1 |
| `setuptools (80.7.1)` | 1 |
| `setuptools (80.9.0)` | 3 |
| `setuptools (82.0.1)` | 4 |
| `setuptools (83.0.0)` | 3 |
| `setuptools (84.0.0)` | 6 |

## .data schemes

| Value | Count |
|---|---:|
| `data` | 2 |
| `scripts` | 2 |

## Expanded filename tags

| Value | Count |
|---|---:|
| `cp310-abi3-manylinux2014_x86_64` | 1 |
| `cp310-abi3-manylinux_2_17_x86_64` | 1 |
| `cp310-abi3-win_amd64` | 1 |
| `cp311-abi3-manylinux_2_28_x86_64` | 1 |
| `cp312-abi3-manylinux_2_26_x86_64` | 1 |
| `cp312-abi3-manylinux_2_28_x86_64` | 1 |
| `cp312-cp312-macosx_10_12_x86_64` | 1 |
| `cp312-cp312-macosx_11_0_arm64` | 1 |
| `cp312-cp312-macosx_11_0_universal2` | 1 |
| `cp312-cp312-manylinux2014_aarch64` | 3 |
| `cp312-cp312-manylinux2014_x86_64` | 2 |
| `cp312-cp312-manylinux_2_17_aarch64` | 3 |
| `cp312-cp312-manylinux_2_17_x86_64` | 2 |
| `cp312-cp312-manylinux_2_26_x86_64` | 1 |
| `cp312-cp312-manylinux_2_27_x86_64` | 3 |
| `cp312-cp312-manylinux_2_28_aarch64` | 3 |
| `cp312-cp312-manylinux_2_28_x86_64` | 7 |
| `cp312-cp312-musllinux_1_2_x86_64` | 2 |
| `cp312-cp312-win_amd64` | 5 |
| `cp37-abi3-win_amd64` | 1 |
| `py2-none-any` | 1 |
| `py3-none-any` | 31 |
| `py3-none-manylinux2014_x86_64` | 2 |
| `py3-none-manylinux_2_17_x86_64` | 2 |

## ZIP creator systems

| Value | Count |
|---|---:|
| `0` | 2415 |
| `3` | 13618 |

## Finding clusters

| Value | Count |
|---|---:|
| `quota.ratio` | 1 |
| `wheel.header-duplicate` | 2 |
| `wheel.script-aggregate-limit` | 2 |
| `zip.extra` | 1 |

## Rejection-cluster investigation

- `wheel.header-duplicate`: the cffi and matplotlib artifacts each contain two `Generator` fields, cffi from its historical toolchain and matplotlib from its meson-python build. The supported model denies duplicated headers because it has not defined ordered or merged generator semantics; this is a consumer-compatibility gap, not a container disagreement.
- `quota.ratio`: SciPy reaches the existing default 100:1 expansion ceiling on three NIST ANOVA test-data members before wheel evaluation, exactly as in v3. The portable profile does not weaken the adversarial resource policy to improve corpus acceptance.
- `wheel.script-aggregate-limit`: uv and ruff each ship one multi-megabyte native executable under `.data/scripts`. Script-scheme members are inspected for launcher transforms inside the checked 1 MiB plan-inspection aggregate, so a single oversized script member exceeds the cap and the artifact is denied. Raising or scoping this budget is a policy decision for a future limits revision, not a silent widening.
- `zip.extra`: the protobuf Windows artifact carries extra field `0x0001` (ZIP64 extended information) in a local header, which `sealr.profile.zip.portable-utf8.v1` denies. This is the only container-stage denial among the 44 additions and would require the strict ZIP64 profile lineage to interpret.

## Predecessor delta

Exactly the two artifacts the immutable v3 report classified as unsupported under the pinned 2.1-2.4 snapshot flip to admitted under the widened `pypa-wheel-core-metadata-2026-08-28` snapshot: hatchling 1.32.0 and wheel 0.48.0, both now measured as Core Metadata 2.5. No other artifact shared with the v3 corpus changed outcome or finding codes, so the widening is the only observable behavior change over the pinned pilot.

| Filename | v3 outcome | v4 outcome | v3 findings | v4 findings |
|---|---|---|---|---|
| `hatchling-1.32.0-py3-none-any.whl` | unsupported | admitted | wheel.metadata-version-unsupported | none |
| `wheel-0.48.0-py3-none-any.whl` | unsupported | admitted | wheel.metadata-version-unsupported | none |

## Additional observations

- Artifacts with Unicode paths: `0`
- Unix-creator executable regular-file members: `118`
- Benign `.data` payloads, absent from the v3 pilot, are now measured on four admitted artifacts: jupyterlab and notebook relocate the `data` scheme, and ninja and pywin32 relocate the `scripts` scheme.
- No measured artifact declares Core Metadata 2.6 yet; that half of the widening is currently exercised only by unit fixtures.
- No measured artifact contains Unicode member paths, so those rule consequences continue to rely on hostile fixtures.

## Artifacts

| Project | Cohort | Outcome | Metadata | Generator | .data | Findings | Filename |
|---|---|---|---|---|---|---|---|
| aiohttp 3.14.3 | linux-aarch64 | admitted | 2.4 | setuptools (83.0.0) | none | none | `aiohttp-3.14.3-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl` |
| ansible-core 2.21.3 | universal | admitted | 2.4 | setuptools (84.0.0) | none | none | `ansible_core-2.21.3-py3-none-any.whl` |
| attrs 26.1.0 | universal | admitted | 2.4 | hatchling 1.29.0 | none | none | `attrs-26.1.0-py3-none-any.whl` |
| boto3 1.43.83 | universal | admitted | 2.1 | setuptools (75.1.0) | none | none | `boto3-1.43.83-py3-none-any.whl` |
| botocore 1.43.83 | universal | admitted | 2.1 | setuptools (75.1.0) | none | none | `botocore-1.43.83-py3-none-any.whl` |
| certifi 2026.7.22 | universal | admitted | 2.4 | setuptools (83.0.0) | none | none | `certifi-2026.7.22-py3-none-any.whl` |
| cffi 2.1.1 | macos-arm64 | denied | unavailable | unavailable | none | wheel.header-duplicate | `cffi-2.1.1-cp312-cp312-macosx_11_0_arm64.whl` |
| charset-normalizer 3.5.1 | linux-musl-x86_64 | admitted | 2.4 | setuptools (84.0.0) | none | none | `charset_normalizer-3.5.1-cp312-cp312-musllinux_1_2_x86_64.whl` |
| click 8.5.0 | universal | admitted | 2.4 | flit 3.12.0 | none | none | `click-8.5.0-py3-none-any.whl` |
| cmake 4.4.2 | linux-x86_64 | admitted | 2.1 | scikit-build-core 1.0.3 | none | none | `cmake-4.4.2-py3-none-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` |
| contourpy 1.3.3 | linux-x86_64 | admitted | 2.1 | meson | none | none | `contourpy-1.3.3-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` |
| coverage 7.16.0 | linux-aarch64 | admitted | 2.4 | setuptools (84.0.0) | none | none | `coverage-7.16.0-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl` |
| cryptography 50.0.0 | linux-x86_64 | admitted | 2.4 | maturin (1.14.1) | none | none | `cryptography-50.0.0-cp311-abi3-manylinux_2_28_x86_64.whl` |
| filelock 3.32.4 | universal | admitted | 2.5 | hatchling 1.32.0 | none | none | `filelock-3.32.4-py3-none-any.whl` |
| flit_core 4.0.2 | universal | admitted | 2.5 | flit 4.0.2 | none | none | `flit_core-4.0.2-py3-none-any.whl` |
| frozenlist 1.8.0 | linux-aarch64 | admitted | 2.4 | setuptools (80.9.0) | none | none | `frozenlist-1.8.0-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl` |
| grpcio 1.83.0 | macos-universal2 | admitted | 2.4 | setuptools (77.0.1) | none | none | `grpcio-1.83.0-cp312-cp312-macosx_11_0_universal2.whl` |
| hatch 1.18.0 | universal | admitted | 2.5 | hatchling 1.32.0 | none | none | `hatch-1.18.0-py3-none-any.whl` |
| hatchling 1.32.0 | universal | admitted | 2.5 | hatchling 1.32.0 | none | none | `hatchling-1.32.0-py3-none-any.whl` |
| idna 3.19 | universal | admitted | 2.5 | flit 4.0.2 | none | none | `idna-3.19-py3-none-any.whl` |
| jinja2 3.1.6 | universal | admitted | 2.4 | flit 3.11.0 | none | none | `jinja2-3.1.6-py3-none-any.whl` |
| jupyterlab 4.6.3 | universal | admitted | 2.4 | hatchling 1.31.0 | data | none | `jupyterlab-4.6.3-py3-none-any.whl` |
| kiwisolver 1.5.1 | windows-x86_64 | admitted | 2.4 | setuptools (84.0.0) | none | none | `kiwisolver-1.5.1-cp312-cp312-win_amd64.whl` |
| lxml 6.1.2 | linux-x86_64 | admitted | 2.4 | setuptools (84.0.0) | none | none | `lxml-6.1.2-cp312-cp312-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl` |
| markupsafe 3.0.3 | linux-x86_64 | admitted | 2.4 | setuptools (80.9.0) | none | none | `markupsafe-3.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` |
| matplotlib 3.11.1 | macos-arm64 | denied | unavailable | unavailable | none | wheel.header-duplicate | `matplotlib-3.11.1-cp312-cp312-macosx_11_0_arm64.whl` |
| ninja 1.13.0 | linux-x86_64 | admitted | 2.1 | scikit-build-core 0.11.5 | scripts | none | `ninja-1.13.0-py3-none-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` |
| notebook 7.6.2 | universal | admitted | 2.5 | hatchling 1.32.0 | data | none | `notebook-7.6.2-py3-none-any.whl` |
| numpy 2.5.2 | linux-x86_64 | admitted | 2.4 | meson | none | none | `numpy-2.5.2-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` |
| orjson 3.12.0 | windows-x86_64 | admitted | 2.4 | maturin (1.14.1) | none | none | `orjson-3.12.0-cp312-cp312-win_amd64.whl` |
| packaging 26.3 | universal | admitted | 2.4 | flit 3.12.0 | none | none | `packaging-26.3-py3-none-any.whl` |
| pandas 3.0.5 | windows-x86_64 | admitted | 2.1 | meson | none | none | `pandas-3.0.5-cp312-cp312-win_amd64.whl` |
| pdm-backend 2.4.9 | universal | admitted | 2.4 | pdm-backend (0.0.0+local) | none | none | `pdm_backend-2.4.9-py3-none-any.whl` |
| pillow 12.3.0 | linux-x86_64 | admitted | 2.4 | setuptools (82.0.1) | none | none | `pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl` |
| pip 26.2.1 | universal | admitted | 2.4 | flit 3.12.0 | none | none | `pip-26.2.1-py3-none-any.whl` |
| platformdirs 4.11.5 | universal | admitted | 2.5 | hatchling 1.32.0 | none | none | `platformdirs-4.11.5-py3-none-any.whl` |
| pluggy 1.6.0 | universal | admitted | 2.4 | setuptools (80.7.1) | none | none | `pluggy-1.6.0-py3-none-any.whl` |
| poetry-core 2.4.1 | universal | admitted | 2.4 | poetry-core 2.4.1 | none | none | `poetry_core-2.4.1-py3-none-any.whl` |
| protobuf 7.36.0 | windows-x86_64 | denied | unavailable | unavailable | none | zip.extra | `protobuf-7.36.0-cp310-abi3-win_amd64.whl` |
| psutil 7.2.2 | windows-x86_64 | admitted | 2.1 | setuptools (75.3.3) | none | none | `psutil-7.2.2-cp37-abi3-win_amd64.whl` |
| pyarrow 25.0.1 | linux-x86_64 | admitted | 2.4 | scikit-build-core 1.0.3 | none | none | `pyarrow-25.0.1-cp312-cp312-manylinux_2_28_x86_64.whl` |
| pybind11 3.1.0 | universal | admitted | 2.4 | scikit-build-core 1.0.3 | none | none | `pybind11-3.1.0-py3-none-any.whl` |
| pydantic-core 2.48.0 | macos-arm64 | admitted | 2.4 | maturin (1.14.1) | none | none | `pydantic_core-2.48.0-cp312-cp312-macosx_11_0_arm64.whl` |
| pytest 9.1.1 | universal | admitted | 2.4 | setuptools (82.0.1) | none | none | `pytest-9.1.1-py3-none-any.whl` |
| pywin32 312 | windows-x86_64 | admitted | 2.4 | setuptools (82.0.1) | scripts | none | `pywin32-312-cp312-cp312-win_amd64.whl` |
| pyyaml 6.0.3 | linux-x86_64 | admitted | 2.4 | setuptools (80.9.0) | none | none | `pyyaml-6.0.3-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl` |
| pyzmq 27.2.0 | linux-x86_64 | admitted | 2.4 | scikit-build-core 1.0.3 | none | none | `pyzmq-27.2.0-cp312-abi3-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl` |
| regex 2026.7.19 | windows-x86_64 | admitted | 2.4 | setuptools (83.0.0) | none | none | `regex-2026.7.19-cp312-cp312-win_amd64.whl` |
| requests 2.34.2 | universal | admitted | 2.4 | setuptools (82.0.1) | none | none | `requests-2.34.2-py3-none-any.whl` |
| rich 15.0.0 | universal | admitted | 2.4 | poetry-core 2.3.1 | none | none | `rich-15.0.0-py3-none-any.whl` |
| rpds-py 2026.6.3 | linux-musl-x86_64 | admitted | 2.4 | maturin (1.14.1) | none | none | `rpds_py-2026.6.3-cp312-cp312-musllinux_1_2_x86_64.whl` |
| ruff 0.16.5 | linux-x86_64 | denied | unavailable | unavailable | none | wheel.script-aggregate-limit | `ruff-0.16.5-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` |
| safetensors 0.8.0 | linux-x86_64 | admitted | 2.4 | maturin (1.13.3) | none | none | `safetensors-0.8.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` |
| scipy 1.18.1 | macos-arm64 | denied | unavailable | unavailable | none | quota.ratio, quota.ratio, quota.ratio | `scipy-1.18.1-cp312-cp312-macosx_12_0_arm64.whl` |
| setuptools 84.0.0 | universal | admitted | 2.4 | setuptools (84.0.0) | none | none | `setuptools-84.0.0-py3-none-any.whl` |
| six 1.17.0 | universal | admitted | 2.1 | setuptools (75.6.0) | none | none | `six-1.17.0-py2.py3-none-any.whl` |
| tokenizers 0.23.1 | windows-x86_64 | admitted | 2.4 | maturin (1.13.1) | none | none | `tokenizers-0.23.1-cp310-abi3-win_amd64.whl` |
| tomli 2.4.1 | universal | admitted | 2.4 | flit 3.12.0 | none | none | `tomli-2.4.1-py3-none-any.whl` |
| typing_extensions 4.16.0 | universal | admitted | 2.4 | flit 3.12.0 | none | none | `typing_extensions-4.16.0-py3-none-any.whl` |
| urllib3 2.7.0 | universal | admitted | 2.4 | hatchling 1.29.0 | none | none | `urllib3-2.7.0-py3-none-any.whl` |
| uv 0.12.7 | linux-x86_64 | denied | unavailable | unavailable | none | wheel.script-aggregate-limit | `uv-0.12.7-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` |
| virtualenv 21.7.7 | universal | admitted | 2.5 | hatchling 1.32.0 | none | none | `virtualenv-21.7.7-py3-none-any.whl` |
| watchfiles 1.2.0 | macos-x86_64 | admitted | 2.4 | maturin (1.13.3) | none | none | `watchfiles-1.2.0-cp312-cp312-macosx_10_12_x86_64.whl` |
| wheel 0.48.0 | universal | admitted | 2.5 | flit 4.0.2 | none | none | `wheel-0.48.0-py3-none-any.whl` |
