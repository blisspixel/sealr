# Verify a published release

This page gives runnable commands for the current immutable prerelease. Historical release notes remain byte-identical to the published GitHub release body, so corrections and clearer examples live here.

Current release:

- tag: `v0.1.0-alpha.11`;
- release: <https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.11>;
- state: prerelease, published, immutable.

## Linux

Download `SHA256SUMS` and `sealr-0.1.0-alpha.11-x86_64-unknown-linux-gnu.tar.gz` into one directory, then run:

```sh
archive='sealr-0.1.0-alpha.11-x86_64-unknown-linux-gnu.tar.gz'
tag='v0.1.0-alpha.11'
commit="$(gh api "repos/blisspixel/sealr/commits/${tag}" --jq .sha)"
if [ "${#commit}" -ne 40 ]; then echo 'could not resolve release tag commit' >&2; exit 1; fi
case "${commit}" in *[!0-9a-f]*) echo 'could not resolve release tag commit' >&2; exit 1;; esac
grep "  ${archive}$" SHA256SUMS | sha256sum --check - || exit 1
gh attestation verify "${archive}" \
  --repo blisspixel/sealr \
  --signer-workflow github.com/blisspixel/sealr/.github/workflows/release.yml \
  --source-digest "${commit}" \
  --source-ref "refs/tags/${tag}" \
  --signer-digest "${commit}" \
  --deny-self-hosted-runners
```

## macOS

Download `SHA256SUMS` and `sealr-0.1.0-alpha.11-aarch64-apple-darwin.tar.gz` into one directory, then run:

```sh
archive='sealr-0.1.0-alpha.11-aarch64-apple-darwin.tar.gz'
tag='v0.1.0-alpha.11'
commit="$(gh api "repos/blisspixel/sealr/commits/${tag}" --jq .sha)"
if [ "${#commit}" -ne 40 ]; then echo 'could not resolve release tag commit' >&2; exit 1; fi
case "${commit}" in *[!0-9a-f]*) echo 'could not resolve release tag commit' >&2; exit 1;; esac
expected="$(awk -v name="${archive}" '$2 == name { print $1 }' SHA256SUMS)"
actual="$(shasum --algorithm 256 "${archive}" | awk '{ print $1 }')"
if [ -z "${expected}" ] || [ "${actual}" != "${expected}" ]; then
  echo 'SHA-256 verification failed' >&2
  exit 1
fi
gh attestation verify "${archive}" \
  --repo blisspixel/sealr \
  --signer-workflow github.com/blisspixel/sealr/.github/workflows/release.yml \
  --source-digest "${commit}" \
  --source-ref "refs/tags/${tag}" \
  --signer-digest "${commit}" \
  --deny-self-hosted-runners
```

## Windows PowerShell

Download `SHA256SUMS` and `sealr-0.1.0-alpha.11-x86_64-pc-windows-msvc.zip` into one directory, then run:

```powershell
$archive = 'sealr-0.1.0-alpha.11-x86_64-pc-windows-msvc.zip'
$tag = 'v0.1.0-alpha.11'
$commit = gh api "repos/blisspixel/sealr/commits/$tag" --jq .sha
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'could not resolve release tag commit' }
$line = (Get-Content -LiteralPath SHA256SUMS) | Where-Object { $_ -match "  $([regex]::Escape($archive))$" }
if (@($line).Count -ne 1) { throw 'expected exactly one checksum entry' }
$expected = ($line -split '  ', 2)[0]
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'SHA-256 verification failed' }
gh attestation verify $archive `
  --repo blisspixel/sealr `
  --signer-workflow github.com/blisspixel/sealr/.github/workflows/release.yml `
  --source-digest $commit `
  --source-ref "refs/tags/$tag" `
  --signer-digest $commit `
  --deny-self-hosted-runners
if ($LASTEXITCODE -ne 0) { throw 'build provenance verification failed' }
```

## Release identity

With a current GitHub CLI, verify the immutable release record:

```sh
gh release verify v0.1.0-alpha.11 --repo blisspixel/sealr
```

Build provenance binds each native archive to the tagged GitHub Actions workflow and source commit. It is not a vulnerability-free claim, an archive-decision attestation, or a substitute for reviewing the security limitations.

## Canonical evidence after archive authentication

The published Alpha.11 archives predate native delivery of the evidence verifier. Native archives built from current main include `sealr-identity-verifier` or `sealr-identity-verifier.exe` beside the `sealr` CLI, with no additional release asset. After a future prerelease carrying that contract has passed the checksum and provenance steps above, the extracted pair can produce and check byte-exact evidence without a source checkout or Rust toolchain:

```sh
./sealr path/to/archive.zip \
  --view view.json --receipt receipt.json --canonical
./sealr-identity-verifier evidence \
  --view view.json --receipt receipt.json --source path/to/archive.zip
```

Verifier exit `0` means the unsigned view and receipt are internally coherent and bound to the supplied source bytes. A coherent rejection receipt also verifies with exit `0`; inspect the evidence verdict separately. The companion is built and attested inside the same archive as the producer, so it cannot authenticate that archive or establish supply-chain independence. It does not execute codecs, reinterpret the source, reconstruct the live layout root, authenticate a signer, or turn the evidence into an attestation.
