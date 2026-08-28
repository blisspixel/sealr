# Verify a published release

This page gives runnable commands for the current immutable prerelease. Historical release notes remain byte-identical to the published GitHub release body, so corrections and clearer examples live here.

Current release:

- tag: `v0.1.0-alpha.9`;
- release: <https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.9>;
- state: prerelease, published, immutable.

## Linux

Download `SHA256SUMS` and `sealr-0.1.0-alpha.9-x86_64-unknown-linux-gnu.tar.gz` into one directory, then run:

```sh
archive='sealr-0.1.0-alpha.9-x86_64-unknown-linux-gnu.tar.gz'
tag='v0.1.0-alpha.9'
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

Download `SHA256SUMS` and `sealr-0.1.0-alpha.9-aarch64-apple-darwin.tar.gz` into one directory, then run:

```sh
archive='sealr-0.1.0-alpha.9-aarch64-apple-darwin.tar.gz'
tag='v0.1.0-alpha.9'
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

Download `SHA256SUMS` and `sealr-0.1.0-alpha.9-x86_64-pc-windows-msvc.zip` into one directory, then run:

```powershell
$archive = 'sealr-0.1.0-alpha.9-x86_64-pc-windows-msvc.zip'
$tag = 'v0.1.0-alpha.9'
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
gh release verify v0.1.0-alpha.9 --repo blisspixel/sealr
```

Build provenance binds each native archive to the tagged GitHub Actions workflow and source commit. It is not a vulnerability-free claim, an archive-decision attestation, or a substitute for reviewing the security limitations.
