# Verify a published release

This page gives runnable commands for the current immutable prerelease. Historical release notes remain byte-identical to the published GitHub release body, so corrections and clearer examples live here.

Current release:

- tag: `v0.1.0-alpha.2`;
- commit: `d29b857d74d1cc8809d088a1f9db5820a3a71c24`;
- release: <https://github.com/blisspixel/sealr/releases/tag/v0.1.0-alpha.2>;
- state: prerelease, published, immutable.

## Linux

Download `SHA256SUMS` and `sealr-0.1.0-alpha.2-x86_64-unknown-linux-gnu.tar.gz` into one directory, then run:

```sh
archive='sealr-0.1.0-alpha.2-x86_64-unknown-linux-gnu.tar.gz'
grep "  ${archive}$" SHA256SUMS | sha256sum --check - || exit 1
gh attestation verify "${archive}" --repo blisspixel/sealr
```

## macOS

Download `SHA256SUMS` and `sealr-0.1.0-alpha.2-aarch64-apple-darwin.tar.gz` into one directory, then run:

```sh
archive='sealr-0.1.0-alpha.2-aarch64-apple-darwin.tar.gz'
expected="$(awk -v name="${archive}" '$2 == name { print $1 }' SHA256SUMS)"
actual="$(shasum --algorithm 256 "${archive}" | awk '{ print $1 }')"
if [ -z "${expected}" ] || [ "${actual}" != "${expected}" ]; then
  echo 'SHA-256 verification failed' >&2
  exit 1
fi
gh attestation verify "${archive}" --repo blisspixel/sealr
```

## Windows PowerShell

Download `SHA256SUMS` and `sealr-0.1.0-alpha.2-x86_64-pc-windows-msvc.zip` into one directory, then run:

```powershell
$archive = 'sealr-0.1.0-alpha.2-x86_64-pc-windows-msvc.zip'
$line = (Get-Content -LiteralPath SHA256SUMS) | Where-Object { $_ -match "  $([regex]::Escape($archive))$" }
if (@($line).Count -ne 1) { throw 'expected exactly one checksum entry' }
$expected = ($line -split '  ', 2)[0]
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'SHA-256 verification failed' }
gh attestation verify $archive --repo blisspixel/sealr
```

## Release identity

With a current GitHub CLI, verify the immutable release record:

```sh
gh release verify v0.1.0-alpha.2 --repo blisspixel/sealr
```

Build provenance binds each native archive to the tagged GitHub Actions workflow and source commit. It is not a vulnerability-free claim, an archive-decision attestation, or a substitute for reviewing the security limitations.
