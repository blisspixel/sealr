[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$expected = [ordered]@{
    'x86_64-unknown-linux-gnu' = [pscustomobject]@{
        Components = 55
        Notices = 11
        Present = @('linux-raw-sys 0.12.1', 'rustix-linux-procfs 0.1.1', 'once_cell 1.21.4')
        Absent = @('errno 0.3.14', 'windows-sys 0.61.2', 'once_cell_polyfill 1.70.2')
    }
    'aarch64-apple-darwin' = [pscustomobject]@{
        Components = 53
        Notices = 9
        Present = @('errno 0.3.14', 'rustix 1.1.4', 'libc 0.2.189')
        Absent = @('linux-raw-sys 0.12.1', 'windows-sys 0.61.2', 'once_cell 1.21.4')
    }
    'x86_64-pc-windows-msvc' = [pscustomobject]@{
        Components = 61
        Notices = 8
        Present = @('windows-sys 0.61.2', 'winx 0.36.4', 'once_cell_polyfill 1.70.2')
        Absent = @('rustix 1.1.4', 'libc 0.2.189', 'errno 0.3.14')
    }
}
$targetRoot = [System.IO.Path]::GetFullPath((Join-Path $workspace 'target'))
[System.IO.Directory]::CreateDirectory($targetRoot) | Out-Null
$temporaryLeaf = "third-party-license-verification-$PID-$([System.Guid]::NewGuid().ToString('N'))"
$temporaryRoot = Join-Path $targetRoot $temporaryLeaf
[System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null

Push-Location $workspace
try {
    & (Join-Path $PSScriptRoot 'generate_third_party_licenses.ps1') -OutputDirectory $temporaryRoot

    foreach ($target in $expected.Keys) {
        $committedPath = Join-Path $workspace "licenses/THIRD_PARTY_LICENSES-$target.txt"
        $generatedPath = Join-Path $temporaryRoot "THIRD_PARTY_LICENSES-$target.txt"
        if (-not (Test-Path -LiteralPath $committedPath -PathType Leaf)) {
            throw "missing committed third-party license bundle: $committedPath"
        }
        if (-not (Test-Path -LiteralPath $generatedPath -PathType Leaf)) {
            throw "generator did not produce third-party license bundle: $generatedPath"
        }

        $committedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $committedPath).Hash
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash
        if ($committedHash -ne $generatedHash) {
            throw "third-party license bundle is stale for $target"
        }

        $bytes = [System.IO.File]::ReadAllBytes($committedPath)
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf) {
            throw "$committedPath has a UTF-8 byte-order mark"
        }
        if ($bytes -contains 0x0d) {
            throw "$committedPath does not use LF-only line endings"
        }
        $licenseText = Get-Content -Raw -LiteralPath $committedPath
        if ($licenseText.Contains($workspace, [StringComparison]::OrdinalIgnoreCase)) {
            throw "$committedPath exposes the local workspace path"
        }
        if ($licenseText -match '(?m)^Declared license: (Unknown|Ignore)$') {
            throw "$committedPath contains unresolved license state"
        }

        $componentMatches = [regex]::Matches(
            $licenseText.Substring(0, $licenseText.IndexOf("LICENSE TEXTS`n", [StringComparison]::Ordinal)),
            '(?m)^(?<component>[A-Za-z0-9][A-Za-z0-9_-]* [^\r\n]+)\nDeclared license: '
        )
        $components = @($componentMatches | ForEach-Object { $_.Groups['component'].Value })
        if ($components.Count -ne $expected[$target].Components) {
            throw "$committedPath has $($components.Count) components; expected $($expected[$target].Components)"
        }
        if (($components | Sort-Object -Unique).Count -ne $components.Count) {
            throw "$committedPath contains duplicate components"
        }

        foreach ($requiredEntry in @('strsim 0.11.1', 'zlib-rs 0.6.7', 'zmij 1.0.23') +
            $expected[$target].Present) {
            if (-not $licenseText.Contains($requiredEntry, [StringComparison]::Ordinal)) {
                throw "$committedPath is missing required component $requiredEntry"
            }
        }
        foreach ($forbiddenEntry in $expected[$target].Absent) {
            if ($licenseText.Contains($forbiddenEntry, [StringComparison]::Ordinal)) {
                throw "$committedPath contains component from another target: $forbiddenEntry"
            }
        }
        foreach ($requiredLicense in @(
                'Apache License 2.0',
                'MIT License',
                'Unicode License v3',
                'zlib License'
            )) {
            if (-not $licenseText.Contains($requiredLicense, [StringComparison]::Ordinal)) {
                throw "$committedPath is missing $requiredLicense"
            }
        }
        if ($target -eq 'x86_64-pc-windows-msvc' -and
            -not $licenseText.Contains('LLVM Exceptions to the Apache 2.0 License', [StringComparison]::Ordinal)) {
            throw "$committedPath is missing the LLVM exception required by winx"
        }

        $noticeCount = [regex]::Matches($licenseText, '(?m)^Original SHA-256: [0-9a-f]{64}$').Count
        if ($noticeCount -ne $expected[$target].Notices) {
            throw "$committedPath has $noticeCount upstream notices; expected $($expected[$target].Notices)"
        }
    }
} finally {
    Pop-Location
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
        $expectedParent = [System.IO.Path]::GetDirectoryName($resolvedTemporaryRoot)
        $resolvedLeaf = [System.IO.Path]::GetFileName($resolvedTemporaryRoot)
        if ($expectedParent -ne $targetRoot -or
            $resolvedLeaf -notmatch '^third-party-license-verification-[0-9]+-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected temporary directory: $resolvedTemporaryRoot"
        }
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}

Write-Host "Verified $($expected.Count) target-specific third-party license bundles."
