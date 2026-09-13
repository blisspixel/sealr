[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$contractPath = Join-Path $workspace 'tests/package-contract/sealr.json'
$contract = Get-Content -Raw -LiteralPath $contractPath | ConvertFrom-Json
$expectedKeys = @(
    'schema', 'package', 'registry', 'rust_version', 'license', 'readme', 'license_file', 'files'
)
$actualKeys = @($contract.PSObject.Properties.Name | Sort-Object)
if (Compare-Object -ReferenceObject ($expectedKeys | Sort-Object) -DifferenceObject $actualKeys) {
    throw 'crate package contract has missing or unknown fields'
}
if ($contract.schema -ne 'sealr.crate-package-contract.v1' -or $contract.package -ne 'sealr') {
    throw 'crate package contract selects an unknown schema or package'
}

Push-Location $workspace
$temporaryRoot = $null
try {
    $metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed with exit code $LASTEXITCODE"
    }
    $publishable = @($metadata.packages | Where-Object { @($_.publish).Count -ne 0 })
    if ($publishable.Count -ne 1 -or $publishable[0].name -ne 'sealr') {
        throw "publishable crate set is not exactly sealr: $(@($publishable.name) -join ', ')"
    }
    $package = $publishable[0]
    if (@($package.publish).Count -ne 1 -or $package.publish[0] -ne $contract.registry) {
        throw 'sealr registry allowlist disagrees with the package contract'
    }
    if ($package.rust_version -ne $contract.rust_version -or $package.license -ne $contract.license) {
        throw 'sealr MSRV or SPDX license disagrees with the package contract'
    }
    if ((Split-Path -Leaf $package.readme) -ne $contract.readme -or
        $null -ne $package.license_file -or
        $null -ne $contract.license_file) {
        throw 'sealr README or license-file metadata disagrees with the package contract'
    }

    $actualFiles = @(& cargo package --locked --allow-dirty -p sealr --list)
    if ($LASTEXITCODE -ne 0) {
        throw "cargo package --list failed with exit code $LASTEXITCODE"
    }
    $actualFiles = @($actualFiles | ForEach-Object { $_.Trim().Replace('\', '/') } | Where-Object { $_ })
    $expectedFiles = @($contract.files | ForEach-Object { ([string]$_).Replace('\', '/') })
    if (($expectedFiles | Sort-Object -Unique).Count -ne $expectedFiles.Count) {
        throw 'crate package contract contains duplicate paths'
    }
    $difference = @(Compare-Object -ReferenceObject ($expectedFiles | Sort-Object) -DifferenceObject ($actualFiles | Sort-Object))
    if ($difference.Count -ne 0) {
        throw "cargo package file list disagrees with the contract: $($difference | Out-String)"
    }

    & cargo package --locked --allow-dirty -p sealr
    if ($LASTEXITCODE -ne 0) {
        throw "cargo package verification failed with exit code $LASTEXITCODE"
    }
    $archive = Join-Path $workspace "target/package/sealr-$($package.version).crate"
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
        throw "cargo package did not create $archive"
    }
    $targetRoot = [IO.Path]::GetFullPath((Join-Path $workspace 'target'))
    $temporaryRoot = Join-Path $targetRoot "crate-package-verification-$PID-$([Guid]::NewGuid().ToString('N'))"
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    & tar -xf $archive -C $temporaryRoot
    if ($LASTEXITCODE -ne 0) {
        throw "crate extraction failed with exit code $LASTEXITCODE"
    }
    $packageRoot = Join-Path $temporaryRoot "sealr-$($package.version)"
    $packagedReadme = Join-Path $packageRoot $contract.readme
    $packagedLicense = Join-Path $packageRoot 'LICENSE'
    foreach ($pair in @(
            @{ Packaged = $packagedReadme; Source = (Join-Path $workspace 'README.md') },
            @{ Packaged = $packagedLicense; Source = (Join-Path $workspace 'LICENSE') }
        )) {
        if (-not (Test-Path -LiteralPath $pair.Packaged -PathType Leaf)) {
            throw "packaged metadata file is missing: $($pair.Packaged)"
        }
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $pair.Packaged).Hash -ne
            (Get-FileHash -Algorithm SHA256 -LiteralPath $pair.Source).Hash) {
            throw "packaged metadata bytes changed: $($pair.Packaged)"
        }
    }
}
finally {
    Pop-Location
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        $resolved = [IO.Path]::GetFullPath($temporaryRoot)
        $targetRoot = [IO.Path]::GetFullPath((Join-Path $workspace 'target'))
        if (-not $resolved.StartsWith($targetRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolved) -notmatch '^crate-package-verification-[0-9]+-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected temporary path: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

Write-Host 'Verified the exact sealr crate package, README, license, registry, and MSRV contract.'
