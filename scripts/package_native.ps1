[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version,
    [string]$TargetTriple,
    [string]$CliBinary,
    [string]$HelperBinary,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$supportedTargets = @(
    'x86_64-unknown-linux-gnu',
    'aarch64-apple-darwin',
    'x86_64-pc-windows-msvc'
)
$linuxTarget = 'x86_64-unknown-linux-gnu'
$helperTarget = 'x86_64-unknown-linux-musl'
$utf8 = [System.Text.UTF8Encoding]::new($false, $true)
$temporaryRoot = $null

function Resolve-RequiredFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Role
    )

    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Role is missing: $resolved"
    }
    return $resolved
}

function Write-LfUtf8 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Text
    )

    $normalized = $Text.Replace("`r`n", "`n").Replace("`r", "`n")
    [System.IO.File]::WriteAllText($Path, $normalized, $utf8)
}

if ([string]::IsNullOrWhiteSpace($TargetTriple)) {
    $targetLine = rustc -vV | Select-String -Pattern '^host: '
    if ($null -eq $targetLine) {
        throw 'rustc did not report its host target'
    }
    $TargetTriple = $targetLine.Line.Substring(6).Trim()
}
if ($TargetTriple -notin $supportedTargets) {
    throw "unsupported native release target: $TargetTriple"
}

$binaryName = if ($TargetTriple -eq 'x86_64-pc-windows-msvc') { 'sealr.exe' } else { 'sealr' }
if ([string]::IsNullOrWhiteSpace($CliBinary)) {
    $CliBinary = Join-Path $workspace "target/release/$binaryName"
}
$resolvedCli = Resolve-RequiredFile -Path $CliBinary -Role 'release CLI binary'

$isLinuxTarget = $TargetTriple -eq $linuxTarget
$resolvedHelper = $null
if ($isLinuxTarget) {
    if ([string]::IsNullOrWhiteSpace($HelperBinary)) {
        $HelperBinary = Join-Path $workspace "target/$helperTarget/release/sealr-worker"
    }
    $resolvedHelper = Resolve-RequiredFile -Path $HelperBinary -Role 'production Linux helper'
} elseif (-not [string]::IsNullOrWhiteSpace($HelperBinary)) {
    throw "helper input is forbidden for non-Linux target $TargetTriple"
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $workspace 'dist'
}
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($outputRoot) | Out-Null

$targetRoot = [System.IO.Path]::GetFullPath((Join-Path $workspace 'target'))
[System.IO.Directory]::CreateDirectory($targetRoot) | Out-Null
$temporaryLeaf = "native-package-$PID-$([System.Guid]::NewGuid().ToString('N'))"
$temporaryRoot = Join-Path $targetRoot $temporaryLeaf
$archiveBase = "sealr-$Version-$TargetTriple"
$packageParent = Join-Path $temporaryRoot 'package'
$packageRoot = Join-Path $packageParent $archiveBase
[System.IO.Directory]::CreateDirectory($packageRoot) | Out-Null

try {
    Copy-Item -LiteralPath $resolvedCli -Destination (Join-Path $packageRoot $binaryName)
    foreach ($name in @('README.md', 'CHANGELOG.md', 'LICENSE')) {
        $source = Resolve-RequiredFile -Path (Join-Path $workspace $name) -Role "release file $name"
        Copy-Item -LiteralPath $source -Destination (Join-Path $packageRoot $name)
    }
    $licenseSource = Resolve-RequiredFile `
        -Path (Join-Path $workspace "licenses/THIRD_PARTY_LICENSES-$TargetTriple.txt") `
        -Role 'target-specific third-party license bundle'
    Copy-Item -LiteralPath $licenseSource `
        -Destination (Join-Path $packageRoot 'THIRD_PARTY_LICENSES.txt')

    if ($isLinuxTarget) {
        $helperDirectory = Join-Path $packageRoot 'libexec/sealr'
        [System.IO.Directory]::CreateDirectory($helperDirectory) | Out-Null
        $packagedHelper = Join-Path $helperDirectory 'sealr-worker'
        Copy-Item -LiteralPath $resolvedHelper -Destination $packagedHelper
        $helperLength = (Get-Item -LiteralPath $resolvedHelper).Length
        if ($helperLength -le 0 -or $helperLength -gt 64MB) {
            throw "production helper length is outside 1..=67108864 bytes: $helperLength"
        }
        $helperHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedHelper).Hash.ToLowerInvariant()
        $manifest = [ordered]@{
            schema = 'sealr.worker-artifact.v1'
            release_version = $Version
            target = $helperTarget
            bootstrap_abi = 1
            byte_len = $helperLength
            sha256 = $helperHash
        }
        $manifestText = ($manifest | ConvertTo-Json -Depth 3) + "`n"
        Write-LfUtf8 -Path (Join-Path $helperDirectory 'sealr-worker.manifest') -Text $manifestText
    }

    if ($TargetTriple -ne 'x86_64-pc-windows-msvc') {
        chmod 755 (Join-Path $packageRoot $binaryName)
        if ($LASTEXITCODE -ne 0) {
            throw "chmod failed for $binaryName with exit code $LASTEXITCODE"
        }
        if ($isLinuxTarget) {
            chmod 755 (Join-Path $packageRoot 'libexec/sealr/sealr-worker')
            if ($LASTEXITCODE -ne 0) {
                throw "chmod failed for sealr-worker with exit code $LASTEXITCODE"
            }
        }
        foreach ($file in Get-ChildItem -LiteralPath $packageRoot -Recurse -File) {
            if ($file.Name -notin @($binaryName, 'sealr-worker')) {
                chmod 644 $file.FullName
                if ($LASTEXITCODE -ne 0) {
                    throw "chmod failed for $($file.FullName) with exit code $LASTEXITCODE"
                }
            }
        }
        foreach ($directory in Get-ChildItem -LiteralPath $packageRoot -Recurse -Directory) {
            chmod 755 $directory.FullName
            if ($LASTEXITCODE -ne 0) {
                throw "chmod failed for $($directory.FullName) with exit code $LASTEXITCODE"
            }
        }
    }

    if ($TargetTriple -eq 'x86_64-pc-windows-msvc') {
        $archivePath = Join-Path $outputRoot "$archiveBase.zip"
        if (Test-Path -LiteralPath $archivePath) {
            Remove-Item -LiteralPath $archivePath -Force
        }
        Push-Location $packageParent
        try {
            Compress-Archive -Path $archiveBase -DestinationPath $archivePath
        } finally {
            Pop-Location
        }
    } else {
        $archivePath = Join-Path $outputRoot "$archiveBase.tar.gz"
        if (Test-Path -LiteralPath $archivePath) {
            Remove-Item -LiteralPath $archivePath -Force
        }
        tar -C $packageParent -czf $archivePath $archiveBase
        if ($LASTEXITCODE -ne 0) {
            throw "tar failed with exit code $LASTEXITCODE"
        }
    }

    $archivePath = Resolve-RequiredFile -Path $archivePath -Role 'native release archive'
    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_OUTPUT)) {
        "archive=$archivePath" >> $env:GITHUB_OUTPUT
        "target=$TargetTriple" >> $env:GITHUB_OUTPUT
    }
    Write-Host "Packaged $archivePath"
} finally {
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
        $expectedParent = [System.IO.Path]::GetDirectoryName($resolvedTemporaryRoot)
        $resolvedLeaf = [System.IO.Path]::GetFileName($resolvedTemporaryRoot)
        if ($expectedParent -ne $targetRoot -or
            $resolvedLeaf -notmatch '^native-package-[0-9]+-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected package directory: $resolvedTemporaryRoot"
        }
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
