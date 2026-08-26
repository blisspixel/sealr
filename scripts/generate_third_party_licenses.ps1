[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$cargoAboutVersion = '0.9.1'
$targets = @(
    'x86_64-unknown-linux-gnu',
    'aarch64-apple-darwin',
    'x86_64-pc-windows-msvc'
)
$utf8 = [System.Text.UTF8Encoding]::new($false, $true)
$temporaryRoot = $null

function ConvertTo-LfText {
    param([Parameter(Mandatory)][string]$Text)

    $lfText = $Text.Replace("`r`n", "`n").Replace("`r", "`n")
    return [System.Text.RegularExpressions.Regex]::Replace(
        $lfText,
        '[\t ]+(?=\n|$)',
        ''
    )
}

function Read-StrictUtf8 {
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    return $utf8.GetString($bytes)
}

function Invoke-CargoAbout {
    param([Parameter(Mandatory)][string[]]$Arguments)

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo-about failed with exit code $LASTEXITCODE"
    }
}

function Test-NoticeFileName {
    param([Parameter(Mandatory)][string]$Name)

    return $Name.StartsWith('NOTICE', [System.StringComparison]::OrdinalIgnoreCase) -or
        $Name.StartsWith('COPYRIGHT', [System.StringComparison]::OrdinalIgnoreCase)
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $workspace 'licenses'
}
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($outputRoot) | Out-Null

$targetRoot = [System.IO.Path]::GetFullPath((Join-Path $workspace 'target'))
[System.IO.Directory]::CreateDirectory($targetRoot) | Out-Null
$temporaryLeaf = "third-party-license-generation-$PID-$([System.Guid]::NewGuid().ToString('N'))"
$temporaryRoot = Join-Path $targetRoot $temporaryLeaf
[System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null

Push-Location $workspace
try {
    $reportedVersion = (& cargo about --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $reportedVersion -ne "cargo-about $cargoAboutVersion") {
        throw "cargo-about $cargoAboutVersion is required, found: $reportedVersion"
    }

    foreach ($target in $targets) {
        $basePath = Join-Path $temporaryRoot "$target-base.txt"
        $jsonPath = Join-Path $temporaryRoot "$target.json"
        $manifestPath = if ($target -eq 'x86_64-unknown-linux-gnu') {
            'tools/release-license-closure/Cargo.toml'
        } else {
            'crates/sealr-cli/Cargo.toml'
        }
        $commonArguments = @(
            '--config', 'about.toml',
            '--locked',
            '--offline',
            '--manifest-path', $manifestPath,
            '--fail',
            '--target', $target
        )
        if ($target -eq 'x86_64-unknown-linux-gnu') {
            $commonArguments += '--no-default-features'
        }

        Invoke-CargoAbout -Arguments (@(
                'about', 'generate', 'scripts/third_party_licenses.hbs'
            ) + $commonArguments + @('--output-file', $basePath))
        Invoke-CargoAbout -Arguments (@(
                'about', 'generate'
            ) + $commonArguments + @('--format', 'json', '--output-file', $jsonPath))

        $aboutData = Read-StrictUtf8 -Path $jsonPath | ConvertFrom-Json -Depth 100
        $packages = @($aboutData.crates)
        if ($packages.Count -eq 0) {
            throw "cargo-about returned no packages for $target"
        }

        $notices = [System.Collections.Generic.SortedDictionary[string, object]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($entry in $packages) {
            $package = $entry.package
            $packageId = "$($package.name)@$($package.version)"
            if ([string]$entry.license -in @('Unknown', 'Ignore')) {
                throw "$packageId has unresolved license state: $($entry.license)"
            }
            if ([string]$package.source -ne 'registry+https://github.com/rust-lang/crates.io-index') {
                throw "$packageId is not from the allowed crates.io registry: $($package.source)"
            }

            $manifestPath = [System.IO.Path]::GetFullPath([string]$package.manifest_path)
            $packageRoot = [System.IO.Path]::GetDirectoryName($manifestPath)
            foreach ($file in @(Get-ChildItem -LiteralPath $packageRoot -File | Where-Object {
                        Test-NoticeFileName -Name $_.Name
                    })) {
                $key = "$($package.name)`0$($package.version)`0$($package.source)`0$($file.Name)"
                if ($notices.ContainsKey($key)) {
                    throw "duplicate upstream notice key for $packageId/$($file.Name)"
                }
                $rawBytes = [System.IO.File]::ReadAllBytes($file.FullName)
                if ($rawBytes.Length -eq 0) {
                    throw "upstream notice is empty: $packageId/$($file.Name)"
                }
                $rawText = $utf8.GetString($rawBytes)
                $notices.Add($key, [pscustomobject]@{
                        Package = $packageId
                        FileName = $file.Name
                        Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
                        Text = ConvertTo-LfText -Text $rawText
                    })
            }
        }

        $baseText = (ConvertTo-LfText -Text (Read-StrictUtf8 -Path $basePath)).TrimEnd("`n")
        $builder = [System.Text.StringBuilder]::new()
        $null = $builder.Append($baseText).Append("`n`n")
        $null = $builder.Append("UPSTREAM NOTICE AND COPYRIGHT FILES`n`n")
        $null = $builder.Append(
            "These root NOTICE* and COPYRIGHT* files come from the exact target dependency closure.`n"
        )
        $null = $builder.Append(
            "Their text is unchanged except that line endings are normalized to LF and trailing horizontal whitespace is removed.`n"
        )

        if ($notices.Count -eq 0) {
            $null = $builder.Append("`nNone.`n")
        } else {
            foreach ($notice in $notices.Values) {
                $null = $builder.Append("`n===============================================================================`n")
                $null = $builder.Append("$($notice.Package) / $($notice.FileName)`n")
                $null = $builder.Append("Original SHA-256: $($notice.Hash)`n")
                $null = $builder.Append("===============================================================================`n`n")
                $null = $builder.Append($notice.Text.TrimEnd("`n")).Append("`n")
            }
        }

        $destination = Join-Path $outputRoot "THIRD_PARTY_LICENSES-$target.txt"
        [System.IO.File]::WriteAllText($destination, $builder.ToString(), $utf8)
        Write-Host "Generated $destination with $($packages.Count) packages and $($notices.Count) upstream notices."
    }
} finally {
    Pop-Location
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
        $expectedParent = [System.IO.Path]::GetDirectoryName($resolvedTemporaryRoot)
        $resolvedLeaf = [System.IO.Path]::GetFileName($resolvedTemporaryRoot)
        if ($expectedParent -ne $targetRoot -or
            $resolvedLeaf -notmatch '^third-party-license-generation-[0-9]+-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected temporary directory: $resolvedTemporaryRoot"
        }
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
