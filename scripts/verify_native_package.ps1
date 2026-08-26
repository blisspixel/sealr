[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArchivePath,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$TargetTriple,
    [string]$LabBinary,
    [string]$WheelLabBinary,
    [string]$PackagedConsumerBinary
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$linuxTarget = 'x86_64-unknown-linux-gnu'
$windowsTarget = 'x86_64-pc-windows-msvc'
$macTarget = 'aarch64-apple-darwin'
$helperTarget = 'x86_64-unknown-linux-musl'
$supportedTargets = @($linuxTarget, $windowsTarget, $macTarget)
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

function Assert-ExactSet {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Actual,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Expected,
        [Parameter(Mandatory)][string]$Role
    )

    $actualSorted = @($Actual | Sort-Object -Unique)
    $expectedSorted = @($Expected | Sort-Object -Unique)
    if ($actualSorted.Count -ne $Actual.Count) {
        throw "$Role contains duplicate entries"
    }
    if ($actualSorted.Count -ne $expectedSorted.Count -or
        ($actualSorted -join "`n") -cne ($expectedSorted -join "`n")) {
        throw "$Role differs from its exact contract. Expected: $($expectedSorted -join ', '). Actual: $($actualSorted -join ', ')"
    }
}

function Invoke-Refusal {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Role
    )

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $start.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw "$Role did not start"
    }
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(5000)) {
        $process.Kill($true)
        $process.WaitForExit()
        throw "$Role did not refuse within five seconds"
    }
    if ($process.ExitCode -eq 0) {
        throw "$Role unexpectedly exited successfully"
    }
}

if ($TargetTriple -notin $supportedTargets) {
    throw "unsupported native release target: $TargetTriple"
}
$resolvedArchive = Resolve-RequiredFile -Path $ArchivePath -Role 'native release archive'
$archiveBase = "sealr-$Version-$TargetTriple"
$isLinuxTarget = $TargetTriple -eq $linuxTarget
$binaryName = if ($TargetTriple -eq $windowsTarget) { 'sealr.exe' } else { 'sealr' }
$expectedFiles = @(
    'CHANGELOG.md',
    'LICENSE',
    'README.md',
    'THIRD_PARTY_LICENSES.txt',
    $binaryName
)
$expectedDirectories = @()
if ($isLinuxTarget) {
    $expectedFiles += @(
        'libexec/sealr/sealr-worker',
        'libexec/sealr/sealr-worker.manifest'
    )
    $expectedDirectories = @('libexec', 'libexec/sealr')
    if ([string]::IsNullOrWhiteSpace($LabBinary)) {
        throw 'Linux package verification requires the repository lab binary'
    }
    if ([string]::IsNullOrWhiteSpace($WheelLabBinary)) {
        throw 'Linux package verification requires the wheel laboratory binary'
    }
    if ([string]::IsNullOrWhiteSpace($PackagedConsumerBinary)) {
        throw 'Linux package verification requires the packaged consumer binary'
    }
    $LabBinary = Resolve-RequiredFile -Path $LabBinary -Role 'repository lab binary'
    $WheelLabBinary = Resolve-RequiredFile -Path $WheelLabBinary -Role 'wheel laboratory binary'
    $PackagedConsumerBinary = Resolve-RequiredFile `
        -Path $PackagedConsumerBinary `
        -Role 'packaged consumer binary'
} elseif (-not [string]::IsNullOrWhiteSpace($LabBinary) -or
    -not [string]::IsNullOrWhiteSpace($WheelLabBinary) -or
    -not [string]::IsNullOrWhiteSpace($PackagedConsumerBinary)) {
    throw "Linux-only verifier binary input is forbidden for target $TargetTriple"
}

$archiveEntries = @()
if ($TargetTriple -eq $windowsTarget) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($resolvedArchive)
    try {
        $archiveEntries = @($archive.Entries | ForEach-Object {
                $name = $_.FullName.Replace('\', '/')
                $unixType = (($_.ExternalAttributes -shr 16) -band 0xf000)
                $entryIsDirectory = $name.EndsWith('/')
                if ($unixType -notin @(0, 0x4000, 0x8000) -or
                    ($unixType -eq 0x4000 -and -not $entryIsDirectory) -or
                    ($unixType -eq 0x8000 -and $entryIsDirectory)) {
                    throw "native ZIP contains a link or unsupported entry type: $name"
                }
                $name
            })
    } finally {
        $archive.Dispose()
    }
} else {
    $archiveEntries = @(tar -tzf $resolvedArchive)
    if ($LASTEXITCODE -ne 0) {
        throw "listing native archive failed with exit code $LASTEXITCODE"
    }
    $verboseEntries = @(tar -tvzf $resolvedArchive)
    if ($LASTEXITCODE -ne 0 -or $verboseEntries.Count -ne $archiveEntries.Count) {
        throw 'verbose native archive listing did not match its entry list'
    }
    for ($index = 0; $index -lt $archiveEntries.Count; $index++) {
        $expectedType = if ($archiveEntries[$index].EndsWith('/')) { 'd' } else { '-' }
        if ([string]::IsNullOrEmpty($verboseEntries[$index]) -or
            $verboseEntries[$index][0] -cne $expectedType) {
            throw "native tar contains a link or unsupported entry type: $($archiveEntries[$index])"
        }
    }
}
if (@($archiveEntries | Sort-Object -Unique).Count -ne $archiveEntries.Count) {
    throw 'native archive contains duplicate entry names'
}
foreach ($entry in $archiveEntries) {
    if ([string]::IsNullOrWhiteSpace($entry) -or
        $entry.StartsWith('/') -or
        $entry.Contains('\') -or
        $entry -notlike "$archiveBase/*" -or
        @($entry.Split('/') | Where-Object { $_ -eq '..' }).Count -ne 0) {
        throw "unsafe or out-of-root archive entry: $entry"
    }
}
$archiveFiles = @($archiveEntries | Where-Object { -not $_.EndsWith('/') } | ForEach-Object {
        $_.Substring($archiveBase.Length + 1)
    })
Assert-ExactSet -Actual $archiveFiles -Expected $expectedFiles -Role 'archive file list'

$targetRoot = [System.IO.Path]::GetFullPath((Join-Path $workspace 'target'))
[System.IO.Directory]::CreateDirectory($targetRoot) | Out-Null
$temporaryLeaf = "native package verification with spaces-$PID-$([System.Guid]::NewGuid().ToString('N'))"
$temporaryRoot = Join-Path $targetRoot $temporaryLeaf
[System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null

try {
    if ($TargetTriple -eq $windowsTarget) {
        Expand-Archive -LiteralPath $resolvedArchive -DestinationPath $temporaryRoot
    } else {
        tar -C $temporaryRoot -xzf $resolvedArchive
        if ($LASTEXITCODE -ne 0) {
            throw "extracting native archive failed with exit code $LASTEXITCODE"
        }
    }
    $packageRoot = Join-Path $temporaryRoot $archiveBase
    if (-not (Test-Path -LiteralPath $packageRoot -PathType Container)) {
        throw "archive did not extract its exact package root: $archiveBase"
    }
    $actualFiles = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -Force -File | ForEach-Object {
            if (-not [string]::IsNullOrEmpty([string]$_.LinkType)) {
                throw "packaged file is a link: $($_.FullName)"
            }
            [System.IO.Path]::GetRelativePath($packageRoot, $_.FullName).Replace('\', '/')
        })
    Assert-ExactSet -Actual $actualFiles -Expected $expectedFiles -Role 'extracted file list'
    $actualDirectories = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -Force -Directory | ForEach-Object {
            if (-not [string]::IsNullOrEmpty([string]$_.LinkType)) {
                throw "packaged directory is a link: $($_.FullName)"
            }
            [System.IO.Path]::GetRelativePath($packageRoot, $_.FullName).Replace('\', '/')
        })
    Assert-ExactSet -Actual $actualDirectories -Expected $expectedDirectories -Role 'extracted directory list'

    $licenseSource = Resolve-RequiredFile `
        -Path (Join-Path $workspace "licenses/THIRD_PARTY_LICENSES-$TargetTriple.txt") `
        -Role 'committed target license bundle'
    $packagedLicense = Join-Path $packageRoot 'THIRD_PARTY_LICENSES.txt'
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $licenseSource).Hash -ne
        (Get-FileHash -Algorithm SHA256 -LiteralPath $packagedLicense).Hash) {
        throw 'packaged third-party license bundle changed'
    }

    $packagedCli = Join-Path $packageRoot $binaryName
    $reportedVersion = (& $packagedCli --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $reportedVersion -ne "sealr $Version") {
        throw "packaged CLI reported unexpected version: $reportedVersion"
    }
    & $packagedCli --help | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'packaged CLI help smoke test failed'
    }

    if ($TargetTriple -ne $windowsTarget) {
        foreach ($relative in $expectedFiles) {
            $expectedMode = if ($relative -in @($binaryName, 'libexec/sealr/sealr-worker')) { '755' } else { '644' }
            $path = Join-Path $packageRoot $relative
            $actualMode = if ($TargetTriple -eq $macTarget) {
                (stat -f '%Lp' -- $path | Out-String).Trim()
            } else {
                (stat --format='%a' -- $path | Out-String).Trim()
            }
            if ($LASTEXITCODE -ne 0 -or $actualMode -ne $expectedMode) {
                throw "packaged mode for $relative is $actualMode; expected $expectedMode"
            }
        }
    }

    if ($isLinuxTarget) {
        $helper = Join-Path $packageRoot 'libexec/sealr/sealr-worker'
        $manifestPath = Join-Path $packageRoot 'libexec/sealr/sealr-worker.manifest'
        $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
        if (($manifestBytes.Length -ge 3 -and $manifestBytes[0] -eq 0xef -and
                $manifestBytes[1] -eq 0xbb -and $manifestBytes[2] -eq 0xbf) -or
            $manifestBytes -contains 0x0d) {
            throw 'worker manifest must be BOM-free UTF-8 with LF line endings'
        }
        $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        $propertyNames = @($manifest.PSObject.Properties.Name)
        Assert-ExactSet -Actual $propertyNames -Expected @(
            'schema', 'release_version', 'target', 'bootstrap_abi', 'byte_len', 'sha256'
        ) -Role 'worker manifest fields'
        $helperLength = (Get-Item -LiteralPath $helper).Length
        $helperHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $helper).Hash.ToLowerInvariant()
        if ($manifest.schema -cne 'sealr.worker-artifact.v1' -or
            $manifest.release_version -cne $Version -or
            $manifest.target -cne $helperTarget -or
            $manifest.bootstrap_abi -ne 1 -or
            $manifest.byte_len -ne $helperLength -or
            [string]$manifest.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $manifest.sha256 -cne $helperHash) {
            throw 'worker manifest does not bind the exact packaged helper identity'
        }
        $elfHeader = readelf --file-header $helper | Out-String
        if ($LASTEXITCODE -ne 0 -or
            $elfHeader -notmatch 'Class:\s+ELF64' -or
            $elfHeader -notmatch 'Machine:\s+Advanced Micro Devices X86-64') {
            throw 'packaged helper is not the required x86_64 ELF artifact'
        }
        $programHeaders = readelf --program-headers $helper | Out-String
        if ($LASTEXITCODE -ne 0 -or $programHeaders -match '\bINTERP\b') {
            throw 'packaged helper must be static and contain no program interpreter'
        }
        Invoke-Refusal -FilePath $helper -Arguments @() -Role 'packaged helper direct invocation'
        Invoke-Refusal -FilePath $helper -Arguments @('--help') -Role 'packaged helper command invocation'
        & $LabBinary package-smoke --worker $helper --bytes $helperLength --sha256 $helperHash
        if ($LASTEXITCODE -ne 0) {
            throw 'extracted helper authentication and handshake smoke failed'
        }
        & $WheelLabBinary supervised-smoke --worker-manifest $manifestPath
        if ($LASTEXITCODE -ne 0) {
            throw 'wheel laboratory did not complete through the extracted worker boundary'
        }
        & $PackagedConsumerBinary --worker-manifest $manifestPath
        if ($LASTEXITCODE -ne 0) {
            throw 'packaged crate consumer did not complete through the extracted worker boundary'
        }

        $smokeArchive = Join-Path $temporaryRoot 'supervised-empty.zip'
        [System.IO.File]::WriteAllBytes(
            $smokeArchive,
            [System.Convert]::FromBase64String('UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==')
        )
        $receiptPath = Join-Path $temporaryRoot 'supervised-receipt.json'
        $viewText = (& $packagedCli `
                --worker-manifest $manifestPath `
                $smokeArchive 2> $receiptPath | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            throw 'packaged CLI did not complete through the extracted worker boundary'
        }
        $view = $viewText | ConvertFrom-Json
        $receipt = Get-Content -Raw -LiteralPath $receiptPath | ConvertFrom-Json
        if ($view.schema -cne 'sealr.view.v1' -or
            $receipt.schema -cne 'sealr.receipt.v2' -or
            $view.admission.status -cne 'admitted' -or
            $view.verification.status -cne 'complete') {
            throw 'packaged CLI supervised smoke returned unexpected semantic output'
        }
    }

    Write-Host "Verified native package $resolvedArchive"
} finally {
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
        $expectedParent = [System.IO.Path]::GetDirectoryName($resolvedTemporaryRoot)
        $resolvedLeaf = [System.IO.Path]::GetFileName($resolvedTemporaryRoot)
        if ($expectedParent -ne $targetRoot -or
            $resolvedLeaf -notmatch '^native package verification with spaces-[0-9]+-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected verification directory: $resolvedTemporaryRoot"
        }
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
