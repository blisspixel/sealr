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

function Invoke-Captured {
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
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(10000)) {
        $process.Kill($true)
        $process.WaitForExit()
        throw "$Role did not finish within ten seconds"
    }
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        Stdout = $stdout.GetAwaiter().GetResult()
        Stderr = $stderr.GetAwaiter().GetResult()
    }
}

function Set-UstarOctal {
    param(
        [Parameter(Mandatory)][byte[]]$Header,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][int]$Length,
        [Parameter(Mandatory)][uint64]$Value
    )

    $digits = [System.Convert]::ToString([int64]$Value, 8)
    if ($digits.Length -gt $Length - 1) {
        throw "ustar octal value does not fit its $Length-byte field"
    }
    $encoded = [System.Text.Encoding]::ASCII.GetBytes(
        $digits.PadLeft($Length - 1, '0') + [char]0
    )
    [System.Array]::Copy($encoded, 0, $Header, $Offset, $Length)
}

function New-UstarHeader {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][uint64]$Size,
        [Parameter(Mandatory)][char]$TypeFlag
    )

    $nameBytes = [System.Text.Encoding]::ASCII.GetBytes($Name)
    if ($nameBytes.Length -eq 0 -or $nameBytes.Length -gt 100) {
        throw 'native-package PAX fixture name is outside the ustar field'
    }
    $header = [byte[]]::new(512)
    [System.Array]::Copy($nameBytes, 0, $header, 0, $nameBytes.Length)
    Set-UstarOctal -Header $header -Offset 100 -Length 8 -Value 420
    Set-UstarOctal -Header $header -Offset 108 -Length 8 -Value 0
    Set-UstarOctal -Header $header -Offset 116 -Length 8 -Value 0
    Set-UstarOctal -Header $header -Offset 124 -Length 12 -Value $Size
    Set-UstarOctal -Header $header -Offset 136 -Length 12 -Value 0
    for ($index = 148; $index -lt 156; $index++) {
        $header[$index] = 0x20
    }
    $header[156] = [byte]$TypeFlag
    $magic = [System.Text.Encoding]::ASCII.GetBytes("ustar$([char]0)00")
    [System.Array]::Copy($magic, 0, $header, 257, $magic.Length)
    Set-UstarOctal -Header $header -Offset 329 -Length 8 -Value 0
    Set-UstarOctal -Header $header -Offset 337 -Length 8 -Value 0
    $checksum = [uint32]0
    foreach ($byte in $header) {
        $checksum += $byte
    }
    $checksumText = [System.Convert]::ToString([int64]$checksum, 8).PadLeft(6, '0')
    if ($checksumText.Length -ne 6) {
        throw 'native-package PAX fixture checksum exceeded the canonical field'
    }
    $checksumBytes = [System.Text.Encoding]::ASCII.GetBytes($checksumText)
    [System.Array]::Copy($checksumBytes, 0, $header, 148, 6)
    $header[154] = 0
    $header[155] = 0x20
    return $header
}

function New-PaxRecord {
    param(
        [Parameter(Mandatory)][string]$Keyword,
        [Parameter(Mandatory)][string]$Value
    )

    $body = " $Keyword=$Value`n"
    $digits = 1
    while ($true) {
        $length = $digits + [System.Text.Encoding]::UTF8.GetByteCount($body)
        $nextDigits = ([string]$length).Length
        if ($nextDigits -eq $digits) {
            return [System.Text.Encoding]::UTF8.GetBytes("$length$body")
        }
        $digits = $nextDigits
    }
}

function Add-PaddedTarRecord {
    param(
        [Parameter(Mandatory)][System.IO.MemoryStream]$Stream,
        [Parameter(Mandatory)][byte[]]$Header,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Payload
    )

    $Stream.Write($Header, 0, $Header.Length)
    $Stream.Write($Payload, 0, $Payload.Length)
    $padding = [int]((512 - ($Stream.Position % 512)) % 512)
    if ($padding -ne 0) {
        $zeros = [byte[]]::new($padding)
        $Stream.Write($zeros, 0, $zeros.Length)
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

    $tarManifestPath = Resolve-RequiredFile `
        -Path (Join-Path $workspace 'crates/sealr/tests/conformance/tar-producers-v1.json') `
        -Role 'portable ustar producer corpus'
    $tarManifest = Get-Content -Raw -LiteralPath $tarManifestPath | ConvertFrom-Json
    $tarFixture = @($tarManifest.fixtures | Where-Object { $_.id -ceq 'gnu-tar-1.35' })
    if ($tarManifest.schema -cne 'sealr.tar-producer-fixtures.v1' -or $tarFixture.Count -ne 1) {
        throw 'portable ustar producer corpus does not contain exactly one GNU tar fixture'
    }
    $tarFixture = $tarFixture[0]
    if ($tarFixture.len -ne 10240 -or
        $tarFixture.source_sha256 -cne '075e5d93ff213f832023b1ecf614a4c39bdf5975edab3aedcb0df7d649073a42' -or
        $tarFixture.layout_sha256 -cne 'f01a9bc4f6bc2d6a92fad5ed1860d19e4b9d35345b0d31412bdbdadcc0af061a' -or
        $tarFixture.content_sha256 -cne '4ae9adac838554433b256510c5a83afc820340d9cdbc720fb37e0ae101b07626') {
        throw 'portable ustar fixture identity changed'
    }
    $tarBytes = [byte[]]::new([int]$tarFixture.len)
    $previousSpanEnd = 0
    foreach ($span in $tarFixture.spans) {
        $spanBytes = [System.Convert]::FromHexString([string]$span.hex)
        $spanOffset = [int]$span.offset
        $spanEnd = $spanOffset + $spanBytes.Length
        if ($spanOffset -lt $previousSpanEnd -or $spanEnd -gt $tarBytes.Length -or
            @($spanBytes | Where-Object { $_ -eq 0 }).Count -ne 0) {
            throw 'portable ustar sparse span is unordered, overlapping, out of range, or contains zero bytes'
        }
        [System.Array]::Copy($spanBytes, 0, $tarBytes, $spanOffset, $spanBytes.Length)
        $previousSpanEnd = $spanEnd
    }
    $tarArchivePath = Join-Path $temporaryRoot 'gnu-portable-ustar.tar'
    [System.IO.File]::WriteAllBytes($tarArchivePath, $tarBytes)
    $tarHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $tarArchivePath).Hash.ToLowerInvariant()
    if ($tarHash -cne $tarFixture.source_sha256) {
        throw "reconstructed portable ustar source digest changed: $tarHash"
    }

    $tarInspect = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-ustar', $tarArchivePath) `
        -Role 'packaged portable ustar inspect'
    if ($tarInspect.ExitCode -ne 0) {
        throw "packaged portable ustar inspect failed: $($tarInspect.Stderr)"
    }
    $tarView = $tarInspect.Stdout | ConvertFrom-Json
    $tarReceipt = $tarInspect.Stderr | ConvertFrom-Json
    if ($tarView.schema -cne 'sealr.view.v1' -or
        $tarReceipt.schema -cne 'sealr.receipt.v2' -or
        $tarView.source.magic -cne 'tar' -or
        $tarView.interpretation.status -cne 'interpreted' -or
        $tarView.admission.status -cne 'admitted' -or
        $tarView.verification.status -cne 'complete' -or
        $tarView.effect.status -cne 'not-requested' -or
        @($tarView.members).Count -ne 1 -or
        $tarView.members[0].path -cne 'gnu.txt' -or
        $tarReceipt.identities.interpretation.id -cne 'sealr.profile.tar.ustar-portable.v1' -or
        $tarReceipt.identities.layout.sealrTreeV2 -cne $tarFixture.layout_sha256 -or
        $tarReceipt.identities.content.sealrTreeV1 -cne $tarFixture.content_sha256) {
        throw 'packaged portable ustar inspect returned unexpected semantic evidence'
    }

    $tarDestination = Join-Path $temporaryRoot 'portable-ustar-output'
    $tarMaterialize = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-ustar', $tarArchivePath, '--dest', $tarDestination) `
        -Role 'packaged portable ustar materialization'
    if ($tarMaterialize.ExitCode -ne 0) {
        throw "packaged portable ustar materialization failed: $($tarMaterialize.Stderr)"
    }
    $tarMaterializedView = $tarMaterialize.Stdout | ConvertFrom-Json
    $tarMaterializedReceipt = $tarMaterialize.Stderr | ConvertFrom-Json
    $tarFiles = @(Get-ChildItem -LiteralPath $tarDestination -Recurse -Force -File | ForEach-Object {
            [System.IO.Path]::GetRelativePath($tarDestination, $_.FullName).Replace('\', '/')
        })
    $leakedStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
    if (-not $tarMaterializedView.wrote -or
        $tarMaterializedView.effect.status -cne 'committed' -or
        $tarMaterializedReceipt.identities.layout.sealrTreeV2 -cne $tarFixture.layout_sha256 -or
        $tarMaterializedReceipt.identities.content.sealrTreeV1 -cne $tarFixture.content_sha256 -or
        $tarFiles.Count -ne 1 -or $tarFiles[0] -cne 'gnu.txt' -or
        [System.IO.File]::ReadAllText((Join-Path $tarDestination 'gnu.txt')) -cne "gnu portable ustar`n" -or
        $leakedStages.Count -ne 0) {
        throw 'packaged portable ustar materialization did not preserve the exact admitted tree'
    }

    $paxPathRecord = New-PaxRecord -Keyword 'path' -Value 'mars/retained.txt'
    $paxSizeRecord = New-PaxRecord -Keyword 'size' -Value '4'
    $paxPayloadStream = [System.IO.MemoryStream]::new()
    try {
        $paxPayloadStream.Write($paxPathRecord, 0, $paxPathRecord.Length)
        $paxPayloadStream.Write($paxSizeRecord, 0, $paxSizeRecord.Length)
        $paxPayload = $paxPayloadStream.ToArray()
    } finally {
        $paxPayloadStream.Dispose()
    }
    $paxStream = [System.IO.MemoryStream]::new()
    try {
        Add-PaddedTarRecord `
            -Stream $paxStream `
            -Header (New-UstarHeader -Name 'PaxHeaders/entry' -Size $paxPayload.Length -TypeFlag 'x') `
            -Payload $paxPayload
        $paxContent = [System.Text.Encoding]::ASCII.GetBytes('mars')
        Add-PaddedTarRecord `
            -Stream $paxStream `
            -Header (New-UstarHeader -Name 'placeholder' -Size 99 -TypeFlag '0') `
            -Payload $paxContent
        $terminator = [byte[]]::new(1024)
        $paxStream.Write($terminator, 0, $terminator.Length)
        $paxBytes = $paxStream.ToArray()
    } finally {
        $paxStream.Dispose()
    }
    if ($paxBytes.Length -ne 3072) {
        throw "native-package PAX fixture length changed: $($paxBytes.Length)"
    }
    $paxArchivePath = Join-Path $temporaryRoot 'portable-pax.tar'
    [System.IO.File]::WriteAllBytes($paxArchivePath, $paxBytes)
    $paxSourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $paxArchivePath).Hash.ToLowerInvariant()
    if ($paxSourceHash -cne '1cf6a8e4db2d214ea6f5565a623942587a70da203ca00bf3b13358a46611b2b6') {
        throw "native-package PAX fixture identity changed: $paxSourceHash"
    }

    $paxInspect = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-pax', $paxArchivePath) `
        -Role 'packaged restricted PAX inspect'
    if ($paxInspect.ExitCode -ne 0) {
        throw "packaged restricted PAX inspect failed: $($paxInspect.Stderr)"
    }
    $paxView = $paxInspect.Stdout | ConvertFrom-Json
    $paxReceipt = $paxInspect.Stderr | ConvertFrom-Json
    if ($paxView.schema -cne 'sealr.view.v1' -or
        $paxReceipt.schema -cne 'sealr.receipt.v2' -or
        $paxView.source.magic -cne 'tar' -or
        $paxView.interpretation.status -cne 'interpreted' -or
        $paxView.admission.status -cne 'admitted' -or
        $paxView.verification.status -cne 'complete' -or
        $paxView.effect.status -cne 'not-requested' -or
        @($paxView.members).Count -ne 1 -or
        $paxView.members[0].path -cne 'mars/retained.txt' -or
        $paxView.members[0].method -cne 'raw' -or
        $paxView.members[0].uncomp_bytes -ne 4 -or
        $paxReceipt.policy.id -cne 'sealr:policy/default/v5' -or
        $paxReceipt.policy.digest.sha256 -cne 'd1268c72f284f8f1b7ce5e06ada17ef7cbbbc5768a876ee93d103ad21e77d019' -or
        $paxReceipt.identities.interpretation.id -cne 'sealr.profile.tar.pax-portable.v1' -or
        $paxReceipt.identities.interpretation.digest.sha256 -cne 'db951f620acf54e67845144e138f9f16994439847a97601e20a424dfea7f4445' -or
        $paxReceipt.identities.layout.sealrTreeV5 -cne '221afc64c85dbd220f75b925587f4fc8e07774df1ca1bd762b8b5bc4747a6fb7' -or
        $paxReceipt.identities.content.sealrTreeV1 -cne 'c668daa1f966425150367b8aafe176477b9960a421f9d35502256845b0a7a1a1') {
        throw 'packaged restricted PAX inspect returned unexpected semantic evidence'
    }

    $paxDefault = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @($paxArchivePath) `
        -Role 'packaged PAX compatibility-default refusal'
    $paxDefaultView = $paxDefault.Stdout | ConvertFrom-Json
    $paxDefaultReceipt = $paxDefault.Stderr | ConvertFrom-Json
    if ($paxDefault.ExitCode -ne 2 -or
        $paxDefaultView.verdict -cne 'rejected' -or
        $paxDefaultView.source.magic -cne 'unknown' -or
        $paxDefaultView.policy.id -cne 'sealr:policy/default/v1' -or
        $paxDefaultView.interpretation.status -cne 'unsupported' -or
        $paxDefaultView.admission.status -cne 'not-evaluated' -or
        @($paxDefaultView.members).Count -ne 0 -or
        $paxDefaultReceipt.identities.interpretation.id -cne 'sealr.profile.zip.strict-ascii.v1' -or
        $paxDefaultReceipt.identities.layout.status -cne 'unavailable' -or
        $paxDefaultReceipt.identities.content.status -cne 'unavailable') {
        throw 'packaged compatibility default unexpectedly recognized restricted PAX'
    }

    $paxDestination = Join-Path $temporaryRoot 'restricted-pax-output'
    $paxMaterialize = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-pax', $paxArchivePath, '--dest', $paxDestination) `
        -Role 'packaged restricted PAX materialization'
    if ($paxMaterialize.ExitCode -ne 0) {
        throw "packaged restricted PAX materialization failed: $($paxMaterialize.Stderr)"
    }
    $paxMaterializedView = $paxMaterialize.Stdout | ConvertFrom-Json
    $paxMaterializedReceipt = $paxMaterialize.Stderr | ConvertFrom-Json
    $paxFiles = @(Get-ChildItem -LiteralPath $paxDestination -Recurse -Force -File | ForEach-Object {
            [System.IO.Path]::GetRelativePath($paxDestination, $_.FullName).Replace('\', '/')
        })
    $paxDirectories = @(Get-ChildItem -LiteralPath $paxDestination -Recurse -Force -Directory | ForEach-Object {
            [System.IO.Path]::GetRelativePath($paxDestination, $_.FullName).Replace('\', '/')
        })
    $leakedStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
    if (-not $paxMaterializedView.wrote -or
        $paxMaterializedView.effect.status -cne 'committed' -or
        $paxMaterializedReceipt.identities.layout.sealrTreeV5 -cne $paxReceipt.identities.layout.sealrTreeV5 -or
        $paxMaterializedReceipt.identities.content.sealrTreeV1 -cne $paxReceipt.identities.content.sealrTreeV1 -or
        $paxFiles.Count -ne 1 -or $paxFiles[0] -cne 'mars/retained.txt' -or
        $paxDirectories.Count -ne 1 -or $paxDirectories[0] -cne 'mars' -or
        [System.IO.File]::ReadAllText((Join-Path $paxDestination 'mars/retained.txt')) -cne 'mars' -or
        $leakedStages.Count -ne 0) {
        throw 'packaged restricted PAX materialization did not preserve the effective admitted tree'
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
        $tarWorkerDestination = Join-Path $temporaryRoot 'portable-ustar-worker-output'
        $tarWorker = Invoke-Captured `
            -FilePath $packagedCli `
            -Arguments @(
                '--format', 'tar-ustar',
                '--worker-manifest', $manifestPath,
                $tarArchivePath,
                '--dest', $tarWorkerDestination
            ) `
            -Role 'packaged portable ustar worker refusal'
        $workerStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
        if ($tarWorker.ExitCode -ne 1 -or
            -not [string]::IsNullOrEmpty($tarWorker.Stdout) -or
            $tarWorker.Stderr -notmatch 'isolation unavailable' -or
            $tarWorker.Stderr -notmatch 'ZIP profiles only' -or
            (Test-Path -LiteralPath $tarWorkerDestination) -or
            $workerStages.Count -ne 0) {
            throw 'packaged portable ustar worker selection did not fail closed without fallback'
        }
        $paxWorkerDestination = Join-Path $temporaryRoot 'restricted-pax-worker-output'
        $paxWorker = Invoke-Captured `
            -FilePath $packagedCli `
            -Arguments @(
                '--format', 'tar-pax',
                '--worker-manifest', $manifestPath,
                $paxArchivePath,
                '--dest', $paxWorkerDestination
            ) `
            -Role 'packaged restricted PAX worker refusal'
        $workerStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
        if ($paxWorker.ExitCode -ne 1 -or
            -not [string]::IsNullOrEmpty($paxWorker.Stdout) -or
            $paxWorker.Stderr -notmatch 'isolation unavailable' -or
            $paxWorker.Stderr -notmatch 'PAX TAR' -or
            (Test-Path -LiteralPath $paxWorkerDestination) -or
            $workerStages.Count -ne 0) {
            throw 'packaged restricted PAX worker selection did not fail closed without fallback'
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
