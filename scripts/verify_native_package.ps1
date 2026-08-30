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

function Get-Crc32 {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

    [uint32]$crc = [uint32]::MaxValue
    foreach ($value in $Bytes) {
        $crc = [uint32]($crc -bxor [uint32]$value)
        for ($bit = 0; $bit -lt 8; $bit++) {
            if (($crc -band 1) -ne 0) {
                $crc = [uint32](($crc -shr 1) -bxor [uint32]3988292384)
            } else {
                $crc = [uint32]($crc -shr 1)
            }
        }
    }
    return [uint32]([uint64]4294967295 - [uint64]$crc)
}

function Add-UInt16LittleEndian {
    param(
        [Parameter(Mandatory)][Collections.Generic.List[byte]]$Bytes,
        [Parameter(Mandatory)][uint16]$Value
    )

    $Bytes.Add([byte]($Value -band 0xff))
    $Bytes.Add([byte](($Value -shr 8) -band 0xff))
}

function Add-UInt32LittleEndian {
    param(
        [Parameter(Mandatory)][Collections.Generic.List[byte]]$Bytes,
        [Parameter(Mandatory)][uint32]$Value
    )

    for ($shift = 0; $shift -lt 32; $shift += 8) {
        $Bytes.Add([byte](($Value -shr $shift) -band 0xff))
    }
}

function New-StoredDeflate {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Payload)

    $bytes = [Collections.Generic.List[byte]]::new()
    $offset = 0
    do {
        $remaining = $Payload.Length - $offset
        $length = [Math]::Min(65535, $remaining)
        $final = ($offset + $length -eq $Payload.Length)
        $bytes.Add([byte]$(if ($final) { 1 } else { 0 }))
        Add-UInt16LittleEndian -Bytes $bytes -Value ([uint16]$length)
        Add-UInt16LittleEndian -Bytes $bytes -Value ([uint16](0xffff - $length))
        if ($length -gt 0) {
            $chunk = [byte[]]::new($length)
            [Array]::Copy($Payload, $offset, $chunk, 0, $length)
            $bytes.AddRange($chunk)
        }
        $offset += $length
    } while ($offset -lt $Payload.Length)
    return ,$bytes.ToArray()
}

# A deterministic minimal gzip member (fixed mtime 0, no optional fields) that
# stores its derived TAR in uncompressed Deflate blocks.
function New-GzipWrappedTar {
    param([Parameter(Mandatory)][byte[]]$Payload)

    $bytes = [Collections.Generic.List[byte]]::new()
    $bytes.AddRange([byte[]]@(0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255))
    $bytes.AddRange((New-StoredDeflate -Payload $Payload))
    Add-UInt32LittleEndian -Bytes $bytes -Value (Get-Crc32 $Payload)
    Add-UInt32LittleEndian -Bytes $bytes -Value ([uint32]$Payload.Length)
    return ,$bytes.ToArray()
}

if ($TargetTriple -notin $supportedTargets) {
    throw "unsupported native release target: $TargetTriple"
}
$resolvedArchive = Resolve-RequiredFile -Path $ArchivePath -Role 'native release archive'
$archiveBase = "sealr-$Version-$TargetTriple"
$isLinuxTarget = $TargetTriple -eq $linuxTarget
$binaryName = if ($TargetTriple -eq $windowsTarget) { 'sealr.exe' } else { 'sealr' }
$identityVerifierName = if ($TargetTriple -eq $windowsTarget) {
    'sealr-identity-verifier.exe'
} else {
    'sealr-identity-verifier'
}
$expectedFiles = @(
    'CHANGELOG.md',
    'LICENSE',
    'README.md',
    'THIRD_PARTY_LICENSES.txt',
    $binaryName,
    $identityVerifierName
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
    $packagedIdentityVerifier = Join-Path $packageRoot $identityVerifierName
    $verifierVersion = (& $packagedIdentityVerifier --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $verifierVersion -cne "sealr-identity-verifier $Version") {
        throw "packaged identity verifier reported unexpected version: $verifierVersion"
    }
    foreach ($helpArguments in @(@('--help'), @('evidence', '--help'))) {
        $help = Invoke-Captured `
            -FilePath $packagedIdentityVerifier `
            -Arguments $helpArguments `
            -Role 'packaged identity verifier help'
        if ($help.ExitCode -ne 0 -or
            [string]::IsNullOrWhiteSpace($help.Stdout) -or
            -not [string]::IsNullOrEmpty($help.Stderr)) {
            throw 'packaged identity verifier help contract failed'
        }
    }
    $verifierMisuse = Invoke-Captured `
        -FilePath $packagedIdentityVerifier `
        -Arguments @('evidence', '--view', 'missing-receipt.json') `
        -Role 'packaged identity verifier misuse'
    if ($verifierMisuse.ExitCode -ne 2 -or
        -not [string]::IsNullOrEmpty($verifierMisuse.Stdout) -or
        $verifierMisuse.Stderr -notmatch '^usage: ') {
        throw 'packaged identity verifier misuse contract failed'
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

    $canonicalViewPath = Join-Path $temporaryRoot 'canonical-view.json'
    $canonicalReceiptPath = Join-Path $temporaryRoot 'canonical-receipt.json'
    $canonicalProducer = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @(
            '--format', 'tar-ustar',
            $tarArchivePath,
            '--view', $canonicalViewPath,
            '--receipt', $canonicalReceiptPath,
            '--canonical'
        ) `
        -Role 'packaged canonical evidence producer'
    if ($canonicalProducer.ExitCode -ne 0 -or
        -not [string]::IsNullOrEmpty($canonicalProducer.Stdout) -or
        -not [string]::IsNullOrEmpty($canonicalProducer.Stderr)) {
        throw 'packaged CLI did not produce canonical evidence silently'
    }
    $canonicalView = Get-Content -Raw -LiteralPath $canonicalViewPath | ConvertFrom-Json
    $canonicalReceipt = Get-Content -Raw -LiteralPath $canonicalReceiptPath | ConvertFrom-Json
    if ($canonicalView.schema -cne 'sealr.view.v2' -or
        $canonicalReceipt.schema -cne 'sealr.receipt.v3' -or
        $canonicalView.admission.status -cne 'admitted' -or
        $canonicalView.verification.status -cne 'complete' -or
        @($canonicalView.members).Count -ne 1) {
        throw 'packaged CLI canonical evidence shape changed'
    }
    $canonicalViewHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $canonicalViewPath).Hash.ToLowerInvariant()
    $canonicalReceiptHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $canonicalReceiptPath).Hash.ToLowerInvariant()
    $canonicalVerification = Invoke-Captured `
        -FilePath $packagedIdentityVerifier `
        -Arguments @(
            'evidence',
            '--view', $canonicalViewPath,
            '--receipt', $canonicalReceiptPath,
            '--source', $tarArchivePath
        ) `
        -Role 'packaged canonical evidence verification'
    $expectedVerification = "verified canonical evidence: view sha256 $canonicalViewHash, receipt sha256 $canonicalReceiptHash, 1 member(s), content root independently verified, source digest checked; layout root remains a producer claim`n"
    if ($canonicalVerification.ExitCode -ne 0 -or
        $canonicalVerification.Stdout -cne $expectedVerification -or
        -not [string]::IsNullOrEmpty($canonicalVerification.Stderr)) {
        throw 'packaged identity verifier did not reproduce the exact admitted evidence contract'
    }

    $rejectedArchivePath = Join-Path $temporaryRoot 'rejected-portable-ustar.tar'
    $rejectedBytes = [System.IO.File]::ReadAllBytes($tarArchivePath)
    $rejectedBytes[0] = $rejectedBytes[0] -bxor 1
    [System.IO.File]::WriteAllBytes($rejectedArchivePath, $rejectedBytes)
    $rejectedViewPath = Join-Path $temporaryRoot 'rejected-view.json'
    $rejectedReceiptPath = Join-Path $temporaryRoot 'rejected-receipt.json'
    $rejectedProducer = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @(
            '--format', 'tar-ustar',
            $rejectedArchivePath,
            '--view', $rejectedViewPath,
            '--receipt', $rejectedReceiptPath,
            '--canonical'
        ) `
        -Role 'packaged rejected canonical evidence producer'
    if ($rejectedProducer.ExitCode -ne 2 -or
        -not [string]::IsNullOrEmpty($rejectedProducer.Stdout) -or
        -not [string]::IsNullOrEmpty($rejectedProducer.Stderr)) {
        throw 'packaged CLI did not produce canonical rejection evidence silently'
    }
    $rejectedView = Get-Content -Raw -LiteralPath $rejectedViewPath | ConvertFrom-Json
    $rejectedReceipt = Get-Content -Raw -LiteralPath $rejectedReceiptPath | ConvertFrom-Json
    if ($rejectedView.schema -cne 'sealr.view.v2' -or
        $rejectedReceipt.schema -cne 'sealr.receipt.v3' -or
        $rejectedView.verdict -cne 'rejected') {
        throw 'packaged CLI canonical rejection evidence shape changed'
    }
    $rejectedVerification = Invoke-Captured `
        -FilePath $packagedIdentityVerifier `
        -Arguments @(
            'evidence',
            '--view', $rejectedViewPath,
            '--receipt', $rejectedReceiptPath,
            '--source', $rejectedArchivePath
        ) `
        -Role 'packaged canonical rejection evidence verification'
    if ($rejectedVerification.ExitCode -ne 0 -or
        $rejectedVerification.Stdout -notmatch '^verified canonical evidence: ' -or
        $rejectedVerification.Stdout -notmatch 'content root unavailable, source digest checked; layout root remains a producer claim\r?\n$' -or
        -not [string]::IsNullOrEmpty($rejectedVerification.Stderr)) {
        throw 'packaged identity verifier did not accept coherent rejection evidence'
    }

    $tamperCases = @(
        [pscustomobject]@{ Label = 'view'; Original = $canonicalViewPath; IsView = $true; IsSource = $false },
        [pscustomobject]@{ Label = 'receipt'; Original = $canonicalReceiptPath; IsView = $false; IsSource = $false },
        [pscustomobject]@{ Label = 'source'; Original = $tarArchivePath; IsView = $false; IsSource = $true }
    )
    foreach ($case in $tamperCases) {
        $tamperedPath = Join-Path $temporaryRoot "tampered-$($case.Label).bin"
        $originalBytes = [System.IO.File]::ReadAllBytes($case.Original)
        $tamperedBytes = [byte[]]::new($originalBytes.Length + 1)
        [System.Array]::Copy($originalBytes, 0, $tamperedBytes, 0, $originalBytes.Length)
        $tamperedBytes[$tamperedBytes.Length - 1] = 0x0a
        [System.IO.File]::WriteAllBytes($tamperedPath, $tamperedBytes)
        $viewUnderTest = if ($case.IsView) { $tamperedPath } else { $canonicalViewPath }
        $receiptUnderTest = if (-not $case.IsView -and -not $case.IsSource) {
            $tamperedPath
        } else {
            $canonicalReceiptPath
        }
        $sourceUnderTest = if ($case.IsSource) { $tamperedPath } else { $tarArchivePath }
        $refusal = Invoke-Captured `
            -FilePath $packagedIdentityVerifier `
            -Arguments @(
                'evidence',
                '--view', $viewUnderTest,
                '--receipt', $receiptUnderTest,
                '--source', $sourceUnderTest
            ) `
            -Role "packaged identity verifier $($case.Label) tamper refusal"
        if ($refusal.ExitCode -ne 1 -or
            -not [string]::IsNullOrEmpty($refusal.Stdout) -or
            $refusal.Stderr -notmatch '^canonical evidence rejected: ') {
            throw "packaged identity verifier did not reject $($case.Label) tampering"
        }
    }
    $pairSubstitution = Invoke-Captured `
        -FilePath $packagedIdentityVerifier `
        -Arguments @(
            'evidence',
            '--view', $canonicalViewPath,
            '--receipt', $rejectedReceiptPath,
            '--source', $tarArchivePath
        ) `
        -Role 'packaged identity verifier pair substitution refusal'
    if ($pairSubstitution.ExitCode -ne 1 -or
        -not [string]::IsNullOrEmpty($pairSubstitution.Stdout) -or
        $pairSubstitution.Stderr -notmatch '^canonical evidence rejected: ') {
        throw 'packaged identity verifier did not reject evidence pair substitution'
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

    $gnuManifestPath = Resolve-RequiredFile `
        -Path (Join-Path $workspace 'crates/sealr/tests/conformance/tar-gnu-longname-producers-v1.json') `
        -Role 'old-GNU long-name producer corpus'
    $gnuManifest = Get-Content -Raw -LiteralPath $gnuManifestPath | ConvertFrom-Json
    $gnuFixture = @($gnuManifest.fixtures | Where-Object { $_.id -ceq 'gnu-tar-1.35' })
    if ($gnuManifest.schema -cne 'sealr.tar-gnu-longname-producer-fixtures.v1' -or
        $gnuFixture.Count -ne 1) {
        throw 'old-GNU long-name producer corpus does not contain exactly one GNU tar fixture'
    }
    $gnuFixture = $gnuFixture[0]
    if ($gnuFixture.len -ne 10240 -or
        $gnuFixture.source_sha256 -cne '0953f9d5cd95b15786620225bca10b4fbecf017c8b06a48ac5872ec985a6a1cc' -or
        $gnuFixture.layout_sha256 -cne 'df34e19111a92bd9785bad127f6dbca2fd45429d61b5e174a9e6c1c318f3dd84' -or
        $gnuFixture.content_sha256 -cne '4f6857e09b37a13750d51e1a36bb43730da3c7592c94495b8d0f5ee41ead4855') {
        throw 'old-GNU long-name fixture identity changed'
    }
    $gnuBytes = [byte[]]::new([int]$gnuFixture.len)
    $previousSpanEnd = 0
    foreach ($span in $gnuFixture.spans) {
        $spanBytes = [System.Convert]::FromHexString([string]$span.hex)
        $spanOffset = [int]$span.offset
        $spanEnd = $spanOffset + $spanBytes.Length
        if ($spanOffset -lt $previousSpanEnd -or $spanEnd -gt $gnuBytes.Length -or
            @($spanBytes | Where-Object { $_ -eq 0 }).Count -ne 0) {
            throw 'old-GNU sparse span is unordered, overlapping, out of range, or contains zero bytes'
        }
        [System.Array]::Copy($spanBytes, 0, $gnuBytes, $spanOffset, $spanBytes.Length)
        $previousSpanEnd = $spanEnd
    }
    $gnuArchivePath = Join-Path $temporaryRoot 'portable-gnu-longname.tar'
    [System.IO.File]::WriteAllBytes($gnuArchivePath, $gnuBytes)
    $gnuHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $gnuArchivePath).Hash.ToLowerInvariant()
    if ($gnuHash -cne $gnuFixture.source_sha256) {
        throw "reconstructed old-GNU source digest changed: $gnuHash"
    }

    $gnuInspect = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-gnu-longname', $gnuArchivePath) `
        -Role 'packaged old-GNU long-name inspect'
    if ($gnuInspect.ExitCode -ne 0) {
        throw "packaged old-GNU long-name inspect failed: $($gnuInspect.Stderr)"
    }
    $gnuView = $gnuInspect.Stdout | ConvertFrom-Json
    $gnuReceipt = $gnuInspect.Stderr | ConvertFrom-Json
    if ($gnuView.schema -cne 'sealr.view.v1' -or
        $gnuReceipt.schema -cne 'sealr.receipt.v2' -or
        $gnuView.source.magic -cne 'tar' -or
        $gnuView.interpretation.status -cne 'interpreted' -or
        $gnuView.admission.status -cne 'admitted' -or
        $gnuView.verification.status -cne 'complete' -or
        $gnuView.effect.status -cne 'not-requested' -or
        @($gnuView.members).Count -ne 1 -or
        $gnuView.members[0].path -cne $gnuFixture.member_path -or
        $gnuView.members[0].method -cne 'raw' -or
        $gnuView.members[0].uncomp_bytes -ne 22 -or
        $gnuReceipt.policy.id -cne 'sealr:policy/default/v6' -or
        $gnuReceipt.policy.digest.sha256 -cne 'aefc8a1baa113d7face30857ef64fe8f47c647fae863a72810b80380f8fd4178' -or
        $gnuReceipt.identities.interpretation.id -cne 'sealr.profile.tar.gnu-longname-portable.v1' -or
        $gnuReceipt.identities.interpretation.digest.sha256 -cne '08fe2698806da997bc42e7e13a45cbf412a4a7056dec39c62456202680b91fa4' -or
        $gnuReceipt.identities.layout.sealrTreeV6 -cne $gnuFixture.layout_sha256 -or
        $gnuReceipt.identities.content.sealrTreeV1 -cne $gnuFixture.content_sha256) {
        throw 'packaged old-GNU long-name inspect returned unexpected semantic evidence'
    }

    $gnuDefault = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @($gnuArchivePath) `
        -Role 'packaged old-GNU compatibility-default refusal'
    $gnuDefaultView = $gnuDefault.Stdout | ConvertFrom-Json
    $gnuDefaultReceipt = $gnuDefault.Stderr | ConvertFrom-Json
    if ($gnuDefault.ExitCode -ne 2 -or
        $gnuDefaultView.verdict -cne 'rejected' -or
        $gnuDefaultView.source.magic -cne 'unknown' -or
        $gnuDefaultView.policy.id -cne 'sealr:policy/default/v1' -or
        $gnuDefaultView.interpretation.status -cne 'unsupported' -or
        $gnuDefaultView.admission.status -cne 'not-evaluated' -or
        @($gnuDefaultView.members).Count -ne 0 -or
        $gnuDefaultReceipt.identities.interpretation.id -cne 'sealr.profile.zip.strict-ascii.v1' -or
        $gnuDefaultReceipt.identities.layout.status -cne 'unavailable' -or
        $gnuDefaultReceipt.identities.content.status -cne 'unavailable') {
        throw 'packaged compatibility default unexpectedly recognized old-GNU long-name TAR'
    }

    $gnuDestination = Join-Path $temporaryRoot 'old-gnu-longname-output'
    $gnuMaterialize = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-gnu-longname', $gnuArchivePath, '--dest', $gnuDestination) `
        -Role 'packaged old-GNU long-name materialization'
    if ($gnuMaterialize.ExitCode -ne 0) {
        throw "packaged old-GNU long-name materialization failed: $($gnuMaterialize.Stderr)"
    }
    $gnuMaterializedView = $gnuMaterialize.Stdout | ConvertFrom-Json
    $gnuMaterializedReceipt = $gnuMaterialize.Stderr | ConvertFrom-Json
    $gnuFiles = @(Get-ChildItem -LiteralPath $gnuDestination -Recurse -Force -File | ForEach-Object {
            [System.IO.Path]::GetRelativePath($gnuDestination, $_.FullName).Replace('\', '/')
        })
    $leakedStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
    $gnuMaterializedPath = Join-Path $gnuDestination ([string]$gnuFixture.member_path)
    if (-not $gnuMaterializedView.wrote -or
        $gnuMaterializedView.effect.status -cne 'committed' -or
        $gnuMaterializedReceipt.identities.layout.sealrTreeV6 -cne $gnuFixture.layout_sha256 -or
        $gnuMaterializedReceipt.identities.content.sealrTreeV1 -cne $gnuFixture.content_sha256 -or
        $gnuFiles.Count -ne 1 -or $gnuFiles[0] -cne $gnuFixture.member_path -or
        [System.IO.File]::ReadAllText($gnuMaterializedPath) -cne "gnu longname portable`n" -or
        $leakedStages.Count -ne 0) {
        throw 'packaged old-GNU long-name materialization did not preserve the effective admitted tree'
    }

    $gzipPaxBytes = New-GzipWrappedTar -Payload $paxBytes
    if ($gzipPaxBytes.Length -ne 3095) {
        throw "native-package gzip-wrapped PAX fixture length changed: $($gzipPaxBytes.Length)"
    }
    $gzipPaxArchivePath = Join-Path $temporaryRoot 'portable-pax.tar.gz'
    [System.IO.File]::WriteAllBytes($gzipPaxArchivePath, $gzipPaxBytes)
    $gzipPaxSourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $gzipPaxArchivePath).Hash.ToLowerInvariant()
    if ($gzipPaxSourceHash -cne 'd69dfb232b999e5bc7e538bf98ce5e23e72526bc3613b77eecb0a1e4b3c1cc34') {
        throw "native-package gzip-wrapped PAX fixture identity changed: $gzipPaxSourceHash"
    }

    $gzipPaxInspect = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-gzip-pax', $gzipPaxArchivePath) `
        -Role 'packaged gzip-wrapped PAX inspect'
    if ($gzipPaxInspect.ExitCode -ne 0) {
        throw "packaged gzip-wrapped PAX inspect failed: $($gzipPaxInspect.Stderr)"
    }
    $gzipPaxView = $gzipPaxInspect.Stdout | ConvertFrom-Json
    $gzipPaxReceipt = $gzipPaxInspect.Stderr | ConvertFrom-Json
    if ($gzipPaxView.schema -cne 'sealr.view.v1' -or
        $gzipPaxReceipt.schema -cne 'sealr.receipt.v2' -or
        $gzipPaxView.source.magic -cne 'gz' -or
        $gzipPaxView.interpretation.status -cne 'interpreted' -or
        $gzipPaxView.admission.status -cne 'admitted' -or
        $gzipPaxView.verification.status -cne 'complete' -or
        $gzipPaxView.effect.status -cne 'not-requested' -or
        @($gzipPaxView.members).Count -ne 1 -or
        $gzipPaxView.members[0].path -cne 'mars/retained.txt' -or
        $gzipPaxView.members[0].method -cne 'raw' -or
        $gzipPaxView.members[0].uncomp_bytes -ne 4 -or
        $gzipPaxReceipt.policy.id -cne 'sealr:policy/default/v7' -or
        $gzipPaxReceipt.policy.digest.sha256 -cne '92d576984b718e8a02bc6044090f8e2b335dbd1abd136d53e5b02d0ffbd978ef' -or
        $gzipPaxReceipt.identities.interpretation.id -cne 'sealr.profile.tar-gzip.pax-portable.v1' -or
        $gzipPaxReceipt.identities.interpretation.digest.sha256 -cne '6cc91b2b8563b5b070b44bf357a5c62e5d9dda0aedc374d7a08cd80da9c5434f' -or
        $gzipPaxReceipt.identities.layout.sealrTreeV7 -cne '3f9a628a8369e254b62ed5c069e5210f3b3679c83b90e753ec29ce6ceb08fc36' -or
        $gzipPaxReceipt.identities.content.sealrTreeV1 -cne 'c668daa1f966425150367b8aafe176477b9960a421f9d35502256845b0a7a1a1') {
        throw 'packaged gzip-wrapped PAX inspect returned unexpected semantic evidence'
    }

    $gzipPaxDefault = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @($gzipPaxArchivePath) `
        -Role 'packaged gzip-wrapped PAX compatibility-default refusal'
    $gzipPaxDefaultView = $gzipPaxDefault.Stdout | ConvertFrom-Json
    $gzipPaxDefaultReceipt = $gzipPaxDefault.Stderr | ConvertFrom-Json
    if ($gzipPaxDefault.ExitCode -ne 2 -or
        $gzipPaxDefaultView.verdict -cne 'rejected' -or
        $gzipPaxDefaultView.source.magic -cne 'gz' -or
        $gzipPaxDefaultView.policy.id -cne 'sealr:policy/default/v1' -or
        $gzipPaxDefaultView.interpretation.status -cne 'unsupported' -or
        $gzipPaxDefaultView.admission.status -cne 'not-evaluated' -or
        @($gzipPaxDefaultView.members).Count -ne 0 -or
        $gzipPaxDefaultReceipt.identities.interpretation.id -cne 'sealr.profile.zip.strict-ascii.v1' -or
        $gzipPaxDefaultReceipt.identities.layout.status -cne 'unavailable' -or
        $gzipPaxDefaultReceipt.identities.content.status -cne 'unavailable') {
        throw 'packaged compatibility default unexpectedly recognized gzip-wrapped PAX'
    }

    $gzipPaxDestination = Join-Path $temporaryRoot 'gzip-pax-output'
    $gzipPaxMaterialize = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-gzip-pax', $gzipPaxArchivePath, '--dest', $gzipPaxDestination) `
        -Role 'packaged gzip-wrapped PAX materialization'
    if ($gzipPaxMaterialize.ExitCode -ne 0) {
        throw "packaged gzip-wrapped PAX materialization failed: $($gzipPaxMaterialize.Stderr)"
    }
    $gzipPaxMaterializedView = $gzipPaxMaterialize.Stdout | ConvertFrom-Json
    $gzipPaxMaterializedReceipt = $gzipPaxMaterialize.Stderr | ConvertFrom-Json
    $gzipPaxFiles = @(Get-ChildItem -LiteralPath $gzipPaxDestination -Recurse -Force -File | ForEach-Object {
            [System.IO.Path]::GetRelativePath($gzipPaxDestination, $_.FullName).Replace('\', '/')
        })
    $gzipPaxDirectories = @(Get-ChildItem -LiteralPath $gzipPaxDestination -Recurse -Force -Directory | ForEach-Object {
            [System.IO.Path]::GetRelativePath($gzipPaxDestination, $_.FullName).Replace('\', '/')
        })
    $leakedStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
    if (-not $gzipPaxMaterializedView.wrote -or
        $gzipPaxMaterializedView.effect.status -cne 'committed' -or
        $gzipPaxMaterializedReceipt.identities.layout.sealrTreeV7 -cne $gzipPaxReceipt.identities.layout.sealrTreeV7 -or
        $gzipPaxMaterializedReceipt.identities.content.sealrTreeV1 -cne $gzipPaxReceipt.identities.content.sealrTreeV1 -or
        $gzipPaxFiles.Count -ne 1 -or $gzipPaxFiles[0] -cne 'mars/retained.txt' -or
        $gzipPaxDirectories.Count -ne 1 -or $gzipPaxDirectories[0] -cne 'mars' -or
        [System.IO.File]::ReadAllText((Join-Path $gzipPaxDestination 'mars/retained.txt')) -cne 'mars' -or
        $leakedStages.Count -ne 0) {
        throw 'packaged gzip-wrapped PAX materialization did not preserve the effective admitted tree'
    }

    $gzipGnuBytes = New-GzipWrappedTar -Payload $gnuBytes
    if ($gzipGnuBytes.Length -ne 10263) {
        throw "native-package gzip-wrapped GNU long-name fixture length changed: $($gzipGnuBytes.Length)"
    }
    $gzipGnuArchivePath = Join-Path $temporaryRoot 'portable-gnu-longname.tar.gz'
    [System.IO.File]::WriteAllBytes($gzipGnuArchivePath, $gzipGnuBytes)
    $gzipGnuSourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $gzipGnuArchivePath).Hash.ToLowerInvariant()
    if ($gzipGnuSourceHash -cne 'ee454a01c3ac8091473f022115363f7ef64b581fbc10763a923d0c6f8f7562f2') {
        throw "native-package gzip-wrapped GNU long-name fixture identity changed: $gzipGnuSourceHash"
    }

    $gzipGnuInspect = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-gzip-gnu-longname', $gzipGnuArchivePath) `
        -Role 'packaged gzip-wrapped GNU long-name inspect'
    if ($gzipGnuInspect.ExitCode -ne 0) {
        throw "packaged gzip-wrapped GNU long-name inspect failed: $($gzipGnuInspect.Stderr)"
    }
    $gzipGnuView = $gzipGnuInspect.Stdout | ConvertFrom-Json
    $gzipGnuReceipt = $gzipGnuInspect.Stderr | ConvertFrom-Json
    if ($gzipGnuView.schema -cne 'sealr.view.v1' -or
        $gzipGnuReceipt.schema -cne 'sealr.receipt.v2' -or
        $gzipGnuView.source.magic -cne 'gz' -or
        $gzipGnuView.interpretation.status -cne 'interpreted' -or
        $gzipGnuView.admission.status -cne 'admitted' -or
        $gzipGnuView.verification.status -cne 'complete' -or
        $gzipGnuView.effect.status -cne 'not-requested' -or
        @($gzipGnuView.members).Count -ne 1 -or
        $gzipGnuView.members[0].path -cne $gnuFixture.member_path -or
        $gzipGnuView.members[0].method -cne 'raw' -or
        $gzipGnuView.members[0].uncomp_bytes -ne 22 -or
        $gzipGnuReceipt.policy.id -cne 'sealr:policy/default/v7' -or
        $gzipGnuReceipt.policy.digest.sha256 -cne '92d576984b718e8a02bc6044090f8e2b335dbd1abd136d53e5b02d0ffbd978ef' -or
        $gzipGnuReceipt.identities.interpretation.id -cne 'sealr.profile.tar-gzip.gnu-longname-portable.v1' -or
        $gzipGnuReceipt.identities.interpretation.digest.sha256 -cne '622943e9629c4acc7cfeb446eb9f2d16bb245db589c1a200e885a9d69a02295a' -or
        $gzipGnuReceipt.identities.layout.sealrTreeV8 -cne '92b635ab1d332b77b7e94852fc341636043363b127698cf42dcb3766c3e883ab' -or
        $gzipGnuReceipt.identities.content.sealrTreeV1 -cne $gnuFixture.content_sha256) {
        throw 'packaged gzip-wrapped GNU long-name inspect returned unexpected semantic evidence'
    }

    $gzipGnuDefault = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @($gzipGnuArchivePath) `
        -Role 'packaged gzip-wrapped GNU compatibility-default refusal'
    $gzipGnuDefaultView = $gzipGnuDefault.Stdout | ConvertFrom-Json
    $gzipGnuDefaultReceipt = $gzipGnuDefault.Stderr | ConvertFrom-Json
    if ($gzipGnuDefault.ExitCode -ne 2 -or
        $gzipGnuDefaultView.verdict -cne 'rejected' -or
        $gzipGnuDefaultView.source.magic -cne 'gz' -or
        $gzipGnuDefaultView.policy.id -cne 'sealr:policy/default/v1' -or
        $gzipGnuDefaultView.interpretation.status -cne 'unsupported' -or
        $gzipGnuDefaultView.admission.status -cne 'not-evaluated' -or
        @($gzipGnuDefaultView.members).Count -ne 0 -or
        $gzipGnuDefaultReceipt.identities.interpretation.id -cne 'sealr.profile.zip.strict-ascii.v1' -or
        $gzipGnuDefaultReceipt.identities.layout.status -cne 'unavailable' -or
        $gzipGnuDefaultReceipt.identities.content.status -cne 'unavailable') {
        throw 'packaged compatibility default unexpectedly recognized gzip-wrapped GNU long-name TAR'
    }

    $gzipGnuDestination = Join-Path $temporaryRoot 'gzip-gnu-longname-output'
    $gzipGnuMaterialize = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-gzip-gnu-longname', $gzipGnuArchivePath, '--dest', $gzipGnuDestination) `
        -Role 'packaged gzip-wrapped GNU long-name materialization'
    if ($gzipGnuMaterialize.ExitCode -ne 0) {
        throw "packaged gzip-wrapped GNU long-name materialization failed: $($gzipGnuMaterialize.Stderr)"
    }
    $gzipGnuMaterializedView = $gzipGnuMaterialize.Stdout | ConvertFrom-Json
    $gzipGnuMaterializedReceipt = $gzipGnuMaterialize.Stderr | ConvertFrom-Json
    $gzipGnuFiles = @(Get-ChildItem -LiteralPath $gzipGnuDestination -Recurse -Force -File | ForEach-Object {
            [System.IO.Path]::GetRelativePath($gzipGnuDestination, $_.FullName).Replace('\', '/')
        })
    $leakedStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
    $gzipGnuMaterializedPath = Join-Path $gzipGnuDestination ([string]$gnuFixture.member_path)
    if (-not $gzipGnuMaterializedView.wrote -or
        $gzipGnuMaterializedView.effect.status -cne 'committed' -or
        $gzipGnuMaterializedReceipt.identities.layout.sealrTreeV8 -cne $gzipGnuReceipt.identities.layout.sealrTreeV8 -or
        $gzipGnuMaterializedReceipt.identities.content.sealrTreeV1 -cne $gzipGnuReceipt.identities.content.sealrTreeV1 -or
        $gzipGnuFiles.Count -ne 1 -or $gzipGnuFiles[0] -cne $gnuFixture.member_path -or
        [System.IO.File]::ReadAllText($gzipGnuMaterializedPath) -cne "gnu longname portable`n" -or
        $leakedStages.Count -ne 0) {
        throw 'packaged gzip-wrapped GNU long-name materialization did not preserve the effective admitted tree'
    }

    # Zstandard CLI v1.5.7 default-level output for the conformance derived TAR
    # holding mission/plan.txt with `verify twice, decode once`.
    $zstdHex = '28b52ffd640007a5030062c5121880a96dc0ffd67f1bf321d16a06b6620b6de647c162f42' +
        '2038a129f1e8cf43843d126fa1683558a6866f59b3abd0e3f43c424598ac944438c94ff7fa6e0ffad15' +
        '0d4887600824deb5b6100e004fc10f92c40c35149a94c11c58d301c0907b01a0133cf00e83dc50ab023' +
        '8562e1326b004ca51b2db'
    $zstdBytes = [System.Convert]::FromHexString($zstdHex)
    if ($zstdBytes.Length -ne 130) {
        throw "native-package zstd-wrapped ustar fixture length changed: $($zstdBytes.Length)"
    }
    $zstdArchivePath = Join-Path $temporaryRoot 'portable-ustar.tar.zst'
    [System.IO.File]::WriteAllBytes($zstdArchivePath, $zstdBytes)
    $zstdSourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zstdArchivePath).Hash.ToLowerInvariant()
    if ($zstdSourceHash -cne '4a467796ef2cd9a9e1a6ed670fa1d1ef15174b95be29b087af7339c32b078dcb') {
        throw "native-package zstd-wrapped ustar fixture identity changed: $zstdSourceHash"
    }

    $zstdInspect = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-zstd-ustar', $zstdArchivePath) `
        -Role 'packaged zstd-wrapped ustar inspect'
    if ($zstdInspect.ExitCode -ne 0) {
        throw "packaged zstd-wrapped ustar inspect failed: $($zstdInspect.Stderr)"
    }
    $zstdView = $zstdInspect.Stdout | ConvertFrom-Json
    $zstdReceipt = $zstdInspect.Stderr | ConvertFrom-Json
    if ($zstdView.schema -cne 'sealr.view.v1' -or
        $zstdReceipt.schema -cne 'sealr.receipt.v2' -or
        $zstdView.source.magic -cne 'zst' -or
        $zstdView.interpretation.status -cne 'interpreted' -or
        $zstdView.admission.status -cne 'admitted' -or
        $zstdView.verification.status -cne 'complete' -or
        $zstdView.effect.status -cne 'not-requested' -or
        @($zstdView.members).Count -ne 1 -or
        $zstdView.members[0].path -cne 'mission/plan.txt' -or
        $zstdView.members[0].method -cne 'raw' -or
        $zstdView.members[0].uncomp_bytes -ne 25 -or
        $zstdReceipt.policy.id -cne 'sealr:policy/default/v8' -or
        $zstdReceipt.policy.digest.sha256 -cne 'd0cfdf4d40e3a88c8e80170494b23e91761802304265e41ce19cb616fa8a1c42' -or
        $zstdReceipt.identities.interpretation.id -cne 'sealr.profile.tar-zstd.ustar-portable.v1' -or
        $zstdReceipt.identities.interpretation.digest.sha256 -cne 'c7d2e708f2f5258eddfb99fbf13661bd2f671a2daa4a45bc1d9603d30d472ae7' -or
        $zstdReceipt.identities.layout.sealrTreeV9 -cne '8638eff6b2507614edc81eaccf4c3168e245febe0d1ee0eeb7651b018233fb63' -or
        $zstdReceipt.identities.content.sealrTreeV1 -cne 'bc8f6d6f7870aeab647cff08db25471a729bd2a41e095d49d6254c49afc34278') {
        throw 'packaged zstd-wrapped ustar inspect returned unexpected semantic evidence'
    }

    $zstdDefault = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @($zstdArchivePath) `
        -Role 'packaged zstd-wrapped ustar compatibility-default refusal'
    $zstdDefaultView = $zstdDefault.Stdout | ConvertFrom-Json
    $zstdDefaultReceipt = $zstdDefault.Stderr | ConvertFrom-Json
    if ($zstdDefault.ExitCode -ne 2 -or
        $zstdDefaultView.verdict -cne 'rejected' -or
        $zstdDefaultView.source.magic -cne 'unknown' -or
        $zstdDefaultView.policy.id -cne 'sealr:policy/default/v1' -or
        $zstdDefaultView.interpretation.status -cne 'unsupported' -or
        $zstdDefaultView.admission.status -cne 'not-evaluated' -or
        @($zstdDefaultView.members).Count -ne 0 -or
        $zstdDefaultReceipt.identities.interpretation.id -cne 'sealr.profile.zip.strict-ascii.v1' -or
        $zstdDefaultReceipt.identities.layout.status -cne 'unavailable' -or
        $zstdDefaultReceipt.identities.content.status -cne 'unavailable') {
        throw 'packaged compatibility default unexpectedly recognized zstd-wrapped ustar'
    }

    $zstdDestination = Join-Path $temporaryRoot 'zstd-ustar-output'
    $zstdMaterialize = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-zstd-ustar', $zstdArchivePath, '--dest', $zstdDestination) `
        -Role 'packaged zstd-wrapped ustar materialization'
    if ($zstdMaterialize.ExitCode -ne 0) {
        throw "packaged zstd-wrapped ustar materialization failed: $($zstdMaterialize.Stderr)"
    }
    $zstdMaterializedView = $zstdMaterialize.Stdout | ConvertFrom-Json
    $zstdMaterializedReceipt = $zstdMaterialize.Stderr | ConvertFrom-Json
    $zstdFiles = @(Get-ChildItem -LiteralPath $zstdDestination -Recurse -Force -File | ForEach-Object {
            [System.IO.Path]::GetRelativePath($zstdDestination, $_.FullName).Replace('\', '/')
        })
    $zstdDirectories = @(Get-ChildItem -LiteralPath $zstdDestination -Recurse -Force -Directory | ForEach-Object {
            [System.IO.Path]::GetRelativePath($zstdDestination, $_.FullName).Replace('\', '/')
        })
    $leakedStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
    if (-not $zstdMaterializedView.wrote -or
        $zstdMaterializedView.effect.status -cne 'committed' -or
        $zstdMaterializedReceipt.identities.layout.sealrTreeV9 -cne $zstdReceipt.identities.layout.sealrTreeV9 -or
        $zstdMaterializedReceipt.identities.content.sealrTreeV1 -cne $zstdReceipt.identities.content.sealrTreeV1 -or
        $zstdFiles.Count -ne 1 -or $zstdFiles[0] -cne 'mission/plan.txt' -or
        $zstdDirectories.Count -ne 1 -or $zstdDirectories[0] -cne 'mission' -or
        [System.IO.File]::ReadAllText((Join-Path $zstdDestination 'mission/plan.txt')) -cne 'verify twice, decode once' -or
        $leakedStages.Count -ne 0) {
        throw 'packaged zstd-wrapped ustar materialization did not preserve the effective admitted tree'
    }

    # XZ Utils v5.8.1 `xz -6 -T1` output for the same conformance derived TAR
    # holding mission/plan.txt with `verify twice, decode once`.
    $xzHex = 'fd377a585a000004e6d6b4460200210116000000742fe5a3e007ff00705d00369a4adff3ff417' +
        '3689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1897bcfa2a38633f7d28f' +
        'c607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59582a4d6308d2ffca92620af736cdb6f7b' +
        '1240ae87699d3cfb3eb7748f4ff4a5b315efe8cd37d00ec921496b86e87ef00018c0180100000853c38' +
        '66b1c467fb020000000004595a'
    $xzBytes = [System.Convert]::FromHexString($xzHex)
    if ($xzBytes.Length -ne 176) {
        throw "native-package xz-wrapped ustar fixture length changed: $($xzBytes.Length)"
    }
    $xzArchivePath = Join-Path $temporaryRoot 'portable-ustar.tar.xz'
    [System.IO.File]::WriteAllBytes($xzArchivePath, $xzBytes)
    $xzSourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $xzArchivePath).Hash.ToLowerInvariant()
    if ($xzSourceHash -cne '54f88a8a4b418364e2c3f7747d9a40aecee3624d0d0880727e674a9cbc60a8ca') {
        throw "native-package xz-wrapped ustar fixture identity changed: $xzSourceHash"
    }

    $xzInspect = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-xz-ustar', $xzArchivePath) `
        -Role 'packaged xz-wrapped ustar inspect'
    if ($xzInspect.ExitCode -ne 0) {
        throw "packaged xz-wrapped ustar inspect failed: $($xzInspect.Stderr)"
    }
    $xzView = $xzInspect.Stdout | ConvertFrom-Json
    $xzReceipt = $xzInspect.Stderr | ConvertFrom-Json
    if ($xzView.schema -cne 'sealr.view.v1' -or
        $xzReceipt.schema -cne 'sealr.receipt.v2' -or
        $xzView.source.magic -cne 'xz' -or
        $xzView.interpretation.status -cne 'interpreted' -or
        $xzView.admission.status -cne 'admitted' -or
        $xzView.verification.status -cne 'complete' -or
        $xzView.effect.status -cne 'not-requested' -or
        @($xzView.members).Count -ne 1 -or
        $xzView.members[0].path -cne 'mission/plan.txt' -or
        $xzView.members[0].method -cne 'raw' -or
        $xzView.members[0].uncomp_bytes -ne 25 -or
        $xzReceipt.policy.id -cne 'sealr:policy/default/v9' -or
        $xzReceipt.policy.digest.sha256 -cne 'c512895c09453f16c07ebeae94712099191b197ba9edaae384dba0fe7bb8b39e' -or
        $xzReceipt.identities.interpretation.id -cne 'sealr.profile.tar-xz.ustar-portable.v1' -or
        $xzReceipt.identities.interpretation.digest.sha256 -cne '16ec815ab3b2c3c5f877ec04e592d1dd1a6ec41f2c7d843dd7aa2bc6b50cfd05' -or
        $xzReceipt.identities.layout.sealrTreeV10 -cne '558d5f8e75966e1ab4b1892e71fcf871f9670f07b3e6ef47ae6e57b6a4e05f8d' -or
        $xzReceipt.identities.content.sealrTreeV1 -cne 'bc8f6d6f7870aeab647cff08db25471a729bd2a41e095d49d6254c49afc34278') {
        throw 'packaged xz-wrapped ustar inspect returned unexpected semantic evidence'
    }

    $xzDefault = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @($xzArchivePath) `
        -Role 'packaged xz-wrapped ustar compatibility-default refusal'
    $xzDefaultView = $xzDefault.Stdout | ConvertFrom-Json
    $xzDefaultReceipt = $xzDefault.Stderr | ConvertFrom-Json
    if ($xzDefault.ExitCode -ne 2 -or
        $xzDefaultView.verdict -cne 'rejected' -or
        $xzDefaultView.source.magic -cne 'unknown' -or
        $xzDefaultView.policy.id -cne 'sealr:policy/default/v1' -or
        $xzDefaultView.interpretation.status -cne 'unsupported' -or
        $xzDefaultView.admission.status -cne 'not-evaluated' -or
        @($xzDefaultView.members).Count -ne 0 -or
        $xzDefaultReceipt.identities.interpretation.id -cne 'sealr.profile.zip.strict-ascii.v1' -or
        $xzDefaultReceipt.identities.layout.status -cne 'unavailable' -or
        $xzDefaultReceipt.identities.content.status -cne 'unavailable') {
        throw 'packaged compatibility default unexpectedly recognized xz-wrapped ustar'
    }

    $xzDestination = Join-Path $temporaryRoot 'xz-ustar-output'
    $xzMaterialize = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-xz-ustar', $xzArchivePath, '--dest', $xzDestination) `
        -Role 'packaged xz-wrapped ustar materialization'
    if ($xzMaterialize.ExitCode -ne 0) {
        throw "packaged xz-wrapped ustar materialization failed: $($xzMaterialize.Stderr)"
    }
    $xzMaterializedView = $xzMaterialize.Stdout | ConvertFrom-Json
    $xzMaterializedReceipt = $xzMaterialize.Stderr | ConvertFrom-Json
    $xzFiles = @(Get-ChildItem -LiteralPath $xzDestination -Recurse -Force -File | ForEach-Object {
            [System.IO.Path]::GetRelativePath($xzDestination, $_.FullName).Replace('\', '/')
        })
    $xzDirectories = @(Get-ChildItem -LiteralPath $xzDestination -Recurse -Force -Directory | ForEach-Object {
            [System.IO.Path]::GetRelativePath($xzDestination, $_.FullName).Replace('\', '/')
        })
    $leakedStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
    if (-not $xzMaterializedView.wrote -or
        $xzMaterializedView.effect.status -cne 'committed' -or
        $xzMaterializedReceipt.identities.layout.sealrTreeV10 -cne $xzReceipt.identities.layout.sealrTreeV10 -or
        $xzMaterializedReceipt.identities.content.sealrTreeV1 -cne $xzReceipt.identities.content.sealrTreeV1 -or
        $xzFiles.Count -ne 1 -or $xzFiles[0] -cne 'mission/plan.txt' -or
        $xzDirectories.Count -ne 1 -or $xzDirectories[0] -cne 'mission' -or
        [System.IO.File]::ReadAllText((Join-Path $xzDestination 'mission/plan.txt')) -cne 'verify twice, decode once' -or
        $leakedStages.Count -ne 0) {
        throw 'packaged xz-wrapped ustar materialization did not preserve the effective admitted tree'
    }

    # CPython 3.12.10 `bz2.compress(tar, 9)` output (bundled libbz2 1.0.8;
    # byte-identical to `bzip2 -9`) for the same conformance derived TAR
    # holding mission/plan.txt with `verify twice, decode once`.
    $bzip2Hex = '425a68393141592653597b1dc2a70000447b91ca0000404005ff0040006f27dfe00400004000' +
        '08200074226a64f51a64d0340640c4d064a0d341a680034d001e6587e2308c005913503e46a288084216' +
        '2fc4d83544cc801bd752180f90d0c026e224716664838d467b58fbfac1cf118147687b09c160a4ad2080' +
        'f498e75a99561f215194f509f0637e2ee48a70a120f63b854e'
    $bzip2Bytes = [System.Convert]::FromHexString($bzip2Hex)
    if ($bzip2Bytes.Length -ne 147) {
        throw "native-package bzip2-wrapped ustar fixture length changed: $($bzip2Bytes.Length)"
    }
    $bzip2ArchivePath = Join-Path $temporaryRoot 'portable-ustar.tar.bz2'
    [System.IO.File]::WriteAllBytes($bzip2ArchivePath, $bzip2Bytes)
    $bzip2SourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $bzip2ArchivePath).Hash.ToLowerInvariant()
    if ($bzip2SourceHash -cne '6cf9b27f72fca2d3c665b7012e2ee8cfc24e7f1b7d5cc0f3aa8c239812ea5e87') {
        throw "native-package bzip2-wrapped ustar fixture identity changed: $bzip2SourceHash"
    }

    $bzip2Inspect = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-bzip2-ustar', $bzip2ArchivePath) `
        -Role 'packaged bzip2-wrapped ustar inspect'
    if ($bzip2Inspect.ExitCode -ne 0) {
        throw "packaged bzip2-wrapped ustar inspect failed: $($bzip2Inspect.Stderr)"
    }
    $bzip2View = $bzip2Inspect.Stdout | ConvertFrom-Json
    $bzip2Receipt = $bzip2Inspect.Stderr | ConvertFrom-Json
    if ($bzip2View.schema -cne 'sealr.view.v1' -or
        $bzip2Receipt.schema -cne 'sealr.receipt.v2' -or
        $bzip2View.source.magic -cne 'bz2' -or
        $bzip2View.interpretation.status -cne 'interpreted' -or
        $bzip2View.admission.status -cne 'admitted' -or
        $bzip2View.verification.status -cne 'complete' -or
        $bzip2View.effect.status -cne 'not-requested' -or
        @($bzip2View.members).Count -ne 1 -or
        $bzip2View.members[0].path -cne 'mission/plan.txt' -or
        $bzip2View.members[0].method -cne 'raw' -or
        $bzip2View.members[0].uncomp_bytes -ne 25 -or
        $bzip2Receipt.policy.id -cne 'sealr:policy/default/v10' -or
        $bzip2Receipt.policy.digest.sha256 -cne 'eada8150e14c0f05dcb25b6c9a90b87d3821fbb5f754192aceaea6d942e9f374' -or
        $bzip2Receipt.identities.interpretation.id -cne 'sealr.profile.tar-bzip2.ustar-portable.v1' -or
        $bzip2Receipt.identities.interpretation.digest.sha256 -cne 'f6711c0c98cff6e3a2c6b266d159413ef891c202b4898b4e1665081dce0f29ee' -or
        $bzip2Receipt.identities.layout.sealrTreeV11 -cne '6adec7927d150611af780ea135964e96cf1581d42a407f637ee752b63ac3894e' -or
        $bzip2Receipt.identities.content.sealrTreeV1 -cne 'bc8f6d6f7870aeab647cff08db25471a729bd2a41e095d49d6254c49afc34278') {
        throw 'packaged bzip2-wrapped ustar inspect returned unexpected semantic evidence'
    }

    $bzip2Default = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @($bzip2ArchivePath) `
        -Role 'packaged bzip2-wrapped ustar compatibility-default refusal'
    $bzip2DefaultView = $bzip2Default.Stdout | ConvertFrom-Json
    $bzip2DefaultReceipt = $bzip2Default.Stderr | ConvertFrom-Json
    if ($bzip2Default.ExitCode -ne 2 -or
        $bzip2DefaultView.verdict -cne 'rejected' -or
        $bzip2DefaultView.source.magic -cne 'unknown' -or
        $bzip2DefaultView.policy.id -cne 'sealr:policy/default/v1' -or
        $bzip2DefaultView.interpretation.status -cne 'unsupported' -or
        $bzip2DefaultView.admission.status -cne 'not-evaluated' -or
        @($bzip2DefaultView.members).Count -ne 0 -or
        $bzip2DefaultReceipt.identities.interpretation.id -cne 'sealr.profile.zip.strict-ascii.v1' -or
        $bzip2DefaultReceipt.identities.layout.status -cne 'unavailable' -or
        $bzip2DefaultReceipt.identities.content.status -cne 'unavailable') {
        throw 'packaged compatibility default unexpectedly recognized bzip2-wrapped ustar'
    }

    $bzip2Destination = Join-Path $temporaryRoot 'bzip2-ustar-output'
    $bzip2Materialize = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', 'tar-bzip2-ustar', $bzip2ArchivePath, '--dest', $bzip2Destination) `
        -Role 'packaged bzip2-wrapped ustar materialization'
    if ($bzip2Materialize.ExitCode -ne 0) {
        throw "packaged bzip2-wrapped ustar materialization failed: $($bzip2Materialize.Stderr)"
    }
    $bzip2MaterializedView = $bzip2Materialize.Stdout | ConvertFrom-Json
    $bzip2MaterializedReceipt = $bzip2Materialize.Stderr | ConvertFrom-Json
    $bzip2Files = @(Get-ChildItem -LiteralPath $bzip2Destination -Recurse -Force -File | ForEach-Object {
            [System.IO.Path]::GetRelativePath($bzip2Destination, $_.FullName).Replace('\', '/')
        })
    $bzip2Directories = @(Get-ChildItem -LiteralPath $bzip2Destination -Recurse -Force -Directory | ForEach-Object {
            [System.IO.Path]::GetRelativePath($bzip2Destination, $_.FullName).Replace('\', '/')
        })
    $leakedStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
    if (-not $bzip2MaterializedView.wrote -or
        $bzip2MaterializedView.effect.status -cne 'committed' -or
        $bzip2MaterializedReceipt.identities.layout.sealrTreeV11 -cne $bzip2Receipt.identities.layout.sealrTreeV11 -or
        $bzip2MaterializedReceipt.identities.content.sealrTreeV1 -cne $bzip2Receipt.identities.content.sealrTreeV1 -or
        $bzip2Files.Count -ne 1 -or $bzip2Files[0] -cne 'mission/plan.txt' -or
        $bzip2Directories.Count -ne 1 -or $bzip2Directories[0] -cne 'mission' -or
        [System.IO.File]::ReadAllText((Join-Path $bzip2Destination 'mission/plan.txt')) -cne 'verify twice, decode once' -or
        $leakedStages.Count -ne 0) {
        throw 'packaged bzip2-wrapped ustar materialization did not preserve the effective admitted tree'
    }

    # 7-Zip 26.02 `7z a -m0=Copy -mhc=off` output holding exactly
    # mission/plan.txt with `verify twice, decode once`: one Copy folder and
    # a raw next header.
    $sevenzHex = '377abcaf271c000435c12a4919000000000000005a00000000000000eaaeb7e6766572696679' +
        '2074776963652c206465636f6465206f6e63650104060001091900070b01000101000c1900080a0103b4' +
        '4165000005011123006d0069007300730069006f006e002f0070006c0061006e002e0074007800740000' +
        '001900140a01000000d4bda237dd0115060100200000000000'
    $sevenzBytes = [System.Convert]::FromHexString($sevenzHex)
    if ($sevenzBytes.Length -ne 147) {
        throw "native-package 7z Copy fixture length changed: $($sevenzBytes.Length)"
    }
    $sevenzArchivePath = Join-Path $temporaryRoot 'mission.7z'
    [System.IO.File]::WriteAllBytes($sevenzArchivePath, $sevenzBytes)
    $sevenzSourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sevenzArchivePath).Hash.ToLowerInvariant()
    if ($sevenzSourceHash -cne 'ebefe20d0dfd944e29a0987e4b182c80595e2a7ec4d1efe3217123e22259c289') {
        throw "native-package 7z Copy fixture identity changed: $sevenzSourceHash"
    }

    $sevenzInspect = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', '7z-copy', $sevenzArchivePath) `
        -Role 'packaged 7z Copy inspect'
    if ($sevenzInspect.ExitCode -ne 0) {
        throw "packaged 7z Copy inspect failed: $($sevenzInspect.Stderr)"
    }
    $sevenzView = $sevenzInspect.Stdout | ConvertFrom-Json
    $sevenzReceipt = $sevenzInspect.Stderr | ConvertFrom-Json
    if ($sevenzView.schema -cne 'sealr.view.v1' -or
        $sevenzReceipt.schema -cne 'sealr.receipt.v2' -or
        $sevenzView.source.magic -cne '7z' -or
        $sevenzView.interpretation.status -cne 'interpreted' -or
        $sevenzView.admission.status -cne 'admitted' -or
        $sevenzView.verification.status -cne 'complete' -or
        $sevenzView.effect.status -cne 'not-requested' -or
        @($sevenzView.members).Count -ne 1 -or
        $sevenzView.members[0].path -cne 'mission/plan.txt' -or
        $sevenzView.members[0].method -cne 'copy' -or
        $sevenzView.members[0].uncomp_bytes -ne 25 -or
        $sevenzReceipt.policy.id -cne 'sealr:policy/default/v11' -or
        $sevenzReceipt.policy.digest.sha256 -cne 'afa0aeb04ceca00706b31dfd250216a87f2af0ada6e98d3815873de0d15172fc' -or
        $sevenzReceipt.identities.interpretation.id -cne 'sealr.profile.7z.copy-portable.v1' -or
        $sevenzReceipt.identities.interpretation.digest.sha256 -cne '7b6604ad59b5aecf9ebdfa42d7d48d3df663813798992741dd6d74ea56f60b75' -or
        $sevenzReceipt.identities.layout.sealrTreeV12 -cne 'df4c1271279959b9fbd90e56078913779e134f52a69c52d959878ad76bff9a9d' -or
        $sevenzReceipt.identities.content.sealrTreeV1 -cne 'bc8f6d6f7870aeab647cff08db25471a729bd2a41e095d49d6254c49afc34278') {
        throw 'packaged 7z Copy inspect returned unexpected semantic evidence'
    }

    $sevenzDefault = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @($sevenzArchivePath) `
        -Role 'packaged 7z Copy compatibility-default refusal'
    $sevenzDefaultView = $sevenzDefault.Stdout | ConvertFrom-Json
    $sevenzDefaultReceipt = $sevenzDefault.Stderr | ConvertFrom-Json
    if ($sevenzDefault.ExitCode -ne 2 -or
        $sevenzDefaultView.verdict -cne 'rejected' -or
        $sevenzDefaultView.source.magic -cne 'unknown' -or
        $sevenzDefaultView.policy.id -cne 'sealr:policy/default/v1' -or
        $sevenzDefaultView.interpretation.status -cne 'unsupported' -or
        $sevenzDefaultView.admission.status -cne 'not-evaluated' -or
        @($sevenzDefaultView.members).Count -ne 0 -or
        $sevenzDefaultReceipt.identities.interpretation.id -cne 'sealr.profile.zip.strict-ascii.v1' -or
        $sevenzDefaultReceipt.identities.layout.status -cne 'unavailable' -or
        $sevenzDefaultReceipt.identities.content.status -cne 'unavailable') {
        throw 'packaged compatibility default unexpectedly recognized the 7z container'
    }

    $sevenzDestination = Join-Path $temporaryRoot 'sevenz-copy-output'
    $sevenzMaterialize = Invoke-Captured `
        -FilePath $packagedCli `
        -Arguments @('--format', '7z-copy', $sevenzArchivePath, '--dest', $sevenzDestination) `
        -Role 'packaged 7z Copy materialization'
    if ($sevenzMaterialize.ExitCode -ne 0) {
        throw "packaged 7z Copy materialization failed: $($sevenzMaterialize.Stderr)"
    }
    $sevenzMaterializedView = $sevenzMaterialize.Stdout | ConvertFrom-Json
    $sevenzMaterializedReceipt = $sevenzMaterialize.Stderr | ConvertFrom-Json
    $sevenzFiles = @(Get-ChildItem -LiteralPath $sevenzDestination -Recurse -Force -File | ForEach-Object {
            [System.IO.Path]::GetRelativePath($sevenzDestination, $_.FullName).Replace('\', '/')
        })
    $sevenzDirectories = @(Get-ChildItem -LiteralPath $sevenzDestination -Recurse -Force -Directory | ForEach-Object {
            [System.IO.Path]::GetRelativePath($sevenzDestination, $_.FullName).Replace('\', '/')
        })
    $leakedStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
    if (-not $sevenzMaterializedView.wrote -or
        $sevenzMaterializedView.effect.status -cne 'committed' -or
        $sevenzMaterializedReceipt.identities.layout.sealrTreeV12 -cne $sevenzReceipt.identities.layout.sealrTreeV12 -or
        $sevenzMaterializedReceipt.identities.content.sealrTreeV1 -cne $sevenzReceipt.identities.content.sealrTreeV1 -or
        $sevenzFiles.Count -ne 1 -or $sevenzFiles[0] -cne 'mission/plan.txt' -or
        $sevenzDirectories.Count -ne 1 -or $sevenzDirectories[0] -cne 'mission' -or
        [System.IO.File]::ReadAllText((Join-Path $sevenzDestination 'mission/plan.txt')) -cne 'verify twice, decode once' -or
        $leakedStages.Count -ne 0) {
        throw 'packaged 7z Copy materialization did not preserve the effective admitted tree'
    }

    if ($TargetTriple -ne $windowsTarget) {
        foreach ($relative in $expectedFiles) {
            $expectedMode = if ($relative -in @(
                    $binaryName,
                    $identityVerifierName,
                    'libexec/sealr/sealr-worker'
                )) { '755' } else { '644' }
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
        $gnuWorkerDestination = Join-Path $temporaryRoot 'old-gnu-longname-worker-output'
        $gnuWorker = Invoke-Captured `
            -FilePath $packagedCli `
            -Arguments @(
                '--format', 'tar-gnu-longname',
                '--worker-manifest', $manifestPath,
                $gnuArchivePath,
                '--dest', $gnuWorkerDestination
            ) `
            -Role 'packaged old-GNU long-name worker refusal'
        $workerStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
        if ($gnuWorker.ExitCode -ne 1 -or
            -not [string]::IsNullOrEmpty($gnuWorker.Stdout) -or
            $gnuWorker.Stderr -notmatch 'isolation unavailable' -or
            $gnuWorker.Stderr -notmatch 'GNU long-name TAR' -or
            (Test-Path -LiteralPath $gnuWorkerDestination) -or
            $workerStages.Count -ne 0) {
            throw 'packaged old-GNU long-name worker selection did not fail closed without fallback'
        }
        $gzipPaxWorkerDestination = Join-Path $temporaryRoot 'gzip-pax-worker-output'
        $gzipPaxWorker = Invoke-Captured `
            -FilePath $packagedCli `
            -Arguments @(
                '--format', 'tar-gzip-pax',
                '--worker-manifest', $manifestPath,
                $gzipPaxArchivePath,
                '--dest', $gzipPaxWorkerDestination
            ) `
            -Role 'packaged gzip-wrapped PAX worker refusal'
        $workerStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
        if ($gzipPaxWorker.ExitCode -ne 1 -or
            -not [string]::IsNullOrEmpty($gzipPaxWorker.Stdout) -or
            $gzipPaxWorker.Stderr -notmatch 'isolation unavailable' -or
            $gzipPaxWorker.Stderr -notmatch 'semantic-record v3' -or
            (Test-Path -LiteralPath $gzipPaxWorkerDestination) -or
            $workerStages.Count -ne 0) {
            throw 'packaged gzip-wrapped PAX worker selection did not fail closed without fallback'
        }
        $gzipGnuWorkerDestination = Join-Path $temporaryRoot 'gzip-gnu-longname-worker-output'
        $gzipGnuWorker = Invoke-Captured `
            -FilePath $packagedCli `
            -Arguments @(
                '--format', 'tar-gzip-gnu-longname',
                '--worker-manifest', $manifestPath,
                $gzipGnuArchivePath,
                '--dest', $gzipGnuWorkerDestination
            ) `
            -Role 'packaged gzip-wrapped GNU long-name worker refusal'
        $workerStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
        if ($gzipGnuWorker.ExitCode -ne 1 -or
            -not [string]::IsNullOrEmpty($gzipGnuWorker.Stdout) -or
            $gzipGnuWorker.Stderr -notmatch 'isolation unavailable' -or
            $gzipGnuWorker.Stderr -notmatch 'semantic-record v3' -or
            (Test-Path -LiteralPath $gzipGnuWorkerDestination) -or
            $workerStages.Count -ne 0) {
            throw 'packaged gzip-wrapped GNU long-name worker selection did not fail closed without fallback'
        }
        $zstdWorkerDestination = Join-Path $temporaryRoot 'zstd-ustar-worker-output'
        $zstdWorker = Invoke-Captured `
            -FilePath $packagedCli `
            -Arguments @(
                '--format', 'tar-zstd-ustar',
                '--worker-manifest', $manifestPath,
                $zstdArchivePath,
                '--dest', $zstdWorkerDestination
            ) `
            -Role 'packaged zstd-wrapped ustar worker refusal'
        $workerStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
        if ($zstdWorker.ExitCode -ne 1 -or
            -not [string]::IsNullOrEmpty($zstdWorker.Stdout) -or
            $zstdWorker.Stderr -notmatch 'isolation unavailable' -or
            $zstdWorker.Stderr -notmatch 'zstd-wrapped TAR' -or
            (Test-Path -LiteralPath $zstdWorkerDestination) -or
            $workerStages.Count -ne 0) {
            throw 'packaged zstd-wrapped ustar worker selection did not fail closed without fallback'
        }
        $xzWorkerDestination = Join-Path $temporaryRoot 'xz-ustar-worker-output'
        $xzWorker = Invoke-Captured `
            -FilePath $packagedCli `
            -Arguments @(
                '--format', 'tar-xz-ustar',
                '--worker-manifest', $manifestPath,
                $xzArchivePath,
                '--dest', $xzWorkerDestination
            ) `
            -Role 'packaged xz-wrapped ustar worker refusal'
        $workerStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
        if ($xzWorker.ExitCode -ne 1 -or
            -not [string]::IsNullOrEmpty($xzWorker.Stdout) -or
            $xzWorker.Stderr -notmatch 'isolation unavailable' -or
            $xzWorker.Stderr -notmatch 'xz-wrapped TAR' -or
            (Test-Path -LiteralPath $xzWorkerDestination) -or
            $workerStages.Count -ne 0) {
            throw 'packaged xz-wrapped ustar worker selection did not fail closed without fallback'
        }
        $bzip2WorkerDestination = Join-Path $temporaryRoot 'bzip2-ustar-worker-output'
        $bzip2Worker = Invoke-Captured `
            -FilePath $packagedCli `
            -Arguments @(
                '--format', 'tar-bzip2-ustar',
                '--worker-manifest', $manifestPath,
                $bzip2ArchivePath,
                '--dest', $bzip2WorkerDestination
            ) `
            -Role 'packaged bzip2-wrapped ustar worker refusal'
        $workerStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
        if ($bzip2Worker.ExitCode -ne 1 -or
            -not [string]::IsNullOrEmpty($bzip2Worker.Stdout) -or
            $bzip2Worker.Stderr -notmatch 'isolation unavailable' -or
            $bzip2Worker.Stderr -notmatch 'bzip2-wrapped TAR' -or
            (Test-Path -LiteralPath $bzip2WorkerDestination) -or
            $workerStages.Count -ne 0) {
            throw 'packaged bzip2-wrapped ustar worker selection did not fail closed without fallback'
        }
        $sevenzWorkerDestination = Join-Path $temporaryRoot 'sevenz-copy-worker-output'
        $sevenzWorker = Invoke-Captured `
            -FilePath $packagedCli `
            -Arguments @(
                '--format', '7z-copy',
                '--worker-manifest', $manifestPath,
                $sevenzArchivePath,
                '--dest', $sevenzWorkerDestination
            ) `
            -Role 'packaged 7z Copy worker refusal'
        $workerStages = @(Get-ChildItem -LiteralPath $temporaryRoot -Force -Directory -Filter '.sealr-stage-*')
        if ($sevenzWorker.ExitCode -ne 1 -or
            -not [string]::IsNullOrEmpty($sevenzWorker.Stdout) -or
            $sevenzWorker.Stderr -notmatch 'isolation unavailable' -or
            $sevenzWorker.Stderr -notmatch '7z container' -or
            (Test-Path -LiteralPath $sevenzWorkerDestination) -or
            $workerStages.Count -ne 0) {
            throw 'packaged 7z Copy worker selection did not fail closed without fallback'
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
