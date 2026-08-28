[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$fuzzRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$expectedCorpus = [IO.Path]::Combine(
    $fuzzRoot,
    'corpus',
    'zip64_strict_ascii_v1'
)
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
)
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $corpus = $expectedCorpus
} else {
    $corpus = [IO.Path]::GetFullPath($OutputDirectory)
    $leaf = [IO.Path]::GetFileName($corpus)
    if ([IO.Path]::GetDirectoryName($corpus) -cne $temporaryBase -or
        $leaf -notmatch '^sealr-zip64-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate ZIP64 seeds outside an exact temporary corpus: $corpus"
    }
}
[IO.Directory]::CreateDirectory($corpus) | Out-Null

function Add-UInt16LittleEndian {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[byte]]$Bytes,
        [Parameter(Mandatory)][uint16]$Value
    )

    $Bytes.Add([byte]($Value -band 0xff))
    $Bytes.Add([byte](($Value -shr 8) -band 0xff))
}

function Add-UInt32LittleEndian {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[byte]]$Bytes,
        [Parameter(Mandatory)][uint32]$Value
    )

    for ($shift = 0; $shift -lt 32; $shift += 8) {
        $Bytes.Add([byte](($Value -shr $shift) -band 0xff))
    }
}

function Add-UInt64LittleEndian {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[byte]]$Bytes,
        [Parameter(Mandatory)][uint64]$Value
    )

    for ($shift = 0; $shift -lt 64; $shift += 8) {
        $Bytes.Add([byte](($Value -shr $shift) -band 0xff))
    }
}

function Add-Zip64Extra {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[byte]]$Bytes,
        [Parameter(Mandatory)][uint64]$UncompressedSize,
        [Parameter(Mandatory)][uint64]$CompressedSize
    )

    Add-UInt16LittleEndian -Bytes $Bytes -Value 1
    Add-UInt16LittleEndian -Bytes $Bytes -Value 16
    Add-UInt64LittleEndian -Bytes $Bytes -Value $UncompressedSize
    Add-UInt64LittleEndian -Bytes $Bytes -Value $CompressedSize
}

function Copy-Bytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $copy = [byte[]]::new($Bytes.Length)
    [Array]::Copy($Bytes, $copy, $Bytes.Length)
    return ,$copy
}

function Get-Prefix {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Length
    )

    $prefix = [byte[]]::new($Length)
    [Array]::Copy($Bytes, $prefix, $Length)
    return ,$prefix
}

function New-StreamingZip64 {
    param(
        [Parameter(Mandatory)][ValidateSet('CpythonZeros', 'ZipRsMaxima')][string]$Shape,
        [bool]$SignedDescriptor = $true
    )

    $name = [byte][char]'a'
    $payload = [byte][char]'x'
    [uint32]$crc = 2363233923
    [uint64]$localValue = if ($Shape -ceq 'CpythonZeros') { 0 } else { [uint64]::MaxValue }
    [uint32]$localLegacy = if ($Shape -ceq 'CpythonZeros') { [uint32]::MaxValue } else { 0 }

    $local = [Collections.Generic.List[byte]]::new()
    Add-UInt32LittleEndian -Bytes $local -Value 0x04034b50
    Add-UInt16LittleEndian -Bytes $local -Value 45
    Add-UInt16LittleEndian -Bytes $local -Value 8
    Add-UInt16LittleEndian -Bytes $local -Value 0
    Add-UInt16LittleEndian -Bytes $local -Value 0
    Add-UInt16LittleEndian -Bytes $local -Value 0
    Add-UInt32LittleEndian -Bytes $local -Value 0
    Add-UInt32LittleEndian -Bytes $local -Value $localLegacy
    Add-UInt32LittleEndian -Bytes $local -Value $localLegacy
    Add-UInt16LittleEndian -Bytes $local -Value 1
    Add-UInt16LittleEndian -Bytes $local -Value 20
    $local.Add($name)
    Add-Zip64Extra -Bytes $local -UncompressedSize $localValue -CompressedSize $localValue
    $local.Add($payload)
    if ($SignedDescriptor) {
        Add-UInt32LittleEndian -Bytes $local -Value 0x08074b50
    }
    Add-UInt32LittleEndian -Bytes $local -Value $crc
    Add-UInt64LittleEndian -Bytes $local -Value 1
    Add-UInt64LittleEndian -Bytes $local -Value 1

    $central = [Collections.Generic.List[byte]]::new()
    Add-UInt32LittleEndian -Bytes $central -Value 0x02014b50
    Add-UInt16LittleEndian -Bytes $central -Value 45
    Add-UInt16LittleEndian -Bytes $central -Value 45
    Add-UInt16LittleEndian -Bytes $central -Value 8
    Add-UInt16LittleEndian -Bytes $central -Value 0
    Add-UInt16LittleEndian -Bytes $central -Value 0
    Add-UInt16LittleEndian -Bytes $central -Value 0
    Add-UInt32LittleEndian -Bytes $central -Value $crc
    Add-UInt32LittleEndian -Bytes $central -Value ([uint32]::MaxValue)
    Add-UInt32LittleEndian -Bytes $central -Value ([uint32]::MaxValue)
    Add-UInt16LittleEndian -Bytes $central -Value 1
    Add-UInt16LittleEndian -Bytes $central -Value 20
    Add-UInt16LittleEndian -Bytes $central -Value 0
    Add-UInt16LittleEndian -Bytes $central -Value 0
    Add-UInt16LittleEndian -Bytes $central -Value 0
    Add-UInt32LittleEndian -Bytes $central -Value 0
    Add-UInt32LittleEndian -Bytes $central -Value 0
    $central.Add($name)
    Add-Zip64Extra -Bytes $central -UncompressedSize 1 -CompressedSize 1

    $archive = [Collections.Generic.List[byte]]::new()
    $archive.AddRange($local)
    [uint32]$centralOffset = $local.Count
    $archive.AddRange($central)
    Add-UInt32LittleEndian -Bytes $archive -Value 0x06054b50
    Add-UInt16LittleEndian -Bytes $archive -Value 0
    Add-UInt16LittleEndian -Bytes $archive -Value 0
    Add-UInt16LittleEndian -Bytes $archive -Value 1
    Add-UInt16LittleEndian -Bytes $archive -Value 1
    Add-UInt32LittleEndian -Bytes $archive -Value ([uint32]$central.Count)
    Add-UInt32LittleEndian -Bytes $archive -Value $centralOffset
    Add-UInt16LittleEndian -Bytes $archive -Value 0
    return ,$archive.ToArray()
}

function New-EmptyGlobalZip64 {
    $archive = [Collections.Generic.List[byte]]::new()
    Add-UInt32LittleEndian -Bytes $archive -Value 0x06064b50
    Add-UInt64LittleEndian -Bytes $archive -Value 44
    Add-UInt16LittleEndian -Bytes $archive -Value 45
    Add-UInt16LittleEndian -Bytes $archive -Value 45
    Add-UInt32LittleEndian -Bytes $archive -Value 0
    Add-UInt32LittleEndian -Bytes $archive -Value 0
    Add-UInt64LittleEndian -Bytes $archive -Value 0
    Add-UInt64LittleEndian -Bytes $archive -Value 0
    Add-UInt64LittleEndian -Bytes $archive -Value 0
    Add-UInt64LittleEndian -Bytes $archive -Value 0
    Add-UInt32LittleEndian -Bytes $archive -Value 0x07064b50
    Add-UInt32LittleEndian -Bytes $archive -Value 0
    Add-UInt64LittleEndian -Bytes $archive -Value 0
    Add-UInt32LittleEndian -Bytes $archive -Value 1
    Add-UInt32LittleEndian -Bytes $archive -Value 0x06054b50
    Add-UInt16LittleEndian -Bytes $archive -Value 0
    Add-UInt16LittleEndian -Bytes $archive -Value 0
    Add-UInt16LittleEndian -Bytes $archive -Value 0
    Add-UInt16LittleEndian -Bytes $archive -Value 0
    Add-UInt32LittleEndian -Bytes $archive -Value ([uint32]::MaxValue)
    Add-UInt32LittleEndian -Bytes $archive -Value 0
    Add-UInt16LittleEndian -Bytes $archive -Value 0
    return ,$archive.ToArray()
}

function Write-Seed {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][byte[]]$Bytes
    )

    if ($Name -notmatch '^[a-z0-9-]+$') {
        throw "invalid seed name: $Name"
    }
    [IO.File]::WriteAllBytes((Join-Path $corpus $Name), $Bytes)
}

$cpythonSeek = [Convert]::FromHexString((
    '504b03042d0000000800000021000b5704bbffffffffffffffff01001400' +
    '6101001000100000000000000005000000000000007374440500504b0102' +
    '2d002d0000000800000021000b5704bb0500000010000000010000000000' +
    '00000000000080010000000061504b050600000000010001002f00000038' +
    '0000000000'
))
$cpythonStreaming = New-StreamingZip64 -Shape CpythonZeros
$zipRsStreaming = New-StreamingZip64 -Shape ZipRsMaxima
$emptyGlobal = New-EmptyGlobalZip64

Write-Seed -Name 'valid-cpython-forced-seek' -Bytes $cpythonSeek
Write-Seed -Name 'valid-cpython-streaming-zeros' -Bytes $cpythonStreaming
Write-Seed -Name 'valid-zip-rs-streaming-maxima' -Bytes $zipRsStreaming
Write-Seed -Name 'valid-empty-global-zip64' -Bytes $emptyGlobal

$extensibleSector = Copy-Bytes $emptyGlobal
$extensibleSector[4] = 45
Write-Seed -Name 'invalid-zip64-eocd-extensible-sector' -Bytes $extensibleSector

$locatorOffset = Copy-Bytes $emptyGlobal
$locatorOffset[64] = 1
Write-Seed -Name 'invalid-zip64-locator-offset' -Bytes $locatorOffset

$unsignedDescriptor = New-StreamingZip64 -Shape ZipRsMaxima -SignedDescriptor $false
Write-Seed -Name 'invalid-unsigned-zip64-descriptor' -Bytes $unsignedDescriptor

$cpythonValues = Copy-Bytes $cpythonStreaming
$cpythonValues[35] = 1
Write-Seed -Name 'invalid-cpython-placeholder-values' -Bytes $cpythonValues

$zipRsValues = Copy-Bytes $zipRsStreaming
$zipRsValues[35] = 0xfe
Write-Seed -Name 'invalid-zip-rs-placeholder-values' -Bytes $zipRsValues

$trailing = [byte[]]::new($cpythonSeek.Length + 1)
[Array]::Copy($cpythonSeek, $trailing, $cpythonSeek.Length)
$trailing[$cpythonSeek.Length] = 0x7f
Write-Seed -Name 'invalid-trailing-byte' -Bytes $trailing

Write-Seed -Name 'invalid-truncated-central-directory' -Bytes (
    Get-Prefix -Bytes $cpythonSeek -Length ($cpythonSeek.Length - 10)
)
Write-Seed -Name 'unsupported-plain-zip32' -Bytes (
    [Convert]::FromHexString('504b0506000000000000000000000000000000000000')
)
Write-Seed -Name 'raw-short' -Bytes ([Text.Encoding]::ASCII.GetBytes('PK'))

Write-Host 'Generated deterministic strict ZIP64 fuzz seeds.'
