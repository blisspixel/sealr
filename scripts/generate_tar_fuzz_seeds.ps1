[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$expectedCorpus = [IO.Path]::Combine($workspace, 'fuzz', 'corpus', 'tar_ustar_portable_v1')
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
        $leaf -notmatch '^sealr-tar-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate TAR seeds outside an exact temporary corpus: $corpus"
    }
}
if ($corpus -cne $expectedCorpus -and
    [IO.Path]::GetDirectoryName($corpus) -cne $temporaryBase) {
    throw "refusing to generate TAR seeds outside an authorized corpus: $corpus"
}
[IO.Directory]::CreateDirectory($corpus) | Out-Null

function Write-Octal {
    param(
        [Parameter(Mandatory)][byte[]]$Header,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][int]$Length,
        [Parameter(Mandatory)][uint64]$Value
    )

    $digits = [Convert]::ToString([int64]$Value, 8)
    if ($digits.Length -gt $Length - 1) {
        throw "octal value $Value does not fit a $Length-byte field"
    }
    for ($index = 0; $index -lt $Length; $index++) {
        $Header[$Offset + $index] = [byte][char]'0'
    }
    $encoded = [Text.Encoding]::ASCII.GetBytes($digits)
    [Array]::Copy($encoded, 0, $Header, $Offset + $Length - 1 - $encoded.Length, $encoded.Length)
    $Header[$Offset + $Length - 1] = 0
}

function Set-Checksum {
    param([Parameter(Mandatory)][byte[]]$Header)

    for ($index = 148; $index -lt 156; $index++) {
        $Header[$index] = [byte][char]' '
    }
    [uint32]$checksum = 0
    foreach ($value in $Header) {
        $checksum += $value
    }
    $octal = [Convert]::ToString([int64]$checksum, 8).PadLeft(6, '0')
    $encoded = [Text.Encoding]::ASCII.GetBytes($octal)
    [Array]::Copy($encoded, 0, $Header, 148, 6)
    $Header[154] = 0
    $Header[155] = [byte][char]' '
}

function Set-ArchiveHeaderChecksum {
    param([Parameter(Mandatory)][byte[]]$Archive)

    if ($Archive.Length -lt 512) {
        throw 'archive is too short to carry a TAR header'
    }
    $header = [byte[]]::new(512)
    [Array]::Copy($Archive, $header, 512)
    Set-Checksum -Header $header
    [Array]::Copy($header, $Archive, 512)
}

function New-Header {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][uint64]$Size,
        [Parameter(Mandatory)][byte]$Typeflag
    )

    $header = [byte[]]::new(512)
    $nameBytes = [Text.Encoding]::UTF8.GetBytes($Name)
    if ($nameBytes.Length -gt 99) {
        throw "seed name is too long: $Name"
    }
    [Array]::Copy($nameBytes, 0, $header, 0, $nameBytes.Length)
    Write-Octal -Header $header -Offset 100 -Length 8 -Value 420
    Write-Octal -Header $header -Offset 108 -Length 8 -Value 0
    Write-Octal -Header $header -Offset 116 -Length 8 -Value 0
    Write-Octal -Header $header -Offset 124 -Length 12 -Value $Size
    Write-Octal -Header $header -Offset 136 -Length 12 -Value 1788000000
    $header[156] = $Typeflag
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes("ustar`0"), 0, $header, 257, 6)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('00'), 0, $header, 263, 2)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes("root`0"), 0, $header, 265, 5)
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes("root`0"), 0, $header, 297, 5)
    Write-Octal -Header $header -Offset 329 -Length 8 -Value 0
    Write-Octal -Header $header -Offset 337 -Length 8 -Value 0
    Set-Checksum -Header $header
    return ,$header
}

function New-Ustar {
    param([Parameter(Mandatory)][object[]]$Entries)

    $stream = [IO.MemoryStream]::new()
    try {
        foreach ($entry in $Entries) {
            [byte[]]$body = $entry.Body
            $header = New-Header -Name $entry.Name -Size $body.Length -Typeflag $entry.Typeflag
            $stream.Write($header)
            $stream.Write($body)
            $padding = (512 - ($body.Length % 512)) % 512
            if ($padding -ne 0) {
                $stream.Write([byte[]]::new($padding))
            }
        }
        $stream.Write([byte[]]::new(1024))
        return ,$stream.ToArray()
    } finally {
        $stream.Dispose()
    }
}

function Copy-Bytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $copy = [byte[]]::new($Bytes.Length)
    [Array]::Copy($Bytes, $copy, $Bytes.Length)
    return ,$copy
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

$empty = [byte[]]::new(1024)
$oneFile = New-Ustar @(
    [pscustomobject]@{
        Name = 'file.txt'
        Body = [Text.Encoding]::ASCII.GetBytes('mars')
        Typeflag = [byte][char]'0'
    }
)
$directoryFile = New-Ustar @(
    [pscustomobject]@{
        Name = 'mission/'
        Body = [byte[]]::new(0)
        Typeflag = [byte][char]'5'
    },
    [pscustomobject]@{
        Name = 'mission/plan.txt'
        Body = [Text.Encoding]::ASCII.GetBytes('verify')
        Typeflag = [byte][char]'0'
    }
)

Write-Seed -Name 'valid-empty-ustar' -Bytes $empty
Write-Seed -Name 'valid-one-file-ustar' -Bytes $oneFile
Write-Seed -Name 'valid-directory-file-ustar' -Bytes $directoryFile

$badChecksum = Copy-Bytes $oneFile
$badChecksum[100] = $badChecksum[100] -bxor 1
Write-Seed -Name 'bad-checksum' -Bytes $badChecksum

$unknownType = New-Ustar @(
    [pscustomobject]@{
        Name = 'unknown'
        Body = [byte[]]::new(0)
        Typeflag = [byte][char]'Z'
    }
)
Write-Seed -Name 'unknown-typeflag' -Bytes $unknownType

$pax = New-Ustar @(
    [pscustomobject]@{
        Name = 'pax'
        Body = [byte[]]::new(0)
        Typeflag = [byte][char]'x'
    }
)
Write-Seed -Name 'unsupported-pax-header' -Bytes $pax

$base256 = New-Ustar @(
    [pscustomobject]@{
        Name = 'base256'
        Body = [byte[]]::new(0)
        Typeflag = [byte][char]'0'
    }
)
$base256[124] = 0x80
Set-ArchiveHeaderChecksum -Archive $base256
Write-Seed -Name 'unsupported-base256-size' -Bytes $base256

$nonzeroPadding = Copy-Bytes $oneFile
$nonzeroPadding[516] = 1
Write-Seed -Name 'nonzero-member-padding' -Bytes $nonzeroPadding

$traversal = New-Ustar @(
    [pscustomobject]@{
        Name = '../escape'
        Body = [Text.Encoding]::ASCII.GetBytes('x')
        Typeflag = [byte][char]'0'
    }
)
Write-Seed -Name 'path-traversal' -Bytes $traversal

$duplicate = New-Ustar @(
    [pscustomobject]@{
        Name = 'duplicate'
        Body = [Text.Encoding]::ASCII.GetBytes('a')
        Typeflag = [byte][char]'0'
    },
    [pscustomobject]@{
        Name = 'duplicate'
        Body = [Text.Encoding]::ASCII.GetBytes('b')
        Typeflag = [byte][char]'0'
    }
)
Write-Seed -Name 'duplicate-path' -Bytes $duplicate

$topology = New-Ustar @(
    [pscustomobject]@{
        Name = 'ancestor'
        Body = [Text.Encoding]::ASCII.GetBytes('file')
        Typeflag = [byte][char]'0'
    },
    [pscustomobject]@{
        Name = 'ancestor/child'
        Body = [Text.Encoding]::ASCII.GetBytes('child')
        Typeflag = [byte][char]'0'
    }
)
Write-Seed -Name 'file-ancestor-conflict' -Bytes $topology

$maxOctal = New-Ustar @(
    [pscustomobject]@{
        Name = 'max-octal'
        Body = [byte[]]::new(0)
        Typeflag = [byte][char]'0'
    }
)
Write-Octal -Header $maxOctal -Offset 124 -Length 12 -Value 8589934591
Set-ArchiveHeaderChecksum -Archive $maxOctal
Write-Seed -Name 'max-octal-size-truncated' -Bytes $maxOctal

$producerManifest = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'crates/sealr/tests/conformance/tar-producers-v1.json'
) | ConvertFrom-Json
$producer = $producerManifest.fixtures | Where-Object { $_.id -ceq 'gnu-tar-1.35' }
if (@($producer).Count -ne 1) {
    throw 'producer manifest does not contain exactly one GNU tar 1.35 fixture'
}
$producerBytes = [byte[]]::new([int]$producer.len)
$previousEnd = 0
foreach ($span in $producer.spans) {
    $spanBytes = [Convert]::FromHexString([string]$span.hex)
    $end = [int]$span.offset + $spanBytes.Length
    if ([int]$span.offset -lt $previousEnd -or $end -gt $producerBytes.Length) {
        throw 'GNU producer fixture spans are not an ordered in-bounds sparse encoding'
    }
    [Array]::Copy($spanBytes, 0, $producerBytes, [int]$span.offset, $spanBytes.Length)
    $previousEnd = $end
}
Write-Seed -Name 'valid-gnu-tar-1-35' -Bytes $producerBytes

Write-Host 'Generated deterministic portable-ustar fuzz seeds.'
