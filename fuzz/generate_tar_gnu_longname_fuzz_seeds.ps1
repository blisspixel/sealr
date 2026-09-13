[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$fuzzRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$expectedCorpus = [IO.Path]::Combine($fuzzRoot, 'corpus', 'tar_gnu_longname_portable_v1')
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
        $leaf -notmatch '^sealr-tar-gnu-longname-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate GNU TAR seeds outside an exact temporary corpus: $corpus"
    }
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
    $encoded = [Text.Encoding]::ASCII.GetBytes(
        [Convert]::ToString([int64]$checksum, 8).PadLeft(6, '0')
    )
    [Array]::Copy($encoded, 0, $Header, 148, 6)
    $Header[154] = 0
    $Header[155] = [byte][char]' '
}

function New-Header {
    param(
        [Parameter(Mandatory)][byte[]]$Name,
        [Parameter(Mandatory)][uint64]$Size,
        [Parameter(Mandatory)][byte]$Typeflag
    )
    if ($Name.Length -eq 0 -or $Name.Length -gt 100) {
        throw 'header name length is outside 1 through 100 bytes'
    }
    $header = [byte[]]::new(512)
    [Array]::Copy($Name, 0, $header, 0, $Name.Length)
    Write-Octal -Header $header -Offset 100 -Length 8 -Value 420
    Write-Octal -Header $header -Offset 108 -Length 8 -Value 0
    Write-Octal -Header $header -Offset 116 -Length 8 -Value 0
    Write-Octal -Header $header -Offset 124 -Length 12 -Value $Size
    Write-Octal -Header $header -Offset 136 -Length 12 -Value 0
    $header[156] = $Typeflag
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes("ustar  `0"), 0, $header, 257, 8)
    Set-Checksum -Header $header
    return ,$header
}

function New-Entry {
    param(
        [Parameter(Mandatory)][byte[]]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Body,
        [Parameter(Mandatory)][byte]$Typeflag,
        [Nullable[uint64]]$HeaderSize
    )
    return [pscustomobject]@{
        Name = $Name
        Body = $Body
        Typeflag = $Typeflag
        HeaderSize = if ($null -eq $HeaderSize) { [uint64]$Body.Length } else { [uint64]$HeaderSize }
    }
}

function New-Archive {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries)
    $stream = [IO.MemoryStream]::new()
    try {
        foreach ($entry in $Entries) {
            [byte[]]$body = $entry.Body
            $stream.Write((New-Header -Name $entry.Name -Size $entry.HeaderSize -Typeflag $entry.Typeflag))
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

function New-LongPayload {
    param([Parameter(Mandatory)][string]$Path)
    [byte[]]$pathBytes = [Text.Encoding]::UTF8.GetBytes($Path)
    [byte[]]$payload = [byte[]]::new($pathBytes.Length + 1)
    [Array]::Copy($pathBytes, $payload, $pathBytes.Length)
    return ,$payload
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

$ascii = [Text.Encoding]::ASCII
$empty = New-Archive @()
$ordinary = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('plain.txt') -Body $ascii.GetBytes('mars') -Typeflag ([byte][char]'0'))
)
$longPath = ('g' * 110) + '.txt'
$longPayload = New-LongPayload $longPath
$gnuLong = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('././@LongLink') -Body $longPayload -Typeflag ([byte][char]'L')),
    (New-Entry -Name $ascii.GetBytes($longPath.Substring(0, 100)) -Body $ascii.GetBytes('gnu') -Typeflag ([byte][char]'0'))
)
$libarchiveLong = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('././@LongName') -Body $longPayload -Typeflag ([byte][char]'L')),
    (New-Entry -Name $ascii.GetBytes('libarchive-base') -Body $ascii.GetBytes('bsd') -Typeflag ([byte][char]'0'))
)
$shortPayload = New-LongPayload 'short.txt'
$shortOverride = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('producer-carrier') -Body $shortPayload -Typeflag ([byte][char]'L')),
    (New-Entry -Name $ascii.GetBytes('base') -Body $ascii.GetBytes('x') -Typeflag ([byte][char]'0'))
)
$twoPairs = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('././@LongLink') -Body (New-LongPayload 'first.txt') -Typeflag ([byte][char]'L')),
    (New-Entry -Name $ascii.GetBytes('first-base') -Body $ascii.GetBytes('1') -Typeflag ([byte][char]'0')),
    (New-Entry -Name $ascii.GetBytes('././@LongName') -Body (New-LongPayload 'second.txt') -Typeflag ([byte][char]'L')),
    (New-Entry -Name $ascii.GetBytes('second-base') -Body $ascii.GetBytes('2') -Typeflag ([byte][char]'0'))
)
$orphan = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('././@LongLink') -Body $shortPayload -Typeflag ([byte][char]'L'))
)
$chained = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('././@LongLink') -Body $shortPayload -Typeflag ([byte][char]'L')),
    (New-Entry -Name $ascii.GetBytes('././@LongName') -Body $shortPayload -Typeflag ([byte][char]'L'))
)
$missingNul = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('././@LongLink') -Body $ascii.GetBytes('missing.txt') -Typeflag ([byte][char]'L')),
    (New-Entry -Name $ascii.GetBytes('base') -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'0'))
)
[byte[]]$embeddedPayload = $ascii.GetBytes("a`0b`0")
$embeddedNul = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('././@LongLink') -Body $embeddedPayload -Typeflag ([byte][char]'L')),
    (New-Entry -Name $ascii.GetBytes('base') -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'0'))
)
$overCap = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('././@LongLink') -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'L') -HeaderSize 8193)
)
$nonzeroPadding = [byte[]]$shortOverride.Clone()
$nonzeroPadding[512 + $shortPayload.Length] = 1
$mixedPaxGnu = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('PaxHeaders/size') -Body ([byte[]]::new(2048)) -Typeflag ([byte][char]'x')),
    (New-Entry -Name $ascii.GetBytes('././@LongLink') -Body $shortPayload -Typeflag ([byte][char]'L')),
    (New-Entry -Name $ascii.GetBytes('file-a') -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'0')),
    (New-Entry -Name $ascii.GetBytes('file-b') -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'0'))
)
$longLinkK = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('././@LongLink') -Body $shortPayload -Typeflag ([byte][char]'K'))
)
$sparse = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('sparse') -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'S'))
)
$base256 = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('base256') -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'0'))
)
$base256[124] = 0x80
$base256Header = [byte[]]::new(512)
[Array]::Copy($base256, 0, $base256Header, 0, 512)
Set-Checksum -Header $base256Header
[Array]::Copy($base256Header, 0, $base256, 0, 512)

Write-Seed -Name 'invalid-base256-size' -Bytes $base256
Write-Seed -Name 'invalid-chained-carrier' -Bytes $chained
Write-Seed -Name 'invalid-embedded-nul' -Bytes $embeddedNul
Write-Seed -Name 'invalid-missing-final-nul' -Bytes $missingNul
Write-Seed -Name 'invalid-nonzero-carrier-padding' -Bytes $nonzeroPadding
Write-Seed -Name 'invalid-orphan-carrier' -Bytes $orphan
Write-Seed -Name 'invalid-oversized-carrier' -Bytes $overCap
Write-Seed -Name 'unsupported-cve-2026-53655-pax-gnu-state' -Bytes $mixedPaxGnu
Write-Seed -Name 'unsupported-long-link-k' -Bytes $longLinkK
Write-Seed -Name 'unsupported-sparse' -Bytes $sparse
Write-Seed -Name 'valid-empty-oldgnu' -Bytes $empty
Write-Seed -Name 'valid-gnu-longlink' -Bytes $gnuLong
Write-Seed -Name 'valid-libarchive-longname' -Bytes $libarchiveLong
Write-Seed -Name 'valid-ordinary-oldgnu' -Bytes $ordinary
Write-Seed -Name 'valid-short-redundant-carrier' -Bytes $shortOverride
Write-Seed -Name 'valid-two-carrier-pairs' -Bytes $twoPairs

Write-Host 'Generated deterministic old-GNU long-name fuzz seeds.'
