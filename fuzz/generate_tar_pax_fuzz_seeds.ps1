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
    'tar_pax_portable_v1'
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
        $leaf -notmatch '^sealr-tar-pax-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate TAR PAX seeds outside an exact temporary corpus: $corpus"
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
    $octal = [Convert]::ToString([int64]$checksum, 8).PadLeft(6, '0')
    $encoded = [Text.Encoding]::ASCII.GetBytes($octal)
    [Array]::Copy($encoded, 0, $Header, 148, 6)
    $Header[154] = 0
    $Header[155] = [byte][char]' '
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

function New-PaxRecord {
    param(
        [Parameter(Mandatory)][string]$Keyword,
        [Parameter(Mandatory)][string]$Value
    )

    $body = "$Keyword=$Value`n"
    $length = $body.Length + 2
    while ($true) {
        $record = "$length $body"
        if ($record.Length -eq $length) {
            return ,[Text.Encoding]::UTF8.GetBytes($record)
        }
        $length = $record.Length
    }
}

function New-Entry {
    param(
        [Parameter(Mandatory)][string]$Name,
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

function New-PaxArchive {
    param([Parameter(Mandatory)][object[]]$Entries)

    $stream = [IO.MemoryStream]::new()
    try {
        foreach ($entry in $Entries) {
            [byte[]]$body = $entry.Body
            $header = New-Header `
                -Name ([string]$entry.Name) `
                -Size ([uint64]$entry.HeaderSize) `
                -Typeflag ([byte]$entry.Typeflag)
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

function Join-ByteArrays {
    param([Parameter(Mandatory)][byte[][]]$Arrays)

    $stream = [IO.MemoryStream]::new()
    try {
        foreach ($array in $Arrays) {
            $stream.Write($array)
        }
        return ,$stream.ToArray()
    } finally {
        $stream.Dispose()
    }
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
$mars = [Text.Encoding]::ASCII.GetBytes('mars')
$sixBytes = [Text.Encoding]::ASCII.GetBytes('verify')
$ordinary = New-PaxArchive @(
    (New-Entry -Name 'ordinary.txt' -Body $mars -Typeflag ([byte][char]'0'))
)
$localPayload = Join-ByteArrays @(
    (New-PaxRecord -Keyword 'path' -Value 'mission/log.txt'),
    (New-PaxRecord -Keyword 'size' -Value '4')
)
$localPathSize = New-PaxArchive @(
    (New-Entry -Name 'PaxHeaders/local' -Body $localPayload -Typeflag ([byte][char]'x')),
    (New-Entry -Name 'placeholder' -Body $mars -Typeflag ([byte][char]'0') -HeaderSize 0)
)
$globalPayload = Join-ByteArrays @(
    (New-PaxRecord -Keyword 'path' -Value 'global.txt'),
    (New-PaxRecord -Keyword 'size' -Value '6')
)
$localPathPayload = New-PaxRecord -Keyword 'path' -Value 'local.txt'
$globalLocalPrecedence = New-PaxArchive @(
    (New-Entry -Name 'PaxHeaders/global' -Body $globalPayload -Typeflag ([byte][char]'g')),
    (New-Entry -Name 'PaxHeaders/local' -Body $localPathPayload -Typeflag ([byte][char]'x')),
    (New-Entry -Name 'first-placeholder' -Body $sixBytes -Typeflag ([byte][char]'0') -HeaderSize 0),
    (New-Entry -Name 'second-placeholder' -Body $sixBytes -Typeflag ([byte][char]'0') -HeaderSize 0)
)
$quotaBoundary = New-PaxArchive @(
    (New-Entry -Name 'one' -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'0')),
    (New-Entry -Name 'two' -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'0'))
)
$malformedLengthPayload = [Text.Encoding]::ASCII.GetBytes("99 path=a`n")
$malformedLength = New-PaxArchive @(
    (New-Entry -Name 'PaxHeaders/malformed' -Body $malformedLengthPayload -Typeflag ([byte][char]'x')),
    (New-Entry -Name 'member' -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'0'))
)
$unsupportedPayload = New-PaxRecord -Keyword 'mtime' -Value '0'
$unsupportedKeyword = New-PaxArchive @(
    (New-Entry -Name 'PaxHeaders/unsupported' -Body $unsupportedPayload -Typeflag ([byte][char]'x')),
    (New-Entry -Name 'member' -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'0'))
)
$orphanLocal = New-PaxArchive @(
    (New-Entry -Name 'PaxHeaders/orphan' -Body $localPathPayload -Typeflag ([byte][char]'x'))
)
$overCapPayload = [byte[]]::new(65537)
$overCapPayload[0] = [byte][char]'1'
$extensionOverCap = New-PaxArchive @(
    (New-Entry -Name 'PaxHeaders/over-cap' -Body $overCapPayload -Typeflag ([byte][char]'x'))
)

Write-Seed -Name 'invalid-extension-over-cap' -Bytes $extensionOverCap
Write-Seed -Name 'invalid-malformed-record-length' -Bytes $malformedLength
Write-Seed -Name 'invalid-orphan-local' -Bytes $orphanLocal
Write-Seed -Name 'unsupported-keyword' -Bytes $unsupportedKeyword
Write-Seed -Name 'valid-empty-ustar-subset' -Bytes $empty
Write-Seed -Name 'valid-global-local-precedence' -Bytes $globalLocalPrecedence
Write-Seed -Name 'valid-local-path-size' -Bytes $localPathSize
Write-Seed -Name 'valid-ordinary-ustar-subset' -Bytes $ordinary
Write-Seed -Name 'valid-quota-boundary-two-files' -Bytes $quotaBoundary

Write-Host 'Generated deterministic portable PAX fuzz seeds.'
