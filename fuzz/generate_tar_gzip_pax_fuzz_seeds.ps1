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
    'tar_gzip_pax_portable_v1'
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
        $leaf -notmatch '^sealr-tar-gzip-pax-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate TAR/gzip PAX seeds outside an exact temporary corpus: $corpus"
    }
}
[IO.Directory]::CreateDirectory($corpus) | Out-Null

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

function Copy-Bytes {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

    $copy = [byte[]]::new($Bytes.Length)
    [Array]::Copy($Bytes, $copy, $Bytes.Length)
    return ,$copy
}

function Join-Bytes {
    param([Parameter(Mandatory)][object[]]$Parts)

    $bytes = [Collections.Generic.List[byte]]::new()
    foreach ($part in $Parts) {
        $bytes.AddRange([byte[]]$part)
    }
    return ,$bytes.ToArray()
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

function New-GzipMember {
    param(
        [Parameter(Mandatory)][byte[]]$Payload,
        [Parameter(Mandatory)][byte[]]$Deflate,
        [byte]$Flags = 0,
        [AllowEmptyCollection()][byte[]]$Extra = @(),
        [string]$OriginalName = 'archive.tar'
    )

    $bytes = [Collections.Generic.List[byte]]::new()
    $bytes.AddRange([byte[]]@(0x1f, 0x8b, 8, $Flags, 0, 0, 0, 0, 0, 255))
    if (($Flags -band 0x04) -ne 0) {
        Add-UInt16LittleEndian -Bytes $bytes -Value ([uint16]$Extra.Length)
        $bytes.AddRange($Extra)
    }
    if (($Flags -band 0x08) -ne 0) {
        $bytes.AddRange([Text.Encoding]::ASCII.GetBytes("$OriginalName`0"))
    }
    if (($Flags -band 0x10) -ne 0) {
        $bytes.AddRange([Text.Encoding]::ASCII.GetBytes("sealr fuzz`0"))
    }
    if (($Flags -band 0x02) -ne 0) {
        Add-UInt16LittleEndian -Bytes $bytes -Value ([uint16]((Get-Crc32 $bytes.ToArray()) -band 0xffff))
    }
    $bytes.AddRange($Deflate)
    Add-UInt32LittleEndian -Bytes $bytes -Value (Get-Crc32 $Payload)
    Add-UInt32LittleEndian -Bytes $bytes -Value ([uint32]$Payload.Length)
    return ,$bytes.ToArray()
}

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

function New-WrappedSeed {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Derived)

    return ,(New-GzipMember -Payload $Derived -Deflate (New-StoredDeflate $Derived))
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
$longNamePayload = [Text.Encoding]::ASCII.GetBytes("unsupported-longname.txt`0")
$gnuCarrier = New-PaxArchive @(
    (New-Entry -Name '././@LongLink' -Body $longNamePayload -Typeflag ([byte][char]'L')),
    (New-Entry -Name 'member' -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'0'))
)

$validEmpty = New-WrappedSeed $empty
$validOrdinary = New-WrappedSeed $ordinary
$badDataCrc = Copy-Bytes $validOrdinary
$badDataCrc[$badDataCrc.Length - 8] = $badDataCrc[$badDataCrc.Length - 8] -bxor 1

Write-Seed 'valid-empty-pax' $validEmpty
Write-Seed 'valid-ordinary-ustar-subset' $validOrdinary
Write-Seed 'valid-local-path-size' (New-WrappedSeed $localPathSize)
Write-Seed 'valid-global-local-precedence' (New-WrappedSeed $globalLocalPrecedence)
Write-Seed 'valid-quota-boundary-two-files' (New-WrappedSeed $quotaBoundary)
Write-Seed 'valid-all-optional-stored' (New-GzipMember `
    -Payload $ordinary `
    -Deflate (New-StoredDeflate $ordinary) `
    -Flags 0x1f `
    -Extra ([byte[]]@(0x53, 0x4c, 3, 0, 0x78, 0x79, 0x7a)))
Write-Seed 'invalid-wrapper-bad-data-crc' $badDataCrc
Write-Seed 'invalid-wrapper-trailing-byte' (Join-Bytes @($validEmpty, [byte[]]@(0x7f)))
Write-Seed 'invalid-wrapper-concatenated-members' (Join-Bytes @($validEmpty, $validOrdinary))
Write-Seed 'invalid-orphan-local' (New-WrappedSeed $orphanLocal)
Write-Seed 'invalid-malformed-record-length' (New-WrappedSeed $malformedLength)
Write-Seed 'invalid-extension-over-cap' (New-WrappedSeed $extensionOverCap)
Write-Seed 'unsupported-keyword' (New-WrappedSeed $unsupportedKeyword)
Write-Seed 'unsupported-gnu-longlink-carrier' (New-WrappedSeed $gnuCarrier)
Write-Seed 'resource-derived-over-cap' (New-WrappedSeed ([byte[]]::new(132096)))

Write-Host 'Generated deterministic public TAR/gzip PAX fuzz seeds.'
