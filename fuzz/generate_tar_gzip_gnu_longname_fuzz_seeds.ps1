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
    'tar_gzip_gnu_longname_portable_v1'
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
        $leaf -notmatch '^sealr-tar-gzip-gnu-longname-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate TAR/gzip GNU long-name seeds outside an exact temporary corpus: $corpus"
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

function New-WrappedSeed {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Derived)

    return ,(New-GzipMember -Payload $Derived -Deflate (New-StoredDeflate $Derived))
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
$shortPayload = New-LongPayload 'short.txt'
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
$overCap = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('././@LongLink') -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'L') -HeaderSize 8193)
)
$longLinkK = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('././@LongLink') -Body $shortPayload -Typeflag ([byte][char]'K'))
)
$sparse = New-Archive @(
    (New-Entry -Name $ascii.GetBytes('sparse') -Body ([byte[]]::new(0)) -Typeflag ([byte][char]'S'))
)

$validEmpty = New-WrappedSeed $empty
$validOrdinary = New-WrappedSeed $ordinary
$badDataCrc = Copy-Bytes $validOrdinary
$badDataCrc[$badDataCrc.Length - 8] = $badDataCrc[$badDataCrc.Length - 8] -bxor 1

Write-Seed 'valid-empty-oldgnu' $validEmpty
Write-Seed 'valid-ordinary-oldgnu' $validOrdinary
Write-Seed 'valid-gnu-longlink' (New-WrappedSeed $gnuLong)
Write-Seed 'valid-two-carrier-pairs' (New-WrappedSeed $twoPairs)
Write-Seed 'valid-all-optional-stored' (New-GzipMember `
    -Payload $ordinary `
    -Deflate (New-StoredDeflate $ordinary) `
    -Flags 0x1f `
    -Extra ([byte[]]@(0x53, 0x4c, 3, 0, 0x78, 0x79, 0x7a)))
Write-Seed 'invalid-wrapper-bad-data-crc' $badDataCrc
Write-Seed 'invalid-wrapper-trailing-byte' (Join-Bytes @($validEmpty, [byte[]]@(0x7f)))
Write-Seed 'invalid-wrapper-concatenated-members' (Join-Bytes @($validEmpty, $validOrdinary))
Write-Seed 'invalid-orphan-carrier' (New-WrappedSeed $orphan)
Write-Seed 'invalid-chained-carrier' (New-WrappedSeed $chained)
Write-Seed 'invalid-oversized-carrier' (New-WrappedSeed $overCap)
Write-Seed 'unsupported-long-link-k' (New-WrappedSeed $longLinkK)
Write-Seed 'unsupported-sparse' (New-WrappedSeed $sparse)
Write-Seed 'resource-derived-over-cap' (New-WrappedSeed ([byte[]]::new(132096)))

Write-Host 'Generated deterministic public TAR/gzip GNU long-name fuzz seeds.'
