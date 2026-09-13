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
    'tar_xz_ustar_portable_v1'
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
        $leaf -notmatch '^sealr-tar-xz-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate TAR/xz seeds outside an exact temporary corpus: $corpus"
    }
}
[IO.Directory]::CreateDirectory($corpus) | Out-Null

function ConvertFrom-Hex {
    param([Parameter(Mandatory)][string]$Hex)

    if ($Hex.Length % 2 -ne 0 -or $Hex -notmatch '^[0-9a-f]+$') {
        throw "invalid pinned hex literal: $Hex"
    }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring(2 * $index, 2), 16)
    }
    return ,$bytes
}

$script:crc32Table = [uint32[]]::new(256)
for ($index = 0; $index -lt 256; $index++) {
    [uint32]$value = [uint32]$index
    for ($bit = 0; $bit -lt 8; $bit++) {
        if (($value -band 1) -ne 0) {
            $value = [uint32]3988292384 -bxor ($value -shr 1)
        } else {
            $value = $value -shr 1
        }
    }
    $script:crc32Table[$index] = $value
}

function Get-Crc32 {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)

    [uint32]$crc = [uint32]4294967295
    foreach ($byte in $Bytes) {
        $crc = $script:crc32Table[($crc -bxor $byte) -band 0xff] -bxor ($crc -shr 8)
    }
    return [uint32]($crc -bxor [uint32]4294967295)
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

function Add-Varint {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[byte]]$Bytes,
        [Parameter(Mandatory)][uint64]$Value
    )

    do {
        $byte = [int]($Value -band 0x7F)
        $Value = $Value -shr 7
        if ($Value -ne 0) {
            $byte = $byte -bor 0x80
        }
        $Bytes.Add([byte]$byte)
    } while ($Value -ne 0)
}

function Join-Bytes {
    param([Parameter(Mandatory)][object[]]$Parts)

    $bytes = [Collections.Generic.List[byte]]::new()
    foreach ($part in $Parts) {
        $bytes.AddRange([byte[]]$part)
    }
    return ,$bytes.ToArray()
}

function New-Lzma2UncompressedChunks {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Payload)

    $bytes = [Collections.Generic.List[byte]]::new()
    $offset = 0
    $first = $true
    while ($offset -lt $Payload.Length) {
        $length = [Math]::Min(0xFFFF, $Payload.Length - $offset)
        $bytes.Add([byte]$(if ($first) { 0x01 } else { 0x02 }))
        $first = $false
        $size = [uint16]($length - 1)
        $bytes.Add([byte](($size -shr 8) -band 0xff))
        $bytes.Add([byte]($size -band 0xff))
        $chunk = [byte[]]::new($length)
        [Array]::Copy($Payload, $offset, $chunk, 0, $length)
        $bytes.AddRange($chunk)
        $offset += $length
    }
    $bytes.Add(0x00)
    return ,$bytes.ToArray()
}

function New-XzStream {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Content,
        [byte]$CheckId = 0x01,
        [int]$BlockBytes = 0,
        [switch]$DeclaredSizes,
        [switch]$CorruptCheck
    )

    $checkLength = switch ($CheckId) {
        0x00 { 0 }
        0x01 { 4 }
        default { throw "unsupported generator check id: $CheckId" }
    }

    $segments = [Collections.Generic.List[byte[]]]::new()
    if ($BlockBytes -le 0 -or $Content.Length -le $BlockBytes) {
        $segments.Add($Content)
    } else {
        $offset = 0
        while ($offset -lt $Content.Length) {
            $length = [Math]::Min($BlockBytes, $Content.Length - $offset)
            $segment = [byte[]]::new($length)
            [Array]::Copy($Content, $offset, $segment, 0, $length)
            $segments.Add($segment)
            $offset += $length
        }
    }

    $stream = [Collections.Generic.List[byte]]::new()
    $stream.AddRange([byte[]]@(0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00))
    $stream.Add(0x00)
    $stream.Add($CheckId)
    Add-UInt32LittleEndian -Bytes $stream -Value (Get-Crc32 -Bytes @([byte]0x00, $CheckId))

    $unpaddedSizes = [Collections.Generic.List[uint64]]::new()
    foreach ($segment in $segments) {
        $lzma2 = New-Lzma2UncompressedChunks -Payload $segment

        $header = [Collections.Generic.List[byte]]::new()
        $header.Add(0x00)
        $header.Add([byte]$(if ($DeclaredSizes) { 0xC0 } else { 0x00 }))
        if ($DeclaredSizes) {
            Add-Varint -Bytes $header -Value ([uint64]$lzma2.Length)
            Add-Varint -Bytes $header -Value ([uint64]$segment.Length)
        }
        Add-Varint -Bytes $header -Value ([uint64]0x21)
        Add-Varint -Bytes $header -Value ([uint64]1)
        $header.Add(0x16)
        while (($header.Count + 4) % 4 -ne 0) {
            $header.Add(0x00)
        }
        $header[0] = [byte]((($header.Count + 4) / 4) - 1)
        Add-UInt32LittleEndian -Bytes $header -Value (Get-Crc32 -Bytes $header.ToArray())

        $blockStart = $stream.Count
        $stream.AddRange($header)
        $stream.AddRange([byte[]]$lzma2)
        $unpaddedSizes.Add([uint64]($stream.Count - $blockStart + $checkLength))
        while (($stream.Count - $blockStart) % 4 -ne 0) {
            $stream.Add(0x00)
        }
        if ($CheckId -eq 0x01) {
            [uint32]$check = Get-Crc32 -Bytes $segment
            if ($CorruptCheck) {
                $check = $check -bxor [uint32]1
            }
            Add-UInt32LittleEndian -Bytes $stream -Value $check
        }
    }

    $indexStart = $stream.Count
    $stream.Add(0x00)
    Add-Varint -Bytes $stream -Value ([uint64]$segments.Count)
    for ($index = 0; $index -lt $segments.Count; $index++) {
        Add-Varint -Bytes $stream -Value $unpaddedSizes[$index]
        Add-Varint -Bytes $stream -Value ([uint64]$segments[$index].Length)
    }
    while (($stream.Count - $indexStart) % 4 -ne 0) {
        $stream.Add(0x00)
    }
    $indexBytes = [byte[]]::new($stream.Count - $indexStart)
    $stream.CopyTo($indexStart, $indexBytes, 0, $indexBytes.Length)
    Add-UInt32LittleEndian -Bytes $stream -Value (Get-Crc32 -Bytes $indexBytes)
    $indexLength = $stream.Count - $indexStart

    $footerBody = [Collections.Generic.List[byte]]::new()
    Add-UInt32LittleEndian -Bytes $footerBody -Value ([uint32](($indexLength / 4) - 1))
    $footerBody.Add(0x00)
    $footerBody.Add($CheckId)
    Add-UInt32LittleEndian -Bytes $stream -Value (Get-Crc32 -Bytes $footerBody.ToArray())
    $stream.AddRange($footerBody)
    $stream.AddRange([byte[]]@([byte][char]'Y', [byte][char]'Z'))
    return ,$stream.ToArray()
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

function New-UstarArchive {
    param([Parameter(Mandatory)][object[]]$Entries)

    $stream = [IO.MemoryStream]::new()
    try {
        foreach ($entry in $Entries) {
            [byte[]]$body = $entry.Body
            $header = New-Header `
                -Name ([string]$entry.Name) `
                -Size ([uint64]$body.Length) `
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

# Pinned real XZ Utils v5.8.1 streams over a one-file portable ustar archive.
# These are deterministic committed bytes, not runtime compressions.
$cliCrc64SingleBlock = ConvertFrom-Hex -Hex (
    'fd377a585a000004e6d6b4460200210116000000742fe5a3e007ff00705d00369a4adf' +
    'f3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1' +
    '897bcfa2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59' +
    '582a4d6308d2ffca92620af736cdb6f7b1240ae87699d3cfb3eb7748f4ff4a5b315efe' +
    '8cd37d00ec921496b86e87ef00018c0180100000853c3866b1c467fb02000000000459' +
    '5a'
)
$cliSha256SingleBlock = ConvertFrom-Hex -Hex (
    'fd377a585a00000ae1fb0ca10200210116000000742fe5a3e007ff00705d00369a4adf' +
    'f3ff4173689225555d5c3da569f20e0f1e46ed67823a5dcf0c5c5749d5f12bb878efa1' +
    '897bcfa2a38633f7d28fc607eaad183da7c2063caa76c99a73e3434b174e4fa5f5dd59' +
    '582a4d6308d2ffca92620af736cdb6f7b1240ae87699d3cfb3eb7748f4ff4a5b315efe' +
    '8cd37d0036631c7b6055995f66c07c86f39bbaa386b893b177c693bb38a5f73aaa8383' +
    '7c0001a40180100000debbc78db6e9df1c02000000000a595a'
)

$emptyTar = [byte[]]::new(1024)
$mars = [Text.Encoding]::ASCII.GetBytes('mars')
$ordinaryTar = New-UstarArchive @(
    ([pscustomobject]@{
        Name = 'ordinary.txt'
        Body = $mars
        Typeflag = [byte][char]'0'
    })
)
$notTar = [Text.Encoding]::ASCII.GetBytes(
    'this xz payload is deliberately not a ustar archive'
)

$validOrdinary = New-XzStream -Content $ordinaryTar
$validEmpty = New-XzStream -Content $emptyTar

$invalidMagic = [byte[]]$validOrdinary.Clone()
$invalidMagic[0] = 0xfe
$invalidTruncated = [byte[]]::new($validOrdinary.Length - 4)
[Array]::Copy($validOrdinary, $invalidTruncated, $invalidTruncated.Length)
$invalidHeaderCrc = [byte[]]$validOrdinary.Clone()
$invalidHeaderCrc[8] = $invalidHeaderCrc[8] -bxor 0x01
$invalidBlockCrc = [byte[]]$validOrdinary.Clone()
$invalidBlockCrc[23] = $invalidBlockCrc[23] -bxor 0x01

Write-Seed 'valid-cli-crc64-single-block' $cliCrc64SingleBlock
Write-Seed 'valid-cli-sha256-single-block' $cliSha256SingleBlock
Write-Seed 'valid-ordinary-ustar-crc32' $validOrdinary
Write-Seed 'valid-empty-ustar-crc32' $validEmpty
Write-Seed 'valid-two-block-crc32' (New-XzStream `
    -Content $ordinaryTar `
    -BlockBytes 1024)
Write-Seed 'valid-declared-sizes-crc32' (New-XzStream `
    -Content $ordinaryTar `
    -DeclaredSizes)
Write-Seed 'invalid-magic' $invalidMagic
Write-Seed 'invalid-truncated' $invalidTruncated
Write-Seed 'invalid-header-crc' $invalidHeaderCrc
Write-Seed 'invalid-block-crc' $invalidBlockCrc
Write-Seed 'invalid-check-mismatch' (New-XzStream `
    -Content $ordinaryTar `
    -CorruptCheck)
Write-Seed 'invalid-trailing-byte' (Join-Bytes @($validEmpty, [byte[]]@(0x7f)))
Write-Seed 'invalid-inner-not-tar' (New-XzStream -Content $notTar)
Write-Seed 'unsupported-check-none' (New-XzStream `
    -Content $ordinaryTar `
    -CheckId 0x00)
Write-Seed 'unsupported-concatenated-streams' (Join-Bytes @($validEmpty, $validOrdinary))
Write-Seed 'unsupported-stream-padding' (Join-Bytes @(
    $validEmpty,
    [byte[]]@(0x00, 0x00, 0x00, 0x00)
))
Write-Seed 'resource-derived-over-cap' (New-XzStream `
    -Content ([byte[]]::new(132096)))

Write-Host 'Generated deterministic public TAR/xz fuzz seeds.'
