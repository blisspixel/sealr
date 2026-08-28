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
    'tar_zstd_ustar_portable_v1'
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
        $leaf -notmatch '^sealr-tar-zstd-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate TAR/zstd seeds outside an exact temporary corpus: $corpus"
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

function Add-UInt32LittleEndian {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[byte]]$Bytes,
        [Parameter(Mandatory)][uint32]$Value
    )

    for ($shift = 0; $shift -lt 32; $shift += 8) {
        $Bytes.Add([byte](($Value -shr $shift) -band 0xff))
    }
}

function Join-Bytes {
    param([Parameter(Mandatory)][object[]]$Parts)

    $bytes = [Collections.Generic.List[byte]]::new()
    foreach ($part in $Parts) {
        $bytes.AddRange([byte[]]$part)
    }
    return ,$bytes.ToArray()
}

function New-RawBlocks {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Payload,
        [int]$BlockBytes = 131072
    )

    if ($BlockBytes -lt 1 -or $BlockBytes -gt 131072) {
        throw "raw zstd block size is outside the RFC 8878 cap: $BlockBytes"
    }
    $bytes = [Collections.Generic.List[byte]]::new()
    $offset = 0
    do {
        $remaining = $Payload.Length - $offset
        $length = [Math]::Min($BlockBytes, $remaining)
        $last = ($offset + $length -eq $Payload.Length)
        $header = [uint32](([uint32]$length -shl 3) -bor $(if ($last) { 1 } else { 0 }))
        $bytes.Add([byte]($header -band 0xff))
        $bytes.Add([byte](($header -shr 8) -band 0xff))
        $bytes.Add([byte](($header -shr 16) -band 0xff))
        if ($length -gt 0) {
            $chunk = [byte[]]::new($length)
            [Array]::Copy($Payload, $offset, $chunk, 0, $length)
            $bytes.AddRange($chunk)
        }
        $offset += $length
    } while ($offset -lt $Payload.Length)
    return ,$bytes.ToArray()
}

function New-ZstdFrame {
    param(
        [Parameter(Mandatory)][byte]$Descriptor,
        [AllowEmptyCollection()][byte[]]$HeaderTail = @(),
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Content,
        [int]$BlockBytes = 131072,
        [AllowEmptyCollection()][byte[]]$Trailer = @()
    )

    $bytes = [Collections.Generic.List[byte]]::new()
    $bytes.AddRange([byte[]]@(0x28, 0xb5, 0x2f, 0xfd))
    $bytes.Add($Descriptor)
    $bytes.AddRange([byte[]]$HeaderTail)
    $bytes.AddRange((New-RawBlocks -Payload $Content -BlockBytes $BlockBytes))
    $bytes.AddRange([byte[]]$Trailer)
    return ,$bytes.ToArray()
}

function New-SingleSegmentFrame {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Content,
        [Parameter(Mandatory)][uint32]$DeclaredContentSize
    )

    $fcs = [Collections.Generic.List[byte]]::new()
    Add-UInt32LittleEndian -Bytes $fcs -Value $DeclaredContentSize
    return ,(New-ZstdFrame `
        -Descriptor 0xa0 `
        -HeaderTail $fcs.ToArray() `
        -Content $Content)
}

function New-SkippableFrame {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Payload)

    $bytes = [Collections.Generic.List[byte]]::new()
    $bytes.AddRange([byte[]]@(0x50, 0x2a, 0x4d, 0x18))
    Add-UInt32LittleEndian -Bytes $bytes -Value ([uint32]$Payload.Length)
    $bytes.AddRange([byte[]]$Payload)
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

# Pinned real Zstandard CLI v1.5.7 frames over a one-file portable ustar
# archive. These are deterministic committed bytes, not runtime compressions.
$cliDefaultSingleSegment = ConvertFrom-Hex -Hex (
    '28b52ffd640007a5030062c5121880a96dc0ffd67f1bf321d16a06b6620b6de647c162' +
    'f422038a129f1e8cf43843d126fa1683558a6866f59b3abd0e3f43c424598ac944438c' +
    '94ff7fa6e0ffad150d4887600824deb5b6100e004fc10f92c40c35149a94c11c58d301' +
    'c0907b01a0133cf00e83dc50ab0238562e1326b004ca51b2db'
)
$cliLevel19SingleSegment = ConvertFrom-Hex -Hex (
    '28b52ffd64000745030092451211907d50fa109d0fdd5d0a65adadfe5f6901c0b14983' +
    '6b94b916846370e3d01fb44e034ca9fd0776e19bc107608c41e5c13f3a2721645201e5' +
    'fc3f40483dc01c8fb9622593c27ba10c0a20f036360e8ee71f9252061612030e14fe81' +
    'd211d9830658982818ca51b2db'
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
    'this raw-block payload is deliberately not a ustar archive'
)

$validEmpty = New-ZstdFrame -Descriptor 0x00 -HeaderTail @(0x00) -Content $emptyTar
$validOrdinary = New-ZstdFrame -Descriptor 0x00 -HeaderTail @(0x08) -Content $ordinaryTar

Write-Seed 'valid-cli-default-single-segment' $cliDefaultSingleSegment
Write-Seed 'valid-cli-level19-single-segment' $cliLevel19SingleSegment
Write-Seed 'valid-empty-ustar-windowed' $validEmpty
Write-Seed 'valid-ordinary-ustar-windowed' $validOrdinary
Write-Seed 'valid-single-segment-fcs' (New-SingleSegmentFrame `
    -Content $ordinaryTar `
    -DeclaredContentSize ([uint32]$ordinaryTar.Length))
Write-Seed 'valid-two-raw-blocks' (New-ZstdFrame `
    -Descriptor 0x00 `
    -HeaderTail @(0x08) `
    -Content $ordinaryTar `
    -BlockBytes 1024)
Write-Seed 'invalid-checksum-lie' (New-ZstdFrame `
    -Descriptor 0x04 `
    -HeaderTail @(0x08) `
    -Content $ordinaryTar `
    -Trailer ([byte[]]@(0x00, 0x00, 0x00, 0x00)))
Write-Seed 'invalid-fcs-lie' (New-SingleSegmentFrame `
    -Content $ordinaryTar `
    -DeclaredContentSize ([uint32]($ordinaryTar.Length + 1)))
Write-Seed 'invalid-trailing-byte' (Join-Bytes @($validEmpty, [byte[]]@(0x7f)))
Write-Seed 'invalid-concatenated-frames' (Join-Bytes @($validEmpty, $validOrdinary))
Write-Seed 'invalid-inner-not-tar' (New-ZstdFrame `
    -Descriptor 0x00 `
    -HeaderTail @(0x00) `
    -Content $notTar)
Write-Seed 'unsupported-skippable-frame' (New-SkippableFrame `
    -Payload ([Text.Encoding]::ASCII.GetBytes('skip')))
Write-Seed 'unsupported-dictionary-bit' (New-ZstdFrame `
    -Descriptor 0x01 `
    -HeaderTail @(0x00, 0x2a) `
    -Content $emptyTar)
Write-Seed 'unsupported-window-over-cap' (New-ZstdFrame `
    -Descriptor 0x00 `
    -HeaderTail @(0x70) `
    -Content ([byte[]]::new(0)))
Write-Seed 'resource-derived-over-cap' (New-ZstdFrame `
    -Descriptor 0x00 `
    -HeaderTail @(0x68) `
    -Content ([byte[]]::new(132096)))

Write-Host 'Generated deterministic public TAR/zstd fuzz seeds.'
