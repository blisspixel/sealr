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
    'sevenz_copy_portable_v1'
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
        $leaf -notmatch '^sealr-sevenz-copy-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate 7z Copy seeds outside an exact temporary corpus: $corpus"
    }
}
[IO.Directory]::CreateDirectory($corpus) | Out-Null

function Get-Crc32 {
    param([Parameter(Mandatory)][byte[]]$Bytes)

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

function Join-Bytes {
    param([Parameter(Mandatory)][object[]]$Parts)

    $bytes = [Collections.Generic.List[byte]]::new()
    foreach ($part in $Parts) {
        $bytes.AddRange([byte[]]$part)
    }
    return ,$bytes.ToArray()
}

function Copy-WithByteXor {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][byte]$Mask
    )

    $mutated = [byte[]]$Bytes.Clone()
    $mutated[$Offset] = $mutated[$Offset] -bxor $Mask
    return ,$mutated
}

# Recompute the two chained header CRCs after a mutation to the next-header
# bytes, so a seed fails only on the exact structural rule under test rather
# than on a header-CRC mismatch. NextHeaderCRC covers the raw header bytes
# [32+offset, end); StartHeaderCRC covers the 20 StartHeader bytes [12, 32),
# which include the just-written NextHeaderCRC field.
function Repair-HeaderCrcs {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes
    )

    $mutated = [byte[]]$Bytes.Clone()
    $nextHeaderBytes = [byte[]]$mutated[32..($mutated.Length - 1)]
    $nextCrc = Get-Crc32 -Bytes $nextHeaderBytes
    [Array]::Copy([BitConverter]::GetBytes([uint32]$nextCrc), 0, $mutated, 28, 4)
    $startHeaderBytes = [byte[]]$mutated[12..31]
    $startCrc = Get-Crc32 -Bytes $startHeaderBytes
    [Array]::Copy([BitConverter]::GetBytes([uint32]$startCrc), 0, $mutated, 8, 4)
    return ,$mutated
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

# Pinned deterministic 7-Zip 26.02 `7z a -m0=Copy -mhc=off` output (raw
# headers) over the standard conformance content. Copy 7z archives contain no
# compressor output, so every hostile seed is a deterministic mutation of
# these committed bytes with the chained header CRCs repaired where the seed
# must fail on a later rule.
$cliFileOnly = ConvertFrom-Hex -Hex (
    '377abcaf271c000435c12a4919000000000000005a00000000000000eaaeb7e6' +
    '7665726966792074776963652c206465636f6465206f6e636501040600010919' +
    '00070b01000101000c1900080a0103b44165000005011123006d006900730073' +
    '0069006f006e002f0070006c0061006e002e0074007800740000001900140a01' +
    '000000d4bda237dd0115060100200000000000'
)
$cliDir = ConvertFrom-Hex -Hex (
    '377abcaf271c0004594020be19000000000000008600000000000000c515cbb7' +
    '7665726966792074776963652c206465636f6465206f6e636501040600010919' +
    '00070b01000101000c1900080a0103b44165000005020e0180190b0000000000' +
    '0000000000001133006d0069007300730069006f006e0000006d006900730073' +
    '0069006f006e002f0070006c0061006e002e0074007800740000001900141201' +
    '000000d4bda237dd010000d4bda237dd01150a010010000000200000000000'
)
$cliMulti = ConvertFrom-Hex -Hex (
    '377abcaf271c000412338a094400000000000000ee00000000000000a7049504' +
    '7665726966792074776963652c206465636f6465206f6e636574686520626f75' +
    '6e64617279206f776e7320746865206d65616e696e67206f6620657665727920' +
    '62797465010406000209192b00070b02000101000101000c192b00080a0103b4' +
    '4165443d37e6000005040e01c00f0140118083006d0069007300730069006f00' +
    '6e0000006d0069007300730069006f006e002f0065006d007000740079002e00' +
    '74007800740000006d0069007300730069006f006e002f0070006c0061006e00' +
    '2e0074007800740000006d0069007300730069006f006e002f00740065006c00' +
    '65006d0065007400720079002e006c006f00670000001900142201000000d4bd' +
    'a237dd010000d4bda237dd010000d4bda237dd010000d4bda237dd0115120100' +
    '100000002000000020000000200000000000'
)
# Stock `7z a -m0=Copy` default: kEncodedHeader (LZMA1-coded header) — the
# named unsupported shape.
$cliEncodedHeader = ConvertFrom-Hex -Hex (
    '377abcaf271c0004f59452dd780000000000000021000000000000009db7c94a' +
    '7665726966792074776963652c206465636f6465206f6e63650000813307ae0f' +
    'cf926e600febeb2d5cf9eaa7997e032f24bd2f25021d1de4439ce2744630c90a' +
    '6dc37dde91e412785742f539bd30d0c0918f644e5bb9f0713b9d5526658e27eb' +
    'bf2feb0de156528f08f8308f33cf29268f9c0a7af76e000017061901095f0007' +
    '0b01000123030101055d001000000c80860a01c515cbb70000'
)

Write-Seed 'valid-cli-fileonly' $cliFileOnly
Write-Seed 'valid-cli-dir-and-empty-matrix' $cliDir
Write-Seed 'valid-cli-multi-two-folders' $cliMulti
Write-Seed 'unsupported-encoded-header' $cliEncodedHeader
Write-Seed 'invalid-magic' (Copy-WithByteXor -Bytes $cliFileOnly -Offset 0 -Mask 0xff)
Write-Seed 'unsupported-major-version' (Repair-HeaderCrcs -Bytes (
    Copy-WithByteXor -Bytes $cliFileOnly -Offset 6 -Mask 0x01))
Write-Seed 'unsupported-minor-version' (Repair-HeaderCrcs -Bytes (
    Copy-WithByteXor -Bytes $cliFileOnly -Offset 7 -Mask 0x01))
Write-Seed 'invalid-start-crc' (Copy-WithByteXor -Bytes $cliFileOnly -Offset 8 -Mask 0x01)
Write-Seed 'invalid-next-crc' (Copy-WithByteXor `
    -Bytes $cliFileOnly -Offset ($cliFileOnly.Length - 1) -Mask 0x01)
$truncated = [byte[]]::new(20)
[Array]::Copy($cliFileOnly, $truncated, $truncated.Length)
Write-Seed 'invalid-truncated' $truncated
Write-Seed 'invalid-trailing-byte' (Join-Bytes @($cliFileOnly, [byte[]]@(0x00)))
# A payload byte flip: parses structurally, member verification denies on the
# declared substream CRC.
Write-Seed 'invalid-payload-crc-lie' (Copy-WithByteXor -Bytes $cliFileOnly -Offset 32 -Mask 0x01)

Write-Host 'Generated deterministic public 7z Copy fuzz seeds.'
