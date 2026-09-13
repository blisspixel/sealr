[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$expectedCorpus = [IO.Path]::Combine(
    $workspace,
    'fuzz',
    'corpus',
    'tar_gzip_ustar_portable_v1'
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
        $leaf -notmatch '^sealr-tar-gzip-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate TAR/gzip seeds outside an exact temporary corpus: $corpus"
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

function Set-AsciiField {
    param(
        [Parameter(Mandatory)][byte[]]$Target,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][int]$Length,
        [Parameter(Mandatory)][string]$Value
    )

    $encoded = [Text.Encoding]::ASCII.GetBytes($Value)
    if ($encoded.Length -gt $Length) {
        throw "ASCII field does not fit its TAR range: $Value"
    }
    [Array]::Copy($encoded, 0, $Target, $Offset, $encoded.Length)
}

function Set-OctalField {
    param(
        [Parameter(Mandatory)][byte[]]$Target,
        [Parameter(Mandatory)][int]$Offset,
        [Parameter(Mandatory)][int]$Length,
        [Parameter(Mandatory)][uint64]$Value
    )

    $digits = [Convert]::ToString([int64]$Value, 8).PadLeft($Length - 1, '0') + "`0"
    Set-AsciiField -Target $Target -Offset $Offset -Length $Length -Value $digits
}

function New-UstarEntry {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Payload,
        [char]$Type = '0'
    )

    $header = [byte[]]::new(512)
    Set-AsciiField $header 0 100 $Name
    Set-OctalField $header 100 8 420
    Set-OctalField $header 108 8 0
    Set-OctalField $header 116 8 0
    Set-OctalField $header 124 12 ([uint64]$Payload.Length)
    Set-OctalField $header 136 12 0
    for ($index = 148; $index -lt 156; $index++) {
        $header[$index] = 0x20
    }
    $header[156] = [byte]$Type
    Set-AsciiField $header 257 6 "ustar`0"
    Set-AsciiField $header 263 2 '00'
    Set-AsciiField $header 265 32 'root'
    Set-AsciiField $header 297 32 'root'
    Set-OctalField $header 329 8 0
    Set-OctalField $header 337 8 0
    $checksum = [uint64](($header | Measure-Object -Sum).Sum)
    $checksumText = [Convert]::ToString([int64]$checksum, 8).PadLeft(6, '0')
    Set-AsciiField $header 148 6 $checksumText
    $header[154] = 0
    $header[155] = 0x20

    $padding = (512 - ($Payload.Length % 512)) % 512
    return ,(Join-Bytes @($header, $Payload, [byte[]]::new($padding)))
}

function New-UstarArchive {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entries)

    $parts = [Collections.Generic.List[object]]::new()
    foreach ($entry in $Entries) {
        $parts.Add([byte[]]$entry)
    }
    $parts.Add([byte[]]::new(1024))
    return ,(Join-Bytes $parts.ToArray())
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

$conformancePath = Join-Path $workspace 'crates/sealr/tests/conformance/tar-gzip-identity-v1.json'
$conformance = Get-Content -Raw -LiteralPath $conformancePath | ConvertFrom-Json
$optionalConformance = [Convert]::FromHexString([string](
    $conformance.cases | Where-Object id -CEQ 'optional-default'
).source_bytes_hex)
$storedConformance = [Convert]::FromHexString([string](
    $conformance.cases | Where-Object id -CEQ 'minimal-stored-deflate'
).source_bytes_hex)
$derivedTar = [Convert]::FromHexString([string]$conformance.derived_tar.bytes_hex)
$fixedDeflate = [Convert]::FromHexString(
    'cbcd2c2ececccfd32fc849ccd32ba92861a001300002331313300d04e8b48181b12183a1a9918989a9b1b10948dcd0c4c8c88841c180810ea0b4b824b108e894a2fc7cbc9e27248feeb92102ca528b32d32a154aca3393537514525293f3535215f2f392531946c1281805a360140c670000'
)
$validFixed = New-GzipMember -Payload $derivedTar -Deflate $fixedDeflate
$validAllOptional = New-GzipMember `
    -Payload $derivedTar `
    -Deflate $fixedDeflate `
    -Flags 0x1f `
    -Extra ([byte[]]@(0x53, 0x4c, 3, 0, 0x78, 0x79, 0x7a))
$emptyTar = [byte[]]::new(1024)
$validEmpty = New-GzipMember -Payload $emptyTar -Deflate (New-StoredDeflate $emptyTar)

Write-Seed 'valid-conformance-optional-dynamic' $optionalConformance
Write-Seed 'valid-conformance-minimal-stored' $storedConformance
Write-Seed 'valid-fixed-deflate' $validFixed
Write-Seed 'valid-all-optional-fixed' $validAllOptional
Write-Seed 'valid-empty-ustar' $validEmpty

$nonTar = [Text.Encoding]::ASCII.GetBytes('derived bytes are not ustar')
Write-Seed 'derived-non-tar' (New-GzipMember $nonTar (New-StoredDeflate $nonTar))

Write-Seed 'truncated-fixed-header' ([byte[]]$validEmpty[0..8])
Write-Seed 'truncated-extra-length' ([byte[]]$validAllOptional[0..10])
Write-Seed 'truncated-extra-payload' ([byte[]]$validAllOptional[0..14])
Write-Seed 'truncated-name' ([byte[]]$validAllOptional[0..24])
Write-Seed 'truncated-comment' ([byte[]]$validAllOptional[0..36])

$headerCrcOnly = New-GzipMember -Payload $emptyTar -Deflate (New-StoredDeflate $emptyTar) -Flags 0x02
Write-Seed 'truncated-header-crc' ([byte[]]$headerCrcOnly[0..10])
Write-Seed 'truncated-deflate' ([byte[]]$validEmpty[0..15])
Write-Seed 'truncated-trailer-crc' ([byte[]]$validEmpty[0..($validEmpty.Length - 8)])
Write-Seed 'truncated-trailer-isize' ([byte[]]$validEmpty[0..($validEmpty.Length - 2)])

$badMagic = Copy-Bytes $validEmpty
$badMagic[1] = 0
Write-Seed 'bad-magic' $badMagic
$badMethod = Copy-Bytes $validEmpty
$badMethod[2] = 7
Write-Seed 'unsupported-method' $badMethod
$reservedFlags = Copy-Bytes $validEmpty
$reservedFlags[3] = 0x20
Write-Seed 'unsupported-reserved-flags' $reservedFlags

$badHeaderCrc = Copy-Bytes $headerCrcOnly
$badHeaderCrc[10] = $badHeaderCrc[10] -bxor 1
Write-Seed 'bad-header-crc' $badHeaderCrc
$badDataCrc = Copy-Bytes $validEmpty
$badDataCrc[$badDataCrc.Length - 8] = $badDataCrc[$badDataCrc.Length - 8] -bxor 1
Write-Seed 'bad-data-crc' $badDataCrc
$badIsize = Copy-Bytes $validEmpty
$badIsize[$badIsize.Length - 4] = $badIsize[$badIsize.Length - 4] -bxor 1
Write-Seed 'bad-isize' $badIsize

$malformedExtras = [ordered]@{
    'invalid-extra-truncated-subfield-header' = [byte[]]@(0x53, 0x4c, 0)
    'invalid-extra-declared-length-overrun' = [byte[]]@(0x53, 0x4c, 4, 0, 0x78)
    'invalid-extra-trailing-remainder' = [byte[]]@(0x53, 0x4c, 0, 0, 0x7f)
    'invalid-extra-si2-zero' = [byte[]]@(0x53, 0, 0, 0)
    'invalid-extra-duplicate-id' = [byte[]]@(0x53, 0x4c, 0, 0, 0x53, 0x4c, 0, 0)
}
foreach ($entry in $malformedExtras.GetEnumerator()) {
    Write-Seed $entry.Key (New-GzipMember `
        -Payload $emptyTar `
        -Deflate (New-StoredDeflate $emptyTar) `
        -Flags 0x04 `
        -Extra $entry.Value)
}

Write-Seed 'concatenated-two-members' (Join-Bytes @($validEmpty, $validFixed))
Write-Seed 'concatenated-three-members' (Join-Bytes @($validEmpty, $validFixed, $validEmpty))
Write-Seed 'trailing-byte' (Join-Bytes @($validEmpty, [byte[]]@(0x7f)))
Write-Seed 'truncated-second-member' (Join-Bytes @($validEmpty, [byte[]]@(0x1f, 0x8b)))

$oneByte = [byte[]]@(0x78)
$validTar = New-UstarArchive @((New-UstarEntry 'safe.txt' $oneByte))
$badChecksumTar = Copy-Bytes $validTar
$badChecksumTar[0] = $badChecksumTar[0] -bxor 1
$nonzeroPaddingTar = Copy-Bytes $validTar
$nonzeroPaddingTar[513] = 0x7f
$duplicateTar = New-UstarArchive @(
    (New-UstarEntry 'same.txt' $oneByte),
    (New-UstarEntry 'same.txt' $oneByte)
)
$ancestorTar = New-UstarArchive @(
    (New-UstarEntry 'a' $oneByte),
    (New-UstarEntry 'a/b' $oneByte)
)
$traversalTar = New-UstarArchive @((New-UstarEntry '../escape' $oneByte))
$paxTar = New-UstarArchive @((New-UstarEntry 'pax' ([byte[]]@()) 'x'))
$unknownTypeTar = New-UstarArchive @((New-UstarEntry 'unknown' ([byte[]]@()) 'Z'))
$deepPath = ((1..17 | ForEach-Object { 'a' }) -join '/')
$deepPathTar = New-UstarArchive @((New-UstarEntry $deepPath $oneByte))

$hostileTarSeeds = [ordered]@{
    'wrapped-bad-tar-checksum' = $badChecksumTar
    'wrapped-nonzero-tar-padding' = $nonzeroPaddingTar
    'wrapped-duplicate-path' = $duplicateTar
    'wrapped-file-ancestor-conflict' = $ancestorTar
    'wrapped-path-traversal' = $traversalTar
    'wrapped-unsupported-pax' = $paxTar
    'wrapped-unknown-typeflag' = $unknownTypeTar
    'wrapped-path-depth-over-cap' = $deepPathTar
}
foreach ($entry in $hostileTarSeeds.GetEnumerator()) {
    Write-Seed $entry.Key (New-GzipMember $entry.Value (New-StoredDeflate $entry.Value))
}

$largeDerived = [byte[]]::new(132096)
$largeDynamicDeflate = [Convert]::FromHexString(
    'edc101010000008220ffaf6e48400100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ef06'
)
Write-Seed 'resource-derived-and-ratio-over-cap' (New-GzipMember $largeDerived $largeDynamicDeflate)

$ratioDerived = [byte[]]::new(65536)
$ratioDynamicDeflate = [Convert]::FromHexString(
    'edc101010000008090feafee080a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a'
)
Write-Seed 'resource-ratio-over-cap' (New-GzipMember $ratioDerived $ratioDynamicDeflate)

$largeMemberPayload = [byte[]]::new(32769)
$largeMemberTar = New-UstarArchive @((New-UstarEntry 'large.bin' $largeMemberPayload))
Write-Seed 'resource-member-over-cap' (New-GzipMember $largeMemberTar (New-StoredDeflate $largeMemberTar))

$totalTar = New-UstarArchive @(
    (New-UstarEntry 'first.bin' ([byte[]]::new(32768))),
    (New-UstarEntry 'second.bin' ([byte[]]::new(32768))),
    (New-UstarEntry 'last.bin' $oneByte)
)
Write-Seed 'resource-total-over-cap' (New-GzipMember $totalTar (New-StoredDeflate $totalTar))

$manyEntries = [Collections.Generic.List[object]]::new()
for ($index = 0; $index -lt 65; $index++) {
    $manyEntries.Add((New-UstarEntry ("f{0:d2}" -f $index) ([byte[]]@())))
}
$manyTar = New-UstarArchive $manyEntries.ToArray()
Write-Seed 'resource-files-and-metadata-over-cap' (New-GzipMember $manyTar (New-StoredDeflate $manyTar))

$metadataOver = New-GzipMember `
    -Payload $emptyTar `
    -Deflate (New-StoredDeflate $emptyTar) `
    -Flags 0x08 `
    -OriginalName ('a' * 32750)
Write-Seed 'resource-wrapper-metadata-over-cap' $metadataOver

Write-Host 'Generated deterministic public TAR/gzip ustar fuzz seeds.'
