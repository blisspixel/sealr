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
    'gzip_rfc1952_single_member_v1'
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
        $leaf -notmatch '^sealr-gzip-fuzz-seeds-[0-9a-f]{32}$') {
        throw "refusing to generate gzip seeds outside an exact temporary corpus: $corpus"
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

function New-GzipMember {
    param(
        [Parameter(Mandatory)][byte]$Flags,
        [Parameter(Mandatory)][byte[]]$Payload,
        [Parameter(Mandatory)][byte[]]$Deflate
    )

    $bytes = [Collections.Generic.List[byte]]::new()
    $bytes.AddRange([byte[]]@(0x1f, 0x8b, 8, $Flags, 0x78, 0x56, 0x34, 0x12, 0, 255))
    if (($Flags -band 0x04) -ne 0) {
        Add-UInt16LittleEndian -Bytes $bytes -Value 3
        $bytes.AddRange([Text.Encoding]::ASCII.GetBytes('xyz'))
    }
    if (($Flags -band 0x08) -ne 0) {
        $bytes.AddRange([Text.Encoding]::ASCII.GetBytes("archive.tar`0"))
    }
    if (($Flags -band 0x10) -ne 0) {
        $bytes.AddRange([Text.Encoding]::ASCII.GetBytes("sealr fixture`0"))
    }
    if (($Flags -band 0x02) -ne 0) {
        $headerCrc = [uint16]((Get-Crc32 -Bytes $bytes.ToArray()) -band 0xffff)
        Add-UInt16LittleEndian -Bytes $bytes -Value $headerCrc
    }
    $bytes.AddRange($Deflate)
    Add-UInt32LittleEndian -Bytes $bytes -Value (Get-Crc32 -Bytes $Payload)
    Add-UInt32LittleEndian -Bytes $bytes -Value ([uint32]$Payload.Length)
    return ,$bytes.ToArray()
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

$mars = [Text.Encoding]::ASCII.GetBytes('mars')
$storedMars = [Convert]::FromHexString('010400fbff6d617273')
$dynamicPayload = [byte[]]::new(4096)
[Array]::Fill[byte]($dynamicPayload, [byte][char]'A')
$dynamicDeflate = [Convert]::FromHexString('edc1010d000000c2a06cef5fca1e0e28000000e0dd00')

$stored = New-GzipMember -Flags 0 -Payload $mars -Deflate $storedMars
$dynamic = New-GzipMember -Flags 0 -Payload $dynamicPayload -Deflate $dynamicDeflate
$text = New-GzipMember -Flags 0x01 -Payload $mars -Deflate $storedMars
$headerCrc = New-GzipMember -Flags 0x02 -Payload $mars -Deflate $storedMars
$extra = New-GzipMember -Flags 0x04 -Payload $mars -Deflate $storedMars
$name = New-GzipMember -Flags 0x08 -Payload $mars -Deflate $storedMars
$comment = New-GzipMember -Flags 0x10 -Payload $mars -Deflate $storedMars
$allOptions = New-GzipMember -Flags 0x1f -Payload $mars -Deflate $storedMars

Write-Seed -Name 'valid-stored-deflate' -Bytes $stored
Write-Seed -Name 'valid-dynamic-deflate' -Bytes $dynamic
Write-Seed -Name 'valid-optional-text' -Bytes $text
Write-Seed -Name 'valid-optional-header-crc' -Bytes $headerCrc
Write-Seed -Name 'valid-optional-extra' -Bytes $extra
Write-Seed -Name 'valid-optional-name' -Bytes $name
Write-Seed -Name 'valid-optional-comment' -Bytes $comment
Write-Seed -Name 'valid-all-optional-fields' -Bytes $allOptions

$badHeaderCrc = Copy-Bytes $headerCrc
$badHeaderCrc[10] = $badHeaderCrc[10] -bxor 1
Write-Seed -Name 'bad-header-crc' -Bytes $badHeaderCrc

$badDataCrc = Copy-Bytes $stored
$badDataCrc[$badDataCrc.Length - 8] = $badDataCrc[$badDataCrc.Length - 8] -bxor 1
Write-Seed -Name 'bad-data-crc' -Bytes $badDataCrc

$badIsize = Copy-Bytes $stored
$badIsize[$badIsize.Length - 4] = $badIsize[$badIsize.Length - 4] -bxor 1
Write-Seed -Name 'bad-isize' -Bytes $badIsize

$concatenated = [byte[]]::new($stored.Length + $dynamic.Length)
[Array]::Copy($stored, 0, $concatenated, 0, $stored.Length)
[Array]::Copy($dynamic, 0, $concatenated, $stored.Length, $dynamic.Length)
Write-Seed -Name 'concatenated-members' -Bytes $concatenated

$trailing = [byte[]]::new($stored.Length + 1)
[Array]::Copy($stored, $trailing, $stored.Length)
$trailing[$stored.Length] = 0x7f
Write-Seed -Name 'trailing-byte' -Bytes $trailing

$zeroPadding = [byte[]]::new($stored.Length + 4)
[Array]::Copy($stored, $zeroPadding, $stored.Length)
Write-Seed -Name 'zero-padding' -Bytes $zeroPadding

Write-Seed -Name 'truncated-fixed-header' -Bytes (Get-Prefix $stored 9)
Write-Seed -Name 'truncated-extra-length' -Bytes (Get-Prefix $extra 11)
Write-Seed -Name 'truncated-extra-payload' -Bytes (Get-Prefix $extra 14)
Write-Seed -Name 'unterminated-name' -Bytes (Get-Prefix $name 21)
Write-Seed -Name 'unterminated-comment' -Bytes (Get-Prefix $comment 23)
Write-Seed -Name 'truncated-header-crc' -Bytes (Get-Prefix $headerCrc 11)
Write-Seed -Name 'truncated-deflate' -Bytes (Get-Prefix $stored 18)
Write-Seed -Name 'truncated-trailer-crc' -Bytes (Get-Prefix $stored ($stored.Length - 7))
Write-Seed -Name 'truncated-trailer-isize' -Bytes (Get-Prefix $stored ($stored.Length - 1))

Write-Host 'Generated deterministic RFC 1952 single-member fuzz seeds.'
