[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$assetRoot = Join-Path $workspace 'docs/assets/readme-walkthrough'
$expected = @(
    'sealr-inspect-allowed-terminal-dark.png',
    'sealr-inspect-allowed-terminal-light.png',
    'sealr-materialize-allowed-terminal-dark.png',
    'sealr-materialize-allowed-terminal-light.png',
    'sealr-reject-parent-path-terminal-dark.png',
    'sealr-reject-parent-path-terminal-light.png'
)
$forbiddenChunks = @('eXIf', 'iTXt', 'tEXt', 'tIME', 'zTXt')
$pngSignature = [byte[]](137, 80, 78, 71, 13, 10, 26, 10)

function Read-UInt32BigEndian {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$Offset
    )

    return [uint32](
        ([uint32]$Bytes[$Offset] -shl 24) -bor
        ([uint32]$Bytes[$Offset + 1] -shl 16) -bor
        ([uint32]$Bytes[$Offset + 2] -shl 8) -bor
        [uint32]$Bytes[$Offset + 3]
    )
}

$actual = @(Get-ChildItem -LiteralPath $assetRoot -File -Filter '*.png' | Sort-Object Name | Select-Object -ExpandProperty Name)
if (($actual -join "`n") -ne ($expected -join "`n")) {
    throw "walkthrough asset set differs from the expected six files`nactual:`n$($actual -join "`n")"
}

foreach ($name in $expected) {
    $path = Join-Path $assetRoot $name
    $file = Get-Item -LiteralPath $path
    if ($file.Length -gt 250KB) {
        throw "$name exceeds 250 KB: $($file.Length) bytes"
    }

    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ($bytes.Length -lt 33) {
        throw "$name is too short to be a PNG"
    }
    for ($index = 0; $index -lt $pngSignature.Length; $index++) {
        if ($bytes[$index] -ne $pngSignature[$index]) {
            throw "$name has an invalid PNG signature"
        }
    }

    $offset = 8
    $width = $null
    $height = $null
    $pixelsPerMeterX = $null
    $pixelsPerMeterY = $null
    $physicalUnit = $null
    $sawEnd = $false
    while ($offset -le $bytes.Length - 12) {
        $length = Read-UInt32BigEndian -Bytes $bytes -Offset $offset
        if ($length -gt [int]::MaxValue) {
            throw "$name contains an oversized PNG chunk"
        }
        $chunkEnd = $offset + 12 + [int]$length
        if ($chunkEnd -gt $bytes.Length) {
            throw "$name contains a truncated PNG chunk"
        }
        $type = [System.Text.Encoding]::ASCII.GetString($bytes, $offset + 4, 4)
        $dataOffset = $offset + 8

        if ($forbiddenChunks -contains $type) {
            throw "$name contains forbidden metadata chunk $type"
        }
        if ($type -eq 'IHDR') {
            if ($length -ne 13) { throw "$name has an invalid IHDR length" }
            $width = Read-UInt32BigEndian -Bytes $bytes -Offset $dataOffset
            $height = Read-UInt32BigEndian -Bytes $bytes -Offset ($dataOffset + 4)
        }
        if ($type -eq 'pHYs') {
            if ($length -ne 9) { throw "$name has an invalid pHYs length" }
            $pixelsPerMeterX = Read-UInt32BigEndian -Bytes $bytes -Offset $dataOffset
            $pixelsPerMeterY = Read-UInt32BigEndian -Bytes $bytes -Offset ($dataOffset + 4)
            $physicalUnit = $bytes[$dataOffset + 8]
        }
        if ($type -eq 'IEND') {
            $sawEnd = $true
            break
        }
        $offset = $chunkEnd
    }

    if (-not $sawEnd) { throw "$name has no IEND chunk" }
    if ($width -ne 1000 -or $height -ne 560) {
        throw "$name must be 1000x560, got ${width}x${height}"
    }
    if ($null -eq $pixelsPerMeterX -or $physicalUnit -ne 1) {
        throw "$name has no physical pixel density in meters"
    }
    $dpiX = $pixelsPerMeterX * 0.0254
    $dpiY = $pixelsPerMeterY * 0.0254
    if ([Math]::Abs($dpiX - 144) -gt 0.1 -or [Math]::Abs($dpiY - 144) -gt 0.1) {
        throw "$name must be 144 DPI, got $dpiX by $dpiY"
    }
}

Write-Host 'walkthrough assets verified: 6 PNGs, 1000x560, 144 DPI, no text metadata, each <= 250 KB'
