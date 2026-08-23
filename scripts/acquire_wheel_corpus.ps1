[CmdletBinding()]
param(
    [string]$Manifest = 'tests/corpus/wheels/manifest.json',
    [string]$CacheDirectory = '.research/wheels'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-BoundedDownload {
    param(
        [Parameter(Mandatory)]
        [Uri]$Uri,
        [Parameter(Mandatory)]
        [string]$Destination,
        [Parameter(Mandatory)]
        [UInt64]$ExpectedSize
    )

    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(10)
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $Uri)
    $request.Headers.UserAgent.ParseAdd('sealr-wheel-compatibility-lab/1')
    $response = $null
    $inputStream = $null
    $outputStream = $null
    try {
        $response = $client.SendAsync(
            $request,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead
        ).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            throw "Wheel download returned HTTP $([int]$response.StatusCode)"
        }
        $contentLength = $response.Content.Headers.ContentLength
        if ($null -ne $contentLength -and [UInt64]$contentLength -ne $ExpectedSize) {
            throw "Wheel response declared $contentLength bytes, expected $ExpectedSize"
        }

        $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $outputStream = [IO.FileStream]::new(
            $Destination,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            64KB,
            [IO.FileOptions]::SequentialScan
        )
        $buffer = [byte[]]::new(64KB)
        $written = [UInt64]0
        while ($true) {
            $read = $inputStream.Read($buffer, 0, $buffer.Length)
            if ($read -eq 0) {
                break
            }
            if ([UInt64]$read -gt ($ExpectedSize - $written)) {
                throw "Wheel response exceeded the declared $ExpectedSize-byte limit"
            }
            $outputStream.Write($buffer, 0, $read)
            $written += [UInt64]$read
        }
        if ($written -ne $ExpectedSize) {
            throw "Wheel response contained $written bytes, expected $ExpectedSize"
        }
        $outputStream.Flush()
    }
    finally {
        if ($null -ne $outputStream) {
            $outputStream.Dispose()
        }
        if ($null -ne $inputStream) {
            $inputStream.Dispose()
        }
        if ($null -ne $response) {
            $response.Dispose()
        }
        $request.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Get-BoundedFileDigest {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [UInt64]$ExpectedSize
    )

    $stream = $null
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $stream = [IO.FileStream]::new(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read,
            64KB,
            [IO.FileOptions]::SequentialScan
        )
        $buffer = [byte[]]::new(64KB)
        $readTotal = [UInt64]0
        while ($true) {
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -eq 0) {
                break
            }
            if ([UInt64]$read -gt ($ExpectedSize - $readTotal)) {
                throw "File exceeded the declared $ExpectedSize-byte limit: $Path"
            }
            $null = $hasher.TransformBlock($buffer, 0, $read, $null, 0)
            $readTotal += [UInt64]$read
        }
        if ($readTotal -ne $ExpectedSize) {
            throw "File contained $readTotal bytes, expected $ExpectedSize`: $Path"
        }
        $null = $hasher.TransformFinalBlock([byte[]]::new(0), 0, 0)
        [pscustomobject]@{
            Size = $readTotal
            Sha256 = [Convert]::ToHexString($hasher.Hash).ToLowerInvariant()
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        $hasher.Dispose()
    }
}

$workspace = Split-Path -Parent $PSScriptRoot
$manifestPath = [IO.Path]::GetFullPath((Join-Path $workspace $Manifest))
$cachePath = [IO.Path]::GetFullPath((Join-Path $workspace $CacheDirectory))
$manifestLength = [UInt64](Get-Item -LiteralPath $manifestPath).Length
if ($manifestLength -gt 1MB) {
    throw 'Wheel corpus manifest exceeds the 1 MiB limit'
}
$manifestObject = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json

if ($manifestObject.schema -ne 'sealr.wheel-corpus.v1') {
    throw "Unsupported wheel corpus schema: $($manifestObject.schema)"
}
$queryDate = [string]$manifestObject.query_date
$parsedDate = [DateTime]::MinValue
if (-not [DateTime]::TryParseExact(
    $queryDate,
    'yyyy-MM-dd',
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::None,
    [ref]$parsedDate
)) {
    throw 'Wheel corpus query_date must use YYYY-MM-DD'
}
$entries = @($manifestObject.entries)
if ($entries.Count -lt 1 -or $entries.Count -gt 128) {
    throw 'Wheel corpus must contain 1 through 128 artifacts'
}

$maxArtifactBytes = 512MB
$maxCorpusBytes = 2GB
$declaredTotal = [UInt64]0
$seenFilenames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$seenDigests = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$priorFilename = $null
foreach ($entry in $entries) {
    $project = [string]$entry.project
    $version = [string]$entry.version
    $filename = [string]$entry.filename
    $digest = [string]$entry.sha256
    $size = [UInt64]$entry.size
    $uri = [Uri][string]$entry.url
    if ($project -cnotmatch '^[A-Za-z0-9._+-]+$' -or
        $version -cnotmatch '^[A-Za-z0-9._+!-]+$' -or
        [string]$entry.cohort -cnotmatch '^[A-Za-z0-9._+-]+$' -or
        $filename.Length -gt 1024 -or
        $filename -cnotmatch '^[A-Za-z0-9._-]+\.whl$' -or
        -not $seenFilenames.Add($filename)) {
        throw "Invalid or duplicate wheel filename: $filename"
    }
    if ($null -ne $priorFilename -and
        [StringComparer]::Ordinal.Compare($priorFilename, $filename) -ge 0) {
        throw 'Wheel corpus entries must be strictly sorted by filename'
    }
    $priorFilename = $filename
    if ($digest -cnotmatch '^[0-9a-f]{64}$' -or -not $seenDigests.Add($digest)) {
        throw "Invalid or duplicate wheel digest: $filename"
    }
    if ($size -eq 0 -or $size -gt $maxArtifactBytes) {
        throw "Invalid wheel size: $filename"
    }
    if ($size -gt ($maxCorpusBytes - $declaredTotal)) {
        throw 'Wheel corpus exceeds the 2 GiB acquisition limit'
    }
    $declaredTotal += $size
    if ($uri.Scheme -cne 'https' -or
        $uri.Host -cne 'files.pythonhosted.org' -or
        $uri.Query.Length -ne 0 -or
        $uri.Fragment.Length -ne 0 -or
        -not $uri.AbsolutePath.StartsWith('/packages/', [StringComparison]::Ordinal) -or
        -not $uri.AbsolutePath.EndsWith("/$filename", [StringComparison]::Ordinal)) {
        throw "Wheel URL is outside the pinned PyPI file host: $filename"
    }
    $expectedProvenance = "https://pypi.org/project/$project/$version/#files"
    if ([string]$entry.provenance_url -cne $expectedProvenance) {
        throw "Wheel provenance URL is not exact: $filename"
    }
}

[IO.Directory]::CreateDirectory($cachePath) | Out-Null
$downloaded = 0
$reused = 0
foreach ($entry in $entries) {
    $filename = [string]$entry.filename
    $digest = [string]$entry.sha256
    $size = [UInt64]$entry.size
    $finalPath = Join-Path $cachePath "$digest.whl"
    $partialPath = Join-Path $cachePath "$digest.part"

    if ([IO.File]::Exists($finalPath)) {
        $actual = Get-BoundedFileDigest -Path $finalPath -ExpectedSize $size
        if ($actual.Sha256 -cne $digest) {
            throw "Cached artifact does not match the manifest: $finalPath"
        }
        $reused++
        Write-Host "verified cached $filename"
        continue
    }

    if ([IO.File]::Exists($partialPath)) {
        Remove-Item -LiteralPath $partialPath
    }
    Write-Host "downloading $filename"
    try {
        Invoke-BoundedDownload -Uri ([Uri][string]$entry.url) -Destination $partialPath -ExpectedSize $size
        $actual = Get-BoundedFileDigest -Path $partialPath -ExpectedSize $size
        if ($actual.Sha256 -cne $digest) {
            throw "Downloaded artifact does not match the manifest: $filename"
        }
        Move-Item -LiteralPath $partialPath -Destination $finalPath
        $downloaded++
    }
    catch {
        if ([IO.File]::Exists($partialPath)) {
            Remove-Item -LiteralPath $partialPath
        }
        throw
    }
}

Write-Host "wheel corpus ready: $downloaded downloaded, $reused reused, $declaredTotal bytes"
