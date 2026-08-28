[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $workspace 'fuzz/seed-manifest.json'
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$semanticManifestPath = Join-Path $workspace 'fuzz/semantic-seed-manifest.json'
$semanticManifest = Get-Content -Raw -LiteralPath $semanticManifestPath | ConvertFrom-Json
$tarManifestPath = Join-Path $workspace 'fuzz/tar-seed-manifest.json'
$tarManifest = Get-Content -Raw -LiteralPath $tarManifestPath | ConvertFrom-Json
$tarPaxManifestPath = Join-Path $workspace 'fuzz/tar-pax-seed-manifest.json'
$tarPaxManifest = Get-Content -Raw -LiteralPath $tarPaxManifestPath | ConvertFrom-Json
$tarGnuLongNameManifestPath = Join-Path $workspace 'fuzz/tar-gnu-longname-seed-manifest.json'
$tarGnuLongNameManifest = Get-Content -Raw -LiteralPath $tarGnuLongNameManifestPath | ConvertFrom-Json
$gzipManifestPath = Join-Path $workspace 'fuzz/gzip-seed-manifest.json'
$gzipManifest = Get-Content -Raw -LiteralPath $gzipManifestPath | ConvertFrom-Json
$tarGzipManifestPath = Join-Path $workspace 'fuzz/tar-gzip-seed-manifest.json'
$tarGzipManifest = Get-Content -Raw -LiteralPath $tarGzipManifestPath | ConvertFrom-Json
$tarGzipPaxManifestPath = Join-Path $workspace 'fuzz/tar-gzip-pax-seed-manifest.json'
$tarGzipPaxManifest = Get-Content -Raw -LiteralPath $tarGzipPaxManifestPath | ConvertFrom-Json
$tarGzipGnuLongNameManifestPath = Join-Path $workspace 'fuzz/tar-gzip-gnu-longname-seed-manifest.json'
$tarGzipGnuLongNameManifest = Get-Content -Raw -LiteralPath $tarGzipGnuLongNameManifestPath | ConvertFrom-Json
$tarZstdManifestPath = Join-Path $workspace 'fuzz/tar-zstd-seed-manifest.json'
$tarZstdManifest = Get-Content -Raw -LiteralPath $tarZstdManifestPath | ConvertFrom-Json
$tarXzManifestPath = Join-Path $workspace 'fuzz/tar-xz-seed-manifest.json'
$tarXzManifest = Get-Content -Raw -LiteralPath $tarXzManifestPath | ConvertFrom-Json
$tarBzip2ManifestPath = Join-Path $workspace 'fuzz/tar-bzip2-seed-manifest.json'
$tarBzip2Manifest = Get-Content -Raw -LiteralPath $tarBzip2ManifestPath | ConvertFrom-Json
$zip64ManifestPath = Join-Path $workspace 'fuzz/zip64-seed-manifest.json'
$zip64Manifest = Get-Content -Raw -LiteralPath $zip64ManifestPath | ConvertFrom-Json

if ($manifest.schema -ne 'sealr.fuzz-seeds.v1' -or
    $manifest.target -ne 'protocol_decoders' -or
    $manifest.toolchain -ne 'nightly-2026-08-01' -or
    $manifest.cargoFuzzVersion -ne '0.13.2' -or
    $manifest.libfuzzerSysVersion -ne '0.4.13') {
    throw 'Fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($semanticManifest.schema -ne 'sealr.semantic-fuzz-seeds.v1' -or
    $semanticManifest.target -ne 'semantic_records' -or
    $semanticManifest.toolchain -ne 'nightly-2026-08-01' -or
    $semanticManifest.cargoFuzzVersion -ne '0.13.2' -or
    $semanticManifest.libfuzzerSysVersion -ne '0.4.13') {
    throw 'Semantic fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($tarManifest.schema -ne 'sealr.tar-fuzz-seeds.v1' -or
    $tarManifest.target -ne 'tar_ustar_portable_v1' -or
    $tarManifest.toolchain -ne 'nightly-2026-08-01' -or
    $tarManifest.cargoFuzzVersion -ne '0.13.2' -or
    $tarManifest.libfuzzerSysVersion -ne '0.4.13') {
    throw 'TAR fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($tarPaxManifest.schema -ne 'sealr.tar-pax-fuzz-seeds.v1' -or
    $tarPaxManifest.target -ne 'tar_pax_portable_v1' -or
    $tarPaxManifest.toolchain -ne 'nightly-2026-08-01' -or
    $tarPaxManifest.cargoFuzzVersion -ne '0.13.2' -or
    $tarPaxManifest.libfuzzerSysVersion -ne '0.4.13') {
    throw 'TAR PAX fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($tarGnuLongNameManifest.schema -ne 'sealr.tar-gnu-longname-fuzz-seeds.v1' -or
    $tarGnuLongNameManifest.target -ne 'tar_gnu_longname_portable_v1' -or
    $tarGnuLongNameManifest.toolchain -ne 'nightly-2026-08-01' -or
    $tarGnuLongNameManifest.cargoFuzzVersion -ne '0.13.2' -or
    $tarGnuLongNameManifest.libfuzzerSysVersion -ne '0.4.13' -or
    $tarGnuLongNameManifest.sanitizer -ne 'address') {
    throw 'TAR GNU long-name fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($gzipManifest.schema -ne 'sealr.gzip-fuzz-seeds.v1' -or
    $gzipManifest.target -ne 'gzip_rfc1952_single_member_v1' -or
    $gzipManifest.toolchain -ne 'nightly-2026-08-01' -or
    $gzipManifest.cargoFuzzVersion -ne '0.13.2' -or
    $gzipManifest.libfuzzerSysVersion -ne '0.4.13') {
    throw 'gzip fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($tarGzipManifest.schema -ne 'sealr.tar-gzip-fuzz-seeds.v1' -or
    $tarGzipManifest.target -ne 'tar_gzip_ustar_portable_v1' -or
    $tarGzipManifest.toolchain -ne 'nightly-2026-08-01' -or
    $tarGzipManifest.cargoFuzzVersion -ne '0.13.2' -or
    $tarGzipManifest.libfuzzerSysVersion -ne '0.4.13' -or
    $tarGzipManifest.sanitizer -ne 'address') {
    throw 'TAR/gzip fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($tarGzipPaxManifest.schema -ne 'sealr.tar-gzip-pax-fuzz-seeds.v1' -or
    $tarGzipPaxManifest.target -ne 'tar_gzip_pax_portable_v1' -or
    $tarGzipPaxManifest.toolchain -ne 'nightly-2026-08-01' -or
    $tarGzipPaxManifest.cargoFuzzVersion -ne '0.13.2' -or
    $tarGzipPaxManifest.libfuzzerSysVersion -ne '0.4.13' -or
    $tarGzipPaxManifest.sanitizer -ne 'address') {
    throw 'TAR/gzip PAX fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($tarGzipGnuLongNameManifest.schema -ne 'sealr.tar-gzip-gnu-longname-fuzz-seeds.v1' -or
    $tarGzipGnuLongNameManifest.target -ne 'tar_gzip_gnu_longname_portable_v1' -or
    $tarGzipGnuLongNameManifest.toolchain -ne 'nightly-2026-08-01' -or
    $tarGzipGnuLongNameManifest.cargoFuzzVersion -ne '0.13.2' -or
    $tarGzipGnuLongNameManifest.libfuzzerSysVersion -ne '0.4.13' -or
    $tarGzipGnuLongNameManifest.sanitizer -ne 'address') {
    throw 'TAR/gzip GNU long-name fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($tarZstdManifest.schema -ne 'sealr.tar-zstd-fuzz-seeds.v1' -or
    $tarZstdManifest.target -ne 'tar_zstd_ustar_portable_v1' -or
    $tarZstdManifest.toolchain -ne 'nightly-2026-08-01' -or
    $tarZstdManifest.cargoFuzzVersion -ne '0.13.2' -or
    $tarZstdManifest.libfuzzerSysVersion -ne '0.4.13' -or
    $tarZstdManifest.sanitizer -ne 'address') {
    throw 'TAR/zstd fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($tarXzManifest.schema -ne 'sealr.tar-xz-fuzz-seeds.v1' -or
    $tarXzManifest.target -ne 'tar_xz_ustar_portable_v1' -or
    $tarXzManifest.toolchain -ne 'nightly-2026-08-01' -or
    $tarXzManifest.cargoFuzzVersion -ne '0.13.2' -or
    $tarXzManifest.libfuzzerSysVersion -ne '0.4.13' -or
    $tarXzManifest.sanitizer -ne 'address') {
    throw 'TAR/xz fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($tarBzip2Manifest.schema -ne 'sealr.tar-bzip2-fuzz-seeds.v1' -or
    $tarBzip2Manifest.target -ne 'tar_bzip2_ustar_portable_v1' -or
    $tarBzip2Manifest.toolchain -ne 'nightly-2026-08-01' -or
    $tarBzip2Manifest.cargoFuzzVersion -ne '0.13.2' -or
    $tarBzip2Manifest.libfuzzerSysVersion -ne '0.4.13' -or
    $tarBzip2Manifest.sanitizer -ne 'address') {
    throw 'TAR/bzip2 fuzz manifest identity or pinned tools changed unexpectedly'
}
if ($zip64Manifest.schema -ne 'sealr.zip64-fuzz-seeds.v1' -or
    $zip64Manifest.target -ne 'zip64_strict_ascii_v1' -or
    $zip64Manifest.toolchain -ne 'nightly-2026-08-01' -or
    $zip64Manifest.cargoFuzzVersion -ne '0.13.2' -or
    $zip64Manifest.libfuzzerSysVersion -ne '0.4.13') {
    throw 'ZIP64 fuzz manifest identity or pinned tools changed unexpectedly'
}

$expectedBounds = [ordered]@{
    maxInputBytes = 4194304
    maxTotalSeconds = 600
    perInputTimeoutSeconds = 5
    rssLimitMiB = 1024
    jobs = 1
}
foreach ($name in $expectedBounds.Keys) {
    if ($manifest.bounds.$name -ne $expectedBounds[$name]) {
        throw "Fuzz bound $name changed unexpectedly"
    }
    if ($semanticManifest.bounds.$name -ne $expectedBounds[$name]) {
        throw "Semantic fuzz bound $name changed unexpectedly"
    }
    if ($tarManifest.bounds.$name -ne $expectedBounds[$name]) {
        throw "TAR fuzz bound $name changed unexpectedly"
    }
    if ($tarPaxManifest.bounds.$name -ne $expectedBounds[$name]) {
        throw "TAR PAX fuzz bound $name changed unexpectedly"
    }
    if ($tarGnuLongNameManifest.bounds.$name -ne $expectedBounds[$name]) {
        throw "TAR GNU long-name fuzz bound $name changed unexpectedly"
    }
}
$expectedGzipBounds = [ordered]@{
    maxInputBytes = 1048576
    maxOutputBytes = 65536
    maxMetadataBytes = 4096
    maxTotalSeconds = 600
    perInputTimeoutSeconds = 5
    rssLimitMiB = 1024
    jobs = 1
}
foreach ($name in $expectedGzipBounds.Keys) {
    if ($gzipManifest.bounds.$name -ne $expectedGzipBounds[$name]) {
        throw "gzip fuzz bound $name changed unexpectedly"
    }
}
$expectedTarGzipBounds = [ordered]@{
    maxInputBytes = 262144
    maxDerivedArchiveBytes = 131072
    maxMetadataBytes = 32768
    maxFiles = 64
    maxMemberBytes = 32768
    maxTotalBytes = 65536
    maxPathDepth = 16
    maxRatio = 32
    maxTotalSeconds = 600
    perInputTimeoutSeconds = 5
    rssLimitMiB = 1024
    jobs = 1
}
foreach ($name in $expectedTarGzipBounds.Keys) {
    if ($tarGzipManifest.bounds.$name -ne $expectedTarGzipBounds[$name]) {
        throw "TAR/gzip fuzz bound $name changed unexpectedly"
    }
    if ($tarGzipPaxManifest.bounds.$name -ne $expectedTarGzipBounds[$name]) {
        throw "TAR/gzip PAX fuzz bound $name changed unexpectedly"
    }
    if ($tarGzipGnuLongNameManifest.bounds.$name -ne $expectedTarGzipBounds[$name]) {
        throw "TAR/gzip GNU long-name fuzz bound $name changed unexpectedly"
    }
    if ($tarZstdManifest.bounds.$name -ne $expectedTarGzipBounds[$name]) {
        throw "TAR/zstd fuzz bound $name changed unexpectedly"
    }
    if ($tarXzManifest.bounds.$name -ne $expectedTarGzipBounds[$name]) {
        throw "TAR/xz fuzz bound $name changed unexpectedly"
    }
    if ($tarBzip2Manifest.bounds.$name -ne $expectedTarGzipBounds[$name]) {
        throw "TAR/bzip2 fuzz bound $name changed unexpectedly"
    }
}
$expectedZip64Bounds = [ordered]@{
    maxInputBytes = 1048576
    maxTotalSeconds = 600
    perInputTimeoutSeconds = 5
    rssLimitMiB = 1024
    jobs = 1
}
foreach ($name in $expectedZip64Bounds.Keys) {
    if ($zip64Manifest.bounds.$name -ne $expectedZip64Bounds[$name]) {
        throw "ZIP64 fuzz bound $name changed unexpectedly"
    }
}
if ($manifest.failureArtifact.directoryName -ne 'sealr-fuzz-artifacts' -or
    $manifest.failureArtifact.uploadOn -ne 'failure' -or
    $manifest.failureArtifact.retentionDays -ne 7) {
    throw 'Fuzz failure artifact policy changed unexpectedly'
}
if ($semanticManifest.failureArtifact.directoryName -ne 'sealr-semantic-fuzz-artifacts' -or
    $semanticManifest.failureArtifact.uploadOn -ne 'failure' -or
    $semanticManifest.failureArtifact.retentionDays -ne 7) {
    throw 'Semantic fuzz failure artifact policy changed unexpectedly'
}
if ($tarManifest.failureArtifact.directoryName -ne 'sealr-tar-ustar-fuzz-artifacts' -or
    $tarManifest.failureArtifact.uploadOn -ne 'failure' -or
    $tarManifest.failureArtifact.retentionDays -ne 7) {
    throw 'TAR fuzz failure artifact policy changed unexpectedly'
}
if ($tarPaxManifest.failureArtifact.directoryName -ne 'sealr-tar-pax-fuzz-artifacts' -or
    $tarPaxManifest.failureArtifact.uploadOn -ne 'failure' -or
    $tarPaxManifest.failureArtifact.retentionDays -ne 7) {
    throw 'TAR PAX fuzz failure artifact policy changed unexpectedly'
}
if ($tarGnuLongNameManifest.failureArtifact.directoryName -ne 'sealr-tar-gnu-longname-fuzz-artifacts' -or
    $tarGnuLongNameManifest.failureArtifact.uploadOn -ne 'failure' -or
    $tarGnuLongNameManifest.failureArtifact.retentionDays -ne 7) {
    throw 'TAR GNU long-name fuzz failure artifact policy changed unexpectedly'
}
if ($gzipManifest.failureArtifact.directoryName -ne 'sealr-gzip-fuzz-artifacts' -or
    $gzipManifest.failureArtifact.uploadOn -ne 'failure' -or
    $gzipManifest.failureArtifact.retentionDays -ne 7) {
    throw 'gzip fuzz failure artifact policy changed unexpectedly'
}
if ($tarGzipManifest.failureArtifact.directoryName -ne 'sealr-tar-gzip-fuzz-artifacts' -or
    $tarGzipManifest.failureArtifact.uploadOn -ne 'failure' -or
    $tarGzipManifest.failureArtifact.retentionDays -ne 7) {
    throw 'TAR/gzip fuzz failure artifact policy changed unexpectedly'
}
if ($tarGzipPaxManifest.failureArtifact.directoryName -ne 'sealr-tar-gzip-pax-fuzz-artifacts' -or
    $tarGzipPaxManifest.failureArtifact.uploadOn -ne 'failure' -or
    $tarGzipPaxManifest.failureArtifact.retentionDays -ne 7) {
    throw 'TAR/gzip PAX fuzz failure artifact policy changed unexpectedly'
}
if ($tarGzipGnuLongNameManifest.failureArtifact.directoryName -ne 'sealr-tar-gzip-gnu-longname-fuzz-artifacts' -or
    $tarGzipGnuLongNameManifest.failureArtifact.uploadOn -ne 'failure' -or
    $tarGzipGnuLongNameManifest.failureArtifact.retentionDays -ne 7) {
    throw 'TAR/gzip GNU long-name fuzz failure artifact policy changed unexpectedly'
}
if ($tarZstdManifest.failureArtifact.directoryName -ne 'sealr-tar-zstd-fuzz-artifacts' -or
    $tarZstdManifest.failureArtifact.uploadOn -ne 'failure' -or
    $tarZstdManifest.failureArtifact.retentionDays -ne 7) {
    throw 'TAR/zstd fuzz failure artifact policy changed unexpectedly'
}
if ($tarXzManifest.failureArtifact.directoryName -ne 'sealr-tar-xz-fuzz-artifacts' -or
    $tarXzManifest.failureArtifact.uploadOn -ne 'failure' -or
    $tarXzManifest.failureArtifact.retentionDays -ne 7) {
    throw 'TAR/xz fuzz failure artifact policy changed unexpectedly'
}
if ($tarBzip2Manifest.failureArtifact.directoryName -ne 'sealr-tar-bzip2-fuzz-artifacts' -or
    $tarBzip2Manifest.failureArtifact.uploadOn -ne 'failure' -or
    $tarBzip2Manifest.failureArtifact.retentionDays -ne 7) {
    throw 'TAR/bzip2 fuzz failure artifact policy changed unexpectedly'
}
if ($zip64Manifest.failureArtifact.directoryName -ne 'sealr-zip64-fuzz-artifacts' -or
    $zip64Manifest.failureArtifact.uploadOn -ne 'failure' -or
    $zip64Manifest.failureArtifact.retentionDays -ne 7) {
    throw 'ZIP64 fuzz failure artifact policy changed unexpectedly'
}

function Assert-ManifestFile {
    param(
        [Parameter(Mandatory)] [object] $Entry
    )

    $declaredPath = [string]$Entry.path
    if ([string]::IsNullOrWhiteSpace($declaredPath) -or
        $declaredPath.Contains('\', [StringComparison]::Ordinal) -or
        [IO.Path]::IsPathRooted($declaredPath)) {
        throw "Fuzz manifest path escapes the workspace: $($Entry.path)"
    }

    $workspaceFullPath = [IO.Path]::GetFullPath($workspace)
    $fullPath = [IO.Path]::GetFullPath((Join-Path $workspaceFullPath $declaredPath))
    $relativePath = [IO.Path]::GetRelativePath($workspaceFullPath, $fullPath).Replace('\', '/')
    if ($relativePath -ne $declaredPath -or
        $relativePath -eq '..' -or
        $relativePath.StartsWith('../', [StringComparison]::Ordinal)) {
        throw "Fuzz manifest path escapes the workspace: $($Entry.path)"
    }

    $currentPath = $workspaceFullPath
    foreach ($component in $relativePath.Split('/')) {
        $currentPath = Join-Path $currentPath $component
        $item = Get-Item -LiteralPath $currentPath
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not [string]::IsNullOrEmpty([string]$item.LinkType)) {
            throw "Fuzz manifest path traverses a link or reparse point: $($Entry.path)"
        }
    }

    $file = Get-Item -LiteralPath $fullPath
    if ($file.PSIsContainer) {
        throw "Fuzz manifest entry is not a file: $($Entry.path)"
    }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
    if ($file.Length -ne $Entry.bytes -or $hash -ne $Entry.sha256) {
        throw "Fuzz manifest mismatch for $($Entry.path)"
    }
}

function Assert-TarPaxManifestContract {
    param([Parameter(Mandatory)] [object] $Candidate)

    $rootProperties = @($Candidate.PSObject.Properties.Name | Sort-Object)
    $expectedRootProperties = @(
        'bounds', 'cargoFuzzVersion', 'dictionary', 'failureArtifact', 'generator', 'generatorSource',
        'libfuzzerSysVersion', 'schema', 'seeds', 'target', 'targetSource', 'toolchain'
    ) | Sort-Object
    if (($rootProperties -join "`n") -cne ($expectedRootProperties -join "`n") -or
        $Candidate.schema -cne 'sealr.tar-pax-fuzz-seeds.v1' -or
        $Candidate.target -cne 'tar_pax_portable_v1' -or
        $Candidate.toolchain -cne 'nightly-2026-08-01' -or
        $Candidate.cargoFuzzVersion -cne '0.13.2' -or
        $Candidate.libfuzzerSysVersion -cne '0.4.13' -or
        $Candidate.generator -cne 'fuzz/generate_tar_pax_fuzz_seeds.ps1') {
        throw 'TAR PAX fuzz manifest root contract changed'
    }
    $boundProperties = @($Candidate.bounds.PSObject.Properties.Name | Sort-Object)
    if (($boundProperties -join "`n") -cne ((@($expectedBounds.Keys) | Sort-Object) -join "`n")) {
        throw 'TAR PAX fuzz manifest bound set changed'
    }
    foreach ($name in $expectedBounds.Keys) {
        if ($Candidate.bounds.$name -ne $expectedBounds[$name]) {
            throw "TAR PAX fuzz manifest weakened bound: $name"
        }
    }
    if ((@($Candidate.failureArtifact.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('directoryName', 'retentionDays', 'uploadOn') | Sort-Object) -join "`n") -or
        $Candidate.failureArtifact.directoryName -cne 'sealr-tar-pax-fuzz-artifacts' -or
        $Candidate.failureArtifact.uploadOn -cne 'failure' -or
        $Candidate.failureArtifact.retentionDays -ne 7) {
        throw 'TAR PAX fuzz manifest artifact contract changed'
    }
    if ((@($Candidate.dictionary.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.dictionary.path -cne 'fuzz/dictionaries/tar_pax_portable_v1_dictionary' -or
        $Candidate.dictionary.bytes -ne 173 -or
        $Candidate.dictionary.sha256 -cne 'cce78803c34817aebdb27cd62be6c8908dae1f4084925e183eedc2b4c69e5348') {
        throw 'TAR PAX fuzz manifest dictionary contract changed'
    }
    if ((@($Candidate.targetSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.targetSource.path -cne 'fuzz/fuzz_targets/tar_pax_portable_v1.rs' -or
        $Candidate.targetSource.bytes -ne 126 -or
        $Candidate.targetSource.sha256 -cne 'f404e35b5c034f2af1dbcfd5d7c1b0c90618e363ac3994134cae7816dc673e18') {
        throw 'TAR PAX fuzz manifest target binding changed'
    }
    if ((@($Candidate.generatorSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.generatorSource.path -cne 'fuzz/generate_tar_pax_fuzz_seeds.ps1' -or
        $Candidate.generatorSource.bytes -ne 8628 -or
        $Candidate.generatorSource.sha256 -cne '72cd0863f83a2edb613defbe22f5281e1dc1ca1eadf1dd4abcfb88691050d7c7') {
        throw 'TAR PAX fuzz manifest generator binding changed'
    }
    $seeds = @($Candidate.seeds)
    $seedPaths = @($seeds.path)
    if ($seeds.Count -ne 9 -or
        @($seedPaths | Select-Object -Unique).Count -ne 9 -or
        ($seedPaths -join "`n") -cne (($seedPaths | Sort-Object) -join "`n")) {
        throw 'TAR PAX fuzz manifest seed set is not exact, unique, and sorted'
    }
    foreach ($seed in $seeds) {
        if ((@($seed.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
                ((@('bytes', 'generated', 'path', 'sha256') | Sort-Object) -join "`n") -or
            $seed.generated -isnot [bool] -or -not $seed.generated) {
            throw 'TAR PAX fuzz manifest seed entry contract changed'
        }
    }
}

Assert-TarPaxManifestContract -Candidate $tarPaxManifest

function Assert-TarGnuLongNameManifestContract {
    param([Parameter(Mandatory)] [object] $Candidate)

    $rootProperties = @($Candidate.PSObject.Properties.Name | Sort-Object)
    $expectedRootProperties = @(
        'bounds', 'cargoFuzzVersion', 'dictionary', 'failureArtifact', 'generator', 'generatorSource',
        'libfuzzerSysVersion', 'sanitizer', 'schema', 'seeds', 'target', 'targetSource',
        'toolchain'
    ) | Sort-Object
    if (($rootProperties -join "`n") -cne ($expectedRootProperties -join "`n") -or
        $Candidate.schema -cne 'sealr.tar-gnu-longname-fuzz-seeds.v1' -or
        $Candidate.target -cne 'tar_gnu_longname_portable_v1' -or
        $Candidate.toolchain -cne 'nightly-2026-08-01' -or
        $Candidate.cargoFuzzVersion -cne '0.13.2' -or
        $Candidate.libfuzzerSysVersion -cne '0.4.13' -or
        $Candidate.sanitizer -cne 'address' -or
        $Candidate.generator -cne 'fuzz/generate_tar_gnu_longname_fuzz_seeds.ps1') {
        throw 'TAR GNU long-name fuzz manifest root contract changed'
    }
    $boundProperties = @($Candidate.bounds.PSObject.Properties.Name | Sort-Object)
    if (($boundProperties -join "`n") -cne ((@($expectedBounds.Keys) | Sort-Object) -join "`n")) {
        throw 'TAR GNU long-name fuzz manifest bound set changed'
    }
    foreach ($name in $expectedBounds.Keys) {
        if ($Candidate.bounds.$name -ne $expectedBounds[$name]) {
            throw "TAR GNU long-name fuzz manifest weakened bound: $name"
        }
    }
    if ((@($Candidate.failureArtifact.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('directoryName', 'retentionDays', 'uploadOn') | Sort-Object) -join "`n") -or
        $Candidate.failureArtifact.directoryName -cne 'sealr-tar-gnu-longname-fuzz-artifacts' -or
        $Candidate.failureArtifact.uploadOn -cne 'failure' -or
        $Candidate.failureArtifact.retentionDays -ne 7) {
        throw 'TAR GNU long-name fuzz manifest artifact contract changed'
    }
    if ((@($Candidate.dictionary.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.dictionary.path -cne 'fuzz/dictionaries/tar_gnu_longname_portable_v1_dictionary' -or
        $Candidate.dictionary.bytes -ne 152 -or
        $Candidate.dictionary.sha256 -cne 'b9caadeab7d22894fad357bb54d107b97c8a45a54121de569d8f2cca5eb37390') {
        throw 'TAR GNU long-name fuzz manifest dictionary contract changed'
    }
    if ((@($Candidate.targetSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.targetSource.path -cne 'fuzz/fuzz_targets/tar_gnu_longname_portable_v1.rs' -or
        $Candidate.targetSource.bytes -ne 135 -or
        $Candidate.targetSource.sha256 -cne '9deaaa5c9a2a19370ce9c93e6c7990bba1308ed1107f8bbf03fece2d080bea27') {
        throw 'TAR GNU long-name fuzz manifest target binding changed'
    }
    if ((@($Candidate.generatorSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.generatorSource.path -cne 'fuzz/generate_tar_gnu_longname_fuzz_seeds.ps1' -or
        $Candidate.generatorSource.bytes -ne 9463 -or
        $Candidate.generatorSource.sha256 -cne 'cba8d79fa86f12d4120c361d3699342a4868e61b8466183803d20bb02dbd8324') {
        throw 'TAR GNU long-name fuzz manifest generator binding changed'
    }
    $seeds = @($Candidate.seeds)
    $seedPaths = @($seeds.path)
    if ($seeds.Count -ne 16 -or
        @($seedPaths | Select-Object -Unique).Count -ne 16 -or
        ($seedPaths -join "`n") -cne (($seedPaths | Sort-Object) -join "`n")) {
        throw 'TAR GNU long-name fuzz manifest seed set is not exact, unique, and sorted'
    }
    foreach ($seed in $seeds) {
        if ((@($seed.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
                ((@('bytes', 'generated', 'path', 'sha256') | Sort-Object) -join "`n") -or
            $seed.generated -isnot [bool] -or -not $seed.generated) {
            throw 'TAR GNU long-name fuzz manifest seed entry contract changed'
        }
    }
}

Assert-TarGnuLongNameManifestContract -Candidate $tarGnuLongNameManifest

function Assert-TarGzipManifestContract {
    param([Parameter(Mandatory)] [object] $Candidate)

    $rootProperties = @($Candidate.PSObject.Properties.Name | Sort-Object)
    $expectedRootProperties = @(
        'bounds', 'cargoFuzzVersion', 'dictionary', 'failureArtifact', 'generator', 'generatorSource',
        'libfuzzerSysVersion', 'sanitizer', 'schema', 'seeds', 'target', 'targetSource',
        'toolchain'
    ) | Sort-Object
    if (($rootProperties -join "`n") -cne ($expectedRootProperties -join "`n") -or
        $Candidate.schema -cne 'sealr.tar-gzip-fuzz-seeds.v1' -or
        $Candidate.target -cne 'tar_gzip_ustar_portable_v1' -or
        $Candidate.toolchain -cne 'nightly-2026-08-01' -or
        $Candidate.cargoFuzzVersion -cne '0.13.2' -or
        $Candidate.libfuzzerSysVersion -cne '0.4.13' -or
        $Candidate.sanitizer -cne 'address' -or
        $Candidate.generator -cne 'fuzz/generate_tar_gzip_fuzz_seeds.ps1') {
        throw 'TAR/gzip fuzz manifest root contract changed'
    }
    $boundProperties = @($Candidate.bounds.PSObject.Properties.Name | Sort-Object)
    if (($boundProperties -join "`n") -cne ((@($expectedTarGzipBounds.Keys) | Sort-Object) -join "`n")) {
        throw 'TAR/gzip fuzz manifest bound set changed'
    }
    foreach ($name in $expectedTarGzipBounds.Keys) {
        if ($Candidate.bounds.$name -ne $expectedTarGzipBounds[$name]) {
            throw "TAR/gzip fuzz manifest weakened bound: $name"
        }
    }
    if ((@($Candidate.failureArtifact.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('directoryName', 'retentionDays', 'uploadOn') | Sort-Object) -join "`n") -or
        $Candidate.failureArtifact.directoryName -cne 'sealr-tar-gzip-fuzz-artifacts' -or
        $Candidate.failureArtifact.uploadOn -cne 'failure' -or
        $Candidate.failureArtifact.retentionDays -ne 7) {
        throw 'TAR/gzip fuzz manifest artifact contract changed'
    }
    if ((@($Candidate.dictionary.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.dictionary.path -cne 'fuzz/dictionaries/tar_gzip_ustar_portable_v1_dictionary' -or
        $Candidate.dictionary.bytes -ne 362 -or
        $Candidate.dictionary.sha256 -cne 'f2df7008a03f32d7e35d4b3b40b78d9afc158eda941abe79e4e7877f78711489') {
        throw 'TAR/gzip fuzz manifest dictionary contract changed'
    }
    if ((@($Candidate.targetSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.targetSource.path -cne 'fuzz/fuzz_targets/tar_gzip_ustar_portable_v1.rs' -or
        $Candidate.targetSource.bytes -ne 2755 -or
        $Candidate.targetSource.sha256 -cne '75f99cc5989199bcb95428840abe706d562767d93955b7346291f2ff2ce3cc9d') {
        throw 'TAR/gzip fuzz manifest target binding changed'
    }
    if ((@($Candidate.generatorSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.generatorSource.path -cne 'fuzz/generate_tar_gzip_fuzz_seeds.ps1' -or
        $Candidate.generatorSource.bytes -ne 14491 -or
        $Candidate.generatorSource.sha256 -cne 'e5bb8a3b56a1e167544d06290629ec9ed9dbc75cfccc43b0c95bbecf22618b4a') {
        throw 'TAR/gzip fuzz manifest generator binding changed'
    }
    $seeds = @($Candidate.seeds)
    $seedPaths = @($seeds.path)
    if ($seeds.Count -ne 44 -or
        @($seedPaths | Select-Object -Unique).Count -ne 44 -or
        ($seedPaths -join "`n") -cne (($seedPaths | Sort-Object) -join "`n")) {
        throw 'TAR/gzip fuzz manifest seed set is not exact, unique, and sorted'
    }
    foreach ($seed in $seeds) {
        if ((@($seed.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
                ((@('bytes', 'generated', 'path', 'sha256') | Sort-Object) -join "`n") -or
            $seed.generated -isnot [bool] -or -not $seed.generated) {
            throw 'TAR/gzip fuzz manifest seed entry contract changed'
        }
    }
}

Assert-TarGzipManifestContract -Candidate $tarGzipManifest

function Assert-TarGzipPaxManifestContract {
    param([Parameter(Mandatory)] [object] $Candidate)

    $rootProperties = @($Candidate.PSObject.Properties.Name | Sort-Object)
    $expectedRootProperties = @(
        'bounds', 'cargoFuzzVersion', 'dictionary', 'failureArtifact', 'generator', 'generatorSource',
        'libfuzzerSysVersion', 'sanitizer', 'schema', 'seeds', 'target', 'targetSource',
        'toolchain'
    ) | Sort-Object
    if (($rootProperties -join "`n") -cne ($expectedRootProperties -join "`n") -or
        $Candidate.schema -cne 'sealr.tar-gzip-pax-fuzz-seeds.v1' -or
        $Candidate.target -cne 'tar_gzip_pax_portable_v1' -or
        $Candidate.toolchain -cne 'nightly-2026-08-01' -or
        $Candidate.cargoFuzzVersion -cne '0.13.2' -or
        $Candidate.libfuzzerSysVersion -cne '0.4.13' -or
        $Candidate.sanitizer -cne 'address' -or
        $Candidate.generator -cne 'fuzz/generate_tar_gzip_pax_fuzz_seeds.ps1') {
        throw 'TAR/gzip PAX fuzz manifest root contract changed'
    }
    $boundProperties = @($Candidate.bounds.PSObject.Properties.Name | Sort-Object)
    if (($boundProperties -join "`n") -cne ((@($expectedTarGzipBounds.Keys) | Sort-Object) -join "`n")) {
        throw 'TAR/gzip PAX fuzz manifest bound set changed'
    }
    foreach ($name in $expectedTarGzipBounds.Keys) {
        if ($Candidate.bounds.$name -ne $expectedTarGzipBounds[$name]) {
            throw "TAR/gzip PAX fuzz manifest weakened bound: $name"
        }
    }
    if ((@($Candidate.failureArtifact.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('directoryName', 'retentionDays', 'uploadOn') | Sort-Object) -join "`n") -or
        $Candidate.failureArtifact.directoryName -cne 'sealr-tar-gzip-pax-fuzz-artifacts' -or
        $Candidate.failureArtifact.uploadOn -cne 'failure' -or
        $Candidate.failureArtifact.retentionDays -ne 7) {
        throw 'TAR/gzip PAX fuzz manifest artifact contract changed'
    }
    if ((@($Candidate.dictionary.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.dictionary.path -cne 'fuzz/dictionaries/tar_gzip_pax_portable_v1_dictionary' -or
        $Candidate.dictionary.bytes -ne 481 -or
        $Candidate.dictionary.sha256 -cne '6f310992ad4122c3aad65ece4228b879046b489a3efccf16c77c9079ec13b425') {
        throw 'TAR/gzip PAX fuzz manifest dictionary contract changed'
    }
    if ((@($Candidate.targetSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.targetSource.path -cne 'fuzz/fuzz_targets/tar_gzip_pax_portable_v1.rs' -or
        $Candidate.targetSource.bytes -ne 2747 -or
        $Candidate.targetSource.sha256 -cne '5510b150c3ab01d97f299236397e43038b63e32fef1ac887de727866e760f3ff') {
        throw 'TAR/gzip PAX fuzz manifest target binding changed'
    }
    if ((@($Candidate.generatorSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.generatorSource.path -cne 'fuzz/generate_tar_gzip_pax_fuzz_seeds.ps1' -or
        $Candidate.generatorSource.bytes -ne 13419 -or
        $Candidate.generatorSource.sha256 -cne 'c8889c731d17f2a1a3b5cf0e09bfe322043f51567c5c1c9a7d2c74d314b6cbf4') {
        throw 'TAR/gzip PAX fuzz manifest generator binding changed'
    }
    $seeds = @($Candidate.seeds)
    $seedPaths = @($seeds.path)
    if ($seeds.Count -ne 15 -or
        @($seedPaths | Select-Object -Unique).Count -ne 15 -or
        ($seedPaths -join "`n") -cne (($seedPaths | Sort-Object) -join "`n")) {
        throw 'TAR/gzip PAX fuzz manifest seed set is not exact, unique, and sorted'
    }
    foreach ($seed in $seeds) {
        if ((@($seed.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
                ((@('bytes', 'generated', 'path', 'sha256') | Sort-Object) -join "`n") -or
            $seed.generated -isnot [bool] -or -not $seed.generated) {
            throw 'TAR/gzip PAX fuzz manifest seed entry contract changed'
        }
    }
}

Assert-TarGzipPaxManifestContract -Candidate $tarGzipPaxManifest

function Assert-TarGzipGnuLongNameManifestContract {
    param([Parameter(Mandatory)] [object] $Candidate)

    $rootProperties = @($Candidate.PSObject.Properties.Name | Sort-Object)
    $expectedRootProperties = @(
        'bounds', 'cargoFuzzVersion', 'dictionary', 'failureArtifact', 'generator', 'generatorSource',
        'libfuzzerSysVersion', 'sanitizer', 'schema', 'seeds', 'target', 'targetSource',
        'toolchain'
    ) | Sort-Object
    if (($rootProperties -join "`n") -cne ($expectedRootProperties -join "`n") -or
        $Candidate.schema -cne 'sealr.tar-gzip-gnu-longname-fuzz-seeds.v1' -or
        $Candidate.target -cne 'tar_gzip_gnu_longname_portable_v1' -or
        $Candidate.toolchain -cne 'nightly-2026-08-01' -or
        $Candidate.cargoFuzzVersion -cne '0.13.2' -or
        $Candidate.libfuzzerSysVersion -cne '0.4.13' -or
        $Candidate.sanitizer -cne 'address' -or
        $Candidate.generator -cne 'fuzz/generate_tar_gzip_gnu_longname_fuzz_seeds.ps1') {
        throw 'TAR/gzip GNU long-name fuzz manifest root contract changed'
    }
    $boundProperties = @($Candidate.bounds.PSObject.Properties.Name | Sort-Object)
    if (($boundProperties -join "`n") -cne ((@($expectedTarGzipBounds.Keys) | Sort-Object) -join "`n")) {
        throw 'TAR/gzip GNU long-name fuzz manifest bound set changed'
    }
    foreach ($name in $expectedTarGzipBounds.Keys) {
        if ($Candidate.bounds.$name -ne $expectedTarGzipBounds[$name]) {
            throw "TAR/gzip GNU long-name fuzz manifest weakened bound: $name"
        }
    }
    if ((@($Candidate.failureArtifact.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('directoryName', 'retentionDays', 'uploadOn') | Sort-Object) -join "`n") -or
        $Candidate.failureArtifact.directoryName -cne 'sealr-tar-gzip-gnu-longname-fuzz-artifacts' -or
        $Candidate.failureArtifact.uploadOn -cne 'failure' -or
        $Candidate.failureArtifact.retentionDays -ne 7) {
        throw 'TAR/gzip GNU long-name fuzz manifest artifact contract changed'
    }
    if ((@($Candidate.dictionary.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.dictionary.path -cne 'fuzz/dictionaries/tar_gzip_gnu_longname_portable_v1_dictionary' -or
        $Candidate.dictionary.bytes -ne 401 -or
        $Candidate.dictionary.sha256 -cne '8ebd10a30426d098956f95b292210674820940c866e0023104de19c334e2f22f') {
        throw 'TAR/gzip GNU long-name fuzz manifest dictionary contract changed'
    }
    if ((@($Candidate.targetSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.targetSource.path -cne 'fuzz/fuzz_targets/tar_gzip_gnu_longname_portable_v1.rs' -or
        $Candidate.targetSource.bytes -ne 2781 -or
        $Candidate.targetSource.sha256 -cne '1ea777656777671195c3a25e2ba68d4ca199d204322bafe9c4e1b9ed6a0f83dd') {
        throw 'TAR/gzip GNU long-name fuzz manifest target binding changed'
    }
    if ((@($Candidate.generatorSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.generatorSource.path -cne 'fuzz/generate_tar_gzip_gnu_longname_fuzz_seeds.ps1' -or
        $Candidate.generatorSource.bytes -ne 11543 -or
        $Candidate.generatorSource.sha256 -cne 'a1adad0c9458bea75e57c3f85a07420e44f384de7c01e529de6b2467a9992180') {
        throw 'TAR/gzip GNU long-name fuzz manifest generator binding changed'
    }
    $seeds = @($Candidate.seeds)
    $seedPaths = @($seeds.path)
    if ($seeds.Count -ne 14 -or
        @($seedPaths | Select-Object -Unique).Count -ne 14 -or
        ($seedPaths -join "`n") -cne (($seedPaths | Sort-Object) -join "`n")) {
        throw 'TAR/gzip GNU long-name fuzz manifest seed set is not exact, unique, and sorted'
    }
    foreach ($seed in $seeds) {
        if ((@($seed.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
                ((@('bytes', 'generated', 'path', 'sha256') | Sort-Object) -join "`n") -or
            $seed.generated -isnot [bool] -or -not $seed.generated) {
            throw 'TAR/gzip GNU long-name fuzz manifest seed entry contract changed'
        }
    }
}

Assert-TarGzipGnuLongNameManifestContract -Candidate $tarGzipGnuLongNameManifest

function Assert-TarZstdManifestContract {
    param([Parameter(Mandatory)] [object] $Candidate)

    $rootProperties = @($Candidate.PSObject.Properties.Name | Sort-Object)
    $expectedRootProperties = @(
        'bounds', 'cargoFuzzVersion', 'dictionary', 'failureArtifact', 'generator', 'generatorSource',
        'libfuzzerSysVersion', 'sanitizer', 'schema', 'seeds', 'target', 'targetSource',
        'toolchain'
    ) | Sort-Object
    if (($rootProperties -join "`n") -cne ($expectedRootProperties -join "`n") -or
        $Candidate.schema -cne 'sealr.tar-zstd-fuzz-seeds.v1' -or
        $Candidate.target -cne 'tar_zstd_ustar_portable_v1' -or
        $Candidate.toolchain -cne 'nightly-2026-08-01' -or
        $Candidate.cargoFuzzVersion -cne '0.13.2' -or
        $Candidate.libfuzzerSysVersion -cne '0.4.13' -or
        $Candidate.sanitizer -cne 'address' -or
        $Candidate.generator -cne 'fuzz/generate_tar_zstd_fuzz_seeds.ps1') {
        throw 'TAR/zstd fuzz manifest root contract changed'
    }
    $boundProperties = @($Candidate.bounds.PSObject.Properties.Name | Sort-Object)
    if (($boundProperties -join "`n") -cne ((@($expectedTarGzipBounds.Keys) | Sort-Object) -join "`n")) {
        throw 'TAR/zstd fuzz manifest bound set changed'
    }
    foreach ($name in $expectedTarGzipBounds.Keys) {
        if ($Candidate.bounds.$name -ne $expectedTarGzipBounds[$name]) {
            throw "TAR/zstd fuzz manifest weakened bound: $name"
        }
    }
    if ((@($Candidate.failureArtifact.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('directoryName', 'retentionDays', 'uploadOn') | Sort-Object) -join "`n") -or
        $Candidate.failureArtifact.directoryName -cne 'sealr-tar-zstd-fuzz-artifacts' -or
        $Candidate.failureArtifact.uploadOn -cne 'failure' -or
        $Candidate.failureArtifact.retentionDays -ne 7) {
        throw 'TAR/zstd fuzz manifest artifact contract changed'
    }
    if ((@($Candidate.dictionary.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.dictionary.path -cne 'fuzz/dictionaries/tar_zstd_ustar_portable_v1_dictionary' -or
        $Candidate.dictionary.bytes -ne 434 -or
        $Candidate.dictionary.sha256 -cne '051a6fd9df2b3048dd054c5ed3a45ba183e2fa92dc7ea0d88933441d82f2f61a') {
        throw 'TAR/zstd fuzz manifest dictionary contract changed'
    }
    if ((@($Candidate.targetSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.targetSource.path -cne 'fuzz/fuzz_targets/tar_zstd_ustar_portable_v1.rs' -or
        $Candidate.targetSource.bytes -ne 2756 -or
        $Candidate.targetSource.sha256 -cne '96d479943121a4293a944d5c91eba7f6fae98d66987e906cb340088d133a0e13') {
        throw 'TAR/zstd fuzz manifest target binding changed'
    }
    if ((@($Candidate.generatorSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.generatorSource.path -cne 'fuzz/generate_tar_zstd_fuzz_seeds.ps1' -or
        $Candidate.generatorSource.bytes -ne 10965 -or
        $Candidate.generatorSource.sha256 -cne '3a804db90f58a4c5ba1c94726aa5faa9da04c0db68345112fe9e1ee45302c4d8') {
        throw 'TAR/zstd fuzz manifest generator binding changed'
    }
    $seeds = @($Candidate.seeds)
    $seedPaths = @($seeds.path)
    if ($seeds.Count -ne 15 -or
        @($seedPaths | Select-Object -Unique).Count -ne 15 -or
        ($seedPaths -join "`n") -cne (($seedPaths | Sort-Object) -join "`n")) {
        throw 'TAR/zstd fuzz manifest seed set is not exact, unique, and sorted'
    }
    foreach ($seed in $seeds) {
        if ((@($seed.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
                ((@('bytes', 'generated', 'path', 'sha256') | Sort-Object) -join "`n") -or
            $seed.generated -isnot [bool] -or -not $seed.generated) {
            throw 'TAR/zstd fuzz manifest seed entry contract changed'
        }
    }
}

Assert-TarZstdManifestContract -Candidate $tarZstdManifest

function Assert-TarXzManifestContract {
    param([Parameter(Mandatory)] [object] $Candidate)

    $rootProperties = @($Candidate.PSObject.Properties.Name | Sort-Object)
    $expectedRootProperties = @(
        'bounds', 'cargoFuzzVersion', 'dictionary', 'failureArtifact', 'generator', 'generatorSource',
        'libfuzzerSysVersion', 'sanitizer', 'schema', 'seeds', 'target', 'targetSource',
        'toolchain'
    ) | Sort-Object
    if (($rootProperties -join "`n") -cne ($expectedRootProperties -join "`n") -or
        $Candidate.schema -cne 'sealr.tar-xz-fuzz-seeds.v1' -or
        $Candidate.target -cne 'tar_xz_ustar_portable_v1' -or
        $Candidate.toolchain -cne 'nightly-2026-08-01' -or
        $Candidate.cargoFuzzVersion -cne '0.13.2' -or
        $Candidate.libfuzzerSysVersion -cne '0.4.13' -or
        $Candidate.sanitizer -cne 'address' -or
        $Candidate.generator -cne 'fuzz/generate_tar_xz_fuzz_seeds.ps1') {
        throw 'TAR/xz fuzz manifest root contract changed'
    }
    $boundProperties = @($Candidate.bounds.PSObject.Properties.Name | Sort-Object)
    if (($boundProperties -join "`n") -cne ((@($expectedTarGzipBounds.Keys) | Sort-Object) -join "`n")) {
        throw 'TAR/xz fuzz manifest bound set changed'
    }
    foreach ($name in $expectedTarGzipBounds.Keys) {
        if ($Candidate.bounds.$name -ne $expectedTarGzipBounds[$name]) {
            throw "TAR/xz fuzz manifest weakened bound: $name"
        }
    }
    if ((@($Candidate.failureArtifact.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('directoryName', 'retentionDays', 'uploadOn') | Sort-Object) -join "`n") -or
        $Candidate.failureArtifact.directoryName -cne 'sealr-tar-xz-fuzz-artifacts' -or
        $Candidate.failureArtifact.uploadOn -cne 'failure' -or
        $Candidate.failureArtifact.retentionDays -ne 7) {
        throw 'TAR/xz fuzz manifest artifact contract changed'
    }
    if ((@($Candidate.dictionary.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.dictionary.path -cne 'fuzz/dictionaries/tar_xz_ustar_portable_v1_dictionary' -or
        $Candidate.dictionary.bytes -ne 502 -or
        $Candidate.dictionary.sha256 -cne '4e12ccfefe1f67d8128a39c45b6b9333e325caaa22d259f87e46e4d1bedb6f04') {
        throw 'TAR/xz fuzz manifest dictionary contract changed'
    }
    if ((@($Candidate.targetSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.targetSource.path -cne 'fuzz/fuzz_targets/tar_xz_ustar_portable_v1.rs' -or
        $Candidate.targetSource.bytes -ne 2745 -or
        $Candidate.targetSource.sha256 -cne '842c2c8d967870bf2449342e1e186d4146875c27940ef7ecbc877e264d1a199d') {
        throw 'TAR/xz fuzz manifest target binding changed'
    }
    if ((@($Candidate.generatorSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.generatorSource.path -cne 'fuzz/generate_tar_xz_fuzz_seeds.ps1' -or
        $Candidate.generatorSource.bytes -ne 14175 -or
        $Candidate.generatorSource.sha256 -cne '8640ead4ae32b2e072a3ffe4ec5503cd567f448c8853293fdd777c8226e8b05c') {
        throw 'TAR/xz fuzz manifest generator binding changed'
    }
    $seeds = @($Candidate.seeds)
    $seedPaths = @($seeds.path)
    if ($seeds.Count -ne 17 -or
        @($seedPaths | Select-Object -Unique).Count -ne 17 -or
        ($seedPaths -join "`n") -cne (($seedPaths | Sort-Object) -join "`n")) {
        throw 'TAR/xz fuzz manifest seed set is not exact, unique, and sorted'
    }
    foreach ($seed in $seeds) {
        if ((@($seed.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
                ((@('bytes', 'generated', 'path', 'sha256') | Sort-Object) -join "`n") -or
            $seed.generated -isnot [bool] -or -not $seed.generated) {
            throw 'TAR/xz fuzz manifest seed entry contract changed'
        }
    }
}

Assert-TarXzManifestContract -Candidate $tarXzManifest

function Assert-TarBzip2ManifestContract {
    param([Parameter(Mandatory)] [object] $Candidate)

    $rootProperties = @($Candidate.PSObject.Properties.Name | Sort-Object)
    $expectedRootProperties = @(
        'bounds', 'cargoFuzzVersion', 'dictionary', 'failureArtifact', 'generator', 'generatorSource',
        'libfuzzerSysVersion', 'sanitizer', 'schema', 'seeds', 'target', 'targetSource',
        'toolchain'
    ) | Sort-Object
    if (($rootProperties -join "`n") -cne ($expectedRootProperties -join "`n") -or
        $Candidate.schema -cne 'sealr.tar-bzip2-fuzz-seeds.v1' -or
        $Candidate.target -cne 'tar_bzip2_ustar_portable_v1' -or
        $Candidate.toolchain -cne 'nightly-2026-08-01' -or
        $Candidate.cargoFuzzVersion -cne '0.13.2' -or
        $Candidate.libfuzzerSysVersion -cne '0.4.13' -or
        $Candidate.sanitizer -cne 'address' -or
        $Candidate.generator -cne 'fuzz/generate_tar_bzip2_fuzz_seeds.ps1') {
        throw 'TAR/bzip2 fuzz manifest root contract changed'
    }
    $boundProperties = @($Candidate.bounds.PSObject.Properties.Name | Sort-Object)
    if (($boundProperties -join "`n") -cne ((@($expectedTarGzipBounds.Keys) | Sort-Object) -join "`n")) {
        throw 'TAR/bzip2 fuzz manifest bound set changed'
    }
    foreach ($name in $expectedTarGzipBounds.Keys) {
        if ($Candidate.bounds.$name -ne $expectedTarGzipBounds[$name]) {
            throw "TAR/bzip2 fuzz manifest weakened bound: $name"
        }
    }
    if ((@($Candidate.failureArtifact.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('directoryName', 'retentionDays', 'uploadOn') | Sort-Object) -join "`n") -or
        $Candidate.failureArtifact.directoryName -cne 'sealr-tar-bzip2-fuzz-artifacts' -or
        $Candidate.failureArtifact.uploadOn -cne 'failure' -or
        $Candidate.failureArtifact.retentionDays -ne 7) {
        throw 'TAR/bzip2 fuzz manifest artifact contract changed'
    }
    if ((@($Candidate.dictionary.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.dictionary.path -cne 'fuzz/dictionaries/tar_bzip2_ustar_portable_v1_dictionary' -or
        $Candidate.dictionary.bytes -ne 425 -or
        $Candidate.dictionary.sha256 -cne '370eff71769ecb3fd10a93e71ffe81f6ebbc9686dd6d626816e4d25d6bd7283a') {
        throw 'TAR/bzip2 fuzz manifest dictionary contract changed'
    }
    if ((@($Candidate.targetSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.targetSource.path -cne 'fuzz/fuzz_targets/tar_bzip2_ustar_portable_v1.rs' -or
        $Candidate.targetSource.bytes -ne 2762 -or
        $Candidate.targetSource.sha256 -cne 'abc133cd0667c2ad25129aca31de020346e5a8eb09b382df6c88535de81e041f') {
        throw 'TAR/bzip2 fuzz manifest target binding changed'
    }
    if ((@($Candidate.generatorSource.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
            ((@('bytes', 'path', 'sha256') | Sort-Object) -join "`n") -or
        $Candidate.generatorSource.path -cne 'fuzz/generate_tar_bzip2_fuzz_seeds.ps1' -or
        $Candidate.generatorSource.bytes -ne 6882 -or
        $Candidate.generatorSource.sha256 -cne 'bafed11cd7559e6ef134fcd6ce56cd4cee22c61e62faaa4883b5fa64fd05aced') {
        throw 'TAR/bzip2 fuzz manifest generator binding changed'
    }
    $seeds = @($Candidate.seeds)
    $seedPaths = @($seeds.path)
    if ($seeds.Count -ne 14 -or
        @($seedPaths | Select-Object -Unique).Count -ne 14 -or
        ($seedPaths -join "`n") -cne (($seedPaths | Sort-Object) -join "`n")) {
        throw 'TAR/bzip2 fuzz manifest seed set is not exact, unique, and sorted'
    }
    foreach ($seed in $seeds) {
        if ((@($seed.PSObject.Properties.Name | Sort-Object) -join "`n") -cne
                ((@('bytes', 'generated', 'path', 'sha256') | Sort-Object) -join "`n") -or
            $seed.generated -isnot [bool] -or -not $seed.generated) {
            throw 'TAR/bzip2 fuzz manifest seed entry contract changed'
        }
    }
}

Assert-TarBzip2ManifestContract -Candidate $tarBzip2Manifest

Assert-ManifestFile -Entry $manifest.dictionary
foreach ($seed in $manifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $semanticManifest.dictionary
foreach ($seed in $semanticManifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $tarManifest.dictionary
foreach ($seed in $tarManifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $tarPaxManifest.dictionary
Assert-ManifestFile -Entry $tarPaxManifest.targetSource
Assert-ManifestFile -Entry $tarPaxManifest.generatorSource
foreach ($seed in $tarPaxManifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $tarGnuLongNameManifest.dictionary
Assert-ManifestFile -Entry $tarGnuLongNameManifest.targetSource
Assert-ManifestFile -Entry $tarGnuLongNameManifest.generatorSource
foreach ($seed in $tarGnuLongNameManifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $gzipManifest.dictionary
foreach ($seed in $gzipManifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $tarGzipManifest.dictionary
Assert-ManifestFile -Entry $tarGzipManifest.targetSource
Assert-ManifestFile -Entry $tarGzipManifest.generatorSource
foreach ($seed in $tarGzipManifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $tarGzipPaxManifest.dictionary
Assert-ManifestFile -Entry $tarGzipPaxManifest.targetSource
Assert-ManifestFile -Entry $tarGzipPaxManifest.generatorSource
foreach ($seed in $tarGzipPaxManifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $tarGzipGnuLongNameManifest.dictionary
Assert-ManifestFile -Entry $tarGzipGnuLongNameManifest.targetSource
Assert-ManifestFile -Entry $tarGzipGnuLongNameManifest.generatorSource
foreach ($seed in $tarGzipGnuLongNameManifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $tarZstdManifest.dictionary
Assert-ManifestFile -Entry $tarZstdManifest.targetSource
Assert-ManifestFile -Entry $tarZstdManifest.generatorSource
foreach ($seed in $tarZstdManifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $tarXzManifest.dictionary
Assert-ManifestFile -Entry $tarXzManifest.targetSource
Assert-ManifestFile -Entry $tarXzManifest.generatorSource
foreach ($seed in $tarXzManifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $tarBzip2Manifest.dictionary
Assert-ManifestFile -Entry $tarBzip2Manifest.targetSource
Assert-ManifestFile -Entry $tarBzip2Manifest.generatorSource
foreach ($seed in $tarBzip2Manifest.seeds) {
    Assert-ManifestFile -Entry $seed
}
Assert-ManifestFile -Entry $zip64Manifest.dictionary
foreach ($seed in $zip64Manifest.seeds) {
    Assert-ManifestFile -Entry $seed
}

$corpusRoot = Join-Path $workspace 'fuzz/corpus/protocol_decoders'
$actualSeeds = @(
    Get-ChildItem -LiteralPath $corpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredSeeds = @($manifest.seeds.path | Sort-Object)
if ($actualSeeds.Count -ne $declaredSeeds.Count -or
    @(Compare-Object $actualSeeds $declaredSeeds).Count -ne 0) {
    throw 'Fuzz corpus and seed manifest contain different paths'
}
$semanticCorpusRoot = Join-Path $workspace 'fuzz/corpus/semantic_records'
$actualSemanticSeeds = @(
    Get-ChildItem -LiteralPath $semanticCorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredSemanticSeeds = @($semanticManifest.seeds.path | Sort-Object)
if ($actualSemanticSeeds.Count -ne $declaredSemanticSeeds.Count -or
    @(Compare-Object $actualSemanticSeeds $declaredSemanticSeeds).Count -ne 0) {
    throw 'Semantic fuzz corpus and seed manifest contain different paths'
}
$tarCorpusRoot = Join-Path $workspace 'fuzz/corpus/tar_ustar_portable_v1'
$actualTarSeeds = @(
    Get-ChildItem -LiteralPath $tarCorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredTarSeeds = @($tarManifest.seeds.path | Sort-Object)
if ($actualTarSeeds.Count -ne $declaredTarSeeds.Count -or
    @(Compare-Object $actualTarSeeds $declaredTarSeeds).Count -ne 0) {
    throw 'TAR fuzz corpus and seed manifest contain different paths'
}
$tarPaxCorpusRoot = Join-Path $workspace 'fuzz/corpus/tar_pax_portable_v1'
$actualTarPaxSeeds = @(
    Get-ChildItem -LiteralPath $tarPaxCorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredTarPaxSeeds = @($tarPaxManifest.seeds.path | Sort-Object)
if ($actualTarPaxSeeds.Count -ne $declaredTarPaxSeeds.Count -or
    @(Compare-Object $actualTarPaxSeeds $declaredTarPaxSeeds).Count -ne 0) {
    throw 'TAR PAX fuzz corpus and seed manifest contain different paths'
}
$tarGnuLongNameCorpusRoot = Join-Path $workspace 'fuzz/corpus/tar_gnu_longname_portable_v1'
$actualTarGnuLongNameSeeds = @(
    Get-ChildItem -LiteralPath $tarGnuLongNameCorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredTarGnuLongNameSeeds = @($tarGnuLongNameManifest.seeds.path | Sort-Object)
if ($actualTarGnuLongNameSeeds.Count -ne $declaredTarGnuLongNameSeeds.Count -or
    @(Compare-Object $actualTarGnuLongNameSeeds $declaredTarGnuLongNameSeeds).Count -ne 0) {
    throw 'TAR GNU long-name fuzz corpus and seed manifest contain different paths'
}
$gzipCorpusRoot = Join-Path $workspace 'fuzz/corpus/gzip_rfc1952_single_member_v1'
$actualGzipSeeds = @(
    Get-ChildItem -LiteralPath $gzipCorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredGzipSeeds = @($gzipManifest.seeds.path | Sort-Object)
if ($actualGzipSeeds.Count -ne $declaredGzipSeeds.Count -or
    @(Compare-Object $actualGzipSeeds $declaredGzipSeeds).Count -ne 0) {
    throw 'gzip fuzz corpus and seed manifest contain different paths'
}
$tarGzipCorpusRoot = Join-Path $workspace 'fuzz/corpus/tar_gzip_ustar_portable_v1'
$actualTarGzipSeeds = @(
    Get-ChildItem -LiteralPath $tarGzipCorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredTarGzipSeeds = @($tarGzipManifest.seeds.path | Sort-Object)
if ($actualTarGzipSeeds.Count -ne $declaredTarGzipSeeds.Count -or
    @(Compare-Object $actualTarGzipSeeds $declaredTarGzipSeeds).Count -ne 0) {
    throw 'TAR/gzip fuzz corpus and seed manifest contain different paths'
}
$tarGzipPaxCorpusRoot = Join-Path $workspace 'fuzz/corpus/tar_gzip_pax_portable_v1'
$actualTarGzipPaxSeeds = @(
    Get-ChildItem -LiteralPath $tarGzipPaxCorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredTarGzipPaxSeeds = @($tarGzipPaxManifest.seeds.path | Sort-Object)
if ($actualTarGzipPaxSeeds.Count -ne $declaredTarGzipPaxSeeds.Count -or
    @(Compare-Object $actualTarGzipPaxSeeds $declaredTarGzipPaxSeeds).Count -ne 0) {
    throw 'TAR/gzip PAX fuzz corpus and seed manifest contain different paths'
}
$tarGzipGnuLongNameCorpusRoot = Join-Path $workspace 'fuzz/corpus/tar_gzip_gnu_longname_portable_v1'
$actualTarGzipGnuLongNameSeeds = @(
    Get-ChildItem -LiteralPath $tarGzipGnuLongNameCorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredTarGzipGnuLongNameSeeds = @($tarGzipGnuLongNameManifest.seeds.path | Sort-Object)
if ($actualTarGzipGnuLongNameSeeds.Count -ne $declaredTarGzipGnuLongNameSeeds.Count -or
    @(Compare-Object $actualTarGzipGnuLongNameSeeds $declaredTarGzipGnuLongNameSeeds).Count -ne 0) {
    throw 'TAR/gzip GNU long-name fuzz corpus and seed manifest contain different paths'
}
$tarZstdCorpusRoot = Join-Path $workspace 'fuzz/corpus/tar_zstd_ustar_portable_v1'
$actualTarZstdSeeds = @(
    Get-ChildItem -LiteralPath $tarZstdCorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredTarZstdSeeds = @($tarZstdManifest.seeds.path | Sort-Object)
if ($actualTarZstdSeeds.Count -ne $declaredTarZstdSeeds.Count -or
    @(Compare-Object $actualTarZstdSeeds $declaredTarZstdSeeds).Count -ne 0) {
    throw 'TAR/zstd fuzz corpus and seed manifest contain different paths'
}
$tarXzCorpusRoot = Join-Path $workspace 'fuzz/corpus/tar_xz_ustar_portable_v1'
$actualTarXzSeeds = @(
    Get-ChildItem -LiteralPath $tarXzCorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredTarXzSeeds = @($tarXzManifest.seeds.path | Sort-Object)
if ($actualTarXzSeeds.Count -ne $declaredTarXzSeeds.Count -or
    @(Compare-Object $actualTarXzSeeds $declaredTarXzSeeds).Count -ne 0) {
    throw 'TAR/xz fuzz corpus and seed manifest contain different paths'
}
$tarBzip2CorpusRoot = Join-Path $workspace 'fuzz/corpus/tar_bzip2_ustar_portable_v1'
$actualTarBzip2Seeds = @(
    Get-ChildItem -LiteralPath $tarBzip2CorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredTarBzip2Seeds = @($tarBzip2Manifest.seeds.path | Sort-Object)
if ($actualTarBzip2Seeds.Count -ne $declaredTarBzip2Seeds.Count -or
    @(Compare-Object $actualTarBzip2Seeds $declaredTarBzip2Seeds).Count -ne 0) {
    throw 'TAR/bzip2 fuzz corpus and seed manifest contain different paths'
}
$zip64CorpusRoot = Join-Path $workspace 'fuzz/corpus/zip64_strict_ascii_v1'
$actualZip64Seeds = @(
    Get-ChildItem -LiteralPath $zip64CorpusRoot -File |
        ForEach-Object { [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/') } |
        Sort-Object
)
$declaredZip64Seeds = @($zip64Manifest.seeds.path | Sort-Object)
if ($actualZip64Seeds.Count -ne $declaredZip64Seeds.Count -or
    @(Compare-Object $actualZip64Seeds $declaredZip64Seeds).Count -ne 0) {
    throw 'ZIP64 fuzz corpus and seed manifest contain different paths'
}

if ([string]$tarManifest.generator -cne 'scripts/generate_tar_fuzz_seeds.ps1') {
    throw 'TAR fuzz seed generator path changed unexpectedly'
}

if ([string]$gzipManifest.generator -cne 'scripts/generate_gzip_fuzz_seeds.ps1') {
    throw 'gzip fuzz seed generator path changed unexpectedly'
}
$generatedGzipSeeds = @(
    $gzipManifest.seeds | Where-Object { $_.generated -is [bool] -and $_.generated }
)
if ($generatedGzipSeeds.Count -ne 27 -or
    @($gzipManifest.seeds | Where-Object { $_.generated -isnot [bool] }).Count -ne 0 -or
    @($gzipManifest.seeds | Where-Object { $_.generated -is [bool] -and -not $_.generated }).Count -ne 0) {
    throw 'gzip fuzz seeds must classify exactly 27 generated entries'
}
$gzipGenerator = Join-Path $workspace ([string]$gzipManifest.generator)
$gzipGenerationRoot = Join-Path (
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
) ("sealr-gzip-fuzz-seeds-{0}" -f [Guid]::NewGuid().ToString('N'))
try {
    & $gzipGenerator -OutputDirectory $gzipGenerationRoot
    $actualGeneratedGzipNames = @(
        Get-ChildItem -LiteralPath $gzipGenerationRoot -File |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedGeneratedGzipNames = @(
        $generatedGzipSeeds.path |
            ForEach-Object { [IO.Path]::GetFileName([string]$_) } |
            Sort-Object
    )
    if ($actualGeneratedGzipNames.Count -ne $expectedGeneratedGzipNames.Count -or
        @(Compare-Object $actualGeneratedGzipNames $expectedGeneratedGzipNames).Count -ne 0) {
        throw 'gzip fuzz seed generator produced a different exact file set'
    }
    foreach ($entry in $generatedGzipSeeds) {
        $generatedPath = Join-Path $gzipGenerationRoot ([IO.Path]::GetFileName([string]$entry.path))
        $generatedFile = Get-Item -LiteralPath $generatedPath
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
        if ($generatedFile.Length -ne $entry.bytes -or $generatedHash -cne [string]$entry.sha256) {
            throw "gzip fuzz seed generator did not reproduce $($entry.path)"
        }
    }
} finally {
    if (Test-Path -LiteralPath $gzipGenerationRoot) {
        $resolvedGenerationRoot = [IO.Path]::GetFullPath($gzipGenerationRoot)
        $generationParent = [IO.Path]::GetDirectoryName($resolvedGenerationRoot)
        $generationLeaf = [IO.Path]::GetFileName($resolvedGenerationRoot)
        $expectedTemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ($generationParent -cne $expectedTemporaryParent -or
            $generationLeaf -notmatch '^sealr-gzip-fuzz-seeds-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected gzip fuzz generation path: $resolvedGenerationRoot"
        }
        Remove-Item -LiteralPath $resolvedGenerationRoot -Recurse -Force
    }
}
if ([string]$tarGzipManifest.generator -cne 'fuzz/generate_tar_gzip_fuzz_seeds.ps1') {
    throw 'TAR/gzip fuzz seed generator path changed unexpectedly'
}
$generatedTarGzipSeeds = @(
    $tarGzipManifest.seeds | Where-Object { $_.generated -is [bool] -and $_.generated }
)
if ($generatedTarGzipSeeds.Count -ne 44 -or
    @($tarGzipManifest.seeds | Where-Object { $_.generated -isnot [bool] }).Count -ne 0 -or
    @($tarGzipManifest.seeds | Where-Object { $_.generated -is [bool] -and -not $_.generated }).Count -ne 0) {
    throw 'TAR/gzip fuzz seeds must classify exactly 44 generated entries'
}
$requiredTarGzipSeeds = @(
    'valid-conformance-optional-dynamic'
    'valid-conformance-minimal-stored'
    'valid-fixed-deflate'
    'valid-all-optional-fixed'
    'invalid-extra-duplicate-id'
    'concatenated-two-members'
    'concatenated-three-members'
    'derived-non-tar'
    'wrapped-path-traversal'
    'wrapped-duplicate-path'
    'resource-derived-and-ratio-over-cap'
    'resource-member-over-cap'
    'resource-ratio-over-cap'
    'resource-total-over-cap'
    'resource-files-and-metadata-over-cap'
    'resource-wrapper-metadata-over-cap'
)
$actualTarGzipSeedNames = @(
    $tarGzipManifest.seeds.path |
        ForEach-Object { [IO.Path]::GetFileName([string]$_) }
)
foreach ($requiredSeed in $requiredTarGzipSeeds) {
    if (@($actualTarGzipSeedNames | Where-Object { $_ -ceq $requiredSeed }).Count -ne 1) {
        throw "TAR/gzip corpus must contain exactly one required seed: $requiredSeed"
    }
}
$tarGzipGenerator = Join-Path $workspace ([string]$tarGzipManifest.generator)
$tarGzipGenerationRoot = Join-Path (
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
) ("sealr-tar-gzip-fuzz-seeds-{0}" -f [Guid]::NewGuid().ToString('N'))
try {
    & $tarGzipGenerator -OutputDirectory $tarGzipGenerationRoot
    $actualGeneratedTarGzipNames = @(
        Get-ChildItem -LiteralPath $tarGzipGenerationRoot -File |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedGeneratedTarGzipNames = @(
        $generatedTarGzipSeeds.path |
            ForEach-Object { [IO.Path]::GetFileName([string]$_) } |
            Sort-Object
    )
    if ($actualGeneratedTarGzipNames.Count -ne $expectedGeneratedTarGzipNames.Count -or
        @(Compare-Object $actualGeneratedTarGzipNames $expectedGeneratedTarGzipNames).Count -ne 0) {
        throw 'TAR/gzip fuzz seed generator produced a different exact file set'
    }
    foreach ($entry in $generatedTarGzipSeeds) {
        $generatedPath = Join-Path $tarGzipGenerationRoot ([IO.Path]::GetFileName([string]$entry.path))
        $generatedFile = Get-Item -LiteralPath $generatedPath
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
        if ($generatedFile.Length -ne $entry.bytes -or $generatedHash -cne [string]$entry.sha256) {
            throw "TAR/gzip fuzz seed generator did not reproduce $($entry.path)"
        }
    }
} finally {
    if (Test-Path -LiteralPath $tarGzipGenerationRoot) {
        $resolvedTarGzipGenerationRoot = [IO.Path]::GetFullPath($tarGzipGenerationRoot)
        $generationParent = [IO.Path]::GetDirectoryName($resolvedTarGzipGenerationRoot)
        $generationLeaf = [IO.Path]::GetFileName($resolvedTarGzipGenerationRoot)
        $expectedTemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ($generationParent -cne $expectedTemporaryParent -or
            $generationLeaf -notmatch '^sealr-tar-gzip-fuzz-seeds-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected TAR/gzip fuzz generation path: $resolvedTarGzipGenerationRoot"
        }
        Remove-Item -LiteralPath $resolvedTarGzipGenerationRoot -Recurse -Force
    }
}
if ([string]$tarGzipPaxManifest.generator -cne 'fuzz/generate_tar_gzip_pax_fuzz_seeds.ps1') {
    throw 'TAR/gzip PAX fuzz seed generator path changed unexpectedly'
}
$generatedTarGzipPaxSeeds = @(
    $tarGzipPaxManifest.seeds | Where-Object { $_.generated -is [bool] -and $_.generated }
)
if ($generatedTarGzipPaxSeeds.Count -ne 15 -or
    @($tarGzipPaxManifest.seeds | Where-Object { $_.generated -isnot [bool] }).Count -ne 0 -or
    @($tarGzipPaxManifest.seeds | Where-Object { $_.generated -is [bool] -and -not $_.generated }).Count -ne 0) {
    throw 'TAR/gzip PAX fuzz seeds must classify exactly 15 generated entries'
}
$requiredTarGzipPaxSeeds = @(
    'invalid-extension-over-cap'
    'invalid-malformed-record-length'
    'invalid-orphan-local'
    'invalid-wrapper-bad-data-crc'
    'invalid-wrapper-concatenated-members'
    'invalid-wrapper-trailing-byte'
    'resource-derived-over-cap'
    'unsupported-gnu-longlink-carrier'
    'unsupported-keyword'
    'valid-all-optional-stored'
    'valid-empty-pax'
    'valid-global-local-precedence'
    'valid-local-path-size'
    'valid-ordinary-ustar-subset'
    'valid-quota-boundary-two-files'
)
$actualTarGzipPaxSeedNames = @(
    $tarGzipPaxManifest.seeds.path |
        ForEach-Object { [IO.Path]::GetFileName([string]$_) }
)
foreach ($requiredSeed in $requiredTarGzipPaxSeeds) {
    if (@($actualTarGzipPaxSeedNames | Where-Object { $_ -ceq $requiredSeed }).Count -ne 1) {
        throw "TAR/gzip PAX corpus must contain exactly one required seed: $requiredSeed"
    }
}
$tarGzipPaxGenerator = Join-Path $workspace ([string]$tarGzipPaxManifest.generator)
$tarGzipPaxGenerationRoot = Join-Path (
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
) ("sealr-tar-gzip-pax-fuzz-seeds-{0}" -f [Guid]::NewGuid().ToString('N'))
try {
    & $tarGzipPaxGenerator -OutputDirectory $tarGzipPaxGenerationRoot
    $actualGeneratedTarGzipPaxNames = @(
        Get-ChildItem -LiteralPath $tarGzipPaxGenerationRoot -File |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedGeneratedTarGzipPaxNames = @(
        $generatedTarGzipPaxSeeds.path |
            ForEach-Object { [IO.Path]::GetFileName([string]$_) } |
            Sort-Object
    )
    if ($actualGeneratedTarGzipPaxNames.Count -ne $expectedGeneratedTarGzipPaxNames.Count -or
        @(Compare-Object $actualGeneratedTarGzipPaxNames $expectedGeneratedTarGzipPaxNames).Count -ne 0) {
        throw 'TAR/gzip PAX fuzz seed generator produced a different exact file set'
    }
    foreach ($entry in $generatedTarGzipPaxSeeds) {
        $generatedPath = Join-Path $tarGzipPaxGenerationRoot ([IO.Path]::GetFileName([string]$entry.path))
        $generatedFile = Get-Item -LiteralPath $generatedPath
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
        if ($generatedFile.Length -ne $entry.bytes -or $generatedHash -cne [string]$entry.sha256) {
            throw "TAR/gzip PAX fuzz seed generator did not reproduce $($entry.path)"
        }
    }
} finally {
    if (Test-Path -LiteralPath $tarGzipPaxGenerationRoot) {
        $resolvedTarGzipPaxGenerationRoot = [IO.Path]::GetFullPath($tarGzipPaxGenerationRoot)
        $generationParent = [IO.Path]::GetDirectoryName($resolvedTarGzipPaxGenerationRoot)
        $generationLeaf = [IO.Path]::GetFileName($resolvedTarGzipPaxGenerationRoot)
        $expectedTemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ($generationParent -cne $expectedTemporaryParent -or
            $generationLeaf -notmatch '^sealr-tar-gzip-pax-fuzz-seeds-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected TAR/gzip PAX fuzz generation path: $resolvedTarGzipPaxGenerationRoot"
        }
        Remove-Item -LiteralPath $resolvedTarGzipPaxGenerationRoot -Recurse -Force
    }
}
if ([string]$tarGzipGnuLongNameManifest.generator -cne 'fuzz/generate_tar_gzip_gnu_longname_fuzz_seeds.ps1') {
    throw 'TAR/gzip GNU long-name fuzz seed generator path changed unexpectedly'
}
$generatedTarGzipGnuLongNameSeeds = @(
    $tarGzipGnuLongNameManifest.seeds |
        Where-Object { $_.generated -is [bool] -and $_.generated }
)
if ($generatedTarGzipGnuLongNameSeeds.Count -ne 14 -or
    @($tarGzipGnuLongNameManifest.seeds | Where-Object { $_.generated -isnot [bool] }).Count -ne 0 -or
    @($tarGzipGnuLongNameManifest.seeds | Where-Object { $_.generated -is [bool] -and -not $_.generated }).Count -ne 0) {
    throw 'TAR/gzip GNU long-name fuzz seeds must classify exactly 14 generated entries'
}
$requiredTarGzipGnuLongNameSeeds = @(
    'invalid-chained-carrier'
    'invalid-orphan-carrier'
    'invalid-oversized-carrier'
    'invalid-wrapper-bad-data-crc'
    'invalid-wrapper-concatenated-members'
    'invalid-wrapper-trailing-byte'
    'resource-derived-over-cap'
    'unsupported-long-link-k'
    'unsupported-sparse'
    'valid-all-optional-stored'
    'valid-empty-oldgnu'
    'valid-gnu-longlink'
    'valid-ordinary-oldgnu'
    'valid-two-carrier-pairs'
)
$actualTarGzipGnuLongNameSeedNames = @(
    $tarGzipGnuLongNameManifest.seeds.path |
        ForEach-Object { [IO.Path]::GetFileName([string]$_) }
)
foreach ($requiredSeed in $requiredTarGzipGnuLongNameSeeds) {
    if (@($actualTarGzipGnuLongNameSeedNames | Where-Object { $_ -ceq $requiredSeed }).Count -ne 1) {
        throw "TAR/gzip GNU long-name corpus must contain exactly one required seed: $requiredSeed"
    }
}
$tarGzipGnuLongNameGenerator = Join-Path $workspace ([string]$tarGzipGnuLongNameManifest.generator)
$tarGzipGnuLongNameGenerationRoot = Join-Path (
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
) ("sealr-tar-gzip-gnu-longname-fuzz-seeds-{0}" -f [Guid]::NewGuid().ToString('N'))
try {
    & $tarGzipGnuLongNameGenerator -OutputDirectory $tarGzipGnuLongNameGenerationRoot
    $actualGeneratedTarGzipGnuLongNameNames = @(
        Get-ChildItem -LiteralPath $tarGzipGnuLongNameGenerationRoot -File |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedGeneratedTarGzipGnuLongNameNames = @(
        $generatedTarGzipGnuLongNameSeeds.path |
            ForEach-Object { [IO.Path]::GetFileName([string]$_) } |
            Sort-Object
    )
    if ($actualGeneratedTarGzipGnuLongNameNames.Count -ne $expectedGeneratedTarGzipGnuLongNameNames.Count -or
        @(Compare-Object $actualGeneratedTarGzipGnuLongNameNames $expectedGeneratedTarGzipGnuLongNameNames).Count -ne 0) {
        throw 'TAR/gzip GNU long-name fuzz seed generator produced a different exact file set'
    }
    foreach ($entry in $generatedTarGzipGnuLongNameSeeds) {
        $generatedPath = Join-Path $tarGzipGnuLongNameGenerationRoot ([IO.Path]::GetFileName([string]$entry.path))
        $generatedFile = Get-Item -LiteralPath $generatedPath
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
        if ($generatedFile.Length -ne $entry.bytes -or $generatedHash -cne [string]$entry.sha256) {
            throw "TAR/gzip GNU long-name fuzz seed generator did not reproduce $($entry.path)"
        }
    }
} finally {
    if (Test-Path -LiteralPath $tarGzipGnuLongNameGenerationRoot) {
        $resolvedTarGzipGnuLongNameGenerationRoot = [IO.Path]::GetFullPath($tarGzipGnuLongNameGenerationRoot)
        $generationParent = [IO.Path]::GetDirectoryName($resolvedTarGzipGnuLongNameGenerationRoot)
        $generationLeaf = [IO.Path]::GetFileName($resolvedTarGzipGnuLongNameGenerationRoot)
        $expectedTemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ($generationParent -cne $expectedTemporaryParent -or
            $generationLeaf -notmatch '^sealr-tar-gzip-gnu-longname-fuzz-seeds-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected TAR/gzip GNU long-name fuzz generation path: $resolvedTarGzipGnuLongNameGenerationRoot"
        }
        Remove-Item -LiteralPath $resolvedTarGzipGnuLongNameGenerationRoot -Recurse -Force
    }
}
if ([string]$tarZstdManifest.generator -cne 'fuzz/generate_tar_zstd_fuzz_seeds.ps1') {
    throw 'TAR/zstd fuzz seed generator path changed unexpectedly'
}
$generatedTarZstdSeeds = @(
    $tarZstdManifest.seeds | Where-Object { $_.generated -is [bool] -and $_.generated }
)
if ($generatedTarZstdSeeds.Count -ne 15 -or
    @($tarZstdManifest.seeds | Where-Object { $_.generated -isnot [bool] }).Count -ne 0 -or
    @($tarZstdManifest.seeds | Where-Object { $_.generated -is [bool] -and -not $_.generated }).Count -ne 0) {
    throw 'TAR/zstd fuzz seeds must classify exactly 15 generated entries'
}
$requiredTarZstdSeeds = @(
    'invalid-checksum-lie'
    'invalid-concatenated-frames'
    'invalid-fcs-lie'
    'invalid-inner-not-tar'
    'invalid-trailing-byte'
    'resource-derived-over-cap'
    'unsupported-dictionary-bit'
    'unsupported-skippable-frame'
    'unsupported-window-over-cap'
    'valid-cli-default-single-segment'
    'valid-cli-level19-single-segment'
    'valid-empty-ustar-windowed'
    'valid-ordinary-ustar-windowed'
    'valid-single-segment-fcs'
    'valid-two-raw-blocks'
)
$actualTarZstdSeedNames = @(
    $tarZstdManifest.seeds.path |
        ForEach-Object { [IO.Path]::GetFileName([string]$_) }
)
foreach ($requiredSeed in $requiredTarZstdSeeds) {
    if (@($actualTarZstdSeedNames | Where-Object { $_ -ceq $requiredSeed }).Count -ne 1) {
        throw "TAR/zstd corpus must contain exactly one required seed: $requiredSeed"
    }
}
$tarZstdGenerator = Join-Path $workspace ([string]$tarZstdManifest.generator)
$tarZstdGenerationRoot = Join-Path (
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
) ("sealr-tar-zstd-fuzz-seeds-{0}" -f [Guid]::NewGuid().ToString('N'))
try {
    & $tarZstdGenerator -OutputDirectory $tarZstdGenerationRoot
    $actualGeneratedTarZstdNames = @(
        Get-ChildItem -LiteralPath $tarZstdGenerationRoot -File |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedGeneratedTarZstdNames = @(
        $generatedTarZstdSeeds.path |
            ForEach-Object { [IO.Path]::GetFileName([string]$_) } |
            Sort-Object
    )
    if ($actualGeneratedTarZstdNames.Count -ne $expectedGeneratedTarZstdNames.Count -or
        @(Compare-Object $actualGeneratedTarZstdNames $expectedGeneratedTarZstdNames).Count -ne 0) {
        throw 'TAR/zstd fuzz seed generator produced a different exact file set'
    }
    foreach ($entry in $generatedTarZstdSeeds) {
        $generatedPath = Join-Path $tarZstdGenerationRoot ([IO.Path]::GetFileName([string]$entry.path))
        $generatedFile = Get-Item -LiteralPath $generatedPath
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
        if ($generatedFile.Length -ne $entry.bytes -or $generatedHash -cne [string]$entry.sha256) {
            throw "TAR/zstd fuzz seed generator did not reproduce $($entry.path)"
        }
    }
} finally {
    if (Test-Path -LiteralPath $tarZstdGenerationRoot) {
        $resolvedTarZstdGenerationRoot = [IO.Path]::GetFullPath($tarZstdGenerationRoot)
        $generationParent = [IO.Path]::GetDirectoryName($resolvedTarZstdGenerationRoot)
        $generationLeaf = [IO.Path]::GetFileName($resolvedTarZstdGenerationRoot)
        $expectedTemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ($generationParent -cne $expectedTemporaryParent -or
            $generationLeaf -notmatch '^sealr-tar-zstd-fuzz-seeds-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected TAR/zstd fuzz generation path: $resolvedTarZstdGenerationRoot"
        }
        Remove-Item -LiteralPath $resolvedTarZstdGenerationRoot -Recurse -Force
    }
}
if ([string]$tarXzManifest.generator -cne 'fuzz/generate_tar_xz_fuzz_seeds.ps1') {
    throw 'TAR/xz fuzz seed generator path changed unexpectedly'
}
$generatedTarXzSeeds = @(
    $tarXzManifest.seeds | Where-Object { $_.generated -is [bool] -and $_.generated }
)
if ($generatedTarXzSeeds.Count -ne 17 -or
    @($tarXzManifest.seeds | Where-Object { $_.generated -isnot [bool] }).Count -ne 0 -or
    @($tarXzManifest.seeds | Where-Object { $_.generated -is [bool] -and -not $_.generated }).Count -ne 0) {
    throw 'TAR/xz fuzz seeds must classify exactly 17 generated entries'
}
$requiredTarXzSeeds = @(
    'invalid-block-crc'
    'invalid-check-mismatch'
    'invalid-header-crc'
    'invalid-inner-not-tar'
    'invalid-magic'
    'invalid-trailing-byte'
    'invalid-truncated'
    'resource-derived-over-cap'
    'unsupported-check-none'
    'unsupported-concatenated-streams'
    'unsupported-stream-padding'
    'valid-cli-crc64-single-block'
    'valid-cli-sha256-single-block'
    'valid-declared-sizes-crc32'
    'valid-empty-ustar-crc32'
    'valid-ordinary-ustar-crc32'
    'valid-two-block-crc32'
)
$actualTarXzSeedNames = @(
    $tarXzManifest.seeds.path |
        ForEach-Object { [IO.Path]::GetFileName([string]$_) }
)
foreach ($requiredSeed in $requiredTarXzSeeds) {
    if (@($actualTarXzSeedNames | Where-Object { $_ -ceq $requiredSeed }).Count -ne 1) {
        throw "TAR/xz corpus must contain exactly one required seed: $requiredSeed"
    }
}
$tarXzGenerator = Join-Path $workspace ([string]$tarXzManifest.generator)
$tarXzGenerationRoot = Join-Path (
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
) ("sealr-tar-xz-fuzz-seeds-{0}" -f [Guid]::NewGuid().ToString('N'))
try {
    & $tarXzGenerator -OutputDirectory $tarXzGenerationRoot
    $actualGeneratedTarXzNames = @(
        Get-ChildItem -LiteralPath $tarXzGenerationRoot -File |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedGeneratedTarXzNames = @(
        $generatedTarXzSeeds.path |
            ForEach-Object { [IO.Path]::GetFileName([string]$_) } |
            Sort-Object
    )
    if ($actualGeneratedTarXzNames.Count -ne $expectedGeneratedTarXzNames.Count -or
        @(Compare-Object $actualGeneratedTarXzNames $expectedGeneratedTarXzNames).Count -ne 0) {
        throw 'TAR/xz fuzz seed generator produced a different exact file set'
    }
    foreach ($entry in $generatedTarXzSeeds) {
        $generatedPath = Join-Path $tarXzGenerationRoot ([IO.Path]::GetFileName([string]$entry.path))
        $generatedFile = Get-Item -LiteralPath $generatedPath
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
        if ($generatedFile.Length -ne $entry.bytes -or $generatedHash -cne [string]$entry.sha256) {
            throw "TAR/xz fuzz seed generator did not reproduce $($entry.path)"
        }
    }
} finally {
    if (Test-Path -LiteralPath $tarXzGenerationRoot) {
        $resolvedTarXzGenerationRoot = [IO.Path]::GetFullPath($tarXzGenerationRoot)
        $generationParent = [IO.Path]::GetDirectoryName($resolvedTarXzGenerationRoot)
        $generationLeaf = [IO.Path]::GetFileName($resolvedTarXzGenerationRoot)
        $expectedTemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ($generationParent -cne $expectedTemporaryParent -or
            $generationLeaf -notmatch '^sealr-tar-xz-fuzz-seeds-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected TAR/xz fuzz generation path: $resolvedTarXzGenerationRoot"
        }
        Remove-Item -LiteralPath $resolvedTarXzGenerationRoot -Recurse -Force
    }
}

if ([string]$tarBzip2Manifest.generator -cne 'fuzz/generate_tar_bzip2_fuzz_seeds.ps1') {
    throw 'TAR/bzip2 fuzz seed generator path changed unexpectedly'
}
$generatedTarBzip2Seeds = @(
    $tarBzip2Manifest.seeds | Where-Object { $_.generated -is [bool] -and $_.generated }
)
if ($generatedTarBzip2Seeds.Count -ne 14 -or
    @($tarBzip2Manifest.seeds | Where-Object { $_.generated -isnot [bool] }).Count -ne 0 -or
    @($tarBzip2Manifest.seeds | Where-Object { $_.generated -is [bool] -and -not $_.generated }).Count -ne 0) {
    throw 'TAR/bzip2 fuzz seeds must classify exactly 14 generated entries'
}
$requiredTarBzip2Seeds = @(
    'invalid-block-crc'
    'invalid-footer-corruption'
    'invalid-magic'
    'invalid-payload-corruption'
    'invalid-trailing-byte'
    'invalid-truncated'
    'resource-derived-over-cap'
    'unsupported-bzip1-version'
    'unsupported-concatenated-streams'
    'unsupported-empty-stream'
    'unsupported-level-zero'
    'unsupported-randomized-block'
    'valid-cli-level1-single-block'
    'valid-cli-level9-single-block'
)
$actualTarBzip2SeedNames = @(
    $tarBzip2Manifest.seeds.path |
        ForEach-Object { [IO.Path]::GetFileName([string]$_) }
)
foreach ($requiredSeed in $requiredTarBzip2Seeds) {
    if (@($actualTarBzip2SeedNames | Where-Object { $_ -ceq $requiredSeed }).Count -ne 1) {
        throw "TAR/bzip2 corpus must contain exactly one required seed: $requiredSeed"
    }
}
$tarBzip2Generator = Join-Path $workspace ([string]$tarBzip2Manifest.generator)
$tarBzip2GenerationRoot = Join-Path (
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
) ("sealr-tar-bzip2-fuzz-seeds-{0}" -f [Guid]::NewGuid().ToString('N'))
try {
    & $tarBzip2Generator -OutputDirectory $tarBzip2GenerationRoot
    $actualGeneratedTarBzip2Names = @(
        Get-ChildItem -LiteralPath $tarBzip2GenerationRoot -File |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedGeneratedTarBzip2Names = @(
        $generatedTarBzip2Seeds.path |
            ForEach-Object { [IO.Path]::GetFileName([string]$_) } |
            Sort-Object
    )
    if ($actualGeneratedTarBzip2Names.Count -ne $expectedGeneratedTarBzip2Names.Count -or
        @(Compare-Object $actualGeneratedTarBzip2Names $expectedGeneratedTarBzip2Names).Count -ne 0) {
        throw 'TAR/bzip2 fuzz seed generator produced a different exact file set'
    }
    foreach ($entry in $generatedTarBzip2Seeds) {
        $generatedPath = Join-Path $tarBzip2GenerationRoot ([IO.Path]::GetFileName([string]$entry.path))
        $generatedFile = Get-Item -LiteralPath $generatedPath
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
        if ($generatedFile.Length -ne $entry.bytes -or $generatedHash -cne [string]$entry.sha256) {
            throw "TAR/bzip2 fuzz seed generator did not reproduce $($entry.path)"
        }
    }
} finally {
    if (Test-Path -LiteralPath $tarBzip2GenerationRoot) {
        $resolvedTarBzip2GenerationRoot = [IO.Path]::GetFullPath($tarBzip2GenerationRoot)
        $generationParent = [IO.Path]::GetDirectoryName($resolvedTarBzip2GenerationRoot)
        $generationLeaf = [IO.Path]::GetFileName($resolvedTarBzip2GenerationRoot)
        $expectedTemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ($generationParent -cne $expectedTemporaryParent -or
            $generationLeaf -notmatch '^sealr-tar-bzip2-fuzz-seeds-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected TAR/bzip2 fuzz generation path: $resolvedTarBzip2GenerationRoot"
        }
        Remove-Item -LiteralPath $resolvedTarBzip2GenerationRoot -Recurse -Force
    }
}
if ([string]$zip64Manifest.generator -cne 'fuzz/generate_zip64_fuzz_seeds.ps1') {
    throw 'ZIP64 fuzz seed generator path changed unexpectedly'
}
$generatedZip64Seeds = @(
    $zip64Manifest.seeds | Where-Object { $_.generated -is [bool] -and $_.generated }
)
if ($generatedZip64Seeds.Count -ne 13 -or
    @($zip64Manifest.seeds | Where-Object { $_.generated -isnot [bool] }).Count -ne 0 -or
    @($zip64Manifest.seeds | Where-Object { $_.generated -is [bool] -and -not $_.generated }).Count -ne 0) {
    throw 'ZIP64 fuzz seeds must classify exactly 13 generated entries'
}
$producerShapes = @(
    $zip64Manifest.seeds |
        Where-Object { $null -ne $_.PSObject.Properties['producerShape'] } |
        ForEach-Object { '{0}={1}' -f [string]$_.path, [string]$_.producerShape } |
        Sort-Object
)
$expectedProducerShapes = @(
    'fuzz/corpus/zip64_strict_ascii_v1/valid-cpython-forced-seek=cpython-seek-forced'
    'fuzz/corpus/zip64_strict_ascii_v1/valid-cpython-streaming-zeros=cpython-streaming-zero-pair'
    'fuzz/corpus/zip64_strict_ascii_v1/valid-zip-rs-streaming-maxima=zip-rs-streaming-max-pair'
) | Sort-Object
if (($producerShapes -join "`n") -cne ($expectedProducerShapes -join "`n")) {
    throw 'ZIP64 fuzz producer shapes must bind the exact CPython and zip-rs corpus'
}
$zip64Generator = Join-Path $workspace ([string]$zip64Manifest.generator)
$zip64GenerationRoot = Join-Path (
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
) ("sealr-zip64-fuzz-seeds-{0}" -f [Guid]::NewGuid().ToString('N'))
try {
    & $zip64Generator -OutputDirectory $zip64GenerationRoot
    $actualGeneratedZip64Names = @(
        Get-ChildItem -LiteralPath $zip64GenerationRoot -File |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedGeneratedZip64Names = @(
        $generatedZip64Seeds.path |
            ForEach-Object { [IO.Path]::GetFileName([string]$_) } |
            Sort-Object
    )
    if ($actualGeneratedZip64Names.Count -ne $expectedGeneratedZip64Names.Count -or
        @(Compare-Object $actualGeneratedZip64Names $expectedGeneratedZip64Names).Count -ne 0) {
        throw 'ZIP64 fuzz seed generator produced a different exact file set'
    }
    foreach ($entry in $generatedZip64Seeds) {
        $generatedPath = Join-Path $zip64GenerationRoot ([IO.Path]::GetFileName([string]$entry.path))
        $generatedFile = Get-Item -LiteralPath $generatedPath
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
        if ($generatedFile.Length -ne $entry.bytes -or $generatedHash -cne [string]$entry.sha256) {
            throw "ZIP64 fuzz seed generator did not reproduce $($entry.path)"
        }
    }
} finally {
    if (Test-Path -LiteralPath $zip64GenerationRoot) {
        $resolvedZip64GenerationRoot = [IO.Path]::GetFullPath($zip64GenerationRoot)
        $zip64GenerationParent = [IO.Path]::GetDirectoryName($resolvedZip64GenerationRoot)
        $zip64GenerationLeaf = [IO.Path]::GetFileName($resolvedZip64GenerationRoot)
        $expectedTemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ($zip64GenerationParent -cne $expectedTemporaryParent -or
            $zip64GenerationLeaf -notmatch '^sealr-zip64-fuzz-seeds-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected ZIP64 fuzz generation path: $resolvedZip64GenerationRoot"
        }
        Remove-Item -LiteralPath $resolvedZip64GenerationRoot -Recurse -Force
    }
}
$generatedTarSeeds = @($tarManifest.seeds | Where-Object { $_.generated -is [bool] -and $_.generated })
$handwrittenTarSeeds = @($tarManifest.seeds | Where-Object { $_.generated -is [bool] -and -not $_.generated })
if ($generatedTarSeeds.Count -ne 13 -or
    $handwrittenTarSeeds.Count -ne 2 -or
    @($tarManifest.seeds | Where-Object { $_.generated -isnot [bool] }).Count -ne 0) {
    throw 'TAR fuzz seeds must classify exactly 13 generated and two handwritten entries'
}
$tarGenerator = Join-Path $workspace ([string]$tarManifest.generator)
$tarGenerationRoot = Join-Path (
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
) ("sealr-tar-fuzz-seeds-{0}" -f [Guid]::NewGuid().ToString('N'))
try {
    & $tarGenerator -OutputDirectory $tarGenerationRoot
    $actualGeneratedNames = @(
        Get-ChildItem -LiteralPath $tarGenerationRoot -File |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedGeneratedNames = @(
        $generatedTarSeeds.path |
            ForEach-Object { [IO.Path]::GetFileName([string]$_) } |
            Sort-Object
    )
    if ($actualGeneratedNames.Count -ne $expectedGeneratedNames.Count -or
        @(Compare-Object $actualGeneratedNames $expectedGeneratedNames).Count -ne 0) {
        throw 'TAR fuzz seed generator produced a different exact file set'
    }
    foreach ($entry in $generatedTarSeeds) {
        $generatedPath = Join-Path $tarGenerationRoot ([IO.Path]::GetFileName([string]$entry.path))
        $generatedFile = Get-Item -LiteralPath $generatedPath
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
        if ($generatedFile.Length -ne $entry.bytes -or $generatedHash -cne [string]$entry.sha256) {
            throw "TAR fuzz seed generator did not reproduce $($entry.path)"
        }
    }
} finally {
    if (Test-Path -LiteralPath $tarGenerationRoot) {
        $resolvedGenerationRoot = [IO.Path]::GetFullPath($tarGenerationRoot)
        $generationParent = [IO.Path]::GetDirectoryName($resolvedGenerationRoot)
        $generationLeaf = [IO.Path]::GetFileName($resolvedGenerationRoot)
        $expectedTemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ($generationParent -cne $expectedTemporaryParent -or
            $generationLeaf -notmatch '^sealr-tar-fuzz-seeds-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected TAR fuzz generation path: $resolvedGenerationRoot"
        }
        Remove-Item -LiteralPath $resolvedGenerationRoot -Recurse -Force
    }
}

if ([string]$tarPaxManifest.generator -cne 'fuzz/generate_tar_pax_fuzz_seeds.ps1') {
    throw 'TAR PAX fuzz seed generator path changed unexpectedly'
}
$generatedTarPaxSeeds = @(
    $tarPaxManifest.seeds | Where-Object { $_.generated -is [bool] -and $_.generated }
)
if ($generatedTarPaxSeeds.Count -ne 9 -or
    @($tarPaxManifest.seeds | Where-Object { $_.generated -isnot [bool] }).Count -ne 0 -or
    @($tarPaxManifest.seeds | Where-Object { $_.generated -is [bool] -and -not $_.generated }).Count -ne 0) {
    throw 'TAR PAX fuzz seeds must classify exactly nine generated entries'
}
$requiredTarPaxSeeds = @(
    'valid-ordinary-ustar-subset'
    'valid-local-path-size'
    'valid-global-local-precedence'
    'invalid-malformed-record-length'
    'unsupported-keyword'
    'invalid-orphan-local'
    'valid-quota-boundary-two-files'
    'invalid-extension-over-cap'
)
$actualTarPaxSeedNames = @(
    $tarPaxManifest.seeds.path |
        ForEach-Object { [IO.Path]::GetFileName([string]$_) }
)
foreach ($requiredSeed in $requiredTarPaxSeeds) {
    if (@($actualTarPaxSeedNames | Where-Object { $_ -ceq $requiredSeed }).Count -ne 1) {
        throw "TAR PAX corpus must contain exactly one required seed: $requiredSeed"
    }
}
$tarPaxGenerator = Join-Path $workspace ([string]$tarPaxManifest.generator)
$tarPaxGenerationRoot = Join-Path (
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
) ("sealr-tar-pax-fuzz-seeds-{0}" -f [Guid]::NewGuid().ToString('N'))
try {
    & $tarPaxGenerator -OutputDirectory $tarPaxGenerationRoot
    $actualGeneratedTarPaxNames = @(
        Get-ChildItem -LiteralPath $tarPaxGenerationRoot -File |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedGeneratedTarPaxNames = @(
        $generatedTarPaxSeeds.path |
            ForEach-Object { [IO.Path]::GetFileName([string]$_) } |
            Sort-Object
    )
    if ($actualGeneratedTarPaxNames.Count -ne $expectedGeneratedTarPaxNames.Count -or
        @(Compare-Object $actualGeneratedTarPaxNames $expectedGeneratedTarPaxNames).Count -ne 0) {
        throw 'TAR PAX fuzz seed generator produced a different exact file set'
    }
    foreach ($entry in $generatedTarPaxSeeds) {
        $generatedPath = Join-Path $tarPaxGenerationRoot ([IO.Path]::GetFileName([string]$entry.path))
        $generatedFile = Get-Item -LiteralPath $generatedPath
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
        if ($generatedFile.Length -ne $entry.bytes -or $generatedHash -cne [string]$entry.sha256) {
            throw "TAR PAX fuzz seed generator did not reproduce $($entry.path)"
        }
    }
} finally {
    if (Test-Path -LiteralPath $tarPaxGenerationRoot) {
        $resolvedTarPaxGenerationRoot = [IO.Path]::GetFullPath($tarPaxGenerationRoot)
        $generationParent = [IO.Path]::GetDirectoryName($resolvedTarPaxGenerationRoot)
        $generationLeaf = [IO.Path]::GetFileName($resolvedTarPaxGenerationRoot)
        $expectedTemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ($generationParent -cne $expectedTemporaryParent -or
            $generationLeaf -notmatch '^sealr-tar-pax-fuzz-seeds-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected TAR PAX fuzz generation path: $resolvedTarPaxGenerationRoot"
        }
        Remove-Item -LiteralPath $resolvedTarPaxGenerationRoot -Recurse -Force
    }
}

if ([string]$tarGnuLongNameManifest.generator -cne 'fuzz/generate_tar_gnu_longname_fuzz_seeds.ps1') {
    throw 'TAR GNU long-name fuzz seed generator path changed unexpectedly'
}
$generatedTarGnuLongNameSeeds = @(
    $tarGnuLongNameManifest.seeds |
        Where-Object { $_.generated -is [bool] -and $_.generated }
)
if ($generatedTarGnuLongNameSeeds.Count -ne 16 -or
    @($tarGnuLongNameManifest.seeds | Where-Object { $_.generated -isnot [bool] }).Count -ne 0 -or
    @($tarGnuLongNameManifest.seeds | Where-Object { $_.generated -is [bool] -and -not $_.generated }).Count -ne 0) {
    throw 'TAR GNU long-name fuzz seeds must classify exactly 16 generated entries'
}
$requiredTarGnuLongNameSeeds = @(
    'invalid-base256-size'
    'invalid-chained-carrier'
    'invalid-embedded-nul'
    'invalid-missing-final-nul'
    'invalid-nonzero-carrier-padding'
    'invalid-orphan-carrier'
    'invalid-oversized-carrier'
    'unsupported-cve-2026-53655-pax-gnu-state'
    'unsupported-long-link-k'
    'unsupported-sparse'
    'valid-empty-oldgnu'
    'valid-gnu-longlink'
    'valid-libarchive-longname'
    'valid-ordinary-oldgnu'
    'valid-short-redundant-carrier'
    'valid-two-carrier-pairs'
)
$actualTarGnuLongNameSeedNames = @(
    $tarGnuLongNameManifest.seeds.path |
        ForEach-Object { [IO.Path]::GetFileName([string]$_) }
)
foreach ($requiredSeed in $requiredTarGnuLongNameSeeds) {
    if (@($actualTarGnuLongNameSeedNames | Where-Object { $_ -ceq $requiredSeed }).Count -ne 1) {
        throw "TAR GNU long-name corpus must contain exactly one required seed: $requiredSeed"
    }
}
$tarGnuLongNameGenerator = Join-Path $workspace ([string]$tarGnuLongNameManifest.generator)
$tarGnuLongNameGenerationRoot = Join-Path (
    [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
) ("sealr-tar-gnu-longname-fuzz-seeds-{0}" -f [Guid]::NewGuid().ToString('N'))
try {
    & $tarGnuLongNameGenerator -OutputDirectory $tarGnuLongNameGenerationRoot
    $actualGeneratedTarGnuLongNameNames = @(
        Get-ChildItem -LiteralPath $tarGnuLongNameGenerationRoot -File |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedGeneratedTarGnuLongNameNames = @(
        $generatedTarGnuLongNameSeeds.path |
            ForEach-Object { [IO.Path]::GetFileName([string]$_) } |
            Sort-Object
    )
    if ($actualGeneratedTarGnuLongNameNames.Count -ne $expectedGeneratedTarGnuLongNameNames.Count -or
        @(Compare-Object $actualGeneratedTarGnuLongNameNames $expectedGeneratedTarGnuLongNameNames).Count -ne 0) {
        throw 'TAR GNU long-name fuzz seed generator produced a different exact file set'
    }
    foreach ($entry in $generatedTarGnuLongNameSeeds) {
        $generatedPath = Join-Path $tarGnuLongNameGenerationRoot ([IO.Path]::GetFileName([string]$entry.path))
        $generatedFile = Get-Item -LiteralPath $generatedPath
        $generatedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $generatedPath).Hash.ToLowerInvariant()
        if ($generatedFile.Length -ne $entry.bytes -or $generatedHash -cne [string]$entry.sha256) {
            throw "TAR GNU long-name fuzz seed generator did not reproduce $($entry.path)"
        }
    }
} finally {
    if (Test-Path -LiteralPath $tarGnuLongNameGenerationRoot) {
        $resolvedTarGnuLongNameGenerationRoot = [IO.Path]::GetFullPath($tarGnuLongNameGenerationRoot)
        $generationParent = [IO.Path]::GetDirectoryName($resolvedTarGnuLongNameGenerationRoot)
        $generationLeaf = [IO.Path]::GetFileName($resolvedTarGnuLongNameGenerationRoot)
        $expectedTemporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if ($generationParent -cne $expectedTemporaryParent -or
            $generationLeaf -notmatch '^sealr-tar-gnu-longname-fuzz-seeds-[0-9a-f]{32}$') {
            throw "refusing to remove unexpected TAR GNU long-name fuzz generation path: $resolvedTarGnuLongNameGenerationRoot"
        }
        Remove-Item -LiteralPath $resolvedTarGnuLongNameGenerationRoot -Recurse -Force
    }
}

$fuzzCargo = Get-Content -Raw -LiteralPath (Join-Path $workspace 'fuzz/Cargo.toml')
$fuzzLock = Get-Content -Raw -LiteralPath (Join-Path $workspace 'fuzz/Cargo.lock')
$semanticTarget = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/semantic_records.rs'
)
$tarTarget = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/tar_ustar_portable_v1.rs'
)
$tarPaxTarget = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/tar_pax_portable_v1.rs'
)
$tarGnuLongNameTarget = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/tar_gnu_longname_portable_v1.rs'
)
$gzipTarget = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/gzip_rfc1952_single_member_v1.rs'
)
$tarGzipTarget = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/tar_gzip_ustar_portable_v1.rs'
)
$tarGzipPaxTarget = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/tar_gzip_pax_portable_v1.rs'
)
$tarGzipGnuLongNameTarget = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/tar_gzip_gnu_longname_portable_v1.rs'
)
$tarZstdTarget = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/tar_zstd_ustar_portable_v1.rs'
)
$tarXzTarget = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/tar_xz_ustar_portable_v1.rs'
)
$tarBzip2Target = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/tar_bzip2_ustar_portable_v1.rs'
)
$zip64Target = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/zip64_strict_ascii_v1.rs'
)
$workflow = Get-Content -Raw -LiteralPath (Join-Path $workspace '.github/workflows/fuzz.yml')
$releaseWorkflow = Get-Content -Raw -LiteralPath (Join-Path $workspace '.github/workflows/release.yml')
$publisher = Get-Content -Raw -LiteralPath (Join-Path $workspace 'scripts/publish_release.ps1')

function Get-UniqueWorkflowBlock {
    param(
        [Parameter(Mandatory)] [string] $Content,
        [Parameter(Mandatory)] [string] $Pattern,
        [Parameter(Mandatory)] [string] $Label
    )

    $matches = [regex]::Matches($Content, $Pattern)
    if ($matches.Count -ne 1) {
        throw "Scheduled fuzz workflow must contain exactly one $Label block"
    }
    return $matches[0].Value
}

function Get-WorkflowJobBlock {
    param(
        [Parameter(Mandatory)] [string] $Content,
        [Parameter(Mandatory)] [string] $JobName
    )

    $pattern = '(?ms)^  {0}:\r?\n.*?(?=^  [A-Za-z0-9_-]+:\r?$|\z)' -f
        [regex]::Escape($JobName)
    return Get-UniqueWorkflowBlock -Content $Content -Pattern $pattern -Label "jobs.$JobName"
}

function Normalize-WorkflowBlock {
    param(
        [Parameter(Mandatory)] [string] $Block
    )

    return $Block.Replace("`r`n", "`n").TrimEnd("`r", "`n")
}

function Assert-ExactWorkflowJob {
    param(
        [Parameter(Mandatory)] [string] $ActualJob,
        [Parameter(Mandatory)] [string] $ExpectedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    $actual = Normalize-WorkflowBlock $ActualJob
    $expected = Normalize-WorkflowBlock $ExpectedJob
    if ($actual -cne $expected) {
        $mismatch = 0
        while ($mismatch -lt [Math]::Min($expected.Length, $actual.Length) -and
            $expected[$mismatch] -ceq $actual[$mismatch]) {
            $mismatch += 1
        }
        throw @"
$Label job must exactly match its manifest-derived workflow contract.
First mismatch: $mismatch; expected length: $($expected.Length); actual length: $($actual.Length).
Expected:
$expected
Actual:
$actual
"@
    }
}

function Assert-FuzzJobContract {
    param(
        [Parameter(Mandatory)] [string] $JobBlock,
        [Parameter(Mandatory)] [object] $JobManifest,
        [Parameter(Mandatory)] [string] $JobName,
        [Parameter(Mandatory)] [string] $JobDisplayName,
        [Parameter(Mandatory)] [string] $FuzzStepName,
        [Parameter(Mandatory)] [string] $ReproducerName
    )

    $target = [string]$JobManifest.target
    $toolchain = [string]$JobManifest.toolchain
    $cargoFuzzVersion = [string]$JobManifest.cargoFuzzVersion
    $dictionaryPath = [string]$JobManifest.dictionary.path
    $artifactDirectory = [string]$JobManifest.failureArtifact.directoryName
    $jobs = [string]$JobManifest.bounds.jobs
    $maxInputBytes = [string]$JobManifest.bounds.maxInputBytes
    $maxTotalSeconds = [string]$JobManifest.bounds.maxTotalSeconds
    $timeoutSeconds = [string]$JobManifest.bounds.perInputTimeoutSeconds
    $rssLimitMiB = [string]$JobManifest.bounds.rssLimitMiB
    $sanitizerProperty = $JobManifest.PSObject.Properties['sanitizer']

    Assert-ExactWorkflowJob -ActualJob $JobBlock -ExpectedJob (@(
            ('  {0}:' -f $JobName)
            "    name: $JobDisplayName"
            '    runs-on: ubuntu-latest'
            '    timeout-minutes: 20'
            '    steps:'
            '      - name: Check out repository'
            '        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1'
            ''
            '      - name: Install pinned nightly'
            "        run: rustup toolchain install $toolchain --profile minimal"
            ''
            '      - name: Install pinned cargo-fuzz'
            "        run: cargo +$toolchain install cargo-fuzz --version $cargoFuzzVersion --locked"
            ''
            '      - name: Verify seed and configuration manifest'
            '        shell: pwsh'
            '        run: pwsh -NoLogo -NoProfile -File scripts/verify_fuzz_seeds.ps1'
            ''
            "      - name: $FuzzStepName"
            '        shell: bash'
            '        run: |'
            '          set -euo pipefail'
            ('          artifact_dir="${RUNNER_TEMP}/' + $artifactDirectory + '/"')
            '          mkdir -p "${artifact_dir}"'
            ("          cargo +$toolchain fuzz run \" )
            '            --fuzz-dir fuzz \'
            $(if ($null -ne $sanitizerProperty) {
                    "            --sanitizer $([string]$sanitizerProperty.Value) \"
                })
            ("            --jobs $jobs \" )
            ("            $target \" )
            '            -- \'
            ("            -jobs=$jobs \" )
            ("            -max_len=$maxInputBytes \" )
            ("            -max_total_time=$maxTotalSeconds \" )
            ("            -timeout=$timeoutSeconds \" )
            ("            -rss_limit_mb=$rssLimitMiB \" )
            '            -artifact_prefix="${artifact_dir}" \'
            ("            -dict=$dictionaryPath \" )
            '            -print_final_stats=1'
            ''
            '      - name: Preserve reproducer after a failure'
            '        if: failure()'
            '        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1'
            '        with:'
            "          name: $ReproducerName"
            ('          path: ${{ runner.temp }}/' + $artifactDirectory + '/')
            '          if-no-files-found: ignore'
            "          retention-days: $($JobManifest.failureArtifact.retentionDays)"
        ) -join "`n") -Label $target
}

function Get-FuzzCargoMetadata {
    param(
        [Parameter(Mandatory)] [string] $ManifestPath,
        [switch] $Locked,
        [switch] $NoDeps
    )

    $arguments = @(
        'metadata'
        '--format-version'
        '1'
        '--manifest-path'
        $ManifestPath
    )
    if ($NoDeps) {
        $arguments = @('metadata', '--no-deps') + $arguments[1..($arguments.Count - 1)]
    }
    if ($Locked) {
        $arguments = @('metadata', '--locked') + $arguments[1..($arguments.Count - 1)]
    }

    $json = & cargo @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed for fuzz manifest: $ManifestPath"
    }
    return ($json -join "`n") | ConvertFrom-Json -Depth 100
}

function Get-OptionalMetadataText {
    param(
        [Parameter(Mandatory)] [object] $Object,
        [Parameter(Mandatory)] [string] $Property
    )

    $value = $Object.PSObject.Properties[$Property]
    if ($null -eq $value -or $null -eq $value.Value) {
        return ''
    }
    return [string]$value.Value
}

function Get-CanonicalCargoHome {
    if (-not [string]::IsNullOrWhiteSpace($env:CARGO_HOME)) {
        return [IO.Path]::GetFullPath($env:CARGO_HOME)
    }
    return [IO.Path]::GetFullPath(
        (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.cargo')
    )
}

function Assert-NoCargoConfiguration {
    $candidateDirectories = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    [void]$candidateDirectories.Add((Get-CanonicalCargoHome))

    $cursor = [IO.Path]::GetFullPath($workspace)
    while ($true) {
        [void]$candidateDirectories.Add((Join-Path $cursor '.cargo'))
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) {
            break
        }
        $cursor = $parent.FullName
    }

    foreach ($directory in $candidateDirectories) {
        foreach ($name in @('config', 'config.toml')) {
            $candidate = Join-Path $directory $name
            if ([IO.File]::Exists($candidate) -or [IO.Directory]::Exists($candidate)) {
                throw "Fuzz evidence refuses Cargo configuration that can replace registry sources: $candidate"
            }
        }
    }
}

function Assert-FuzzMetadataBinding {
    param(
        [Parameter(Mandatory)] [object] $Metadata,
        [Parameter(Mandatory)] [string] $ManifestPath,
        [switch] $RequireDependencies
    )

    $packages = @($Metadata.packages | Where-Object { $_.name -ceq 'sealr-fuzz' })
    if ($packages.Count -ne 1) {
        throw 'Cargo metadata must contain exactly one sealr-fuzz package'
    }
    $package = $packages[0]

    $targetNames = @($package.targets.name | Sort-Object)
    $expectedTargetNames = @(
        'gzip_rfc1952_single_member_v1'
        'protocol_decoders'
        'semantic_records'
        'tar_bzip2_ustar_portable_v1'
        'tar_gnu_longname_portable_v1'
        'tar_gzip_gnu_longname_portable_v1'
        'tar_gzip_pax_portable_v1'
        'tar_gzip_ustar_portable_v1'
        'tar_pax_portable_v1'
        'tar_ustar_portable_v1'
        'tar_xz_ustar_portable_v1'
        'tar_zstd_ustar_portable_v1'
        'zip64_strict_ascii_v1'
    )
    if (($targetNames -join "`n") -cne ($expectedTargetNames -join "`n")) {
        throw 'Cargo metadata must contain exactly the gzip, protocol, semantic, TAR, PAX, GNU long-name TAR, TAR/gzip, TAR/gzip PAX, TAR/gzip GNU long-name, TAR/zstd, TAR/xz, TAR/bzip2, and ZIP64 fuzz targets'
    }
    $manifestDirectory = Split-Path ([IO.Path]::GetFullPath($ManifestPath)) -Parent
    foreach ($targetContract in @(
        @{
            Name = 'protocol_decoders'
            RelativePath = 'fuzz_targets/protocol_decoders.rs'
        }
        @{
            Name = 'semantic_records'
            RelativePath = 'fuzz_targets/semantic_records.rs'
        }
        @{
            Name = 'tar_ustar_portable_v1'
            RelativePath = 'fuzz_targets/tar_ustar_portable_v1.rs'
        }
        @{
            Name = 'tar_pax_portable_v1'
            RelativePath = 'fuzz_targets/tar_pax_portable_v1.rs'
        }
        @{
            Name = 'tar_gnu_longname_portable_v1'
            RelativePath = 'fuzz_targets/tar_gnu_longname_portable_v1.rs'
        }
        @{
            Name = 'gzip_rfc1952_single_member_v1'
            RelativePath = 'fuzz_targets/gzip_rfc1952_single_member_v1.rs'
        }
        @{
            Name = 'tar_gzip_ustar_portable_v1'
            RelativePath = 'fuzz_targets/tar_gzip_ustar_portable_v1.rs'
        }
        @{
            Name = 'tar_gzip_pax_portable_v1'
            RelativePath = 'fuzz_targets/tar_gzip_pax_portable_v1.rs'
        }
        @{
            Name = 'tar_gzip_gnu_longname_portable_v1'
            RelativePath = 'fuzz_targets/tar_gzip_gnu_longname_portable_v1.rs'
        }
        @{
            Name = 'tar_zstd_ustar_portable_v1'
            RelativePath = 'fuzz_targets/tar_zstd_ustar_portable_v1.rs'
        }
        @{
            Name = 'tar_xz_ustar_portable_v1'
            RelativePath = 'fuzz_targets/tar_xz_ustar_portable_v1.rs'
        }
        @{
            Name = 'tar_bzip2_ustar_portable_v1'
            RelativePath = 'fuzz_targets/tar_bzip2_ustar_portable_v1.rs'
        }
        @{
            Name = 'zip64_strict_ascii_v1'
            RelativePath = 'fuzz_targets/zip64_strict_ascii_v1.rs'
        }
    )) {
        $matchingTargets = @(
            $package.targets |
                Where-Object { $_.name -ceq [string]$targetContract.Name }
        )
        if ($matchingTargets.Count -ne 1) {
            throw "Cargo metadata must contain exactly one $($targetContract.Name) target"
        }
        $target = $matchingTargets[0]
        $expectedTargetPath = [IO.Path]::GetFullPath(
            (Join-Path $manifestDirectory ([string]$targetContract.RelativePath))
        )
        $actualTargetPath = [IO.Path]::GetFullPath([string]$target.src_path)
        if ($actualTargetPath -cne $expectedTargetPath -or
            @($target.kind).Count -ne 1 -or $target.kind[0] -cne 'bin' -or
            @($target.crate_types).Count -ne 1 -or $target.crate_types[0] -cne 'bin' -or
            [string]$target.edition -cne '2021' -or
            [bool]$target.doc -or [bool]$target.doctest -or [bool]$target.test) {
            throw "$($targetContract.Name) Cargo metadata must bind its exact non-test fuzz target"
        }
    }

    if ($RequireDependencies) {
        $dependencies = @($package.dependencies)
        $dependencyNames = @($dependencies.name | Sort-Object)
        $expectedNames = @('libfuzzer-sys', 'sealr', 'sealr-worker-protocol')
        if (($dependencyNames -join "`n") -cne ($expectedNames -join "`n")) {
            throw 'Fuzz Cargo metadata contains an unexpected dependency set'
        }

        $sealrDependency = @($dependencies | Where-Object { $_.name -ceq 'sealr' })
        $protocolDependency = @(
            $dependencies | Where-Object { $_.name -ceq 'sealr-worker-protocol' }
        )
        $libfuzzerDependency = @(
            $dependencies | Where-Object { $_.name -ceq 'libfuzzer-sys' }
        )
        $expectedSealrPath = [IO.Path]::GetFullPath(
            (Join-Path $workspace 'crates/sealr')
        )
        $expectedProtocolPath = [IO.Path]::GetFullPath(
            (Join-Path $workspace 'crates/sealr-protocol')
        )
        if ($sealrDependency.Count -ne 1 -or
            [string]$sealrDependency[0].req -cne '=0.1.0-alpha.11' -or
            [IO.Path]::GetFullPath((Get-OptionalMetadataText $sealrDependency[0] 'path')) -cne $expectedSealrPath -or
            (@($sealrDependency[0].features) -join "`n") -cne '__internal-fuzzing' -or
            [bool]$sealrDependency[0].optional -or
            -not [bool]$sealrDependency[0].uses_default_features -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $sealrDependency[0] 'source')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $sealrDependency[0] 'rename')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $sealrDependency[0] 'kind')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $sealrDependency[0] 'target')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $sealrDependency[0] 'registry'))) {
            throw 'Cargo metadata must enable only the exact hidden Sealr fuzz feature dependency'
        }
        if ($protocolDependency.Count -ne 1 -or
            [string]$protocolDependency[0].req -cne '=0.1.0-alpha.11' -or
            [IO.Path]::GetFullPath((Get-OptionalMetadataText $protocolDependency[0] 'path')) -cne $expectedProtocolPath -or
            @($protocolDependency[0].features).Count -ne 0 -or
            [bool]$protocolDependency[0].optional -or
            -not [bool]$protocolDependency[0].uses_default_features -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $protocolDependency[0] 'source')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $protocolDependency[0] 'rename')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $protocolDependency[0] 'kind')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $protocolDependency[0] 'target')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $protocolDependency[0] 'registry'))) {
            throw 'Cargo metadata must bind the exact worker-protocol fuzz dependency'
        }
        if ($libfuzzerDependency.Count -ne 1 -or
            [string]$libfuzzerDependency[0].req -cne '=0.4.13' -or
            @($libfuzzerDependency[0].features).Count -ne 0 -or
            [bool]$libfuzzerDependency[0].optional -or
            -not [bool]$libfuzzerDependency[0].uses_default_features -or
            (Get-OptionalMetadataText $libfuzzerDependency[0] 'source') -cne 'registry+https://github.com/rust-lang/crates.io-index' -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $libfuzzerDependency[0] 'path')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $libfuzzerDependency[0] 'rename')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $libfuzzerDependency[0] 'kind')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $libfuzzerDependency[0] 'target')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $libfuzzerDependency[0] 'registry'))) {
            throw 'Cargo metadata must bind the exact libfuzzer-sys dependency'
        }

        $rootNodes = @($Metadata.resolve.nodes | Where-Object { $_.id -ceq $package.id })
        if ($rootNodes.Count -ne 1) {
            throw 'Cargo metadata must resolve exactly one sealr-fuzz root node'
        }
        $resolvedEdges = @(
            $rootNodes[0].deps | Where-Object { $_.name -ceq 'libfuzzer_sys' }
        )
        if ($resolvedEdges.Count -ne 1 -or
            @($resolvedEdges[0].dep_kinds).Count -ne 1 -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $resolvedEdges[0].dep_kinds[0] 'kind')) -or
            -not [string]::IsNullOrEmpty((Get-OptionalMetadataText $resolvedEdges[0].dep_kinds[0] 'target'))) {
            throw 'Cargo resolve graph must contain one unconditional libfuzzer-sys edge'
        }
        $resolvedPackages = @(
            $Metadata.packages |
                Where-Object { $_.id -ceq [string]$resolvedEdges[0].pkg }
        )
        $resolvedManifestPath = if ($resolvedPackages.Count -eq 1) {
            [IO.Path]::GetFullPath(
                (Get-OptionalMetadataText $resolvedPackages[0] 'manifest_path')
            )
        } else {
            ''
        }
        $registrySourceRoot = [IO.Path]::GetFullPath(
            (Join-Path (Get-CanonicalCargoHome) 'registry/src')
        )
        $resolvedManifestRelative = if ($resolvedManifestPath.Length -gt 0) {
            [IO.Path]::GetRelativePath($registrySourceRoot, $resolvedManifestPath)
        } else {
            '..'
        }
        if ($resolvedPackages.Count -ne 1 -or
            [string]$resolvedPackages[0].name -cne 'libfuzzer-sys' -or
            [string]$resolvedPackages[0].version -cne '0.4.13' -or
            (Get-OptionalMetadataText $resolvedPackages[0] 'source') -cne 'registry+https://github.com/rust-lang/crates.io-index' -or
            [IO.Path]::IsPathRooted($resolvedManifestRelative) -or
            $resolvedManifestRelative -eq '..' -or
            $resolvedManifestRelative.StartsWith(
                '..' + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::Ordinal
            ) -or
            $resolvedManifestRelative.StartsWith(
                '..' + [IO.Path]::AltDirectorySeparatorChar,
                [StringComparison]::Ordinal
            )) {
            throw 'Resolved libfuzzer-sys package must be the exact crates.io release'
        }
    }
}

function Assert-SemanticFuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $expectedSource = @(
        '#![no_main]'
        ''
        'use libfuzzer_sys::fuzz_target;'
        ''
        'fuzz_target!(|input: &[u8]| {'
        '    sealr::__fuzz_semantic_records(input);'
        '});'
    ) -join "`n"
    if ((Normalize-WorkflowBlock $TargetSource) -cne $expectedSource) {
        throw 'Semantic fuzz target source must call the exact hidden Sealr semantic driver'
    }
}

function Assert-TarFuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $expectedSource = @(
        '#![no_main]'
        ''
        'use libfuzzer_sys::fuzz_target;'
        ''
        'fuzz_target!(|input: &[u8]| {'
        '    sealr::__fuzz_tar_ustar_portable_v1(input);'
        '});'
    ) -join "`n"
    if ((Normalize-WorkflowBlock $TargetSource) -cne $expectedSource) {
        throw 'TAR fuzz target source must call the exact hidden Sealr ustar driver'
    }
}

function Assert-TarPaxFuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($TargetSource)
    $digest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    if ($bytes.Length -ne $tarPaxManifest.targetSource.bytes -or
        $digest -cne [string]$tarPaxManifest.targetSource.sha256) {
        throw 'TAR PAX fuzz target source differs from its digest-pinned contract'
    }
    $expectedSource = @(
        '#![no_main]'
        ''
        'use libfuzzer_sys::fuzz_target;'
        ''
        'fuzz_target!(|input: &[u8]| {'
        '    sealr::__fuzz_tar_pax_portable_v1(input);'
        '});'
    ) -join "`n"
    if ((Normalize-WorkflowBlock $TargetSource) -cne $expectedSource) {
        throw 'TAR PAX fuzz target source must call the exact hidden Sealr PAX driver'
    }
}

function Assert-TarGnuLongNameFuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($TargetSource)
    $digest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    if ($bytes.Length -ne $tarGnuLongNameManifest.targetSource.bytes -or
        $digest -cne [string]$tarGnuLongNameManifest.targetSource.sha256) {
        throw 'TAR GNU long-name fuzz target source differs from its digest-pinned contract'
    }
    $expectedSource = @(
        '#![no_main]'
        ''
        'use libfuzzer_sys::fuzz_target;'
        ''
        'fuzz_target!(|input: &[u8]| {'
        '    sealr::__fuzz_tar_gnu_longname_portable_v1(input);'
        '});'
    ) -join "`n"
    if ((Normalize-WorkflowBlock $TargetSource) -cne $expectedSource) {
        throw 'TAR GNU long-name fuzz target source must call the exact hidden Sealr driver'
    }
}

function Assert-GzipFuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $expectedSource = @(
        '#![no_main]'
        ''
        'use libfuzzer_sys::fuzz_target;'
        ''
        'fuzz_target!(|input: &[u8]| {'
        '    sealr::__fuzz_gzip_rfc1952_single_member_v1(input);'
        '});'
    ) -join "`n"
    if ((Normalize-WorkflowBlock $TargetSource) -cne $expectedSource) {
        throw 'gzip fuzz target source must call the exact hidden Sealr RFC 1952 driver'
    }
}

function Assert-TarGzipFuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($TargetSource)
    $digest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    if ($bytes.Length -ne $tarGzipManifest.targetSource.bytes -or
        $digest -cne [string]$tarGzipManifest.targetSource.sha256) {
        throw 'TAR/gzip fuzz target source differs from its digest-pinned contract'
    }
    foreach ($contract in @(
        @{ Token = 'fuzz_target!(|input: &[u8]| {'; Count = 1 }
        @{ Token = 'apply_with_options('; Count = 1 }
        @{ Token = 'Policy::default_v4()'; Count = 1 }
        @{ Token = 'policy.max_archive_bytes = MAX_INPUT_BYTES as u64;'; Count = 1 }
        @{ Token = 'policy.max_derived_archive_bytes = Some(131_072);'; Count = 1 }
        @{ Token = 'policy.max_metadata_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_files = 64;'; Count = 1 }
        @{ Token = 'policy.max_member_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_total_bytes = 65_536;'; Count = 1 }
        @{ Token = 'policy.max_path_depth = 16;'; Count = 1 }
        @{ Token = 'policy.max_ratio = Some(32);'; Count = 1 }
        @{ Token = '.with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::UstarPortableV1)'; Count = 1 }
        @{ Token = 'dest: None,'; Count = 1 }
        @{ Token = 'let first = inspect();'; Count = 1 }
        @{ Token = 'let second = inspect();'; Count = 1 }
        @{ Token = 'format!("{:?}", first.archive_ir())'; Count = 1 }
        @{ Token = 'assert_eq!(ir.format(), ArchiveFormat::TarGzipUstar);'; Count = 1 }
    )) {
        $count = [regex]::Matches(
            $TargetSource,
            [regex]::Escape([string]$contract.Token)
        ).Count
        if ($count -ne [int]$contract.Count) {
            throw "TAR/gzip fuzz target must contain exactly $($contract.Count) live contract token(s): $($contract.Token)"
        }
    }
    foreach ($forbidden in @('dest: Some(', '__fuzz_tar_', 'unsafe {')) {
        if ($TargetSource.Contains($forbidden, [StringComparison]::Ordinal)) {
            throw "TAR/gzip public fuzz target contains forbidden source: $forbidden"
        }
    }
}

function Assert-TarGzipPaxFuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($TargetSource)
    $digest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    if ($bytes.Length -ne $tarGzipPaxManifest.targetSource.bytes -or
        $digest -cne [string]$tarGzipPaxManifest.targetSource.sha256) {
        throw 'TAR/gzip PAX fuzz target source differs from its digest-pinned contract'
    }
    foreach ($contract in @(
        @{ Token = 'fuzz_target!(|input: &[u8]| {'; Count = 1 }
        @{ Token = 'apply_with_options('; Count = 1 }
        @{ Token = 'Policy::default_v7()'; Count = 1 }
        @{ Token = 'policy.max_archive_bytes = MAX_INPUT_BYTES as u64;'; Count = 1 }
        @{ Token = 'policy.max_derived_archive_bytes = Some(131_072);'; Count = 1 }
        @{ Token = 'policy.max_metadata_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_files = 64;'; Count = 1 }
        @{ Token = 'policy.max_member_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_total_bytes = 65_536;'; Count = 1 }
        @{ Token = 'policy.max_path_depth = 16;'; Count = 1 }
        @{ Token = 'policy.max_ratio = Some(32);'; Count = 1 }
        @{ Token = '.with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::PaxPortableV1)'; Count = 1 }
        @{ Token = 'dest: None,'; Count = 1 }
        @{ Token = 'let first = inspect();'; Count = 1 }
        @{ Token = 'let second = inspect();'; Count = 1 }
        @{ Token = 'format!("{:?}", first.archive_ir())'; Count = 1 }
        @{ Token = 'assert_eq!(ir.format(), ArchiveFormat::TarGzipPax);'; Count = 1 }
    )) {
        $count = [regex]::Matches(
            $TargetSource,
            [regex]::Escape([string]$contract.Token)
        ).Count
        if ($count -ne [int]$contract.Count) {
            throw "TAR/gzip PAX fuzz target must contain exactly $($contract.Count) live contract token(s): $($contract.Token)"
        }
    }
    foreach ($forbidden in @('dest: Some(', '__fuzz_tar_', 'unsafe {')) {
        if ($TargetSource.Contains($forbidden, [StringComparison]::Ordinal)) {
            throw "TAR/gzip PAX public fuzz target contains forbidden source: $forbidden"
        }
    }
}

function Assert-TarGzipGnuLongNameFuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($TargetSource)
    $digest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    if ($bytes.Length -ne $tarGzipGnuLongNameManifest.targetSource.bytes -or
        $digest -cne [string]$tarGzipGnuLongNameManifest.targetSource.sha256) {
        throw 'TAR/gzip GNU long-name fuzz target source differs from its digest-pinned contract'
    }
    foreach ($contract in @(
        @{ Token = 'fuzz_target!(|input: &[u8]| {'; Count = 1 }
        @{ Token = 'apply_with_options('; Count = 1 }
        @{ Token = 'Policy::default_v7()'; Count = 1 }
        @{ Token = 'policy.max_archive_bytes = MAX_INPUT_BYTES as u64;'; Count = 1 }
        @{ Token = 'policy.max_derived_archive_bytes = Some(131_072);'; Count = 1 }
        @{ Token = 'policy.max_metadata_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_files = 64;'; Count = 1 }
        @{ Token = 'policy.max_member_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_total_bytes = 65_536;'; Count = 1 }
        @{ Token = 'policy.max_path_depth = 16;'; Count = 1 }
        @{ Token = 'policy.max_ratio = Some(32);'; Count = 1 }
        @{ Token = '.with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::GnuLongNamePortableV1)'; Count = 1 }
        @{ Token = 'dest: None,'; Count = 1 }
        @{ Token = 'let first = inspect();'; Count = 1 }
        @{ Token = 'let second = inspect();'; Count = 1 }
        @{ Token = 'format!("{:?}", first.archive_ir())'; Count = 1 }
        @{ Token = 'assert_eq!(ir.format(), ArchiveFormat::TarGzipGnuLongName);'; Count = 1 }
    )) {
        $count = [regex]::Matches(
            $TargetSource,
            [regex]::Escape([string]$contract.Token)
        ).Count
        if ($count -ne [int]$contract.Count) {
            throw "TAR/gzip GNU long-name fuzz target must contain exactly $($contract.Count) live contract token(s): $($contract.Token)"
        }
    }
    foreach ($forbidden in @('dest: Some(', '__fuzz_tar_', 'unsafe {')) {
        if ($TargetSource.Contains($forbidden, [StringComparison]::Ordinal)) {
            throw "TAR/gzip GNU long-name public fuzz target contains forbidden source: $forbidden"
        }
    }
}

function Assert-TarZstdFuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($TargetSource)
    $digest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    if ($bytes.Length -ne $tarZstdManifest.targetSource.bytes -or
        $digest -cne [string]$tarZstdManifest.targetSource.sha256) {
        throw 'TAR/zstd fuzz target source differs from its digest-pinned contract'
    }
    foreach ($contract in @(
        @{ Token = 'fuzz_target!(|input: &[u8]| {'; Count = 1 }
        @{ Token = 'apply_with_options('; Count = 1 }
        @{ Token = 'Policy::default_v8()'; Count = 1 }
        @{ Token = 'policy.max_archive_bytes = MAX_INPUT_BYTES as u64;'; Count = 1 }
        @{ Token = 'policy.max_derived_archive_bytes = Some(131_072);'; Count = 1 }
        @{ Token = 'policy.max_metadata_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_files = 64;'; Count = 1 }
        @{ Token = 'policy.max_member_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_total_bytes = 65_536;'; Count = 1 }
        @{ Token = 'policy.max_path_depth = 16;'; Count = 1 }
        @{ Token = 'policy.max_ratio = Some(32);'; Count = 1 }
        @{ Token = '.with_tar_zstd_interpretation_profile(TarZstdInterpretationProfile::UstarPortableV1)'; Count = 1 }
        @{ Token = 'dest: None,'; Count = 1 }
        @{ Token = 'let first = inspect();'; Count = 1 }
        @{ Token = 'let second = inspect();'; Count = 1 }
        @{ Token = 'format!("{:?}", first.archive_ir())'; Count = 1 }
        @{ Token = 'assert_eq!(ir.format(), ArchiveFormat::TarZstdUstar);'; Count = 1 }
    )) {
        $count = [regex]::Matches(
            $TargetSource,
            [regex]::Escape([string]$contract.Token)
        ).Count
        if ($count -ne [int]$contract.Count) {
            throw "TAR/zstd fuzz target must contain exactly $($contract.Count) live contract token(s): $($contract.Token)"
        }
    }
    foreach ($forbidden in @('dest: Some(', '__fuzz_tar_', 'unsafe {')) {
        if ($TargetSource.Contains($forbidden, [StringComparison]::Ordinal)) {
            throw "TAR/zstd public fuzz target contains forbidden source: $forbidden"
        }
    }
}

function Assert-TarXzFuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($TargetSource)
    $digest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    if ($bytes.Length -ne $tarXzManifest.targetSource.bytes -or
        $digest -cne [string]$tarXzManifest.targetSource.sha256) {
        throw 'TAR/xz fuzz target source differs from its digest-pinned contract'
    }
    foreach ($contract in @(
        @{ Token = 'fuzz_target!(|input: &[u8]| {'; Count = 1 }
        @{ Token = 'apply_with_options('; Count = 1 }
        @{ Token = 'Policy::default_v9()'; Count = 1 }
        @{ Token = 'policy.max_archive_bytes = MAX_INPUT_BYTES as u64;'; Count = 1 }
        @{ Token = 'policy.max_derived_archive_bytes = Some(131_072);'; Count = 1 }
        @{ Token = 'policy.max_metadata_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_files = 64;'; Count = 1 }
        @{ Token = 'policy.max_member_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_total_bytes = 65_536;'; Count = 1 }
        @{ Token = 'policy.max_path_depth = 16;'; Count = 1 }
        @{ Token = 'policy.max_ratio = Some(32);'; Count = 1 }
        @{ Token = '.with_tar_xz_interpretation_profile(TarXzInterpretationProfile::UstarPortableV1)'; Count = 1 }
        @{ Token = 'dest: None,'; Count = 1 }
        @{ Token = 'let first = inspect();'; Count = 1 }
        @{ Token = 'let second = inspect();'; Count = 1 }
        @{ Token = 'format!("{:?}", first.archive_ir())'; Count = 1 }
        @{ Token = 'assert_eq!(ir.format(), ArchiveFormat::TarXzUstar);'; Count = 1 }
    )) {
        $count = [regex]::Matches(
            $TargetSource,
            [regex]::Escape([string]$contract.Token)
        ).Count
        if ($count -ne [int]$contract.Count) {
            throw "TAR/xz fuzz target must contain exactly $($contract.Count) live contract token(s): $($contract.Token)"
        }
    }
    foreach ($forbidden in @('dest: Some(', '__fuzz_tar_', 'unsafe {')) {
        if ($TargetSource.Contains($forbidden, [StringComparison]::Ordinal)) {
            throw "TAR/xz public fuzz target contains forbidden source: $forbidden"
        }
    }
}


function Assert-TarBzip2FuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($TargetSource)
    $digest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
    if ($bytes.Length -ne $tarBzip2Manifest.targetSource.bytes -or
        $digest -cne [string]$tarBzip2Manifest.targetSource.sha256) {
        throw 'TAR/bzip2 fuzz target source differs from its digest-pinned contract'
    }
    foreach ($contract in @(
        @{ Token = 'fuzz_target!(|input: &[u8]| {'; Count = 1 }
        @{ Token = 'apply_with_options('; Count = 1 }
        @{ Token = 'Policy::default_v10()'; Count = 1 }
        @{ Token = 'policy.max_archive_bytes = MAX_INPUT_BYTES as u64;'; Count = 1 }
        @{ Token = 'policy.max_derived_archive_bytes = Some(131_072);'; Count = 1 }
        @{ Token = 'policy.max_metadata_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_files = 64;'; Count = 1 }
        @{ Token = 'policy.max_member_bytes = 32_768;'; Count = 1 }
        @{ Token = 'policy.max_total_bytes = 65_536;'; Count = 1 }
        @{ Token = 'policy.max_path_depth = 16;'; Count = 1 }
        @{ Token = 'policy.max_ratio = Some(32);'; Count = 1 }
        @{ Token = '.with_tar_bzip2_interpretation_profile(TarBzip2InterpretationProfile::UstarPortableV1)'; Count = 1 }
        @{ Token = 'dest: None,'; Count = 1 }
        @{ Token = 'let first = inspect();'; Count = 1 }
        @{ Token = 'let second = inspect();'; Count = 1 }
        @{ Token = 'format!("{:?}", first.archive_ir())'; Count = 1 }
        @{ Token = 'assert_eq!(ir.format(), ArchiveFormat::TarBzip2Ustar);'; Count = 1 }
    )) {
        $count = [regex]::Matches(
            $TargetSource,
            [regex]::Escape([string]$contract.Token)
        ).Count
        if ($count -ne [int]$contract.Count) {
            throw "TAR/bzip2 fuzz target must contain exactly $($contract.Count) live contract token(s): $($contract.Token)"
        }
    }
    foreach ($forbidden in @('dest: Some(', '__fuzz_tar_', 'unsafe {')) {
        if ($TargetSource.Contains($forbidden, [StringComparison]::Ordinal)) {
            throw "TAR/bzip2 public fuzz target contains forbidden source: $forbidden"
        }
    }
}

function Assert-Zip64FuzzTargetSource {
    param([Parameter(Mandatory)] [string] $TargetSource)

    $expectedSource = @(
        '#![no_main]'
        ''
        'use libfuzzer_sys::fuzz_target;'
        'use sealr::{apply_with_options, ApplyOptions, Policy, Request, Source, ZipInterpretationProfile};'
        ''
        'fuzz_target!(|input: &[u8]| {'
        '    let mut policy = Policy::default_v3();'
        '    policy.max_archive_bytes = 1_048_576;'
        '    policy.max_files = 256;'
        '    policy.max_member_bytes = 65_536;'
        '    policy.max_total_bytes = 262_144;'
        '    policy.max_metadata_bytes = 262_144;'
        '    let options = ApplyOptions::new()'
        '        .with_interpretation_profile(ZipInterpretationProfile::Zip64StrictAsciiV1);'
        '    let _ = apply_with_options('
        '        Request {'
        '            source: Source::Bytes {'
        '                path: Some("fuzz.zip"),'
        '                data: input,'
        '            },'
        '            policy: &policy,'
        '            dest: None,'
        '        },'
        '        &options,'
        '    );'
        '});'
    ) -join "`n"
    if ((Normalize-WorkflowBlock $TargetSource) -cne $expectedSource) {
        throw 'ZIP64 fuzz target source must drive the exact bounded public strict-profile path'
    }
}

function Assert-FuzzCargoManifestContract {
    param([Parameter(Mandatory)] [string] $CargoManifest)

    $expectedManifest = @(
        '[package]'
        'name = "sealr-fuzz"'
        'version = "0.0.0"'
        'edition = "2021"'
        'license = "Apache-2.0"'
        'publish = false'
        ''
        '[package.metadata]'
        'cargo-fuzz = true'
        ''
        '[dependencies]'
        'libfuzzer-sys = "=0.4.13"'
        'sealr = { path = "../crates/sealr", version = "=0.1.0-alpha.11", features = ["__internal-fuzzing"] }'
        'sealr-worker-protocol = { path = "../crates/sealr-protocol", version = "=0.1.0-alpha.11" }'
        ''
        '[[bin]]'
        'name = "protocol_decoders"'
        'path = "fuzz_targets/protocol_decoders.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "semantic_records"'
        'path = "fuzz_targets/semantic_records.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "tar_ustar_portable_v1"'
        'path = "fuzz_targets/tar_ustar_portable_v1.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "tar_pax_portable_v1"'
        'path = "fuzz_targets/tar_pax_portable_v1.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "tar_gnu_longname_portable_v1"'
        'path = "fuzz_targets/tar_gnu_longname_portable_v1.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "gzip_rfc1952_single_member_v1"'
        'path = "fuzz_targets/gzip_rfc1952_single_member_v1.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "zip64_strict_ascii_v1"'
        'path = "fuzz_targets/zip64_strict_ascii_v1.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "tar_gzip_ustar_portable_v1"'
        'path = "fuzz_targets/tar_gzip_ustar_portable_v1.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "tar_gzip_pax_portable_v1"'
        'path = "fuzz_targets/tar_gzip_pax_portable_v1.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "tar_gzip_gnu_longname_portable_v1"'
        'path = "fuzz_targets/tar_gzip_gnu_longname_portable_v1.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "tar_zstd_ustar_portable_v1"'
        'path = "fuzz_targets/tar_zstd_ustar_portable_v1.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "tar_xz_ustar_portable_v1"'
        'path = "fuzz_targets/tar_xz_ustar_portable_v1.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[[bin]]'
        'name = "tar_bzip2_ustar_portable_v1"'
        'path = "fuzz_targets/tar_bzip2_ustar_portable_v1.rs"'
        'test = false'
        'doc = false'
        'bench = false'
        ''
        '[workspace]'
    ) -join "`n"
    if ((Normalize-WorkflowBlock $CargoManifest) -cne $expectedManifest) {
        throw 'Fuzz Cargo manifest must exactly match its package, dependency, and target contract'
    }
}

foreach ($required in @(
    'libfuzzer-sys = "=0.4.13"',
    'name = "libfuzzer-sys"',
    'version = "0.4.13"',
    'source = "registry+https://github.com/rust-lang/crates.io-index"',
    'checksum = "a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2"'
)) {
    if (-not ($fuzzCargo.Contains($required, [StringComparison]::Ordinal) -or
            $fuzzLock.Contains($required, [StringComparison]::Ordinal))) {
        throw "Pinned fuzz dependency evidence is missing: $required"
    }
}
$fuzzManifestPath = Join-Path $workspace 'fuzz/Cargo.toml'
Assert-NoCargoConfiguration
$fuzzMetadata = Get-FuzzCargoMetadata -ManifestPath $fuzzManifestPath -Locked
Assert-FuzzMetadataBinding `
    -Metadata $fuzzMetadata `
    -ManifestPath $fuzzManifestPath `
    -RequireDependencies
Assert-SemanticFuzzTargetSource -TargetSource $semanticTarget
Assert-TarFuzzTargetSource -TargetSource $tarTarget
Assert-TarPaxFuzzTargetSource -TargetSource $tarPaxTarget
Assert-TarGnuLongNameFuzzTargetSource -TargetSource $tarGnuLongNameTarget
Assert-GzipFuzzTargetSource -TargetSource $gzipTarget
Assert-TarGzipFuzzTargetSource -TargetSource $tarGzipTarget
Assert-TarGzipPaxFuzzTargetSource -TargetSource $tarGzipPaxTarget
Assert-TarGzipGnuLongNameFuzzTargetSource -TargetSource $tarGzipGnuLongNameTarget
Assert-TarZstdFuzzTargetSource -TargetSource $tarZstdTarget
Assert-TarXzFuzzTargetSource -TargetSource $tarXzTarget
Assert-TarBzip2FuzzTargetSource -TargetSource $tarBzip2Target
Assert-Zip64FuzzTargetSource -TargetSource $zip64Target
Assert-FuzzCargoManifestContract -CargoManifest $fuzzCargo

function Assert-TarGzipTargetMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $Candidate,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($Candidate -ceq $tarGzipTarget) {
        throw "TAR/gzip target regression could not construct its $Label fixture"
    }
    try {
        Assert-TarGzipFuzzTargetSource -TargetSource $Candidate
    } catch {
        return
    }
    throw "TAR/gzip target verifier accepted its $Label fixture"
}

Assert-TarGzipTargetMutationRejected `
    -Candidate $tarGzipTarget.Replace(
        '    let first = inspect();',
        "    if false {`n        let _ = inspect();`n    }`n    let first = inspect();"
    ) `
    -Label 'inert duplicate public apply call'
Assert-TarGzipTargetMutationRejected `
    -Candidate $tarGzipTarget.Replace(
        '    policy.max_total_bytes = 65_536;',
        "    policy.max_total_bytes = 65_536;`n    policy.max_total_bytes = 1_000_000;"
    ) `
    -Label 'duplicate last-wins resource bound'
Assert-TarGzipTargetMutationRejected `
    -Candidate $tarGzipTarget.Replace(
        '    policy.max_derived_archive_bytes = Some(131_072);',
        '    policy.max_derived_archive_bytes = Some(262_144);'
    ) `
    -Label 'weakened derived-output bound'

function Copy-TarGzipManifest {
    return $tarGzipManifest | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
}

foreach ($mutation in @(
    @{
        Label = 'inert manifest evidence'
        Apply = { param($candidate) $candidate | Add-Member -NotePropertyName inertEvidence -NotePropertyValue $true }
    }
    @{
        Label = 'duplicate seed path'
        Apply = { param($candidate) $candidate.seeds[1].path = $candidate.seeds[0].path }
    }
    @{
        Label = 'weakened manifest resource bound'
        Apply = { param($candidate) $candidate.bounds.maxDerivedArchiveBytes = 262144 }
    }
    @{
        Label = 'drifted dictionary digest'
        Apply = { param($candidate) $candidate.dictionary.sha256 = '00' * 32 }
    }
    @{
        Label = 'drifted failure artifact'
        Apply = { param($candidate) $candidate.failureArtifact.directoryName = 'wrong-artifacts' }
    }
)) {
    $candidate = Copy-TarGzipManifest
    & $mutation.Apply $candidate
    $rejected = $false
    try {
        Assert-TarGzipManifestContract -Candidate $candidate
    } catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "TAR/gzip manifest verifier accepted its $($mutation.Label) fixture"
    }
}

function Copy-TarGnuLongNameManifest {
    return $tarGnuLongNameManifest | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
}

foreach ($mutation in @(
    @{
        Label = 'inert manifest evidence'
        Apply = { param($candidate) $candidate | Add-Member -NotePropertyName inertEvidence -NotePropertyValue $true }
    }
    @{
        Label = 'duplicate seed path'
        Apply = { param($candidate) $candidate.seeds[1].path = $candidate.seeds[0].path }
    }
    @{
        Label = 'weakened manifest input bound'
        Apply = { param($candidate) $candidate.bounds.maxInputBytes = 8388608 }
    }
    @{
        Label = 'disabled sanitizer'
        Apply = { param($candidate) $candidate.sanitizer = 'none' }
    }
    @{
        Label = 'drifted dictionary digest'
        Apply = { param($candidate) $candidate.dictionary.sha256 = '00' * 32 }
    }
    @{
        Label = 'drifted failure artifact'
        Apply = { param($candidate) $candidate.failureArtifact.directoryName = 'wrong-artifacts' }
    }
)) {
    $candidate = Copy-TarGnuLongNameManifest
    & $mutation.Apply $candidate
    $rejected = $false
    try {
        Assert-TarGnuLongNameManifestContract -Candidate $candidate
    } catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "TAR GNU long-name manifest verifier accepted its $($mutation.Label) fixture"
    }
}

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
)
$temporaryFixture = [IO.Path]::GetFullPath(
    (Join-Path $temporaryBase ("sealr-fuzz-binding-{0}" -f [Guid]::NewGuid().ToString('N')))
)
if ([IO.Path]::GetDirectoryName($temporaryFixture) -cne $temporaryBase) {
    throw "Refusing to create Cargo regression fixture outside the temporary root: $temporaryFixture"
}
$inertTomlRejected = $false
$localLibfuzzerRejected = $false
$patchedLibfuzzerRejected = $false
$vendoredLibfuzzerRejected = $false
try {
    [void][IO.Directory]::CreateDirectory(
        (Join-Path $temporaryFixture 'fuzz_targets')
    )
    $inertToml = @'
[package]
name = "sealr-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[package.metadata]
inert_contract = '''
[[bin]]
name = "semantic_records"
path = "fuzz_targets/semantic_records.rs"
test = false
doc = false
bench = false
[sentinel]
'''

[[bin]]
name = 'semantic_records'
path = 'fuzz_targets/protocol_decoders.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'protocol_decoders'
path = 'fuzz_targets/protocol_decoders.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'tar_ustar_portable_v1'
path = 'fuzz_targets/tar_ustar_portable_v1.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'tar_pax_portable_v1'
path = 'fuzz_targets/tar_pax_portable_v1.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'tar_gnu_longname_portable_v1'
path = 'fuzz_targets/tar_gnu_longname_portable_v1.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'gzip_rfc1952_single_member_v1'
path = 'fuzz_targets/gzip_rfc1952_single_member_v1.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'zip64_strict_ascii_v1'
path = 'fuzz_targets/zip64_strict_ascii_v1.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'tar_gzip_ustar_portable_v1'
path = 'fuzz_targets/tar_gzip_ustar_portable_v1.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'tar_gzip_pax_portable_v1'
path = 'fuzz_targets/tar_gzip_pax_portable_v1.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'tar_gzip_gnu_longname_portable_v1'
path = 'fuzz_targets/tar_gzip_gnu_longname_portable_v1.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'tar_zstd_ustar_portable_v1'
path = 'fuzz_targets/tar_zstd_ustar_portable_v1.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'tar_xz_ustar_portable_v1'
path = 'fuzz_targets/tar_xz_ustar_portable_v1.rs'
test = false
doc = false
bench = false

[[bin]]
name = 'tar_bzip2_ustar_portable_v1'
path = 'fuzz_targets/tar_bzip2_ustar_portable_v1.rs'
test = false
doc = false
bench = false

[workspace]
'@
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'Cargo.toml'),
        $inertToml,
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/protocol_decoders.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/semantic_records.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/tar_ustar_portable_v1.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/tar_pax_portable_v1.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/tar_gnu_longname_portable_v1.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/gzip_rfc1952_single_member_v1.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/zip64_strict_ascii_v1.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/tar_gzip_ustar_portable_v1.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/tar_gzip_pax_portable_v1.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/tar_gzip_gnu_longname_portable_v1.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/tar_zstd_ustar_portable_v1.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/tar_xz_ustar_portable_v1.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fuzz_targets/tar_bzip2_ustar_portable_v1.rs'),
        "fn main() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    $inertMetadata = Get-FuzzCargoMetadata `
        -ManifestPath (Join-Path $temporaryFixture 'Cargo.toml') `
        -NoDeps
    try {
        Assert-FuzzMetadataBinding `
            -Metadata $inertMetadata `
            -ManifestPath (Join-Path $temporaryFixture 'Cargo.toml')
    } catch {
        $inertTomlRejected = $true
    }

    [void][IO.Directory]::CreateDirectory(
        (Join-Path $temporaryFixture 'fake-libfuzzer/src')
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fake-libfuzzer/Cargo.toml'),
        "[package]`nname = 'libfuzzer-sys'`nversion = '0.4.13'`nedition = '2021'`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'fake-libfuzzer/src/lib.rs'),
        "pub fn inert() {}`n",
        [Text.UTF8Encoding]::new($false)
    )
    $sealrDependencyPath = ([IO.Path]::GetFullPath(
        (Join-Path $workspace 'crates/sealr')
    )).Replace('\', '/')
    $protocolDependencyPath = ([IO.Path]::GetFullPath(
        (Join-Path $workspace 'crates/sealr-protocol')
    )).Replace('\', '/')
    $localSubstitutionToml = @"
[package]
name = "sealr-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
libfuzzer-sys = { path = "fake-libfuzzer", version = "=0.4.13" }
sealr = { path = "$sealrDependencyPath", version = "=0.1.0-alpha.11", features = ["__internal-fuzzing"] }
sealr-worker-protocol = { path = "$protocolDependencyPath", version = "=0.1.0-alpha.11" }

[[bin]]
name = "protocol_decoders"
path = "fuzz_targets/protocol_decoders.rs"
test = false
doc = false
bench = false

[[bin]]
name = "semantic_records"
path = "fuzz_targets/semantic_records.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tar_ustar_portable_v1"
path = "fuzz_targets/tar_ustar_portable_v1.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tar_pax_portable_v1"
path = "fuzz_targets/tar_pax_portable_v1.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tar_gnu_longname_portable_v1"
path = "fuzz_targets/tar_gnu_longname_portable_v1.rs"
test = false
doc = false
bench = false

[[bin]]
name = "gzip_rfc1952_single_member_v1"
path = "fuzz_targets/gzip_rfc1952_single_member_v1.rs"
test = false
doc = false
bench = false

[[bin]]
name = "zip64_strict_ascii_v1"
path = "fuzz_targets/zip64_strict_ascii_v1.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tar_gzip_ustar_portable_v1"
path = "fuzz_targets/tar_gzip_ustar_portable_v1.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tar_gzip_pax_portable_v1"
path = "fuzz_targets/tar_gzip_pax_portable_v1.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tar_gzip_gnu_longname_portable_v1"
path = "fuzz_targets/tar_gzip_gnu_longname_portable_v1.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tar_zstd_ustar_portable_v1"
path = "fuzz_targets/tar_zstd_ustar_portable_v1.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tar_xz_ustar_portable_v1"
path = "fuzz_targets/tar_xz_ustar_portable_v1.rs"
test = false
doc = false
bench = false

[[bin]]
name = "tar_bzip2_ustar_portable_v1"
path = "fuzz_targets/tar_bzip2_ustar_portable_v1.rs"
test = false
doc = false
bench = false

[workspace]
"@
    [IO.File]::WriteAllText(
        (Join-Path $temporaryFixture 'Cargo.toml'),
        $localSubstitutionToml,
        [Text.UTF8Encoding]::new($false)
    )
    $localSubstitutionMetadata = Get-FuzzCargoMetadata `
        -ManifestPath (Join-Path $temporaryFixture 'Cargo.toml') `
        -NoDeps
    try {
        Assert-FuzzMetadataBinding `
            -Metadata $localSubstitutionMetadata `
            -ManifestPath (Join-Path $temporaryFixture 'Cargo.toml') `
            -RequireDependencies
    } catch {
        $localLibfuzzerRejected = $true
    }

    $workspaceTableOffset = $fuzzCargo.IndexOf(
        '[workspace]',
        [StringComparison]::Ordinal
    )
    if ($workspaceTableOffset -lt 0) {
        throw 'Canonical fuzz manifest is missing its workspace table'
    }
    $patchTable = "[patch.crates-io]`nlibfuzzer-sys = { path = `"fake-libfuzzer`" }`n`n"
    $patchedSubstitutionToml = $fuzzCargo.Insert($workspaceTableOffset, $patchTable)
    if ($patchedSubstitutionToml.Remove($workspaceTableOffset, $patchTable.Length) -cne
        $fuzzCargo) {
        throw 'Patched libfuzzer regression changed more than its patch table'
    }
    try {
        Assert-FuzzCargoManifestContract -CargoManifest $patchedSubstitutionToml
    } catch {
        $patchedLibfuzzerRejected = $true
    }

    $vendoredMetadata = $fuzzMetadata |
        ConvertTo-Json -Depth 100 |
        ConvertFrom-Json -Depth 100
    $vendoredPackages = @(
        $vendoredMetadata.packages |
            Where-Object { $_.name -ceq 'libfuzzer-sys' -and $_.version -ceq '0.4.13' }
    )
    if ($vendoredPackages.Count -ne 1) {
        throw 'Vendored-source regression could not locate the resolved libfuzzer package'
    }
    $vendoredPackages[0].manifest_path = Join-Path (
        Join-Path $temporaryFixture 'vendor/libfuzzer-sys'
    ) 'Cargo.toml'
    try {
        Assert-FuzzMetadataBinding `
            -Metadata $vendoredMetadata `
            -ManifestPath $fuzzManifestPath `
            -RequireDependencies
    } catch {
        $vendoredLibfuzzerRejected = $true
    }
} finally {
    if ([IO.Directory]::Exists($temporaryFixture)) {
        [IO.Directory]::Delete($temporaryFixture, $true)
    }
}
if (-not $inertTomlRejected) {
    throw 'Semantic target binding accepted an inert expected block and remapped live Cargo target'
}
if (-not $localLibfuzzerRejected) {
    throw 'Fuzz dependency binding accepted a local libfuzzer-sys substitution'
}
if (-not $patchedLibfuzzerRejected) {
    throw 'Fuzz dependency binding accepted a crates.io-patched libfuzzer-sys substitution'
}
if (-not $vendoredLibfuzzerRejected) {
    throw 'Fuzz dependency binding accepted a registry-labelled vendored libfuzzer source'
}

$protocolJob = Get-WorkflowJobBlock -Content $workflow -JobName 'protocol'
$semanticJob = Get-WorkflowJobBlock -Content $workflow -JobName 'semantic'
$tarJob = Get-WorkflowJobBlock -Content $workflow -JobName 'tar_ustar'
$tarPaxJob = Get-WorkflowJobBlock -Content $workflow -JobName 'tar_pax'
$tarGnuLongNameJob = Get-WorkflowJobBlock -Content $workflow -JobName 'tar_gnu_longname'
$gzipJob = Get-WorkflowJobBlock -Content $workflow -JobName 'gzip'
$tarGzipJob = Get-WorkflowJobBlock -Content $workflow -JobName 'tar_gzip_ustar'
$zip64Job = Get-WorkflowJobBlock -Content $workflow -JobName 'zip64'
$tarGzipPaxJob = Get-WorkflowJobBlock -Content $workflow -JobName 'tar_gzip_pax'
$tarGzipGnuLongNameJob = Get-WorkflowJobBlock -Content $workflow -JobName 'tar_gzip_gnu_longname'
$tarZstdJob = Get-WorkflowJobBlock -Content $workflow -JobName 'tar_zstd_ustar'
$tarXzJob = Get-WorkflowJobBlock -Content $workflow -JobName 'tar_xz_ustar'
$tarBzip2Job = Get-WorkflowJobBlock -Content $workflow -JobName 'tar_bzip2_ustar'
Assert-FuzzJobContract `
    -JobBlock $protocolJob `
    -JobManifest $manifest `
    -JobName 'protocol' `
    -JobDisplayName 'Bounded worker protocol' `
    -FuzzStepName 'Fuzz bounded protocol decoders' `
    -ReproducerName 'protocol-decoder-reproducer'
Assert-FuzzJobContract `
    -JobBlock $semanticJob `
    -JobManifest $semanticManifest `
    -JobName 'semantic' `
    -JobDisplayName 'Bounded semantic records' `
    -FuzzStepName 'Fuzz bounded semantic records' `
    -ReproducerName 'semantic-record-reproducer'
Assert-FuzzJobContract `
    -JobBlock $tarJob `
    -JobManifest $tarManifest `
    -JobName 'tar_ustar' `
    -JobDisplayName 'Bounded raw POSIX ustar' `
    -FuzzStepName 'Fuzz bounded raw POSIX ustar' `
    -ReproducerName 'tar-ustar-reproducer'
Assert-FuzzJobContract `
    -JobBlock $tarPaxJob `
    -JobManifest $tarPaxManifest `
    -JobName 'tar_pax' `
    -JobDisplayName 'Bounded raw POSIX PAX' `
    -FuzzStepName 'Fuzz bounded raw POSIX PAX' `
    -ReproducerName 'tar-pax-reproducer'
Assert-FuzzJobContract `
    -JobBlock $tarGnuLongNameJob `
    -JobManifest $tarGnuLongNameManifest `
    -JobName 'tar_gnu_longname' `
    -JobDisplayName 'Bounded raw GNU long-name TAR' `
    -FuzzStepName 'Fuzz bounded raw GNU long-name TAR' `
    -ReproducerName 'tar-gnu-longname-reproducer'
Assert-FuzzJobContract `
    -JobBlock $gzipJob `
    -JobManifest $gzipManifest `
    -JobName 'gzip' `
    -JobDisplayName 'Bounded RFC 1952 gzip' `
    -FuzzStepName 'Fuzz bounded RFC 1952 gzip' `
    -ReproducerName 'gzip-rfc1952-reproducer'
Assert-FuzzJobContract `
    -JobBlock $tarGzipJob `
    -JobManifest $tarGzipManifest `
    -JobName 'tar_gzip_ustar' `
    -JobDisplayName 'Bounded public TAR gzip ustar' `
    -FuzzStepName 'Fuzz bounded public TAR gzip ustar' `
    -ReproducerName 'tar-gzip-ustar-reproducer'
Assert-FuzzJobContract `
    -JobBlock $zip64Job `
    -JobManifest $zip64Manifest `
    -JobName 'zip64' `
    -JobDisplayName 'Bounded strict ZIP64' `
    -FuzzStepName 'Fuzz bounded strict ZIP64 planning' `
    -ReproducerName 'zip64-strict-reproducer'
Assert-FuzzJobContract `
    -JobBlock $tarGzipPaxJob `
    -JobManifest $tarGzipPaxManifest `
    -JobName 'tar_gzip_pax' `
    -JobDisplayName 'Bounded gzip-wrapped restricted PAX TAR' `
    -FuzzStepName 'Fuzz bounded gzip-wrapped restricted PAX TAR' `
    -ReproducerName 'tar-gzip-pax-reproducer'
Assert-FuzzJobContract `
    -JobBlock $tarGzipGnuLongNameJob `
    -JobManifest $tarGzipGnuLongNameManifest `
    -JobName 'tar_gzip_gnu_longname' `
    -JobDisplayName 'Bounded gzip-wrapped GNU long-name TAR' `
    -FuzzStepName 'Fuzz bounded gzip-wrapped GNU long-name TAR' `
    -ReproducerName 'tar-gzip-gnu-longname-reproducer'
Assert-FuzzJobContract `
    -JobBlock $tarZstdJob `
    -JobManifest $tarZstdManifest `
    -JobName 'tar_zstd_ustar' `
    -JobDisplayName 'Bounded zstd-wrapped portable ustar TAR' `
    -FuzzStepName 'Fuzz bounded zstd-wrapped portable ustar TAR' `
    -ReproducerName 'tar-zstd-ustar-reproducer'
Assert-FuzzJobContract `
    -JobBlock $tarXzJob `
    -JobManifest $tarXzManifest `
    -JobName 'tar_xz_ustar' `
    -JobDisplayName 'Bounded xz-wrapped portable ustar TAR' `
    -FuzzStepName 'Fuzz bounded xz-wrapped portable ustar TAR' `
    -ReproducerName 'tar-xz-ustar-reproducer'
Assert-FuzzJobContract `
    -JobBlock $tarBzip2Job `
    -JobManifest $tarBzip2Manifest `
    -JobName 'tar_bzip2_ustar' `
    -JobDisplayName 'Bounded bzip2-wrapped portable ustar TAR' `
    -FuzzStepName 'Fuzz bounded bzip2-wrapped portable ustar TAR' `
    -ReproducerName 'tar-bzip2-ustar-reproducer'

function Assert-FuzzWorkflowContract {
    param(
        [Parameter(Mandatory)] [string] $CandidateWorkflow,
        [Parameter(Mandatory)] [string] $ExpectedProtocolJob,
        [Parameter(Mandatory)] [string] $ExpectedSemanticJob,
        [Parameter(Mandatory)] [string] $ExpectedTarJob,
        [Parameter(Mandatory)] [string] $ExpectedTarPaxJob,
        [Parameter(Mandatory)] [string] $ExpectedTarGnuLongNameJob,
        [Parameter(Mandatory)] [string] $ExpectedGzipJob,
        [Parameter(Mandatory)] [string] $ExpectedTarGzipJob,
        [Parameter(Mandatory)] [string] $ExpectedZip64Job,
        [Parameter(Mandatory)] [string] $ExpectedTarGzipPaxJob,
        [Parameter(Mandatory)] [string] $ExpectedTarGzipGnuLongNameJob,
        [Parameter(Mandatory)] [string] $ExpectedTarZstdJob,
        [Parameter(Mandatory)] [string] $ExpectedTarXzJob,
        [Parameter(Mandatory)] [string] $ExpectedTarBzip2Job
    )

    $expectedHeader = @(
        'name: Scheduled fuzz'
        ''
        'on:'
        '  schedule:'
        '    - cron: "31 8 * * 1"'
        '  workflow_dispatch:'
        ''
        'permissions:'
        '  contents: read'
        ''
        'concurrency:'
        '  group: scheduled-fuzz-${{ github.ref }}'
        '  cancel-in-progress: false'
        ''
        'jobs:'
    ) -join "`n"
    $expectedWorkflow = $expectedHeader + "`n" +
        (Normalize-WorkflowBlock $ExpectedProtocolJob) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedSemanticJob) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedTarJob) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedTarPaxJob) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedTarGnuLongNameJob) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedGzipJob) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedTarGzipJob) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedZip64Job) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedTarGzipPaxJob) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedTarGzipGnuLongNameJob) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedTarZstdJob) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedTarXzJob) + "`n`n" +
        (Normalize-WorkflowBlock $ExpectedTarBzip2Job)
    if ((Normalize-WorkflowBlock $CandidateWorkflow) -cne $expectedWorkflow) {
        throw 'Scheduled fuzz workflow must exactly match its trigger, authority, concurrency, and job contracts'
    }
}

Assert-FuzzWorkflowContract `
    -CandidateWorkflow $workflow `
    -ExpectedProtocolJob $protocolJob `
    -ExpectedSemanticJob $semanticJob `
    -ExpectedTarJob $tarJob `
    -ExpectedTarPaxJob $tarPaxJob `
    -ExpectedTarGnuLongNameJob $tarGnuLongNameJob `
    -ExpectedGzipJob $gzipJob `
    -ExpectedTarGzipJob $tarGzipJob `
    -ExpectedZip64Job $zip64Job `
    -ExpectedTarGzipPaxJob $tarGzipPaxJob `
    -ExpectedTarGzipGnuLongNameJob $tarGzipGnuLongNameJob `
    -ExpectedTarZstdJob $tarZstdJob `
    -ExpectedTarXzJob $tarXzJob `
    -ExpectedTarBzip2Job $tarBzip2Job
$manualOnlyWorkflow = [regex]::Replace(
    $workflow,
    '(?m)^  schedule:\r?\n    - cron: "31 8 \* \* 1"\r?\n',
    '',
    1
)
if ($manualOnlyWorkflow -ceq $workflow) {
    throw 'Fuzz workflow regression could not construct its manual-only fixture'
}
$manualOnlyRejected = $false
try {
    Assert-FuzzWorkflowContract `
        -CandidateWorkflow $manualOnlyWorkflow `
        -ExpectedProtocolJob $protocolJob `
        -ExpectedSemanticJob $semanticJob `
        -ExpectedTarJob $tarJob `
        -ExpectedTarPaxJob $tarPaxJob `
        -ExpectedTarGnuLongNameJob $tarGnuLongNameJob `
        -ExpectedGzipJob $gzipJob `
        -ExpectedTarGzipJob $tarGzipJob `
        -ExpectedZip64Job $zip64Job `
        -ExpectedTarGzipPaxJob $tarGzipPaxJob `
        -ExpectedTarGzipGnuLongNameJob $tarGzipGnuLongNameJob `
        -ExpectedTarZstdJob $tarZstdJob `
        -ExpectedTarXzJob $tarXzJob `
        -ExpectedTarBzip2Job $tarBzip2Job
} catch {
    $manualOnlyRejected = $true
}
if (-not $manualOnlyRejected) {
    throw 'Fuzz workflow verifier accepted a manual-only campaign without its weekly trigger'
}

$duplicateTarGzipWorkflow = (Normalize-WorkflowBlock $workflow) + "`n`n" +
    (Normalize-WorkflowBlock $tarGzipJob)
$duplicateTarGzipWorkflowRejected = $false
try {
    [void](Get-WorkflowJobBlock `
        -Content $duplicateTarGzipWorkflow `
        -JobName 'tar_gzip_ustar')
} catch {
    $duplicateTarGzipWorkflowRejected = $true
}
if (-not $duplicateTarGzipWorkflowRejected) {
    throw 'Fuzz workflow verifier accepted a duplicate public TAR/gzip job'
}

function Assert-SemanticJobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $semanticJob) {
        throw "Semantic fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $semanticManifest `
            -JobName 'semantic' `
            -JobDisplayName 'Bounded semantic records' `
            -FuzzStepName 'Fuzz bounded semantic records' `
            -ReproducerName 'semantic-record-reproducer'
    } catch {
        return
    }
    throw "Semantic fuzz verifier accepted its $Label fixture"
}

$expectedSemanticMaxLen = '-max_len={0} \' -f $semanticManifest.bounds.maxInputBytes
$weakenedSemanticJob = $semanticJob.Replace($expectedSemanticMaxLen, '-max_len=64 \')
Assert-SemanticJobMutationRejected `
    -MutatedJob $weakenedSemanticJob `
    -Label 'weakened semantic job masked by protocol-job tokens'

$duplicateSemanticJob = $semanticJob.Replace(
    $expectedSemanticMaxLen,
    "$expectedSemanticMaxLen`n            -max_len=64 \"
)
Assert-SemanticJobMutationRejected `
    -MutatedJob $duplicateSemanticJob `
    -Label 'duplicate last-wins semantic bound'

$quotedDuplicateSemanticJob = $semanticJob.Replace(
    $expectedSemanticMaxLen,
    "$expectedSemanticMaxLen`n            `"-max_len=64`" \"
)
Assert-SemanticJobMutationRejected `
    -MutatedJob $quotedDuplicateSemanticJob `
    -Label 'quoted duplicate last-wins semantic bound'

$inactiveSemanticJob = $semanticJob.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-SemanticJobMutationRejected `
    -MutatedJob $inactiveSemanticJob `
    -Label 'inactive fuzz command followed by a successful no-op'

$secondCommandSemanticJob = $semanticJob.Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          true"
)
Assert-SemanticJobMutationRejected `
    -MutatedJob $secondCommandSemanticJob `
    -Label 'second fuzz-step command'

$expectedArtifactPath = '          path: ${{ runner.temp }}/sealr-semantic-fuzz-artifacts/'
$inertArtifactSemanticJob = $semanticJob.Replace(
    $expectedArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedArtifactPath.Trim())`n        with:"
)
Assert-SemanticJobMutationRejected `
    -MutatedJob $inertArtifactSemanticJob `
    -Label 'inert artifact evidence with a drifted upload path'

function Assert-TarJobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $tarJob) {
        throw "TAR fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $tarManifest `
            -JobName 'tar_ustar' `
            -JobDisplayName 'Bounded raw POSIX ustar' `
            -FuzzStepName 'Fuzz bounded raw POSIX ustar' `
            -ReproducerName 'tar-ustar-reproducer'
    } catch {
        return
    }
    throw "TAR fuzz verifier accepted its $Label fixture"
}

$expectedTarMaxLen = '-max_len={0} \' -f $tarManifest.bounds.maxInputBytes
$weakenedTarJob = $tarJob.Replace($expectedTarMaxLen, '-max_len=64 \')
Assert-TarJobMutationRejected `
    -MutatedJob $weakenedTarJob `
    -Label 'weakened TAR job masked by other job tokens'

$duplicateTarJob = $tarJob.Replace(
    $expectedTarMaxLen,
    "$expectedTarMaxLen`n            -max_len=64 \"
)
Assert-TarJobMutationRejected `
    -MutatedJob $duplicateTarJob `
    -Label 'duplicate last-wins TAR bound'

$inactiveTarJob = $tarJob.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-TarJobMutationRejected `
    -MutatedJob $inactiveTarJob `
    -Label 'inactive TAR command followed by a successful no-op'

$secondCommandTarJob = $tarJob.Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          true"
)
Assert-TarJobMutationRejected `
    -MutatedJob $secondCommandTarJob `
    -Label 'second TAR fuzz-step command'

$expectedTarArtifactPath = '          path: ${{ runner.temp }}/sealr-tar-ustar-fuzz-artifacts/'
$inertArtifactTarJob = $tarJob.Replace(
    $expectedTarArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedTarArtifactPath.Trim())`n        with:"
)
Assert-TarJobMutationRejected `
    -MutatedJob $inertArtifactTarJob `
    -Label 'inert TAR artifact evidence with a drifted upload path'

function Assert-TarPaxJobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $tarPaxJob) {
        throw "TAR PAX fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $tarPaxManifest `
            -JobName 'tar_pax' `
            -JobDisplayName 'Bounded raw POSIX PAX' `
            -FuzzStepName 'Fuzz bounded raw POSIX PAX' `
            -ReproducerName 'tar-pax-reproducer'
    } catch {
        return
    }
    throw "TAR PAX fuzz verifier accepted its $Label fixture"
}

$expectedTarPaxMaxLen = '-max_len={0} \' -f $tarPaxManifest.bounds.maxInputBytes
$weakenedTarPaxJob = $tarPaxJob.Replace($expectedTarPaxMaxLen, '-max_len=64 \')
Assert-TarPaxJobMutationRejected `
    -MutatedJob $weakenedTarPaxJob `
    -Label 'weakened TAR PAX job masked by other job tokens'

$duplicateTarPaxJob = $tarPaxJob.Replace(
    $expectedTarPaxMaxLen,
    "$expectedTarPaxMaxLen`n            -max_len=64 \"
)
Assert-TarPaxJobMutationRejected `
    -MutatedJob $duplicateTarPaxJob `
    -Label 'duplicate last-wins TAR PAX bound'

$inactiveTarPaxJob = $tarPaxJob.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-TarPaxJobMutationRejected `
    -MutatedJob $inactiveTarPaxJob `
    -Label 'inactive TAR PAX command followed by a successful no-op'

$secondCommandTarPaxJob = $tarPaxJob.Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          true"
)
Assert-TarPaxJobMutationRejected `
    -MutatedJob $secondCommandTarPaxJob `
    -Label 'second TAR PAX fuzz-step command'

$expectedTarPaxArtifactPath = '          path: ${{ runner.temp }}/sealr-tar-pax-fuzz-artifacts/'
$inertArtifactTarPaxJob = $tarPaxJob.Replace(
    $expectedTarPaxArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedTarPaxArtifactPath.Trim())`n        with:"
)
Assert-TarPaxJobMutationRejected `
    -MutatedJob $inertArtifactTarPaxJob `
    -Label 'inert TAR PAX artifact evidence with a drifted upload path'

function Assert-TarGnuLongNameJobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $tarGnuLongNameJob) {
        throw "TAR GNU long-name fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $tarGnuLongNameManifest `
            -JobName 'tar_gnu_longname' `
            -JobDisplayName 'Bounded raw GNU long-name TAR' `
            -FuzzStepName 'Fuzz bounded raw GNU long-name TAR' `
            -ReproducerName 'tar-gnu-longname-reproducer'
    } catch {
        return
    }
    throw "TAR GNU long-name fuzz verifier accepted its $Label fixture"
}

$expectedTarGnuLongNameMaxLen = '-max_len={0} \' -f $tarGnuLongNameManifest.bounds.maxInputBytes
$weakenedTarGnuLongNameJob = $tarGnuLongNameJob.Replace(
    $expectedTarGnuLongNameMaxLen,
    '-max_len=64 \'
)
Assert-TarGnuLongNameJobMutationRejected `
    -MutatedJob $weakenedTarGnuLongNameJob `
    -Label 'weakened input bound masked by other job tokens'

$duplicateTarGnuLongNameJob = $tarGnuLongNameJob.Replace(
    $expectedTarGnuLongNameMaxLen,
    "$expectedTarGnuLongNameMaxLen`n            -max_len=64 \"
)
Assert-TarGnuLongNameJobMutationRejected `
    -MutatedJob $duplicateTarGnuLongNameJob `
    -Label 'duplicate last-wins input bound'

$inactiveTarGnuLongNameJob = $tarGnuLongNameJob.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-TarGnuLongNameJobMutationRejected `
    -MutatedJob $inactiveTarGnuLongNameJob `
    -Label 'inactive command followed by a successful no-op'

$secondCommandTarGnuLongNameJob = $tarGnuLongNameJob.Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          true"
)
Assert-TarGnuLongNameJobMutationRejected `
    -MutatedJob $secondCommandTarGnuLongNameJob `
    -Label 'second fuzz-step command'

$weakenedTarGnuLongNameSanitizer = $tarGnuLongNameJob.Replace(
    '            --sanitizer address \',
    '            --sanitizer none \'
)
Assert-TarGnuLongNameJobMutationRejected `
    -MutatedJob $weakenedTarGnuLongNameSanitizer `
    -Label 'weakened sanitizer'

$expectedTarGnuLongNameArtifactPath = '          path: ${{ runner.temp }}/sealr-tar-gnu-longname-fuzz-artifacts/'
$inertArtifactTarGnuLongNameJob = $tarGnuLongNameJob.Replace(
    $expectedTarGnuLongNameArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedTarGnuLongNameArtifactPath.Trim())`n        with:"
)
Assert-TarGnuLongNameJobMutationRejected `
    -MutatedJob $inertArtifactTarGnuLongNameJob `
    -Label 'inert artifact evidence with a drifted upload path'

function Assert-GzipJobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $gzipJob) {
        throw "gzip fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $gzipManifest `
            -JobName 'gzip' `
            -JobDisplayName 'Bounded RFC 1952 gzip' `
            -FuzzStepName 'Fuzz bounded RFC 1952 gzip' `
            -ReproducerName 'gzip-rfc1952-reproducer'
    } catch {
        return
    }
    throw "gzip fuzz verifier accepted its $Label fixture"
}

$expectedGzipMaxLen = '-max_len={0} \' -f $gzipManifest.bounds.maxInputBytes
$weakenedGzipJob = $gzipJob.Replace($expectedGzipMaxLen, '-max_len=64 \')
Assert-GzipJobMutationRejected `
    -MutatedJob $weakenedGzipJob `
    -Label 'weakened gzip job masked by other job tokens'

$duplicateGzipJob = $gzipJob.Replace(
    $expectedGzipMaxLen,
    "$expectedGzipMaxLen`n            -max_len=64 \"
)
Assert-GzipJobMutationRejected `
    -MutatedJob $duplicateGzipJob `
    -Label 'duplicate last-wins gzip bound'

$inactiveGzipJob = $gzipJob.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-GzipJobMutationRejected `
    -MutatedJob $inactiveGzipJob `
    -Label 'inactive gzip command followed by a successful no-op'

$secondCommandGzipJob = $gzipJob.Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          true"
)
Assert-GzipJobMutationRejected `
    -MutatedJob $secondCommandGzipJob `
    -Label 'second gzip fuzz-step command'

$expectedGzipArtifactPath = '          path: ${{ runner.temp }}/sealr-gzip-fuzz-artifacts/'
$inertArtifactGzipJob = $gzipJob.Replace(
    $expectedGzipArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedGzipArtifactPath.Trim())`n        with:"
)
Assert-GzipJobMutationRejected `
    -MutatedJob $inertArtifactGzipJob `
    -Label 'inert gzip artifact evidence with a drifted upload path'

function Assert-TarGzipJobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $tarGzipJob) {
        throw "TAR/gzip fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $tarGzipManifest `
            -JobName 'tar_gzip_ustar' `
            -JobDisplayName 'Bounded public TAR gzip ustar' `
            -FuzzStepName 'Fuzz bounded public TAR gzip ustar' `
            -ReproducerName 'tar-gzip-ustar-reproducer'
    } catch {
        return
    }
    throw "TAR/gzip fuzz verifier accepted its $Label fixture"
}

$expectedTarGzipMaxLen = '-max_len={0} \' -f $tarGzipManifest.bounds.maxInputBytes
$weakenedTarGzipJob = $tarGzipJob.Replace($expectedTarGzipMaxLen, '-max_len=524288 \')
Assert-TarGzipJobMutationRejected `
    -MutatedJob $weakenedTarGzipJob `
    -Label 'weakened public TAR/gzip input bound'

$duplicateTarGzipJob = $tarGzipJob.Replace(
    $expectedTarGzipMaxLen,
    "$expectedTarGzipMaxLen`n            -max_len=524288 \"
)
Assert-TarGzipJobMutationRejected `
    -MutatedJob $duplicateTarGzipJob `
    -Label 'duplicate last-wins public TAR/gzip input bound'

$inactiveTarGzipJob = $tarGzipJob.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-TarGzipJobMutationRejected `
    -MutatedJob $inactiveTarGzipJob `
    -Label 'inactive public TAR/gzip fuzz command followed by a no-op'

$secondCommandTarGzipJob = $tarGzipJob.Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          true"
)
Assert-TarGzipJobMutationRejected `
    -MutatedJob $secondCommandTarGzipJob `
    -Label 'second public TAR/gzip fuzz-step command'

$weakenedTarGzipSanitizer = $tarGzipJob.Replace(
    '            --sanitizer address \',
    '            --sanitizer none \'
)
Assert-TarGzipJobMutationRejected `
    -MutatedJob $weakenedTarGzipSanitizer `
    -Label 'weakened public TAR/gzip sanitizer'

$driftedTarGzipDictionary = $tarGzipJob.Replace(
    '            -dict=fuzz/dictionaries/tar_gzip_ustar_portable_v1_dictionary \',
    '            -dict=fuzz/dictionaries/gzip_rfc1952_single_member_v1_dictionary \'
)
Assert-TarGzipJobMutationRejected `
    -MutatedJob $driftedTarGzipDictionary `
    -Label 'drifted public TAR/gzip dictionary'

$expectedTarGzipArtifactPath = '          path: ${{ runner.temp }}/sealr-tar-gzip-fuzz-artifacts/'
$inertArtifactTarGzipJob = $tarGzipJob.Replace(
    $expectedTarGzipArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedTarGzipArtifactPath.Trim())`n        with:"
)
Assert-TarGzipJobMutationRejected `
    -MutatedJob $inertArtifactTarGzipJob `
    -Label 'inert public TAR/gzip artifact evidence with drifted upload path'

function Assert-Zip64JobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $zip64Job) {
        throw "ZIP64 fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $zip64Manifest `
            -JobName 'zip64' `
            -JobDisplayName 'Bounded strict ZIP64' `
            -FuzzStepName 'Fuzz bounded strict ZIP64 planning' `
            -ReproducerName 'zip64-strict-reproducer'
    } catch {
        return
    }
    throw "ZIP64 fuzz verifier accepted its $Label fixture"
}

$expectedZip64MaxLen = '-max_len={0} \' -f $zip64Manifest.bounds.maxInputBytes
$weakenedZip64Job = $zip64Job.Replace($expectedZip64MaxLen, '-max_len=64 \')
Assert-Zip64JobMutationRejected `
    -MutatedJob $weakenedZip64Job `
    -Label 'weakened ZIP64 job masked by other job tokens'

$duplicateZip64Job = $zip64Job.Replace(
    $expectedZip64MaxLen,
    "$expectedZip64MaxLen`n            -max_len=64 \"
)
Assert-Zip64JobMutationRejected `
    -MutatedJob $duplicateZip64Job `
    -Label 'duplicate last-wins ZIP64 bound'

$inactiveZip64Job = $zip64Job.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-Zip64JobMutationRejected `
    -MutatedJob $inactiveZip64Job `
    -Label 'inactive ZIP64 command followed by a successful no-op'

$expectedZip64ArtifactPath = '          path: ${{ runner.temp }}/sealr-zip64-fuzz-artifacts/'
$inertArtifactZip64Job = $zip64Job.Replace(
    $expectedZip64ArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedZip64ArtifactPath.Trim())`n        with:"
)
Assert-Zip64JobMutationRejected `
    -MutatedJob $inertArtifactZip64Job `
    -Label 'inert ZIP64 artifact evidence with a drifted upload path'

function Assert-TarGzipPaxJobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $tarGzipPaxJob) {
        throw "TAR/gzip PAX fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $tarGzipPaxManifest `
            -JobName 'tar_gzip_pax' `
            -JobDisplayName 'Bounded gzip-wrapped restricted PAX TAR' `
            -FuzzStepName 'Fuzz bounded gzip-wrapped restricted PAX TAR' `
            -ReproducerName 'tar-gzip-pax-reproducer'
    } catch {
        return
    }
    throw "TAR/gzip PAX fuzz verifier accepted its $Label fixture"
}

$expectedTarGzipPaxMaxLen = '-max_len={0} \' -f $tarGzipPaxManifest.bounds.maxInputBytes
$weakenedTarGzipPaxJob = $tarGzipPaxJob.Replace(
    $expectedTarGzipPaxMaxLen,
    '-max_len=524288 \'
)
Assert-TarGzipPaxJobMutationRejected `
    -MutatedJob $weakenedTarGzipPaxJob `
    -Label 'weakened input bound masked by other job tokens'

$duplicateTarGzipPaxJob = $tarGzipPaxJob.Replace(
    $expectedTarGzipPaxMaxLen,
    "$expectedTarGzipPaxMaxLen`n            -max_len=524288 \"
)
Assert-TarGzipPaxJobMutationRejected `
    -MutatedJob $duplicateTarGzipPaxJob `
    -Label 'duplicate last-wins input bound'

$inactiveTarGzipPaxJob = $tarGzipPaxJob.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-TarGzipPaxJobMutationRejected `
    -MutatedJob $inactiveTarGzipPaxJob `
    -Label 'inactive command followed by a successful no-op'

$secondCommandTarGzipPaxJob = $tarGzipPaxJob.Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          true"
)
Assert-TarGzipPaxJobMutationRejected `
    -MutatedJob $secondCommandTarGzipPaxJob `
    -Label 'second fuzz-step command'

$weakenedTarGzipPaxSanitizer = $tarGzipPaxJob.Replace(
    '            --sanitizer address \',
    '            --sanitizer none \'
)
Assert-TarGzipPaxJobMutationRejected `
    -MutatedJob $weakenedTarGzipPaxSanitizer `
    -Label 'weakened sanitizer'

$expectedTarGzipPaxArtifactPath = '          path: ${{ runner.temp }}/sealr-tar-gzip-pax-fuzz-artifacts/'
$inertArtifactTarGzipPaxJob = $tarGzipPaxJob.Replace(
    $expectedTarGzipPaxArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedTarGzipPaxArtifactPath.Trim())`n        with:"
)
Assert-TarGzipPaxJobMutationRejected `
    -MutatedJob $inertArtifactTarGzipPaxJob `
    -Label 'inert artifact evidence with a drifted upload path'

function Assert-TarGzipGnuLongNameJobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $tarGzipGnuLongNameJob) {
        throw "TAR/gzip GNU long-name fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $tarGzipGnuLongNameManifest `
            -JobName 'tar_gzip_gnu_longname' `
            -JobDisplayName 'Bounded gzip-wrapped GNU long-name TAR' `
            -FuzzStepName 'Fuzz bounded gzip-wrapped GNU long-name TAR' `
            -ReproducerName 'tar-gzip-gnu-longname-reproducer'
    } catch {
        return
    }
    throw "TAR/gzip GNU long-name fuzz verifier accepted its $Label fixture"
}

$expectedTarGzipGnuLongNameMaxLen = '-max_len={0} \' -f $tarGzipGnuLongNameManifest.bounds.maxInputBytes
$weakenedTarGzipGnuLongNameJob = $tarGzipGnuLongNameJob.Replace(
    $expectedTarGzipGnuLongNameMaxLen,
    '-max_len=524288 \'
)
Assert-TarGzipGnuLongNameJobMutationRejected `
    -MutatedJob $weakenedTarGzipGnuLongNameJob `
    -Label 'weakened input bound masked by other job tokens'

$duplicateTarGzipGnuLongNameJob = $tarGzipGnuLongNameJob.Replace(
    $expectedTarGzipGnuLongNameMaxLen,
    "$expectedTarGzipGnuLongNameMaxLen`n            -max_len=524288 \"
)
Assert-TarGzipGnuLongNameJobMutationRejected `
    -MutatedJob $duplicateTarGzipGnuLongNameJob `
    -Label 'duplicate last-wins input bound'

$inactiveTarGzipGnuLongNameJob = $tarGzipGnuLongNameJob.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-TarGzipGnuLongNameJobMutationRejected `
    -MutatedJob $inactiveTarGzipGnuLongNameJob `
    -Label 'inactive command followed by a successful no-op'

$secondCommandTarGzipGnuLongNameJob = $tarGzipGnuLongNameJob.Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          true"
)
Assert-TarGzipGnuLongNameJobMutationRejected `
    -MutatedJob $secondCommandTarGzipGnuLongNameJob `
    -Label 'second fuzz-step command'

$weakenedTarGzipGnuLongNameSanitizer = $tarGzipGnuLongNameJob.Replace(
    '            --sanitizer address \',
    '            --sanitizer none \'
)
Assert-TarGzipGnuLongNameJobMutationRejected `
    -MutatedJob $weakenedTarGzipGnuLongNameSanitizer `
    -Label 'weakened sanitizer'

$expectedTarGzipGnuLongNameArtifactPath = '          path: ${{ runner.temp }}/sealr-tar-gzip-gnu-longname-fuzz-artifacts/'
$inertArtifactTarGzipGnuLongNameJob = $tarGzipGnuLongNameJob.Replace(
    $expectedTarGzipGnuLongNameArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedTarGzipGnuLongNameArtifactPath.Trim())`n        with:"
)
Assert-TarGzipGnuLongNameJobMutationRejected `
    -MutatedJob $inertArtifactTarGzipGnuLongNameJob `
    -Label 'inert artifact evidence with a drifted upload path'

function Assert-TarZstdJobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $tarZstdJob) {
        throw "TAR/zstd fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $tarZstdManifest `
            -JobName 'tar_zstd_ustar' `
            -JobDisplayName 'Bounded zstd-wrapped portable ustar TAR' `
            -FuzzStepName 'Fuzz bounded zstd-wrapped portable ustar TAR' `
            -ReproducerName 'tar-zstd-ustar-reproducer'
    } catch {
        return
    }
    throw "TAR/zstd fuzz verifier accepted its $Label fixture"
}

$expectedTarZstdMaxLen = '-max_len={0} \' -f $tarZstdManifest.bounds.maxInputBytes
$weakenedTarZstdJob = $tarZstdJob.Replace(
    $expectedTarZstdMaxLen,
    '-max_len=524288 \'
)
Assert-TarZstdJobMutationRejected `
    -MutatedJob $weakenedTarZstdJob `
    -Label 'weakened input bound masked by other job tokens'

$duplicateTarZstdJob = $tarZstdJob.Replace(
    $expectedTarZstdMaxLen,
    "$expectedTarZstdMaxLen`n            -max_len=524288 \"
)
Assert-TarZstdJobMutationRejected `
    -MutatedJob $duplicateTarZstdJob `
    -Label 'duplicate last-wins input bound'

$inactiveTarZstdJob = $tarZstdJob.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-TarZstdJobMutationRejected `
    -MutatedJob $inactiveTarZstdJob `
    -Label 'inactive command followed by a successful no-op'

$secondCommandTarZstdJob = $tarZstdJob.Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          true"
)
Assert-TarZstdJobMutationRejected `
    -MutatedJob $secondCommandTarZstdJob `
    -Label 'second fuzz-step command'

$weakenedTarZstdSanitizer = $tarZstdJob.Replace(
    '            --sanitizer address \',
    '            --sanitizer none \'
)
Assert-TarZstdJobMutationRejected `
    -MutatedJob $weakenedTarZstdSanitizer `
    -Label 'weakened sanitizer'

$expectedTarZstdArtifactPath = '          path: ${{ runner.temp }}/sealr-tar-zstd-fuzz-artifacts/'
$inertArtifactTarZstdJob = $tarZstdJob.Replace(
    $expectedTarZstdArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedTarZstdArtifactPath.Trim())`n        with:"
)
Assert-TarZstdJobMutationRejected `
    -MutatedJob $inertArtifactTarZstdJob `
    -Label 'inert artifact evidence with a drifted upload path'

function Assert-TarXzJobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $tarXzJob) {
        throw "TAR/xz fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $tarXzManifest `
            -JobName 'tar_xz_ustar' `
            -JobDisplayName 'Bounded xz-wrapped portable ustar TAR' `
            -FuzzStepName 'Fuzz bounded xz-wrapped portable ustar TAR' `
            -ReproducerName 'tar-xz-ustar-reproducer'
    } catch {
        return
    }
    throw "TAR/xz fuzz verifier accepted its $Label fixture"
}

$expectedTarXzMaxLen = '-max_len={0} \' -f $tarXzManifest.bounds.maxInputBytes
$weakenedTarXzJob = $tarXzJob.Replace(
    $expectedTarXzMaxLen,
    '-max_len=524288 \'
)
Assert-TarXzJobMutationRejected `
    -MutatedJob $weakenedTarXzJob `
    -Label 'weakened input bound masked by other job tokens'

$duplicateTarXzJob = $tarXzJob.Replace(
    $expectedTarXzMaxLen,
    "$expectedTarXzMaxLen`n            -max_len=524288 \"
)
Assert-TarXzJobMutationRejected `
    -MutatedJob $duplicateTarXzJob `
    -Label 'duplicate last-wins input bound'

$inactiveTarXzJob = $tarXzJob.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-TarXzJobMutationRejected `
    -MutatedJob $inactiveTarXzJob `
    -Label 'inactive command followed by a successful no-op'

$secondCommandTarXzJob = $tarXzJob.Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          true"
)
Assert-TarXzJobMutationRejected `
    -MutatedJob $secondCommandTarXzJob `
    -Label 'second fuzz-step command'

$weakenedTarXzSanitizer = $tarXzJob.Replace(
    '            --sanitizer address \',
    '            --sanitizer none \'
)
Assert-TarXzJobMutationRejected `
    -MutatedJob $weakenedTarXzSanitizer `
    -Label 'weakened sanitizer'

$expectedTarXzArtifactPath = '          path: ${{ runner.temp }}/sealr-tar-xz-fuzz-artifacts/'
$inertArtifactTarXzJob = $tarXzJob.Replace(
    $expectedTarXzArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedTarXzArtifactPath.Trim())`n        with:"
)
Assert-TarXzJobMutationRejected `
    -MutatedJob $inertArtifactTarXzJob `
    -Label 'inert artifact evidence with a drifted upload path'


function Assert-TarBzip2JobMutationRejected {
    param(
        [Parameter(Mandatory)] [string] $MutatedJob,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($MutatedJob -ceq $tarBzip2Job) {
        throw "TAR/bzip2 fuzz verifier regression could not construct its $Label fixture"
    }
    try {
        Assert-FuzzJobContract `
            -JobBlock $MutatedJob `
            -JobManifest $tarBzip2Manifest `
            -JobName 'tar_bzip2_ustar' `
            -JobDisplayName 'Bounded bzip2-wrapped portable ustar TAR' `
            -FuzzStepName 'Fuzz bounded bzip2-wrapped portable ustar TAR' `
            -ReproducerName 'tar-bzip2-ustar-reproducer'
    } catch {
        return
    }
    throw "TAR/bzip2 fuzz verifier accepted its $Label fixture"
}

$expectedTarBzip2MaxLen = '-max_len={0} \' -f $tarBzip2Manifest.bounds.maxInputBytes
$weakenedTarBzip2Job = $tarBzip2Job.Replace(
    $expectedTarBzip2MaxLen,
    '-max_len=524288 \'
)
Assert-TarBzip2JobMutationRejected `
    -MutatedJob $weakenedTarBzip2Job `
    -Label 'weakened input bound masked by other job tokens'

$duplicateTarBzip2Job = $tarBzip2Job.Replace(
    $expectedTarBzip2MaxLen,
    "$expectedTarBzip2MaxLen`n            -max_len=524288 \"
)
Assert-TarBzip2JobMutationRejected `
    -MutatedJob $duplicateTarBzip2Job `
    -Label 'duplicate last-wins input bound'

$inactiveTarBzip2Job = $tarBzip2Job.Replace(
    '          set -euo pipefail',
    "          if false; then`n          set -euo pipefail"
).Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          fi`n          true"
)
Assert-TarBzip2JobMutationRejected `
    -MutatedJob $inactiveTarBzip2Job `
    -Label 'inactive command followed by a successful no-op'

$secondCommandTarBzip2Job = $tarBzip2Job.Replace(
    '            -print_final_stats=1',
    "            -print_final_stats=1`n          true"
)
Assert-TarBzip2JobMutationRejected `
    -MutatedJob $secondCommandTarBzip2Job `
    -Label 'second fuzz-step command'

$weakenedTarBzip2Sanitizer = $tarBzip2Job.Replace(
    '            --sanitizer address \',
    '            --sanitizer none \'
)
Assert-TarBzip2JobMutationRejected `
    -MutatedJob $weakenedTarBzip2Sanitizer `
    -Label 'weakened sanitizer'

$expectedTarBzip2ArtifactPath = '          path: ${{ runner.temp }}/sealr-tar-bzip2-fuzz-artifacts/'
$inertArtifactTarBzip2Job = $tarBzip2Job.Replace(
    $expectedTarBzip2ArtifactPath,
    '          path: ${{ runner.temp }}/wrong-artifacts/'
).Replace(
    '        with:',
    "        env:`n          INERT_MANIFEST_EVIDENCE: |`n            $($expectedTarBzip2ArtifactPath.Trim())`n        with:"
)
Assert-TarBzip2JobMutationRejected `
    -MutatedJob $inertArtifactTarBzip2Job `
    -Label 'inert artifact evidence with a drifted upload path'

foreach ($required in @(
    'Require exact protected main fuzz evidence',
    'actions/workflows/fuzz.yml/runs',
    'Bounded worker protocol',
    'Bounded semantic records',
    'Bounded raw POSIX ustar',
    'Bounded raw POSIX PAX',
    'Bounded raw GNU long-name TAR',
    'Bounded RFC 1952 gzip',
    'Bounded public TAR gzip ustar',
    'Bounded strict ZIP64',
    'Bounded gzip-wrapped restricted PAX TAR',
    'Bounded gzip-wrapped GNU long-name TAR',
    'Bounded zstd-wrapped portable ustar TAR',
    'Bounded xz-wrapped portable ustar TAR',
    'Bounded bzip2-wrapped portable ustar TAR'
)) {
    if (-not $releaseWorkflow.Contains($required, [StringComparison]::Ordinal)) {
        throw "Release workflow is missing exact fuzz evidence: $required"
    }
}
foreach ($required in @(
    "`$FuzzWorkflow = '.github/workflows/fuzz.yml'",
    '$ExpectedFuzzJobs = @(',
    "'Bounded worker protocol'",
    "'Bounded semantic records'",
    "'Bounded raw POSIX ustar'",
    "'Bounded raw POSIX PAX'",
    "'Bounded raw GNU long-name TAR'",
    "'Bounded RFC 1952 gzip'",
    "'Bounded public TAR gzip ustar'",
    "'Bounded strict ZIP64'",
    "'Bounded gzip-wrapped restricted PAX TAR'",
    "'Bounded gzip-wrapped GNU long-name TAR'",
    "'Bounded zstd-wrapped portable ustar TAR'",
    "'Bounded xz-wrapped portable ustar TAR'",
    "'Bounded bzip2-wrapped portable ustar TAR'",
    'Get-ExactFuzzState',
    'fuzz_run_id'
)) {
    if (-not $publisher.Contains($required, [StringComparison]::Ordinal)) {
        throw "Release publisher is missing exact fuzz evidence: $required"
    }
}

Write-Host "Fuzz seed verification passed: $($actualSeeds.Count) protocol, $($actualSemanticSeeds.Count) semantic, $($actualTarSeeds.Count) TAR, $($actualTarPaxSeeds.Count) TAR PAX, $($actualTarGnuLongNameSeeds.Count) TAR GNU long-name, $($actualGzipSeeds.Count) gzip, $($actualTarGzipSeeds.Count) TAR/gzip, $($actualTarGzipPaxSeeds.Count) TAR/gzip PAX, $($actualTarGzipGnuLongNameSeeds.Count) TAR/gzip GNU long-name, $($actualTarZstdSeeds.Count) TAR/zstd, $($actualTarXzSeeds.Count) TAR/xz, $($actualTarBzip2Seeds.Count) TAR/bzip2, and $($actualZip64Seeds.Count) ZIP64 seeds, pinned nightly and tool versions."
