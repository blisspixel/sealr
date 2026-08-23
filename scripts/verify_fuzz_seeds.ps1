[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $workspace 'fuzz/seed-manifest.json'
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json

if ($manifest.schema -ne 'sealr.fuzz-seeds.v1' -or
    $manifest.target -ne 'protocol_decoders' -or
    $manifest.toolchain -ne 'nightly-2026-08-01' -or
    $manifest.cargoFuzzVersion -ne '0.13.2' -or
    $manifest.libfuzzerSysVersion -ne '0.4.13') {
    throw 'Fuzz manifest identity or pinned tools changed unexpectedly'
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
}
if ($manifest.failureArtifact.directoryName -ne 'sealr-fuzz-artifacts' -or
    $manifest.failureArtifact.uploadOn -ne 'failure' -or
    $manifest.failureArtifact.retentionDays -ne 7) {
    throw 'Fuzz failure artifact policy changed unexpectedly'
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

Assert-ManifestFile -Entry $manifest.dictionary
foreach ($seed in $manifest.seeds) {
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

$fuzzCargo = Get-Content -Raw -LiteralPath (Join-Path $workspace 'fuzz/Cargo.toml')
$fuzzLock = Get-Content -Raw -LiteralPath (Join-Path $workspace 'fuzz/Cargo.lock')
$workflow = Get-Content -Raw -LiteralPath (Join-Path $workspace '.github/workflows/fuzz.yml')
$releaseWorkflow = Get-Content -Raw -LiteralPath (Join-Path $workspace '.github/workflows/release.yml')
$publisher = Get-Content -Raw -LiteralPath (Join-Path $workspace 'scripts/publish_release.ps1')
foreach ($required in @(
    'libfuzzer-sys = "=0.4.13"',
    'name = "libfuzzer-sys"',
    'version = "0.4.13"'
)) {
    if (-not ($fuzzCargo.Contains($required, [StringComparison]::Ordinal) -or
            $fuzzLock.Contains($required, [StringComparison]::Ordinal))) {
        throw "Pinned fuzz dependency evidence is missing: $required"
    }
}
foreach ($required in @(
    'nightly-2026-08-01',
    'cargo-fuzz --version 0.13.2 --locked',
    '-max_len=4194304',
    '-max_total_time=600',
    '-timeout=5',
    '-rss_limit_mb=1024',
    '-jobs=1',
    'artifact_dir="${RUNNER_TEMP}/sealr-fuzz-artifacts/"',
    'if: failure()',
    'path: ${{ runner.temp }}/sealr-fuzz-artifacts/',
    'retention-days: 7'
)) {
    if (-not $workflow.Contains($required, [StringComparison]::Ordinal)) {
        throw "Scheduled fuzz workflow is missing a pinned bound: $required"
    }
}

foreach ($required in @(
    'Require exact protected main fuzz evidence',
    'actions/workflows/fuzz.yml/runs',
    'Bounded worker protocol'
)) {
    if (-not $releaseWorkflow.Contains($required, [StringComparison]::Ordinal)) {
        throw "Release workflow is missing exact fuzz evidence: $required"
    }
}
foreach ($required in @(
    "`$FuzzWorkflow = '.github/workflows/fuzz.yml'",
    "`$ExpectedFuzzJob = 'Bounded worker protocol'",
    'Get-ExactFuzzState',
    'fuzz_run_id'
)) {
    if (-not $publisher.Contains($required, [StringComparison]::Ordinal)) {
        throw "Release publisher is missing exact fuzz evidence: $required"
    }
}

Write-Host "Fuzz seed verification passed: $($actualSeeds.Count) seeds, pinned nightly and tool versions."
