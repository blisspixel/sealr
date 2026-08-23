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

function Assert-ManifestFile {
    param(
        [Parameter(Mandatory)] [object] $Entry
    )

    $fullPath = [IO.Path]::GetFullPath((Join-Path $workspace $Entry.path))
    if (-not $fullPath.StartsWith($workspace, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Fuzz manifest path escapes the workspace: $($Entry.path)"
    }
    $file = Get-Item -LiteralPath $fullPath
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
    '-jobs=1'
)) {
    if (-not $workflow.Contains($required, [StringComparison]::Ordinal)) {
        throw "Scheduled fuzz workflow is missing a pinned bound: $required"
    }
}

Write-Host "Fuzz seed verification passed: $($actualSeeds.Count) seeds, pinned nightly and tool versions."
