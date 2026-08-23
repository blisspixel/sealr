[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $workspace 'fuzz/seed-manifest.json'
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$semanticManifestPath = Join-Path $workspace 'fuzz/semantic-seed-manifest.json'
$semanticManifest = Get-Content -Raw -LiteralPath $semanticManifestPath | ConvertFrom-Json

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
Assert-ManifestFile -Entry $semanticManifest.dictionary
foreach ($seed in $semanticManifest.seeds) {
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

$fuzzCargo = Get-Content -Raw -LiteralPath (Join-Path $workspace 'fuzz/Cargo.toml')
$fuzzLock = Get-Content -Raw -LiteralPath (Join-Path $workspace 'fuzz/Cargo.lock')
$semanticTarget = Get-Content -Raw -LiteralPath (
    Join-Path $workspace 'fuzz/fuzz_targets/semantic_records.rs'
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

function Assert-SemanticFuzzMetadataBinding {
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
    $expectedTargetNames = @('protocol_decoders', 'semantic_records')
    if (($targetNames -join "`n") -cne ($expectedTargetNames -join "`n")) {
        throw 'Cargo metadata must contain exactly the protocol and semantic fuzz targets'
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
            [string]$sealrDependency[0].req -cne '=0.1.0-alpha.5' -or
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
            [string]$protocolDependency[0].req -cne '=0.1.0-alpha.5' -or
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
        'sealr = { path = "../crates/sealr", version = "=0.1.0-alpha.5", features = ["__internal-fuzzing"] }'
        'sealr-worker-protocol = { path = "../crates/sealr-protocol", version = "=0.1.0-alpha.5" }'
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
Assert-SemanticFuzzMetadataBinding `
    -Metadata $fuzzMetadata `
    -ManifestPath $fuzzManifestPath `
    -RequireDependencies
Assert-SemanticFuzzTargetSource -TargetSource $semanticTarget
Assert-FuzzCargoManifestContract -CargoManifest $fuzzCargo

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
    $inertMetadata = Get-FuzzCargoMetadata `
        -ManifestPath (Join-Path $temporaryFixture 'Cargo.toml') `
        -NoDeps
    try {
        Assert-SemanticFuzzMetadataBinding `
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
sealr = { path = "$sealrDependencyPath", version = "=0.1.0-alpha.5", features = ["__internal-fuzzing"] }
sealr-worker-protocol = { path = "$protocolDependencyPath", version = "=0.1.0-alpha.5" }

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
        Assert-SemanticFuzzMetadataBinding `
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
        Assert-SemanticFuzzMetadataBinding `
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

function Assert-FuzzWorkflowContract {
    param(
        [Parameter(Mandatory)] [string] $CandidateWorkflow,
        [Parameter(Mandatory)] [string] $ExpectedProtocolJob,
        [Parameter(Mandatory)] [string] $ExpectedSemanticJob
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
        (Normalize-WorkflowBlock $ExpectedSemanticJob)
    if ((Normalize-WorkflowBlock $CandidateWorkflow) -cne $expectedWorkflow) {
        throw 'Scheduled fuzz workflow must exactly match its trigger, authority, concurrency, and job contracts'
    }
}

Assert-FuzzWorkflowContract `
    -CandidateWorkflow $workflow `
    -ExpectedProtocolJob $protocolJob `
    -ExpectedSemanticJob $semanticJob
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
        -ExpectedSemanticJob $semanticJob
} catch {
    $manualOnlyRejected = $true
}
if (-not $manualOnlyRejected) {
    throw 'Fuzz workflow verifier accepted a manual-only campaign without its weekly trigger'
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

Write-Host "Fuzz seed verification passed: $($actualSeeds.Count) protocol and $($actualSemanticSeeds.Count) semantic seeds, pinned nightly and tool versions."
