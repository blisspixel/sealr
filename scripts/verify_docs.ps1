[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$repositoryMarkdown = @(& git -C $workspace ls-files --cached --others --exclude-standard -- '*.md')
if ($LASTEXITCODE -ne 0) {
    throw 'Could not enumerate repository Markdown files'
}
$markdownFiles = @($repositoryMarkdown | Sort-Object -Unique | ForEach-Object {
    Get-Item -LiteralPath (Join-Path $workspace $_)
})

$broken = [System.Collections.Generic.List[string]]::new()
foreach ($file in $markdownFiles) {
    $text = Get-Content -Raw -LiteralPath $file.FullName
    $targets = [System.Collections.Generic.List[string]]::new()
    foreach ($match in [regex]::Matches($text, '(?m)!?\[[^\]]*\]\((?<target>[^)]+)\)')) {
        $targets.Add($match.Groups['target'].Value)
    }
    foreach ($match in [regex]::Matches($text, '(?i)\b(?:src|srcset)="(?<target>[^"]+)"')) {
        $targets.Add($match.Groups['target'].Value)
    }

    foreach ($rawTarget in $targets) {
        $target = $rawTarget.Trim()
        if ($target.StartsWith('<') -and $target.EndsWith('>')) {
            $target = $target.Substring(1, $target.Length - 2)
        }
        if ($target -match '^(?:https?://|mailto:|#)' -or [string]::IsNullOrWhiteSpace($target)) {
            continue
        }
        $target = $target.Split('#', 2)[0]
        $resolved = [IO.Path]::GetFullPath((Join-Path $file.DirectoryName $target))
        if (-not $resolved.StartsWith($workspace, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $resolved)) {
            $relativeFile = [IO.Path]::GetRelativePath($workspace, $file.FullName)
            $broken.Add("$relativeFile -> $rawTarget")
        }
    }
}
if ($broken.Count -ne 0) {
    throw "Broken local documentation targets:`n$($broken -join "`n")"
}

$findingsSource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/findings.rs')
$registry = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/findings.md')
$asStringBody = [regex]::Match(
    $findingsSource,
    '(?s)pub fn as_str\(self\).*?match self \{(?<body>.*?)\n\s*\}\n\s*\}'
).Groups['body'].Value
if ([string]::IsNullOrWhiteSpace($asStringBody)) {
    throw 'Could not parse FindingCode::as_str'
}
$findingCodes = @([regex]::Matches($asStringBody, '=>\s*"(?<code>[a-z0-9._]+)"') |
    ForEach-Object { $_.Groups['code'].Value } |
    Sort-Object -Unique)
foreach ($code in $findingCodes) {
    if (-not $registry.Contains("``$code``", [StringComparison]::Ordinal)) {
        throw "Implemented finding code is missing from docs/findings.md: $code"
    }
}

$safety = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/safety.md')
$requiredMaterializationTerms = @(
    'sealr.materialization.v2',
    'same-volume-random-128-mode-0700',
    'same-volume-random-128-protected-token-user-dacl',
    'mkdirat-mode-0700-openat-nofollow-safe-parent',
    'ntcreatefile-parent-handle-create-directory-explicit-dacl-nofollow',
    'renameat2-noreplace',
    'renameatx-np-excl',
    'ntsetinformationfile-retained-source-parent-noreplace',
    'windows-local-ntfs-v1',
    'windows-protected-token-user-v1'
)
foreach ($term in $requiredMaterializationTerms) {
    if (-not $safety.Contains($term, [StringComparison]::Ordinal)) {
        throw "docs/safety.md is missing current materialization evidence: $term"
    }
}

$cargo = Get-Content -Raw -LiteralPath (Join-Path $workspace 'Cargo.toml')
$version = [regex]::Match($cargo, '(?m)^version = "(?<value>[^"]+)"$').Groups['value'].Value
$rustVersion = [regex]::Match($cargo, '(?m)^rust-version = "(?<value>[^"]+)"$').Groups['value'].Value
$license = [regex]::Match($cargo, '(?m)^license = "(?<value>[^"]+)"$').Groups['value'].Value
$readme = Get-Content -Raw -LiteralPath (Join-Path $workspace 'README.md')
$roadmap = Get-Content -Raw -LiteralPath (Join-Path $workspace 'ROADMAP.md')
if ([string]::IsNullOrWhiteSpace($version) -or -not $readme.Contains("v$version", [StringComparison]::Ordinal)) {
    throw 'README release version does not match Cargo.toml'
}
if ([string]::IsNullOrWhiteSpace($rustVersion) -or
    -not $readme.Contains("Rust $rustVersion", [StringComparison]::Ordinal) -or
    -not $roadmap.Contains("Rust $rustVersion", [StringComparison]::Ordinal)) {
    throw 'Documented Rust version does not match Cargo.toml'
}
if ($license -ne 'Apache-2.0' -or
    -not $readme.Contains('[Apache-2.0](LICENSE)', [StringComparison]::Ordinal)) {
    throw 'README license does not match Cargo.toml'
}
$licenseText = Get-Content -Raw -LiteralPath (Join-Path $workspace 'LICENSE')
if (-not $licenseText.Contains('Apache License', [StringComparison]::Ordinal) -or
    -not $licenseText.Contains('Version 2.0, January 2004', [StringComparison]::Ordinal) -or
    -not $licenseText.Contains('END OF TERMS AND CONDITIONS', [StringComparison]::Ordinal)) {
    throw 'LICENSE does not contain the Apache License 2.0 text'
}

$releaseWorkflow = Get-Content -Raw -LiteralPath (Join-Path $workspace '.github/workflows/release.yml')
$publisher = Get-Content -Raw -LiteralPath (Join-Path $workspace 'scripts/publish_release.ps1')
$candidateFixture = Get-Content -Raw -LiteralPath (Join-Path $workspace 'scripts/verify_release_candidate.sh')
$releaseWorkflowVersion = [regex]::Match(
    $releaseWorkflow,
    '(?m)^\s*RELEASE_VERSION:\s*(?<value>[^\s#]+)\s*$'
).Groups['value'].Value
$publisherVersion = [regex]::Match(
    $publisher,
    "(?m)^\`$Version = '(?<value>[^']+)'\s*$"
).Groups['value'].Value
$candidateTag = [regex]::Match(
    $candidateFixture,
    '(?m)^tag="(?<value>[^"]+)"\s*$'
).Groups['value'].Value
if ($releaseWorkflowVersion -ne $version -or
    $publisherVersion -ne $version -or
    $candidateTag -ne "v$version") {
    throw 'Release workflow, publisher, or candidate tag version does not match Cargo.toml'
}

$helperPackaging = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/helper-packaging.md')
foreach ($term in @(
    'libexec/sealr/sealr-worker',
    'libexec/sealr/sealr-worker.manifest',
    'sealr.worker-artifact.v1',
    'x86_64-unknown-linux-musl',
    'production-only helper graph',
    'macOS and Windows archives retain their exact five-file contracts'
)) {
    if (-not $helperPackaging.Contains($term, [StringComparison]::Ordinal)) {
        throw "docs/helper-packaging.md is missing its exact package contract: $term"
    }
}
foreach ($workflow in @(
    @{ Name = 'CI'; Text = (Get-Content -Raw -LiteralPath (Join-Path $workspace '.github/workflows/ci.yml')) }
    @{ Name = 'release'; Text = $releaseWorkflow }
)) {
    foreach ($script in @('scripts/package_native.ps1', 'scripts/verify_native_package.ps1')) {
        if (-not $workflow.Text.Contains($script, [StringComparison]::Ordinal)) {
            throw "The $($workflow.Name) workflow does not enforce $script"
        }
    }
}

$workflowTitleTemplate = [regex]::Match(
    $releaseWorkflow,
    '(?m)^\s*release_title="(?<value>[^"]+)"\s*$'
).Groups['value'].Value
$publisherTitleTemplate = [regex]::Match(
    $publisher,
    '(?m)^\$ReleaseTitle = "(?<value>[^"]+)"\s*$'
).Groups['value'].Value
$candidateTitle = [regex]::Match(
    $candidateFixture,
    '(?m)^title="(?<value>[^"]+)"\s*$'
).Groups['value'].Value
$workflowTitle = $workflowTitleTemplate.Replace('${RELEASE_VERSION}', $version)
$publisherTitle = $publisherTitleTemplate.Replace('${Version}', $version)
if ([string]::IsNullOrWhiteSpace($candidateTitle) -or
    $workflowTitle -ne $candidateTitle -or
    $publisherTitle -ne $candidateTitle) {
    throw 'Release workflow, publisher, and candidate fixture titles do not match'
}

$candidateAllowedBlock = [regex]::Match(
    $candidateFixture,
    "(?s)allowed='\[(?<body>.*?)\]'"
).Groups['body'].Value
$candidateAssets = @([regex]::Matches($candidateAllowedBlock, '"(?<name>[^"]+)"') |
    ForEach-Object { $_.Groups['name'].Value } |
    Sort-Object -Unique)
$expectedReleaseAssets = @(
    'SHA256SUMS'
    "sealr-$version-aarch64-apple-darwin.tar.gz"
    "sealr-$version-x86_64-pc-windows-msvc.zip"
    "sealr-$version-x86_64-unknown-linux-gnu.tar.gz"
) | Sort-Object
$assetDifference = @(Compare-Object -ReferenceObject $expectedReleaseAssets -DifferenceObject $candidateAssets)
if ($assetDifference.Count -ne 0 -or $candidateAssets.Count -ne $expectedReleaseAssets.Count) {
    throw 'Release candidate fixture assets do not match the current version and native target set'
}

$releaseNotesPath = Join-Path $workspace "docs/releases/v$version.md"
if (-not [IO.File]::Exists($releaseNotesPath)) {
    throw "Release notes are missing for v$version"
}
$releaseNotes = Get-Content -Raw -LiteralPath $releaseNotesPath
if (-not $releaseNotes.StartsWith("# sealr $version`n", [StringComparison]::Ordinal) -and
    -not $releaseNotes.StartsWith("# sealr $version`r`n", [StringComparison]::Ordinal)) {
    throw "Release notes heading does not match v$version"
}

$ciWorkflow = Get-Content -Raw -LiteralPath (Join-Path $workspace '.github/workflows/ci.yml')
$qualityStart = $ciWorkflow.IndexOf("  quality:`n", [StringComparison]::Ordinal)
$platformStart = $ciWorkflow.IndexOf("  platform:`n", [StringComparison]::Ordinal)
$zipDiffStart = $ciWorkflow.IndexOf("  zipdiff:`n", [StringComparison]::Ordinal)
$supplyChainStart = $ciWorkflow.IndexOf("  supply-chain:`n", [StringComparison]::Ordinal)
$requiredStart = $ciWorkflow.IndexOf("  required:`n", [StringComparison]::Ordinal)
if ($qualityStart -lt 0 -or
    $platformStart -le $qualityStart -or
    $zipDiffStart -le $platformStart -or
    $supplyChainStart -le $zipDiffStart -or
    $requiredStart -le $supplyChainStart) {
    throw 'Could not locate the required quality and platform CI jobs'
}
$qualityJob = $ciWorkflow.Substring($qualityStart, $platformStart - $qualityStart)
$platformJob = $ciWorkflow.Substring($platformStart, $zipDiffStart - $platformStart)
$semanticPeakCommand = @'
cargo test --locked --release -p sealr --lib semantic_record::peak_live::completion_reconstruction_peak_live_is_bounded -- --ignored --exact --nocapture --test-threads=1
'@.Trim()
foreach ($job in @(
    @{ Name = 'quality'; Text = $qualityJob; Runner = 'runs-on: ubuntu-latest' }
    @{ Name = 'platform'; Text = $platformJob; Runner = 'os: [macos-latest, windows-latest]' }
)) {
    $normalizedJob = [regex]::Replace($job.Text, '\s+', ' ').Trim()
    if (-not $job.Text.Contains($job.Runner, [StringComparison]::Ordinal) -or
        ([regex]::Matches($job.Text, '(?m)^\s*- name: Measure near-limit semantic completion heap\s*$')).Count -ne 1 -or
        ([regex]::Matches($normalizedJob, [regex]::Escape($semanticPeakCommand))).Count -ne 1) {
        throw "The $($job.Name) CI job does not contain the exact required semantic peak-live probe"
    }
}

$requiredJob = $ciWorkflow.Substring($requiredStart)
foreach ($fragment in @(
    '    name: Required CI',
    '    if: ${{ always() }}',
    '    needs: [quality, platform, zipdiff, supply-chain]',
    '          QUALITY_RESULT: ${{ needs.quality.result }}',
    '          PLATFORM_RESULT: ${{ needs.platform.result }}',
    '          ZIPDIFF_RESULT: ${{ needs.zipdiff.result }}',
    "          SUPPLY_CHAIN_RESULT: `${{ needs['supply-chain'].result }}",
    '          exit "${failed}"'
)) {
    if (-not $requiredJob.Contains($fragment, [StringComparison]::Ordinal)) {
        throw "The Required CI aggregator is missing its exact dependency contract: $fragment"
    }
}

$semanticRecordDoc = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/semantic-record.md')
foreach ($term in @(
    'same verifier calls that write the corresponding stage files',
    'byte-for-byte canonical equality for both outputs',
    'public outcome and hidden `VerifiedArchive` backend integration'
)) {
    if (-not $semanticRecordDoc.Contains($term, [StringComparison]::Ordinal)) {
        throw "docs/semantic-record.md is missing materialization retention parity: $term"
    }
}
$shadowV1Path = Join-Path $workspace 'crates/sealr/tests/conformance/semantic-shadow-v1.json'
$shadowV2Path = Join-Path $workspace 'crates/sealr/tests/conformance/semantic-shadow-v2.json'
$shadowV1Sha256 = 'b064c6945ca31603914d45a3d18775750bf30ddb667c356eb6d331673a9feb59'
$shadowV2Sha256 = '9243570b35667aaf9142483d823cb676391e8ba4a90b3594928533a0139b1967'
foreach ($artifact in @(
    @{ Name = 'semantic-shadow-v1'; Path = $shadowV1Path; Bytes = 17119; Sha256 = $shadowV1Sha256 }
    @{ Name = 'semantic-shadow-v2'; Path = $shadowV2Path; Bytes = 19769; Sha256 = $shadowV2Sha256 }
)) {
    if (-not [IO.File]::Exists($artifact.Path) -or
        (Get-Item -LiteralPath $artifact.Path).Length -ne $artifact.Bytes -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact.Path).Hash.ToLowerInvariant() -ne $artifact.Sha256) {
        throw "$($artifact.Name) raw bytes do not match the frozen conformance artifact"
    }
}

$shadowV1 = Get-Content -Raw -LiteralPath $shadowV1Path | ConvertFrom-Json
$shadowV1Cases = @(
    'store-complete'
    'deflate-complete'
    'descriptor-complete'
    'unknown-magic-terminal'
    'name-mismatch-terminal'
    'member-quota-terminal'
    'crc-mismatch-stopped'
    'declared-lie-stopped'
    'invalid-deflate-stopped'
    'trailing-deflate-stopped'
    'source-io-stopped'
    'setup-failure'
)
if ($shadowV1.schema -ne 'sealr.semantic-shadow.v1' -or
    @(Compare-Object $shadowV1Cases @($shadowV1.cases.name) -SyncWindow 0).Count -ne 0) {
    throw 'semantic-shadow-v1 schema or ordered cases drifted'
}

$shadowV2 = Get-Content -Raw -LiteralPath $shadowV2Path | ConvertFrom-Json
$shadowV2Cases = @(
    'strict-v2-mixed-memory-complete'
    'strict-v2-mixed-private-file-complete'
    'same-extra-strict-v1-complete'
    'same-extra-strict-v2-terminal'
    'dotdot-terminal'
    'interleaved-exact-topology-terminal'
    'interleaved-folded-topology-terminal'
    'total-quota-exact-complete'
    'total-quota-one-under-terminal'
    'ratio-quota-exact-complete'
    'ratio-quota-one-under-terminal'
    'covering-inconsistent-terminal'
)
if ($shadowV2.schema -ne 'sealr.semantic-shadow.v2' -or
    $shadowV2.predecessor.schema -ne 'sealr.semantic-shadow.v1' -or
    $shadowV2.predecessor.path -ne 'crates/sealr/tests/conformance/semantic-shadow-v1.json' -or
    $shadowV2.predecessor.bytes -ne 17119 -or
    $shadowV2.predecessor.sha256 -ne $shadowV1Sha256 -or
    @(Compare-Object @('41414141414141414141414141414141') @($shadowV2.operation_ids) -SyncWindow 0).Count -ne 0 -or
    @(Compare-Object $shadowV2Cases @($shadowV2.cases.evidence.name) -SyncWindow 0).Count -ne 0) {
    throw 'semantic-shadow-v2 predecessor, schema, or ordered additions drifted'
}
$backendTwins = @($shadowV2.cases | Where-Object { $_.parity_group -eq 'strict-v2-mixed-backends' })
if ($backendTwins.Count -ne 2 -or
    @(Compare-Object @('memory-borrowed', 'private-file') @($backendTwins.backend) -SyncWindow 0).Count -ne 0) {
    throw 'semantic-shadow-v2 must contain exactly one ordered memory/private backend pair'
}
foreach ($field in @(
    'profile_id', 'policy_id', 'policy_sha256', 'requested_effect', 'retention',
    'finding_code', 'interpretation', 'admission', 'verification', 'effect', 'phase',
    'cause', 'verified_members', 'pending_members', 'source_sha256', 'request_id', 'plan_id',
    'pending_ir_sha256', 'final_ir_sha256', 'frontier', 'findings', 'findings_sha256',
    'planning_frame_sha256', 'completion_frame_sha256'
)) {
    $left = ConvertTo-Json -InputObject $backendTwins[0].evidence.$field -Depth 20 -Compress
    $right = ConvertTo-Json -InputObject $backendTwins[1].evidence.$field -Depth 20 -Compress
    if ($left -cne $right) {
        throw "semantic-shadow-v2 backend evidence differs at $field"
    }
}
if (-not $semanticRecordDoc.Contains($shadowV1Sha256, [StringComparison]::Ordinal) -or
    -not $semanticRecordDoc.Contains($shadowV2Sha256, [StringComparison]::Ordinal) -or
    -not $semanticRecordDoc.Contains('19,769 bytes', [StringComparison]::Ordinal)) {
    throw 'docs/semantic-record.md does not pin both shadow artifacts and the v2 byte length'
}

Write-Host "Documentation verification passed: $($markdownFiles.Count) Markdown files, $($findingCodes.Count) finding codes."
