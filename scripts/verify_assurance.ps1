[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-TextContains {
    param(
        [string]$Text,
        [string]$Expected,
        [string]$Context
    )

    Assert-True -Condition $Text.Contains($Expected) -Message "$Context is missing exact text: $Expected"
}

function Read-JsonFile {
    param([string]$Path)

    Assert-True -Condition (Test-Path -LiteralPath $Path -PathType Leaf) -Message "missing JSON file: $Path"
    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "invalid JSON in ${Path}: $($_.Exception.Message)"
    }
}

function Assert-NonemptyText {
    param(
        [AllowNull()][object]$Value,
        [string]$Context
    )

    Assert-True -Condition ($Value -is [string]) -Message "$Context must be a string"
    Assert-True -Condition (-not [string]::IsNullOrWhiteSpace([string]$Value)) -Message "$Context must not be empty"
}

$manifestPath = Join-Path $RepositoryRoot 'tests/assurance/manifest.json'
$ledgerPath = Join-Path $RepositoryRoot 'tests/assurance/promotion-ledger.json'
$manifest = Read-JsonFile -Path $manifestPath
$ledger = Read-JsonFile -Path $ledgerPath

Assert-True -Condition ($manifest.schema -eq 'sealr.assurance-discovery.v1') -Message 'assurance manifest schema drifted'
Assert-True -Condition ($manifest.schedule -eq '29 9 * * 3') -Message 'assurance schedule drifted'
Assert-True -Condition ([int]$manifest.artifact_retention_days -eq 30) -Message 'assurance artifact retention drifted'
Assert-True -Condition ($manifest.tools.kani -eq '0.67.0') -Message 'Kani version drifted'
Assert-True -Condition ($manifest.tools.cargo_mutants -eq '27.1.0') -Message 'cargo-mutants version drifted'
Assert-True -Condition ($manifest.tools.cargo_llvm_cov -eq '0.9.0') -Message 'cargo-llvm-cov version drifted'
Assert-True -Condition ($manifest.tools.cargo_semver_checks -eq '0.49.0') -Message 'cargo-semver-checks version drifted'
Assert-True -Condition ($manifest.tools.rust -eq '1.98.0') -Message 'assurance Rust version drifted'
Assert-True -Condition ($manifest.semver_tool_archive_sha256 -eq '72f6834d75d28a66e02c9fd6a230ce901bb30eee6067b85867a97445df040e4a') -Message 'cargo-semver-checks archive digest drifted'
Assert-True -Condition ($manifest.semver_baseline_tag -eq 'v0.1.0-alpha.11') -Message 'semver baseline tag drifted'
Assert-True -Condition ($manifest.semver_baseline_rev -eq 'a1f2bf62a5a432a20b045db327ce9a6e4bdf8f6b') -Message 'semver baseline revision drifted'
Assert-True -Condition ($manifest.semver_baseline_version -eq '0.1.0-alpha.11') -Message 'semver baseline version drifted'
Assert-True -Condition ($manifest.semver_command -eq 'cargo-semver-checks check-release --manifest-path crates/sealr/Cargo.toml --baseline-root <packaged-alpha.11-root> --release-type minor') -Message 'semver command drifted'
Assert-True -Condition ($manifest.semver_known_warnings -eq 'tests/assurance/semver-alpha11-known-warnings.txt') -Message 'semver known-warning path drifted'
Assert-True -Condition ($manifest.semver_expected_summary -eq '196 checks: 193 pass, 0 fail, 3 warn, 57 skip') -Message 'semver expected summary drifted'
Assert-True -Condition ($manifest.kani_command -eq 'cargo kani --manifest-path verification/kani/Cargo.toml --package sealr --default-unwind 1') -Message 'Kani command drifted'
Assert-True -Condition ($manifest.kani_manifest -eq 'verification/kani/Cargo.toml') -Message 'Kani proof manifest path drifted'
Assert-True -Condition ($manifest.kani_compiler_rust -eq '1.93.0-nightly (53732d5e0 2025-11-20)') -Message 'Kani compiler Rust version drifted'
Assert-NonemptyText -Value $manifest.kani_compatibility_assumption -Context 'Kani compatibility assumption'
Assert-NonemptyText -Value $manifest.kani_compatibility_nonclaim -Context 'Kani compatibility nonclaim'
Assert-True -Condition ($manifest.promotion_ledger -eq 'tests/assurance/promotion-ledger.json') -Message 'promotion ledger path drifted'

$knownWarningsPath = Join-Path $RepositoryRoot ([string]$manifest.semver_known_warnings)
Assert-True -Condition (Test-Path -LiteralPath $knownWarningsPath -PathType Leaf) -Message 'semver known-warning file is missing'
$knownWarnings = @(Get-Content -LiteralPath $knownWarningsPath)
Assert-True -Condition ($knownWarnings.Count -eq 7) -Message 'semver known-warning debt must contain exactly seven items'
Assert-True -Condition (($knownWarnings | Select-Object -Unique).Count -eq $knownWarnings.Count) -Message 'semver known-warning debt contains duplicates'
foreach ($knownWarning in $knownWarnings) {
    Assert-NonemptyText -Value $knownWarning -Context 'semver known warning'
}

$workflowPath = Join-Path $RepositoryRoot ([string]$manifest.workflow)
Assert-True -Condition (Test-Path -LiteralPath $workflowPath -PathType Leaf) -Message 'scheduled assurance workflow is missing'
$workflow = Get-Content -LiteralPath $workflowPath -Raw
Assert-TextContains -Text $workflow -Expected "    - cron: '$($manifest.schedule)'" -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected "  RUST_VERSION: $($manifest.tools.rust)" -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected "  KANI_VERSION: $($manifest.tools.kani)" -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected "  CARGO_MUTANTS_VERSION: $($manifest.tools.cargo_mutants)" -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected "  CARGO_LLVM_COV_VERSION: $($manifest.tools.cargo_llvm_cov)" -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected "  CARGO_SEMVER_CHECKS_VERSION: $($manifest.tools.cargo_semver_checks)" -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected "  CARGO_SEMVER_CHECKS_ARCHIVE_SHA256: $($manifest.semver_tool_archive_sha256)" -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected "  SEMVER_BASELINE_TAG: $($manifest.semver_baseline_tag)" -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected "  SEMVER_BASELINE_REV: $($manifest.semver_baseline_rev)" -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected "  SEMVER_BASELINE_VERSION: $($manifest.semver_baseline_version)" -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected ([string]$manifest.kani_command) -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected 'cargo install kani-verifier --version "${KANI_VERSION}" --locked' -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected 'cargo install cargo-mutants --version "${CARGO_MUTANTS_VERSION}" --locked' -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected 'cargo-mutants mutants --version | grep --fixed-strings "${CARGO_MUTANTS_VERSION}"' -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected 'cargo install cargo-llvm-cov --version "${CARGO_LLVM_COV_VERSION}" --locked' -Context 'assurance workflow'
Assert-TextContains -Text $workflow -Expected '          cargo-mutants mutants \' -Context 'mutation discovery'
Assert-TextContains -Text $workflow -Expected "            --re 'CheckedInterval::from_offset_len|QuotaState::consume|ratio_exceeds'" -Context 'mutation discovery'
Assert-TextContains -Text $workflow -Expected "            --exclude-re 'kani_proofs'" -Context 'mutation discovery'
Assert-TextContains -Text $workflow -Expected 'test -f target/assurance-discovery/mutation/mutants.out/outcomes.json' -Context 'mutation discovery'
Assert-TextContains -Text $workflow -Expected '            0|2|3)' -Context 'mutation discovery'
Assert-TextContains -Text $workflow -Expected 'cargo-mutants infrastructure, usage, filter, or baseline failed' -Context 'mutation discovery'
Assert-TextContains -Text $workflow -Expected '            --summary-only' -Context 'coverage discovery'
Assert-TextContains -Text $workflow -Expected '            --output-path target/assurance-discovery/coverage.json' -Context 'coverage discovery'
Assert-TextContains -Text $workflow -Expected '          fetch-depth: 0' -Context 'semver discovery'
Assert-TextContains -Text $workflow -Expected '            "https://github.com/obi1kenobi/cargo-semver-checks/releases/download/v${CARGO_SEMVER_CHECKS_VERSION}/cargo-semver-checks-x86_64-unknown-linux-gnu.tar.gz"' -Context 'semver discovery'
Assert-TextContains -Text $workflow -Expected '          echo "${CARGO_SEMVER_CHECKS_ARCHIVE_SHA256}  ${archive}" |' -Context 'semver discovery'
Assert-TextContains -Text $workflow -Expected '            actual_revision="$(git rev-parse "${SEMVER_BASELINE_TAG}^{commit}")"' -Context 'semver discovery'
Assert-TextContains -Text $workflow -Expected '            CARGO_TARGET_DIR="${baseline_target}" cargo package \' -Context 'semver discovery'
Assert-TextContains -Text $workflow -Expected '              --manifest-path "${baseline_source}/crates/sealr/Cargo.toml"' -Context 'semver discovery'
Assert-TextContains -Text $workflow -Expected '            "${tool}" check-release \' -Context 'semver discovery'
Assert-TextContains -Text $workflow -Expected '              --baseline-root "${baseline_package}"' -Context 'semver discovery'
Assert-TextContains -Text $workflow -Expected '              --release-type minor' -Context 'semver discovery'
Assert-TextContains -Text $workflow -Expected '            tests/assurance/semver-alpha11-known-warnings.txt \' -Context 'semver discovery'
Assert-TextContains -Text $workflow -Expected "            '$($manifest.semver_expected_summary)' \" -Context 'semver discovery'
Assert-TextContains -Text $workflow -Expected '          path: target/assurance-discovery/semver/semver.log' -Context 'semver discovery'
Assert-True -Condition (-not $workflow.Contains('--fail-under')) -Message 'coverage discovery must not contain a percentage gate'
Assert-True -Condition (-not $workflow.Contains('codecov')) -Message 'coverage discovery must not publish a headline score'
Assert-True -Condition ([regex]::Matches($workflow, 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a').Count -eq 4) -Message 'every discovery report must use the pinned upload action'
Assert-True -Condition ([regex]::Matches($workflow, 'retention-days: 30').Count -eq 4) -Message 'every discovery report must use the manifest retention period'

$cargoManifest = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'crates/sealr/Cargo.toml') -Raw
Assert-TextContains -Text $cargoManifest -Expected '[package.metadata.cargo-semver-checks.lints]' -Context 'sealr Cargo manifest'
Assert-TextContains -Text $cargoManifest -Expected 'struct_marked_non_exhaustive = "warn"' -Context 'sealr Cargo manifest'
Assert-TextContains -Text $cargoManifest -Expected 'struct_pub_field_missing = "warn"' -Context 'sealr Cargo manifest'
Assert-TextContains -Text $cargoManifest -Expected 'struct_pub_field_now_doc_hidden = "warn"' -Context 'sealr Cargo manifest'
Assert-TextContains -Text $cargoManifest -Expected 'unexpected_cfgs = { level = "warn", check-cfg = [''cfg(kani)''] }' -Context 'sealr Cargo manifest'
Assert-TextContains -Text $cargoManifest -Expected '[package.metadata.kani.flags]' -Context 'sealr Cargo manifest'
Assert-TextContains -Text $cargoManifest -Expected 'default-unwind = "1"' -Context 'sealr Cargo manifest'

$workspaceVersionMatch = [regex]::Match((Get-Content -LiteralPath (Join-Path $RepositoryRoot 'Cargo.toml') -Raw), '(?m)^version = "([^"]+)"$')
Assert-True -Condition $workspaceVersionMatch.Success -Message 'workspace release version is missing'
$kaniManifestPath = Join-Path $RepositoryRoot ([string]$manifest.kani_manifest)
$kaniManifest = Get-Content -LiteralPath $kaniManifestPath -Raw
Assert-TextContains -Text $kaniManifest -Expected '[workspace]' -Context 'Kani proof manifest'
Assert-TextContains -Text $kaniManifest -Expected 'name = "sealr"' -Context 'Kani proof manifest'
Assert-TextContains -Text $kaniManifest -Expected ('version = "{0}"' -f $workspaceVersionMatch.Groups[1].Value) -Context 'Kani proof manifest'
Assert-TextContains -Text $kaniManifest -Expected 'rust-version = "1.93"' -Context 'Kani proof manifest'
Assert-TextContains -Text $kaniManifest -Expected 'license = "Apache-2.0"' -Context 'Kani proof manifest'
Assert-TextContains -Text $kaniManifest -Expected 'path = "src/lib.rs"' -Context 'Kani proof manifest'
Assert-TextContains -Text $kaniManifest -Expected '[package.metadata.kani.flags]' -Context 'Kani proof manifest'
Assert-TextContains -Text $kaniManifest -Expected 'default-unwind = "1"' -Context 'Kani proof manifest'
Assert-True -Condition (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $kaniManifestPath) 'Cargo.lock') -PathType Leaf) -Message 'Kani proof manifest lock is missing'
$kaniCrateSource = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $kaniManifestPath) 'src/lib.rs') -Raw
foreach ($sourceModule in @('interval', 'quota', 'ratio')) {
    Assert-TextContains -Text $kaniCrateSource -Expected "../../../crates/sealr/src/$sourceModule.rs" -Context 'Kani proof crate'
}

$harnesses = @($manifest.kani_harnesses)
Assert-True -Condition ($harnesses.Count -eq 3) -Message 'exactly three bounded Kani harness records are required'
$harnessIds = @{}
foreach ($harness in $harnesses) {
    Assert-NonemptyText -Value $harness.id -Context 'Kani harness id'
    Assert-True -Condition (-not $harnessIds.ContainsKey([string]$harness.id)) -Message "duplicate Kani harness id: $($harness.id)"
    $harnessIds[[string]$harness.id] = $true
    Assert-NonemptyText -Value $harness.symbol -Context "Kani harness $($harness.id) symbol"
    Assert-True -Condition (@($harness.domain).Count -gt 0) -Message "Kani harness $($harness.id) has no domain"
    foreach ($domainEntry in @($harness.domain)) {
        Assert-NonemptyText -Value $domainEntry -Context "Kani harness $($harness.id) domain"
    }
    foreach ($assumption in @($harness.assumptions)) {
        Assert-NonemptyText -Value $assumption -Context "Kani harness $($harness.id) assumption"
    }
    Assert-True -Condition ([int]$harness.unwind_bound -eq 1) -Message "Kani harness $($harness.id) unwind bound drifted"
    Assert-True -Condition (@('cadical', 'kissat') -contains [string]$harness.solver) -Message "Kani harness $($harness.id) solver is not pinned"
    Assert-NonemptyText -Value $harness.property -Context "Kani harness $($harness.id) property"
    Assert-NonemptyText -Value $harness.nonclaim -Context "Kani harness $($harness.id) nonclaim"

    $symbolParts = ([string]$harness.symbol).Split('::')
    $sourceName = $symbolParts[0]
    $functionName = $symbolParts[$symbolParts.Count - 1]
    $sourcePath = Join-Path $RepositoryRoot "crates/sealr/src/$sourceName.rs"
    Assert-True -Condition (Test-Path -LiteralPath $sourcePath -PathType Leaf) -Message "Kani source is missing: $sourcePath"
    $source = Get-Content -LiteralPath $sourcePath -Raw
    Assert-TextContains -Text $source -Expected '#[cfg(kani)]' -Context "Kani source $sourceName"
    Assert-TextContains -Text $source -Expected '#[kani::proof]' -Context "Kani source $sourceName"
    Assert-TextContains -Text $source -Expected "fn $functionName()" -Context "Kani source $sourceName"
    if ($harness.solver -ne 'cadical') {
        Assert-TextContains -Text $source -Expected "#[kani::solver($($harness.solver))]" -Context "Kani source $sourceName"
    }
}

$reports = @($manifest.discovery_reports)
Assert-True -Condition ($reports.Count -eq 3) -Message 'mutation, coverage, and semver discovery reports must all be declared'
Assert-True -Condition ((@($reports.tool) -contains 'cargo-mutants') -and (@($reports.tool) -contains 'cargo-llvm-cov') -and (@($reports.tool) -contains 'cargo-semver-checks')) -Message 'discovery report tools drifted'
foreach ($report in $reports) {
    Assert-NonemptyText -Value $report.id -Context 'discovery report id'
    Assert-NonemptyText -Value $report.scope -Context "discovery report $($report.id) scope"
    Assert-NonemptyText -Value $report.bounded_by -Context "discovery report $($report.id) bound"
    Assert-NonemptyText -Value $report.result_policy -Context "discovery report $($report.id) result policy"
    Assert-NonemptyText -Value $report.nonclaim -Context "discovery report $($report.id) nonclaim"
}

Assert-True -Condition ($ledger.schema -eq 'sealr.assurance-promotion-ledger.v1') -Message 'promotion ledger schema drifted'
Assert-True -Condition ($ledger.required_workflow -eq '.github/workflows/ci.yml') -Message 'required workflow path drifted'
Assert-True -Condition ([int]$ledger.minimum_consecutive_successful_main_runs -eq 10) -Message 'promotion stability threshold must remain ten'
Assert-NonemptyText -Value $ledger.failure_policy -Context 'promotion failure policy'

$requiredWorkflowPath = Join-Path $RepositoryRoot ([string]$ledger.required_workflow)
$requiredWorkflow = Get-Content -LiteralPath $requiredWorkflowPath -Raw
$checks = @($ledger.checks)
Assert-True -Condition ($checks.Count -eq 6) -Message 'promotion ledger must cover all six scheduled evidence categories'
$checkIds = @{}
$categories = @{}
foreach ($check in $checks) {
    Assert-NonemptyText -Value $check.id -Context 'promotion check id'
    Assert-True -Condition (-not $checkIds.ContainsKey([string]$check.id)) -Message "duplicate promotion check id: $($check.id)"
    $checkIds[[string]$check.id] = $true
    Assert-NonemptyText -Value $check.category -Context "promotion check $($check.id) category"
    Assert-True -Condition (-not $categories.ContainsKey([string]$check.category)) -Message "evidence categories must remain separate: $($check.category)"
    $categories[[string]$check.category] = $true
    Assert-NonemptyText -Value $check.scheduled_workflow -Context "promotion check $($check.id) workflow"
    Assert-True -Condition (Test-Path -LiteralPath (Join-Path $RepositoryRoot ([string]$check.scheduled_workflow)) -PathType Leaf) -Message "promotion check $($check.id) workflow is missing"
    Assert-NonemptyText -Value $check.scheduled_job -Context "promotion check $($check.id) job"
    Assert-NonemptyText -Value $check.domain -Context "promotion check $($check.id) domain"
    Assert-NonemptyText -Value $check.nonclaim -Context "promotion check $($check.id) nonclaim"
    Assert-True -Condition (@($check.local_reproduction).Count -gt 0) -Message "promotion check $($check.id) lacks local reproduction"
    foreach ($command in @($check.local_reproduction)) {
        Assert-NonemptyText -Value $command -Context "promotion check $($check.id) local reproduction"
    }
    Assert-True -Condition (([int]$check.timeout_minutes -gt 0) -and ([int]$check.timeout_minutes -le 60)) -Message "promotion check $($check.id) is not time bounded"
    Assert-NonemptyText -Value $check.required_ci_marker -Context "promotion check $($check.id) required CI marker"

    $runs = @($check.stable_main_runs)
    $runIds = @{}
    $commits = @{}
    $previousObservedAt = [DateTimeOffset]::MinValue
    for ($index = 0; $index -lt $runs.Count; $index++) {
        $run = $runs[$index]
        Assert-True -Condition ([int]$run.sequence -eq ($index + 1)) -Message "promotion check $($check.id) run sequence is not consecutive"
        Assert-True -Condition ([long]$run.run_id -gt 0) -Message "promotion check $($check.id) has an invalid run id"
        Assert-True -Condition (-not $runIds.ContainsKey([string]$run.run_id)) -Message "promotion check $($check.id) repeats a run id"
        $runIds[[string]$run.run_id] = $true
        Assert-True -Condition (([string]$run.commit) -match '^[0-9a-f]{40}$') -Message "promotion check $($check.id) has an invalid commit"
        Assert-True -Condition (-not $commits.ContainsKey([string]$run.commit)) -Message "promotion check $($check.id) repeats a main commit"
        $commits[[string]$run.commit] = $true
        Assert-True -Condition ($run.branch -eq 'main') -Message "promotion check $($check.id) includes a non-main run"
        Assert-True -Condition ($run.event -eq 'schedule') -Message "promotion check $($check.id) includes a nonscheduled run"
        Assert-True -Condition ($run.conclusion -eq 'success') -Message "promotion check $($check.id) includes an unsuccessful run"
        $expectedUrl = "https://github.com/blisspixel/sealr/actions/runs/$($run.run_id)"
        Assert-True -Condition ($run.url -eq $expectedUrl) -Message "promotion check $($check.id) run URL does not bind its id"
        $observedAt = [DateTimeOffset]::MinValue
        Assert-True -Condition ([DateTimeOffset]::TryParse([string]$run.observed_at, [ref]$observedAt)) -Message "promotion check $($check.id) has an invalid observation time"
        Assert-True -Condition ($observedAt -gt $previousObservedAt) -Message "promotion check $($check.id) observations are not chronological"
        $previousObservedAt = $observedAt
    }

    $expectedEligible = [bool]$check.promotable -and ($runs.Count -ge [int]$ledger.minimum_consecutive_successful_main_runs)
    Assert-True -Condition ([bool]$check.eligible -eq $expectedEligible) -Message "promotion check $($check.id) eligibility disagrees with its stable history"
    if ([bool]$check.promoted) {
        Assert-True -Condition ([bool]$check.promotable) -Message "discovery-only check $($check.id) cannot be promoted"
        Assert-True -Condition ([bool]$check.eligible) -Message "promotion check $($check.id) entered required CI before eligibility"
        Assert-TextContains -Text $requiredWorkflow -Expected ([string]$check.required_ci_marker) -Context 'required CI workflow'
    }
    else {
        Assert-True -Condition (-not $requiredWorkflow.Contains([string]$check.required_ci_marker)) -Message "unpromoted check $($check.id) appears in required CI"
    }
}

Write-Host "assurance contracts verified: $($harnesses.Count) Kani harnesses, $($reports.Count) discovery reports, and $($checks.Count) promotion records"
