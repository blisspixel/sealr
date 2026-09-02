[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$contractPath = Join-Path $workspace 'tests/package-contract/adopter-pilot.json'
$contract = Get-Content -Raw -LiteralPath $contractPath | ConvertFrom-Json -Depth 20

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory)] [object] $Value,
        [Parameter(Mandatory)] [string[]] $Expected,
        [Parameter(Mandatory)] [string] $Label
    )

    [string[]] $actual = @($Value.PSObject.Properties.Name)
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    [string[]] $expectedSorted = @($Expected)
    [Array]::Sort($expectedSorted, [StringComparer]::Ordinal)
    if (($actual -join "`n") -cne ($expectedSorted -join "`n")) {
        throw "$Label has missing or unknown fields"
    }
}

function Assert-Equal {
    param(
        [AllowNull()] [object] $Expected,
        [AllowNull()] [object] $Actual,
        [Parameter(Mandatory)] [string] $Label
    )

    if ([string]$Expected -cne [string]$Actual) {
        throw "$Label changed: expected '$Expected', observed '$Actual'"
    }
}

function Assert-Contains {
    param(
        [Parameter(Mandatory)] [string] $Text,
        [Parameter(Mandatory)] [string] $Expected,
        [Parameter(Mandatory)] [string] $Label
    )

    if (-not $Text.Contains($Expected, [StringComparison]::Ordinal)) {
        throw "$Label is missing exact contract text: $Expected"
    }
}

function Assert-ExactStringList {
    param(
        [Parameter(Mandatory)] [object] $Actual,
        [Parameter(Mandatory)] [string[]] $Expected,
        [Parameter(Mandatory)] [string] $Label
    )

    [string[]] $actualList = @($Actual | ForEach-Object { [string]$_ })
    if (($actualList -join "`n") -cne ($Expected -join "`n")) {
        throw "$Label changed or were reordered"
    }
}

Assert-ExactProperties -Value $contract -Expected @(
    'schema', 'status', 'release', 'crate', 'pilot_release_gate', 'native', 'semantics',
    'handoff', 'selection', 'forbidden_acquisition', 'required_proofs', 'negative_matrix',
    'report_fields', 'nonclaims'
) -Label 'adopter contract'
Assert-ExactProperties -Value $contract.release -Expected @(
    'version', 'tag', 'commit', 'rust_version', 'role'
) -Label 'adopter release'
Assert-ExactProperties -Value $contract.crate -Expected @(
    'package', 'requirement', 'registry', 'delivery', 'publication_source', 'packaged_with',
    'source_package_sha256', 'source_package_bytes', 'manifest_template'
) -Label 'adopter crate'
Assert-ExactProperties -Value $contract.pilot_release_gate -Expected @(
    'version', 'select_after_adopter_scope', 'clean_protected_main_tag',
    'matching_source_and_native_release', 'truthful_packaged_documentation',
    'registry_readback_required', 'retroactive_alpha13_publication'
) -Label 'adopter pilot release gate'
Assert-ExactProperties -Value $contract.native -Expected @(
    'target', 'archive', 'archive_sha256', 'archive_bytes', 'runner', 'operating_system',
    'architecture', 'abi', 'kernel', 'supervised_floor', 'worker_manifest',
    'worker_manifest_schema', 'worker_target', 'worker_bootstrap_abi', 'worker_feature_id',
    'verifier'
) -Label 'adopter native package'
Assert-ExactProperties -Value $contract.semantics -Expected @(
    'interpretation_profile', 'interpretation_profile_sha256', 'policy', 'policy_sha256',
    'consumer_profile', 'consumer_profile_sha256', 'specification_snapshot', 'view_schema',
    'receipt_schema', 'canonicalization'
) -Label 'adopter semantics'
Assert-ExactProperties -Value $contract.handoff -Expected @(
    'report_schema', 'adapter', 'target_model', 'installer_version', 'installer_filename',
    'installer_sha256'
) -Label 'adopter handoff'
Assert-ExactProperties -Value $contract.selection -Expected @(
    'consumer_kind', 'platform', 'workflow', 'maintainer_independence', 'must_own_ci',
    'sealr_fork_or_copied_fixture'
) -Label 'adopter selection'

Assert-Equal 'sealr.external-adopter-pilot.v1' $contract.schema 'adopter schema'
Assert-Equal 'verified-baseline-awaiting-external-adopter-and-new-pilot-release' $contract.status 'adopter status'
Assert-Equal '0.1.0-alpha.13' $contract.release.version 'baseline release version'
Assert-Equal '2fab2cfcd54dc065d02e25e74c3bfb227555ca90' $contract.release.commit 'baseline release commit'
if ([string]$contract.release.version -notmatch '^0\.1\.0-alpha\.[1-9][0-9]*$' -or
    [string]$contract.release.tag -cne "v$($contract.release.version)" -or
    [string]$contract.release.commit -notmatch '^[0-9a-f]{40}$') {
    throw 'adopter release identity is not canonical'
}
Assert-Equal "=$($contract.release.version)" $contract.crate.requirement 'adopter crate requirement'
Assert-Equal "sealr-$($contract.release.version)-$($contract.native.target).tar.gz" $contract.native.archive 'adopter native archive'
Assert-Equal 'technical-baseline-not-publication-candidate' $contract.release.role 'baseline release role'
Assert-Equal 'new-clean-release-tag-required' $contract.crate.publication_source 'crate publication source'
Assert-Equal 'cargo 1.98.0' $contract.crate.packaged_with 'crate packaging toolchain'
if ([string]$contract.crate.source_package_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [uint64]$contract.crate.source_package_bytes -eq 0) {
    throw 'adopter source package identity is not canonical'
}
Assert-Equal 'fb70684a71ec770bdf151176ef624244dd571de2c37bc7860e45db4c2607743e' $contract.crate.source_package_sha256 'baseline source package digest'
Assert-Equal 553812 $contract.crate.source_package_bytes 'baseline source package size'
if ([string]$contract.native.archive_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [uint64]$contract.native.archive_bytes -eq 0) {
    throw 'adopter native archive identity is not canonical'
}
Assert-Equal '8f74d52566a275193261d82d3977e0b469b4c6c7d1a3f588f0b3a982a1f5892d' $contract.native.archive_sha256 'baseline native archive digest'
Assert-Equal 3040308 $contract.native.archive_bytes 'baseline native archive size'

Push-Location $workspace
try {
    $metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json -Depth 20
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
$package = @($metadata.packages | Where-Object { $_.name -ceq $contract.crate.package })
if ($package.Count -ne 1) {
    throw 'adopter crate package is missing or duplicated in workspace metadata'
}
Assert-Equal $contract.release.version $package[0].version 'adopter crate version'
Assert-Equal $contract.release.rust_version $package[0].rust_version 'adopter crate Rust version'
if (@($package[0].publish).Count -ne 1) {
    throw 'adopter crate must allow exactly one registry'
}
Assert-Equal $contract.crate.registry $package[0].publish[0] 'adopter crate registry'

$crateContract = Get-Content -Raw -LiteralPath (Join-Path $workspace 'tests/package-contract/sealr.json') |
    ConvertFrom-Json -Depth 20
Assert-Equal $contract.crate.package $crateContract.package 'crate package contract name'
Assert-Equal $contract.crate.registry $crateContract.registry 'crate package contract registry'
Assert-Equal $contract.release.rust_version $crateContract.rust_version 'crate package contract Rust version'

$manifestPath = Join-Path $workspace $contract.crate.manifest_template
if (-not [IO.File]::Exists($manifestPath)) {
    throw "adopter manifest template is missing: $manifestPath"
}
$manifest = Get-Content -Raw -LiteralPath $manifestPath
$dependency = [regex]::Match($manifest, '(?m)^sealr = "(?<value>[^"]+)"\r?$').Groups['value'].Value
$manifestRust = [regex]::Match($manifest, '(?m)^rust-version = "(?<value>[^"]+)"\r?$').Groups['value'].Value
Assert-Equal $contract.crate.requirement $dependency 'handoff Sealr dependency'
Assert-Equal $contract.release.rust_version $manifestRust 'handoff Rust version'
Assert-Equal 'verified-tag-package-not-for-retroactive-publication' $contract.crate.delivery 'crate delivery state'

$rootReadme = Get-Content -Raw -LiteralPath (Join-Path $workspace 'README.md')
Assert-Contains $rootReadme 'This GitHub-only prerelease does not publish a crate to crates.io.' 'baseline packaged README publication status'
$crateManifest = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/Cargo.toml')
Assert-Contains $crateManifest 'readme = "../../README.md"' 'baseline packaged README source'

Assert-Equal 'unassigned-new-prerelease' $contract.pilot_release_gate.version 'pilot release version state'
foreach ($field in @(
    'select_after_adopter_scope', 'clean_protected_main_tag',
    'matching_source_and_native_release', 'truthful_packaged_documentation',
    'registry_readback_required'
)) {
    Assert-Equal $true $contract.pilot_release_gate.$field "pilot release gate $field"
}
Assert-Equal $false $contract.pilot_release_gate.retroactive_alpha13_publication 'Alpha.13 publication gate'

Assert-Equal 'publisher-or-registry-or-build-backend-or-installer' $contract.selection.consumer_kind 'adopter consumer kind'
Assert-Equal $contract.native.target $contract.selection.platform 'adopter selection platform'
Assert-Equal 'python-wheel' $contract.selection.workflow 'adopter workflow'
Assert-Equal $true $contract.selection.maintainer_independence 'adopter maintainer independence'
Assert-Equal $true $contract.selection.must_own_ci 'adopter must own CI'
Assert-Equal $false $contract.selection.sealr_fork_or_copied_fixture 'adopter must not be a Sealr fixture'

Assert-ExactStringList -Actual $contract.forbidden_acquisition -Expected @(
    'local-path-dependency',
    'mutable-branch',
    'unpublished-workspace-crate',
    'internal-feature',
    'wheel-laboratory',
    'cli-internals',
    'private-semantic-records'
) -Label 'adopter forbidden acquisition'

$nativeContract = Get-Content -Raw -LiteralPath (Join-Path $workspace 'tests/package-contract/native.json') |
    ConvertFrom-Json -Depth 20
$native = @($nativeContract.targets | Where-Object { $_.target -ceq $contract.native.target })
if ($native.Count -ne 1) {
    throw 'adopter native target is missing or duplicated in native package contract'
}
foreach ($field in @('runner', 'operating_system', 'architecture', 'abi', 'kernel')) {
    Assert-Equal $contract.native.$field $native[0].$field "adopter native $field"
}
Assert-Equal 'Landlock ABI 3 plus the documented x86_64 seccomp filter' $contract.native.supervised_floor 'adopter supervised floor'

$identity = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/tests/conformance/identity-v1.json') |
    ConvertFrom-Json -Depth 100
$profile = @($identity.profiles | Where-Object { $_.id -ceq $contract.semantics.interpretation_profile })
if ($profile.Count -ne 1) {
    throw 'adopter interpretation profile is missing or duplicated in identity conformance'
}
Assert-Equal $contract.semantics.interpretation_profile_sha256 $profile[0].digest.sha256 'adopter interpretation profile digest'

$policySource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/policy.rs')
Assert-Contains $policySource "id: `"$($contract.semantics.policy)`".into()" 'default policy id'
Assert-Contains $policySource "`"$($contract.semantics.policy_sha256)`"" 'default policy digest'

$wheelModel = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/wheel/model.rs')
Assert-Contains $wheelModel "CONSUMER_PROFILE_ID: &str = `"$($contract.semantics.consumer_profile)`"" 'wheel consumer profile'
Assert-Contains $wheelModel "SPEC_SNAPSHOT_ID: &str = `"$($contract.semantics.specification_snapshot)`"" 'wheel specification snapshot'
$wheelTest = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/tests/wheel_consumer_api.rs')
Assert-Contains $wheelTest "`"$($contract.semantics.consumer_profile_sha256)`"" 'wheel consumer profile digest'

$applySource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/apply.rs')
Assert-Contains $applySource "view.schema = `"$($contract.semantics.view_schema)`"" 'canonical view schema'
Assert-Contains $applySource "receipt.schema = `"$($contract.semantics.receipt_schema)`"" 'canonical receipt schema'
Assert-Contains $applySource "receipt.canonicalization = Some(`"$($contract.semantics.canonicalization)`")" 'canonical evidence algorithm'

$supervisedSource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/supervised.rs')
Assert-Contains $supervisedSource "WORKER_MANIFEST_NAME: &str = `"$([IO.Path]::GetFileName($contract.native.worker_manifest))`"" 'worker manifest name'
Assert-Contains $supervisedSource "WORKER_MANIFEST_SCHEMA: &str = `"$($contract.native.worker_manifest_schema)`"" 'worker manifest schema'
Assert-Contains $supervisedSource "WORKER_HELPER_TARGET: &str = `"$($contract.native.worker_target)`"" 'worker helper target'
$protocolSource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/worker_protocol/mod.rs')
Assert-Contains $protocolSource "HELPER_BOOTSTRAP_ABI: u64 = $($contract.native.worker_bootstrap_abi);" 'worker bootstrap ABI'
Assert-Contains $protocolSource "HELPER_FEATURE_ID: u64 = $($contract.native.worker_feature_id);" 'worker feature id'

$stageSource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/examples/pypa_installer_handoff/stage.rs')
Assert-Contains $stageSource "TARGET_MODEL: &str = `"$($contract.handoff.target_model)`"" 'handoff target model'
Assert-Contains $stageSource "ADAPTER_ID: &str = `"$($contract.handoff.adapter)`"" 'handoff adapter'
Assert-Contains $stageSource "`"$($contract.handoff.installer_sha256)`"" 'handoff installer digest'
$mainSource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/examples/pypa_installer_handoff/main.rs')
Assert-Contains $mainSource "schema: `"$($contract.handoff.report_schema)`"" 'handoff report schema'
$requirements = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/examples/pypa_installer_handoff/requirements.txt')
Assert-Contains $requirements "installer==$($contract.handoff.installer_version)" 'handoff installer version'
Assert-Contains $requirements "--hash=sha256:$($contract.handoff.installer_sha256)" 'handoff requirement digest'

Assert-ExactStringList -Actual $contract.required_proofs -Expected @(
    'authenticated-native-archive',
    'version-match-before-source-transfer',
    'independent-canonical-evidence-verification',
    'source-unavailable-before-consumer',
    'no-post-admission-wheel-open',
    'bounded-capability-member-transfer',
    'exact-output-and-mode-audit',
    'failure-class-separation'
) -Label 'adopter required proofs'

Assert-ExactStringList -Actual $contract.report_fields -Expected @(
    'adopter-repository-and-commit',
    'locked-crate-version-and-registry-checksum',
    'native-archive-filename-and-sha256',
    'sealr-release-tag-commit',
    'supported-os-python-installer-and-target-model',
    'corpus-selection-rule-and-byte-addressed-manifest',
    'outcome-counts-by-class',
    'investigated-rejection-clusters',
    'setup-and-public-api-friction',
    'requested-semantic-or-schema-changes',
    'no-reopen-and-negative-test-results',
    'explicit-nonclaims'
) -Label 'adopter report fields'

Assert-ExactStringList -Actual $contract.nonclaims -Expected @(
    'not-production-containment',
    'not-malware-detection',
    'not-general-poetry-support',
    'not-crates-io-alpha13',
    'not-supply-chain-independent-verifier'
) -Label 'adopter nonclaims'

$matrix = @($contract.negative_matrix)
if ($matrix.Count -ne 11) {
    throw 'adopter negative matrix must contain exactly eleven cases'
}
$matrixIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($row in $matrix) {
    Assert-ExactProperties -Value $row -Expected @('id', 'mutation', 'required_result') -Label "negative matrix $($row.id)"
    if (-not $matrixIds.Add([string]$row.id)) {
        throw "duplicate negative matrix id: $($row.id)"
    }
}

$pilotDoc = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/adopter-pilot.md')
foreach ($term in @(
    'No external adopter has passed this contract.',
    'must not be retroactively published to crates.io',
    'new prerelease',
    $contract.release.commit,
    $contract.crate.source_package_sha256,
    $contract.native.archive_sha256,
    [string]$contract.native.archive_bytes,
    $contract.semantics.interpretation_profile_sha256,
    $contract.semantics.consumer_profile_sha256,
    $contract.native.supervised_floor,
    'supply-chain independence',
    'A Sealr fork, copied example, or fixture maintained inside this repository does not qualify.',
    'This contract does not claim production containment, malware detection, general Poetry support, crates.io publication of Alpha.13, or supply-chain independence of the packaged verifier.'
)) {
    Assert-Contains $pilotDoc $term 'adopter pilot documentation'
}
foreach ($row in $matrix) {
    Assert-Contains $pilotDoc ([string]$row.mutation) "negative matrix $($row.id) mutation"
    Assert-Contains $pilotDoc ([string]$row.required_result) "negative matrix $($row.id) result"
}

$roadmap = Get-Content -Raw -LiteralPath (Join-Path $workspace 'ROADMAP.md')
Assert-Contains $roadmap 'docs/adopter-pilot.md' 'roadmap adopter contract link'
$nearTerm = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/near-term.md')
Assert-Contains $nearTerm 'adopter-pilot.md' 'near-term adopter contract link'
Assert-Contains $rootReadme 'docs/adopter-pilot.md' 'README adopter contract link'
$releasing = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/releasing.md')
Assert-Contains $releasing 'Publish the source crate for the pilot' 'release process crate publication gate'
$distribution = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/distribution-contract.md')
Assert-Contains $distribution $contract.crate.source_package_sha256 'distribution contract source package digest'
$changelog = Get-Content -Raw -LiteralPath (Join-Path $workspace 'CHANGELOG.md')
Assert-Contains $changelog 'machine-checked external-adopter contract' 'changelog adopter contract'
$usefulness = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/usefulness.md')
Assert-Contains $usefulness 'no external adopter treats the public representation as authority' 'usefulness still requires an external adopter'

$ci = Get-Content -Raw -LiteralPath (Join-Path $workspace '.github/workflows/ci.yml')
$ciCommand = 'run: pwsh -NoLogo -NoProfile -File scripts/verify_adopter_contract.ps1'
if (([regex]::Matches($ci, [regex]::Escape($ciCommand))).Count -ne 1) {
    throw 'required CI must invoke the adopter contract verifier exactly once'
}

$tagRef = "$($contract.release.tag)^{}"
$tagCommit = (& git -C $workspace rev-parse --verify $tagRef 2>$null)
if ($LASTEXITCODE -eq 0) {
    Assert-Equal $contract.release.commit $tagCommit.Trim() 'adopter release tag commit'
}

Write-Host 'Verified the external-adopter baseline, proof contract, and new-release gate.'
