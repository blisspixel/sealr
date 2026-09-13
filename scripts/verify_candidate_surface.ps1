[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$contractPath = Join-Path $workspace 'tests/package-contract/candidate-surface.json'
$contract = Get-Content -Raw -LiteralPath $contractPath | ConvertFrom-Json -Depth 20
$pilot = Get-Content -Raw -LiteralPath (Join-Path $workspace 'tests/package-contract/adopter-pilot.json') |
    ConvertFrom-Json -Depth 20

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

function Assert-ClassifiedSet {
    param(
        [Parameter(Mandatory)] [object] $Inventory,
        [Parameter(Mandatory)] [string[]] $SourceIds,
        [Parameter(Mandatory)] [string[]] $Classes,
        [Parameter(Mandatory)] [string] $Label,
        [string] $RequiredPilotId
    )

    $entries = @($Inventory)
    if ($entries.Count -ne $SourceIds.Count) {
        throw "$Label count $($entries.Count) does not match source $($SourceIds.Count)"
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pilotIds = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $entries) {
        Assert-ExactProperties -Value $entry -Expected @('id', 'class') -Label "$Label $($entry.id)"
        $id = [string]$entry.id
        $class = [string]$entry.class
        if (-not $seen.Add($id)) {
            throw "duplicate $Label id: $id"
        }
        if ($Classes -notcontains $class) {
            throw "$Label $id has unknown class $class"
        }
        if ($SourceIds -notcontains $id) {
            throw "$Label is not a source identity: $id"
        }
        if ($class -ceq 'candidate-stable-for-pilot') {
            $pilotIds.Add($id)
        }
    }
    foreach ($id in $SourceIds) {
        if (-not $seen.Contains($id)) {
            throw "source $Label is missing from the candidate surface: $id"
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($RequiredPilotId)) {
        if ($pilotIds.Count -ne 1 -or $pilotIds[0] -cne $RequiredPilotId) {
            throw "exactly $RequiredPilotId must be the candidate-stable-for-pilot $Label"
        }
    }
}

Assert-ExactProperties -Value $contract -Expected @(
    'schema', 'status', 'freeze', 'follows', 'classes', 'interpretation_profiles',
    'policies', 'identities', 'evidence_schemas', 'pilot_operations', 'cli',
    'distribution', 'internal_features', 'planned_for_replacement', 'evidence_lineage_migration'
) -Label 'candidate surface'
Assert-Equal 'sealr.candidate-surface.v2' $contract.schema 'candidate surface schema'
Assert-Equal 'inventory-not-a-freeze' $contract.status 'candidate surface status'
Assert-Equal $false $contract.freeze 'candidate surface must not claim a freeze'
Assert-Equal 'automated-downstream-evidence' $contract.follows 'candidate surface follows'
$classes = @($contract.classes | ForEach-Object { [string]$_ })
$expectedClasses = @(
    'candidate-stable-for-pilot',
    'preview',
    'internal',
    'planned-for-replacement'
)
if (($classes -join "`n") -cne ($expectedClasses -join "`n")) {
    throw 'candidate surface classes changed or were reordered'
}

$irSource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/ir.rs')
$sourceProfiles = @(
    [regex]::Matches($irSource, 'pub const [A-Z0-9_]+: &str =\s*"(?<id>sealr\.profile\.[^"]+)"') |
        ForEach-Object { $_.Groups['id'].Value }
)
if ($sourceProfiles.Count -eq 0) {
    throw 'could not parse public interpretation profile constants'
}
Assert-ClassifiedSet -Inventory $contract.interpretation_profiles -SourceIds $sourceProfiles -Classes $classes `
    -Label 'profile' -RequiredPilotId ([string]$pilot.semantics.interpretation_profile)

$policySource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/policy.rs')
$sourcePolicies = @(
    [regex]::Matches($policySource, 'id: "(?<id>sealr:policy/default/v[0-9]+)"') |
        ForEach-Object { $_.Groups['id'].Value }
)
if ($sourcePolicies.Count -eq 0) {
    throw 'could not parse default policy identifiers'
}
Assert-ClassifiedSet -Inventory $contract.policies -SourceIds $sourcePolicies -Classes $classes `
    -Label 'policy' -RequiredPilotId ([string]$pilot.semantics.policy)

$identitySource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/identity.rs')
$treeIds = @(
    [regex]::Matches($identitySource, 'pub const TREE_ENCODING[A-Z0-9_]*: &str = "(?<id>sealrTreeV[0-9]+)"') |
        ForEach-Object { $_.Groups['id'].Value }
)
$wheelSource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/wheel/model.rs')
$wheelIds = @(
    [regex]::Matches(
        $wheelSource,
        'pub const (?:CONSUMER_PROFILE_ID|CONSUMER_PROFILE_SCHEMA|SPEC_SNAPSHOT_ID|ARTIFACT_ENCODING_ID|PLAN_ENCODING_ID|REALIZATION_ENCODING_ID): &str = "(?<id>[^"]+)"'
    ) | ForEach-Object { $_.Groups['id'].Value }
)
$sourceIdentities = @($wheelIds + $treeIds)
Assert-ClassifiedSet -Inventory $contract.identities -SourceIds $sourceIdentities -Classes $classes -Label 'identity'
$pilotIdentityIds = @(
    [string]$pilot.semantics.consumer_profile,
    'sealr.wheel-consumer-profile.v1',
    [string]$pilot.semantics.specification_snapshot,
    'sealrWheelArtifactV1',
    'sealrWheelInstallPlanV1',
    'sealrWheelRealizationV1'
)
foreach ($entry in @($contract.identities)) {
    $id = [string]$entry.id
    $class = [string]$entry.class
    if ($pilotIdentityIds -contains $id) {
        Assert-Equal 'candidate-stable-for-pilot' $class "identity $id class"
    } elseif ($id.StartsWith('sealrTreeV', [StringComparison]::Ordinal)) {
        Assert-Equal 'preview' $class "identity $id class"
    }
}

$applySource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/apply.rs')
$evidenceSeen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($match in [regex]::Matches(
    $applySource + "`n" + $irSource,
    '"(?<id>sealr\.(?:view|receipt|archive-ir)\.v[0-9]+)"'
)) {
    [void]$evidenceSeen.Add($match.Groups['id'].Value)
}
$sourceEvidence = @($evidenceSeen)
Assert-ClassifiedSet -Inventory $contract.evidence_schemas -SourceIds $sourceEvidence -Classes $classes -Label 'evidence schema'
foreach ($entry in @($contract.evidence_schemas)) {
    $id = [string]$entry.id
    $class = [string]$entry.class
    if ($id -ceq [string]$pilot.semantics.view_schema -or $id -ceq [string]$pilot.semantics.receipt_schema) {
        Assert-Equal 'candidate-stable-for-pilot' $class "evidence $id class"
    }
}

$operations = @($contract.pilot_operations | ForEach-Object { [string]$_ })
$expectedOperations = @(
    'apply',
    'apply_with_options',
    'Request',
    'apply_supervised',
    'inspect_supervised',
    'LinuxWorker',
    'evaluate_wheel',
    'realize_identity',
    'VerifiedArchive::read_member',
    'VerifiedArchive::read_member_prefix',
    'Outcome::canonical_evidence'
)
if (($operations -join "`n") -cne ($expectedOperations -join "`n")) {
    throw 'pilot operations changed or were reordered'
}

Assert-ExactProperties -Value $contract.cli -Expected @(
    'class', 'admitted_exit', 'not_admitted_exit', 'effect_failed_exit', 'operational_exit'
) -Label 'candidate CLI'
Assert-Equal 'preview' $contract.cli.class 'CLI class'
Assert-Equal 0 $contract.cli.admitted_exit 'CLI admitted exit'
Assert-Equal 2 $contract.cli.not_admitted_exit 'CLI not-admitted exit'
Assert-Equal 3 $contract.cli.effect_failed_exit 'CLI effect-failed exit'
Assert-Equal 1 $contract.cli.operational_exit 'CLI operational exit'
Assert-Contains $applySource '=> 0,' 'CLI admitted exit implementation'
Assert-Contains $applySource '=> 3,' 'CLI effect-failed exit implementation'
Assert-Contains $applySource '_ => 2,' 'CLI not-admitted exit implementation'

Assert-ExactProperties -Value $contract.distribution -Expected @(
    'msrv', 'msrv_class', 'semver_policy', 'publishable_crate', 'linux_archive_class',
    'other_archive_class', 'linux_files', 'helper_manifest_schema', 'verifier'
) -Label 'candidate distribution'
$workspaceCargo = Get-Content -Raw -LiteralPath (Join-Path $workspace 'Cargo.toml')
$msrv = [regex]::Match($workspaceCargo, '(?m)^rust-version = "(?<value>[^"]+)"$').Groups['value'].Value
Assert-Equal $msrv $contract.distribution.msrv 'distribution MSRV'
Assert-Equal 'candidate-stable-for-pilot' $contract.distribution.msrv_class 'MSRV class'
Assert-Equal 'prerelease-changelog-required' $contract.distribution.semver_policy 'SemVer policy'
Assert-Equal 'sealr' $contract.distribution.publishable_crate 'publishable crate'
Assert-Equal 'candidate-stable-for-pilot' $contract.distribution.linux_archive_class 'Linux archive class'
Assert-Equal 'preview' $contract.distribution.other_archive_class 'other archive class'
Assert-Equal ([string]$pilot.native.worker_manifest_schema) $contract.distribution.helper_manifest_schema 'helper manifest schema'
Assert-Equal ([string]$pilot.native.verifier) $contract.distribution.verifier 'verifier name'
$linuxFiles = @($contract.distribution.linux_files | ForEach-Object { [string]$_ })
$expectedLinuxFiles = @(
    'CHANGELOG.md',
    'LICENSE',
    'README.md',
    'THIRD_PARTY_LICENSES.txt',
    'sealr',
    'sealr-identity-verifier',
    'libexec/sealr/sealr-worker',
    'libexec/sealr/sealr-worker.manifest'
)
if (($linuxFiles -join "`n") -cne ($expectedLinuxFiles -join "`n")) {
    throw 'Linux native archive file inventory changed or was reordered'
}

$crateManifest = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/Cargo.toml')
$featureBlock = [regex]::Match($crateManifest, '(?ms)^\[features\](?<body>.*?)(?:^\[|\Z)').Groups['body'].Value
$sourceFeatures = @(
    [regex]::Matches($featureBlock, '(?m)^(__internal-[A-Za-z0-9-]+)\s*=') |
        ForEach-Object { $_.Groups[1].Value }
)
$inventoryFeatures = @($contract.internal_features | ForEach-Object { [string]$_ })
if (($inventoryFeatures -join "`n") -cne ($sourceFeatures -join "`n")) {
    throw 'internal feature inventory does not match crates/sealr/Cargo.toml'
}

$replacements = @($contract.planned_for_replacement)
if ($replacements.Count -ne 4) {
    throw 'planned-for-replacement inventory changed'
}
$replacementIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$replacementTargets = @{
    'Verdict' = 'Outcome axes and VerifiedArchive'
    'receipt.schema.v2-default-lineage' = 'sealr.receipt.v3'
    'view.schema.v1-default-lineage' = 'sealr.view.v2'
    'Policy.atomic' = 'Durability'
}
$replacementRules = @{
    'Verdict' = 'sealr.verdict-consumer-migration.v1'
    'receipt.schema.v2-default-lineage' = 'sealr.evidence-lineage-migration.v1'
    'view.schema.v1-default-lineage' = 'sealr.evidence-lineage-migration.v1'
    'Policy.atomic' = 'sealr.policy-durability-migration.v1'
}
foreach ($entry in $replacements) {
    Assert-ExactProperties -Value $entry -Expected @(
        'id', 'reason', 'migration_status', 'migration_rule', 'target'
    ) -Label "replacement $($entry.id)"
    if (-not $replacementTargets.ContainsKey([string]$entry.id) -or
        -not $replacementIds.Add([string]$entry.id)) {
        throw "unknown or duplicate planned replacement: $($entry.id)"
    }
    if ([string]::IsNullOrWhiteSpace([string]$entry.reason)) {
        throw "planned replacement $($entry.id) has no reason"
    }
    $target = $replacementTargets[[string]$entry.id]
    Assert-Equal $target $entry.target "replacement $($entry.id) target"
    Assert-Equal 'consumer-contract-tested' $entry.migration_status "replacement $($entry.id) status"
    Assert-Equal $replacementRules[[string]$entry.id] $entry.migration_rule "replacement $($entry.id) rule"
}

$migration = $contract.evidence_lineage_migration
Assert-ExactProperties -Value $migration -Expected @(
    'id', 'scope', 'rust_emission', 'cli_selection', 'legacy_defaults_preserved',
    'fallback', 'native_check', 'fixture', 'cases'
) -Label 'evidence lineage migration'
Assert-Equal 'sealr.evidence-lineage-migration.v1' $migration.id 'migration rule'
Assert-Equal 'inspection-without-effects' $migration.scope 'migration consumer scope'
Assert-Equal 'Outcome::canonical_evidence' $migration.rust_emission 'migration Rust emission'
Assert-Equal '--canonical' $migration.cli_selection 'migration CLI selection'
Assert-Equal $true $migration.legacy_defaults_preserved 'migration preserves legacy defaults'
Assert-Equal $false $migration.fallback 'migration forbids evidence fallback'
Assert-Equal 'scripts/verify_native_package.ps1' $migration.native_check 'migration executable check'
Assert-ExactProperties -Value $migration.fixture -Expected @(
    'manifest', 'id', 'source_sha256', 'rejection'
) -Label 'migration fixture'
Assert-Equal 'crates/sealr/tests/conformance/tar-producers-v1.json' $migration.fixture.manifest 'migration fixture manifest'
Assert-Equal 'gnu-tar-1.35' $migration.fixture.id 'migration fixture id'
Assert-Equal '075e5d93ff213f832023b1ecf614a4c39bdf5975edab3aedcb0df7d649073a42' `
    $migration.fixture.source_sha256 'migration fixture digest'
Assert-Equal 'first-header-byte-xor-1' $migration.fixture.rejection 'migration rejection mutation'
$producerManifest = Get-Content -Raw -LiteralPath (Join-Path $workspace $migration.fixture.manifest) | ConvertFrom-Json
$producerFixture = @($producerManifest.fixtures | Where-Object { $_.id -ceq $migration.fixture.id })
if ($producerFixture.Count -ne 1) {
    throw 'migration fixture must identify exactly one committed producer artifact'
}
Assert-Equal $migration.fixture.source_sha256 $producerFixture[0].source_sha256 'migration producer binding'

$expectedMigrationCases = @(
    @('canonical-admitted', 'sealr.view.v2', 'sealr.receipt.v3', 0, 'archive-admitted', '$canonicalViewPath', '$canonicalReceiptPath'),
    @('legacy-pair', 'sealr.view.v1', 'sealr.receipt.v2', 1, 'evidence-refused', '$legacyViewPath', '$legacyReceiptPath'),
    @('legacy-view-canonical-receipt', 'sealr.view.v1', 'sealr.receipt.v3', 1, 'evidence-refused', '$legacyViewPath', '$canonicalReceiptPath'),
    @('canonical-view-legacy-receipt', 'sealr.view.v2', 'sealr.receipt.v2', 1, 'evidence-refused', '$canonicalViewPath', '$legacyReceiptPath'),
    @('canonical-rejected', 'sealr.view.v2', 'sealr.receipt.v3', 0, 'archive-not-admitted', '$rejectedViewPath', '$rejectedReceiptPath')
)
$nativeSource = Get-Content -Raw -LiteralPath (Join-Path $workspace $migration.native_check)
$migrationBlocks = [regex]::Matches($nativeSource,
    '(?s)# BEGIN sealr\.evidence-lineage-migration\.v1\r?\n(?<body>.*?)# END sealr\.evidence-lineage-migration\.v1')
if ($migrationBlocks.Count -ne 1) {
    throw 'native package verification must contain exactly one versioned migration matrix'
}
$nativeCases = [regex]::Matches($migrationBlocks[0].Groups['body'].Value, '(?s)\[pscustomobject\]@\{(?<row>.*?)\}')
$migrationCases = @($migration.cases)
if ($migrationCases.Count -ne 5 -or $nativeCases.Count -ne 5) {
    throw 'migration requires exactly five documented and executable consumer cases'
}
for ($caseIndex = 0; $caseIndex -lt $expectedMigrationCases.Count; $caseIndex++) {
    $case = $migrationCases[$caseIndex]
    $expected = $expectedMigrationCases[$caseIndex]
    Assert-ExactProperties -Value $case -Expected @(
        'id', 'view_schema', 'receipt_schema', 'verifier_exit', 'consumer_decision'
    ) -Label "migration case $caseIndex"
    Assert-Equal $expected[0] $case.id 'migration case order and id'
    Assert-Equal $expected[1] $case.view_schema "migration $($case.id) view"
    Assert-Equal $expected[2] $case.receipt_schema "migration $($case.id) receipt"
    Assert-Equal $expected[3] $case.verifier_exit "migration $($case.id) verifier exit"
    Assert-Equal $expected[4] $case.consumer_decision "migration $($case.id) consumer decision"
    $nativeCase = $nativeCases[$caseIndex].Groups['row'].Value
    foreach ($term in @(
        "Label = '$($case.id)'", "View = $($expected[5])", "Receipt = $($expected[6])",
        "ExpectedVerifierExit = $($case.verifier_exit)", "ExpectedDecision = '$($case.consumer_decision)'"
    )) {
        Assert-Contains $nativeCase $term "executable migration $($case.id)"
    }
}
foreach ($term in @(
    'function Get-EvidenceMigrationDecision {',
    '$Verification.ExitCode -ne 0',
    '$document.admission.status -cne ''admitted''',
    '$document.verification.status -cne ''complete''',
    '$document.effect.status -cne ''not-requested''',
    '$rejectedBytes[0] = $rejectedBytes[0] -bxor 1'
)) {
    Assert-Contains $nativeSource $term 'migration acceptance and rejection contract'
}

$consumerContracts = Get-Content -Raw -LiteralPath (Join-Path $workspace 'tests/package-contract/consumer-migrations.json') | ConvertFrom-Json -Depth 20
Assert-ExactProperties $consumerContracts @('schema', 'verdict', 'durability') 'consumer migrations'
Assert-Equal 'sealr.consumer-migrations.v1' $consumerContracts.schema 'consumer migration schema'
$verdictMigration = $consumerContracts.verdict
Assert-ExactProperties $verdictMigration @(
    'id', 'target', 'consumer', 'cases', 'examples', 'late_effect_test', 'legacy_compatibility_preserved'
) 'verdict migration'
Assert-Equal $replacementRules.Verdict $verdictMigration.id 'verdict migration rule'
Assert-Equal $replacementTargets.Verdict $verdictMigration.target 'verdict migration target'
Assert-Equal 'tests/packaged-consumer/src/outcome_migration.rs' $verdictMigration.consumer 'verdict consumer'
Assert-Equal 'inspected-capability|committed-materialization|structural-denial|crc-denial|effect-setup-failure|source-unavailable' `
    ($verdictMigration.cases -join '|') 'verdict cases'
Assert-Equal 'crates/sealr/examples/deepr_content_gate/main.rs|crates/sealr/examples/pypa_installer_handoff/main.rs' `
    ($verdictMigration.examples -join '|') 'verdict examples'
Assert-Equal 'mutated_staged_content_never_publishes' $verdictMigration.late_effect_test 'late-effect evidence'
Assert-Equal $true $verdictMigration.legacy_compatibility_preserved 'verdict compatibility'
$verdictConsumer = Get-Content -Raw -LiteralPath (Join-Path $workspace $verdictMigration.consumer)
foreach ($case in $verdictMigration.cases) {
    Assert-Contains $verdictConsumer ('"' + $case + '"') 'executable verdict case'
}
foreach ($path in $verdictMigration.examples) {
    $exampleSource = Get-Content -Raw -LiteralPath (Join-Path $workspace $path)
    Assert-Contains $exampleSource 'verified_archive()' 'consumer capability authority'
    Assert-Contains $exampleSource 'EffectStatus::' 'consumer effect decision'
    if ($exampleSource -match '\.(?:rejected|wrote)\(\)') {
        throw "supported consumer still gates on a compatibility verdict: $path"
    }
}
$applySource = Get-Content -Raw -LiteralPath (Join-Path $workspace 'crates/sealr/src/apply.rs')
Assert-Contains $applySource ('fn ' + $verdictMigration.late_effect_test + '()') 'real late-effect regression'

$durabilityMigration = $consumerContracts.durability
Assert-ExactProperties $durabilityMigration @(
    'id', 'target', 'consumer', 'input_types', 'modes', 'tests', 'policy_encoding_preserved',
    'worker_encoding_preserved', 'power_loss_guarantee'
) 'durability migration'
Assert-Equal $replacementRules['Policy.atomic'] $durabilityMigration.id 'durability migration rule'
Assert-Equal $replacementTargets['Policy.atomic'] $durabilityMigration.target 'durability migration target'
Assert-Equal 'crates/sealr/tests/durability_migration.rs' $durabilityMigration.consumer 'durability consumer'
Assert-Equal 'Policy|PolicyDocument' ($durabilityMigration.input_types -join '|') 'durability inputs'
Assert-Equal $true $durabilityMigration.policy_encoding_preserved 'durability policy encoding'
Assert-Equal $true $durabilityMigration.worker_encoding_preserved 'durability worker encoding'
Assert-Equal $false $durabilityMigration.power_loss_guarantee 'durability nonclaim'
if (@($durabilityMigration.modes).Count -ne 2) { throw 'durability requires exactly two existing modes' }
$expectedModes = @(@('FlushOnly', $false, 'flush-only'), @('MemberSync', $true, 'member-sync'))
for ($index = 0; $index -lt $expectedModes.Count; $index++) {
    $mode = $durabilityMigration.modes[$index]
    Assert-ExactProperties $mode @('variant', 'legacy_atomic', 'receipt') 'durability mode'
    Assert-Equal $expectedModes[$index][0] $mode.variant 'durability variant'
    Assert-Equal $expectedModes[$index][1] $mode.legacy_atomic 'durability legacy mapping'
    Assert-Equal $expectedModes[$index][2] $mode.receipt 'durability receipt mapping'
}
Assert-Equal 'named_policy_durability_preserves_every_legacy_encoding|document_selection_keeps_validation_and_memoized_identity_consistent|named_rust_controls_do_not_create_a_second_json_policy_language|both_modes_materialize_and_preserve_existing_destinations' `
    ($durabilityMigration.tests -join '|') 'durability test cases'
$durabilityConsumer = Get-Content -Raw -LiteralPath (Join-Path $workspace $durabilityMigration.consumer)
foreach ($test in $durabilityMigration.tests) {
    Assert-Contains $durabilityConsumer ('fn ' + $test + '()') 'executable durability case'
}

$doc = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/candidate-surface.md')
Assert-Contains $doc 'Status: inventory, not a freeze.' 'candidate surface documentation'
Assert-Contains $doc 'Nothing here is frozen.' 'candidate surface documentation'
Assert-Contains $doc 'Do not advertise a stable Sealr 1.0 surface from this page.' 'candidate surface documentation'
foreach ($entry in @($contract.interpretation_profiles)) {
    Assert-Contains $doc "| ``$($entry.id)`` | $($entry.class) |" 'candidate surface profile table'
}
foreach ($entry in @($contract.policies)) {
    Assert-Contains $doc "| ``$($entry.id)`` | $($entry.class) |" 'candidate surface policy table'
}
foreach ($entry in @($contract.identities)) {
    Assert-Contains $doc "| ``$($entry.id)`` | $($entry.class) |" 'candidate surface identity table'
}
foreach ($entry in @($contract.evidence_schemas)) {
    Assert-Contains $doc "| ``$($entry.id)`` | $($entry.class) |" 'candidate surface evidence table'
}
foreach ($operation in $operations) {
    Assert-Contains $doc $operation 'candidate surface operations'
}
foreach ($feature in $inventoryFeatures) {
    Assert-Contains $doc $feature 'candidate surface internal features'
}
foreach ($entry in $replacements) {
    Assert-Contains $doc ([string]$entry.id) 'candidate surface planned replacement'
}
Assert-Contains $doc $migration.id 'candidate surface migration rule'
Assert-Contains $doc $verdictMigration.id 'candidate surface verdict migration'
Assert-Contains $doc $durabilityMigration.id 'candidate surface durability migration'
Assert-Contains $doc 'Migration evidence does not retire compatibility fields or freeze the candidate.' 'candidate surface migration limit'
foreach ($case in $migrationCases) {
    Assert-Contains $doc "| ``$($case.id)`` | ``$($case.view_schema)`` | ``$($case.receipt_schema)`` | ``$($case.verifier_exit)`` | ``$($case.consumer_decision)`` |" `
        'candidate surface migration case'
}
foreach ($file in $linuxFiles) {
    Assert-Contains $doc $file 'candidate surface Linux archive files'
}
Assert-Contains $doc "MSRV | ``$($contract.distribution.msrv)``" 'candidate surface MSRV'
Assert-Contains $doc "exit ``$($contract.cli.admitted_exit)``" 'candidate surface admitted exit'
Assert-Contains $doc "exit ``$($contract.cli.not_admitted_exit)``" 'candidate surface not-admitted exit'
Assert-Contains $doc "exit ``$($contract.cli.effect_failed_exit)``" 'candidate surface effect-failed exit'
Assert-Contains $doc "exit ``$($contract.cli.operational_exit)``" 'candidate surface operational exit'

$apiSurface = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/api-surface.md')
Assert-Contains $apiSurface 'crates/sealr/tests/api_surface.rs' 'API surface compile-time pin'
if (-not [IO.File]::Exists((Join-Path $workspace 'crates/sealr/tests/api_surface.rs'))) {
    throw 'API surface compile-time pin is missing'
}

$ci = Get-Content -Raw -LiteralPath (Join-Path $workspace '.github/workflows/ci.yml')
$ciCommand = 'run: pwsh -NoLogo -NoProfile -File scripts/verify_candidate_surface.ps1'
if (([regex]::Matches($ci, [regex]::Escape($ciCommand))).Count -ne 1) {
    throw 'required CI must invoke the candidate surface verifier exactly once'
}

$roadmap = Get-Content -Raw -LiteralPath (Join-Path $workspace 'ROADMAP.md')
Assert-Contains $roadmap 'docs/candidate-surface.md' 'roadmap candidate surface link'
$nearTerm = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/near-term.md')
Assert-Contains $nearTerm 'candidate-surface.md' 'near-term candidate surface link'
$index = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/index.md')
Assert-Contains $index 'candidate-surface.md' 'documentation index candidate surface link'
$helperPackaging = Get-Content -Raw -LiteralPath (Join-Path $workspace 'docs/helper-packaging.md')
foreach ($file in $linuxFiles) {
    Assert-Contains $helperPackaging $file 'helper packaging Linux archive files'
}

Write-Host 'Verified the candidate surface inventory without treating it as a freeze.'
