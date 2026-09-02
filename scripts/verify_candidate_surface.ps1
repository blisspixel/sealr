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
    'distribution', 'internal_features', 'planned_for_replacement'
) -Label 'candidate surface'
Assert-Equal 'sealr.candidate-surface.v1' $contract.schema 'candidate surface schema'
Assert-Equal 'inventory-not-a-freeze' $contract.status 'candidate surface status'
Assert-Equal $false $contract.freeze 'candidate surface must not claim a freeze'
Assert-Equal 'adopter-feedback' $contract.follows 'candidate surface follows'
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
foreach ($entry in $replacements) {
    Assert-ExactProperties -Value $entry -Expected @('id', 'reason') -Label "replacement $($entry.id)"
    if (-not $replacementIds.Add([string]$entry.id)) {
        throw "duplicate planned replacement: $($entry.id)"
    }
    if ([string]::IsNullOrWhiteSpace([string]$entry.reason)) {
        throw "planned replacement $($entry.id) has no reason"
    }
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
