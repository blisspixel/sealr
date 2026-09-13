[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$workspace = Split-Path $PSScriptRoot -Parent
$contractPath = Join-Path $workspace 'tests/dependency-contract/sealr-runtime.json'
$contract = Get-Content -Raw -LiteralPath $contractPath | ConvertFrom-Json -Depth 100

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory)] [object] $Value,
        [Parameter(Mandatory)] [string[]] $Expected,
        [Parameter(Mandatory)] [string] $Label
    )

    [string[]] $actual = @($Value.PSObject.Properties.Name)
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    [string[]] $sortedExpected = @($Expected)
    [Array]::Sort($sortedExpected, [StringComparer]::Ordinal)
    if (($actual -join "`n") -cne ($sortedExpected -join "`n")) {
        throw "$Label has missing or unknown fields"
    }
}

function Assert-ExactStrings {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Actual,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Expected,
        [Parameter(Mandatory)] [string] $Label
    )

    [string[]] $actualStrings = @($Actual | ForEach-Object { [string] $_ })
    [string[]] $expectedStrings = @($Expected | ForEach-Object { [string] $_ })
    [Array]::Sort($actualStrings, [StringComparer]::Ordinal)
    [Array]::Sort($expectedStrings, [StringComparer]::Ordinal)
    if (($actualStrings -join "`n") -cne ($expectedStrings -join "`n")) {
        throw "$Label changed: expected [$($expectedStrings -join ', ')], observed [$($actualStrings -join ', ')]"
    }
}

Assert-ExactProperties -Value $contract -Expected @(
    'schema',
    'package',
    'canonicalization',
    'maximum_new_packages_per_promoted_codec',
    'forbidden_packages',
    'targets'
) -Label 'dependency contract'
if ($contract.schema -cne 'sealr.runtime-dependency-contract.v1' -or
    $contract.package -cne 'sealr' -or
    $contract.canonicalization -cne 'ordinal-sorted name|version|source lines with one LF terminator; root excluded; normal and build edges included; dev edges excluded' -or
    $contract.maximum_new_packages_per_promoted_codec -ne 2) {
    throw 'dependency contract identity or codec package ceiling changed unexpectedly'
}

$expectedForbidden = @(
    'autotools',
    'bindgen',
    'bzip2-sys',
    'cc',
    'clang-sys',
    'cmake',
    'meson',
    'ninja',
    'pkg-config',
    'system-deps',
    'vcpkg'
)
Assert-ExactStrings -Actual @($contract.forbidden_packages) -Expected $expectedForbidden -Label 'forbidden native-toolchain package set'

$expectedTargets = @(
    'aarch64-apple-darwin',
    'x86_64-pc-windows-msvc',
    'x86_64-unknown-linux-gnu'
)
Assert-ExactStrings -Actual @($contract.targets.target) -Expected $expectedTargets -Label 'release target set'

foreach ($entry in $contract.targets) {
    Assert-ExactProperties -Value $entry -Expected @(
        'target',
        'package_count',
        'graph_sha256',
        'direct_dependencies',
        'links_packages',
        'build_script_packages'
    ) -Label "dependency target $($entry.target)"
    if ([string]$entry.graph_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $entry.package_count -lt 1) {
        throw "dependency target $($entry.target) has an invalid count or graph digest"
    }

    $metadataText = & cargo metadata --locked --format-version 1 --filter-platform ([string]$entry.target)
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed for target $($entry.target)"
    }
    $metadata = $metadataText | ConvertFrom-Json -Depth 100
    $rootPackages = @(
        $metadata.packages | Where-Object {
            $_.name -ceq $contract.package -and
            [IO.Path]::GetFullPath([string]$_.manifest_path) -ceq
                [IO.Path]::GetFullPath((Join-Path $workspace 'crates/sealr/Cargo.toml'))
        }
    )
    if ($rootPackages.Count -ne 1) {
        throw "cargo metadata did not contain exactly one Sealr runtime root for $($entry.target)"
    }
    $root = $rootPackages[0]

    $nodes = @{}
    foreach ($node in $metadata.resolve.nodes) {
        $nodes[[string]$node.id] = $node
    }
    $packages = @{}
    foreach ($package in $metadata.packages) {
        $packages[[string]$package.id] = $package
    }

    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue([string]$root.id)
    while ($queue.Count -ne 0) {
        $current = $queue.Dequeue()
        if (-not $seen.Add($current)) {
            continue
        }
        if (-not $nodes.ContainsKey($current)) {
            throw "runtime dependency node is unavailable for $current"
        }
        foreach ($dependency in $nodes[$current].deps) {
            $includedKinds = @(
                $dependency.dep_kinds | Where-Object {
                    $null -eq $_.kind -or $_.kind -ceq 'build'
                }
            )
            if ($includedKinds.Count -ne 0) {
                $queue.Enqueue([string]$dependency.pkg)
            }
        }
    }

    [string[]] $graphLines = @(
        $seen |
            Where-Object { $_ -cne [string]$root.id } |
            ForEach-Object {
                $package = $packages[$_]
                '{0}|{1}|{2}' -f $package.name, $package.version, ([string]$package.source)
            }
    )
    [Array]::Sort($graphLines, [StringComparer]::Ordinal)
    $canonical = ($graphLines -join "`n") + "`n"
    $graphDigest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonical))
    ).ToLowerInvariant()
    if ($graphLines.Count -ne $entry.package_count -or
        $graphDigest -cne [string]$entry.graph_sha256) {
        throw "runtime dependency graph drifted for $($entry.target): expected $($entry.package_count)/$($entry.graph_sha256), observed $($graphLines.Count)/$graphDigest"
    }

    $rootNode = $nodes[[string]$root.id]
    $direct = @(
        $rootNode.deps |
            Where-Object {
                @($_.dep_kinds | Where-Object { $null -eq $_.kind }).Count -ne 0
            } |
            ForEach-Object name |
            Sort-Object -Unique
    )
    Assert-ExactStrings -Actual $direct -Expected @($entry.direct_dependencies) -Label "direct runtime dependencies for $($entry.target)"

    $linksPackages = @(
        $seen |
            ForEach-Object { $packages[$_] } |
            Where-Object { -not [string]::IsNullOrEmpty([string]$_.links) } |
            ForEach-Object { '{0}:{1}' -f $_.name, $_.links } |
            Sort-Object -Unique
    )
    Assert-ExactStrings -Actual $linksPackages -Expected @($entry.links_packages) -Label "links packages for $($entry.target)"

    $buildScripts = @(
        $seen |
            ForEach-Object { $packages[$_] } |
            Where-Object {
                @($_.targets | Where-Object { $_.kind -contains 'custom-build' }).Count -ne 0
            } |
            ForEach-Object name |
            Sort-Object -Unique
    )
    Assert-ExactStrings -Actual $buildScripts -Expected @($entry.build_script_packages) -Label "build script packages for $($entry.target)"

    $packageNames = @($seen | ForEach-Object { [string]$packages[$_].name })
    $forbiddenPresent = @($packageNames | Where-Object { $_ -cin $expectedForbidden } | Sort-Object -Unique)
    if ($forbiddenPresent.Count -ne 0) {
        throw "forbidden native-toolchain packages entered $($entry.target): $($forbiddenPresent -join ', ')"
    }
}

Write-Host "Verified the exact Sealr runtime and build dependency budget for $($expectedTargets.Count) release targets."
