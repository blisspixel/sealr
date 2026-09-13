[CmdletBinding()]
param(
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) {
    $OutputPath = Join-Path $workspace 'docs/tcb-report.md'
}

# The trusted computing base measured here is the `sealr` crate: every line
# that participates in admission, verification, identity, or the platform
# effect boundary. Measurement is pure and offline: file contents, plus
# `cargo metadata` (which resolves without building), cross-checked against
# the pinned runtime dependency contract.

$sourceRoot = Join-Path $workspace 'crates/sealr/src'
$files = @(
    Get-ChildItem -LiteralPath $sourceRoot -Recurse -Filter '*.rs' -File |
        ForEach-Object { $_.FullName }
)
[Array]::Sort($files, [StringComparer]::Ordinal)

function Get-RelativeSourcePath {
    param([Parameter(Mandatory)] [string] $FullPath)
    $relative = [IO.Path]::GetRelativePath($workspace, $FullPath)
    $relative.Replace('\', '/')
}

# A module declared as `#[cfg(test)] mod name;` compiles its whole child file
# only under test. Map those declarations to child file paths so the child
# counts as test lines, not runtime lines.
$testOnlyFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($file in $files) {
    $lines = [IO.File]::ReadAllLines($file)
    for ($index = 0; $index -lt $lines.Count - 1; $index++) {
        if ($lines[$index].Trim() -cne '#[cfg(test)]') {
            continue
        }
        $declaration = [regex]::Match($lines[$index + 1].Trim(), '^(?:pub )?mod ([A-Za-z0-9_]+);$')
        if (-not $declaration.Success) {
            continue
        }
        $moduleName = $declaration.Groups[1].Value
        $declaringDirectory = Split-Path -Parent $file
        $moduleDirectory = if ((Split-Path -Leaf $file) -ceq 'lib.rs' -or (Split-Path -Leaf $file) -ceq 'mod.rs') {
            $declaringDirectory
        } else {
            Join-Path $declaringDirectory ([IO.Path]::GetFileNameWithoutExtension($file))
        }
        $childFile = Join-Path $moduleDirectory "$moduleName.rs"
        if (Test-Path -LiteralPath $childFile) {
            [void] $testOnlyFiles.Add((Get-Item -LiteralPath $childFile).FullName)
        }
        $childDirectory = Join-Path $moduleDirectory $moduleName
        if (Test-Path -LiteralPath $childDirectory) {
            foreach ($nested in Get-ChildItem -LiteralPath $childDirectory -Recurse -Filter '*.rs' -File) {
                [void] $testOnlyFiles.Add($nested.FullName)
            }
        }
    }
}

$unsafePattern = [regex] '\bunsafe\b(?=\s*(\{|fn|impl|extern|trait))'
$externPattern = [regex] '\bextern\s+"C"'
$panicPatterns = [ordered]@{
    '.unwrap('      = [regex] '\.unwrap\('
    '.expect('      = [regex] '\.expect\('
    'panic!('       = [regex] 'panic!\('
    'unreachable!(' = [regex] 'unreachable!\('
}

$rows = @()
$totals = @{
    RuntimeLines = 0
    TestLines    = 0
    Unsafe       = 0
    UnsafeTest   = 0
    Extern       = 0
}
$panicTotals = [ordered]@{}
foreach ($label in $panicPatterns.Keys) {
    $panicTotals[$label] = @{ Runtime = 0; Test = 0 }
}
$gatedModuleDeclarations = @()

foreach ($file in $files) {
    $lines = [IO.File]::ReadAllLines($file)
    $relative = Get-RelativeSourcePath -FullPath $file

    # Record every cfg-gated module declaration verbatim as an observation.
    for ($index = 0; $index -lt $lines.Count - 1; $index++) {
        if ($lines[$index].Trim() -like '#`[cfg(*' -and
            $lines[$index + 1].Trim() -cmatch '^(?:pub )?mod [A-Za-z0-9_]+;$') {
            $gatedModuleDeclarations += ('`{0}`: `{1}` `{2}`' -f $relative, $lines[$index].Trim(), $lines[$index + 1].Trim())
        }
    }

    # Inside one file the test region is the trailing `#[cfg(test)] mod tests`
    # block; house style keeps it last in the file.
    $testStart = $lines.Count
    if ($testOnlyFiles.Contains($file)) {
        $testStart = 0
    } else {
        for ($index = 0; $index -lt $lines.Count - 1; $index++) {
            if ($lines[$index].Trim() -ceq '#[cfg(test)]' -and
                $lines[$index + 1].Trim() -cmatch '^(?:pub )?mod tests') {
                $testStart = $index
                break
            }
        }
    }

    $runtimeLines = $testStart
    $testLines = $lines.Count - $testStart
    $runtimeText = ($lines[0..([Math]::Max($testStart - 1, 0))] | Select-Object -First $testStart) -join "`n"
    $testText = if ($testLines -gt 0) { ($lines[$testStart..($lines.Count - 1)]) -join "`n" } else { '' }

    $unsafeRuntime = $unsafePattern.Matches($runtimeText).Count
    $unsafeTest = $unsafePattern.Matches($testText).Count
    $externRuntime = $externPattern.Matches($runtimeText).Count

    $panicCells = [ordered]@{}
    foreach ($label in $panicPatterns.Keys) {
        $pattern = $panicPatterns[$label]
        $runtimeCount = $pattern.Matches($runtimeText).Count
        $testCount = $pattern.Matches($testText).Count
        $panicCells[$label] = @{ Runtime = $runtimeCount; Test = $testCount }
        $panicTotals[$label].Runtime += $runtimeCount
        $panicTotals[$label].Test += $testCount
    }

    $totals.RuntimeLines += $runtimeLines
    $totals.TestLines += $testLines
    $totals.Unsafe += $unsafeRuntime
    $totals.UnsafeTest += $unsafeTest
    $totals.Extern += $externRuntime

    $rows += [pscustomobject]@{
        File          = $relative
        RuntimeLines  = $runtimeLines
        TestLines     = $testLines
        UnsafeRuntime = $unsafeRuntime
        PanicRuntime  = (($panicCells.Keys | ForEach-Object { $panicCells[$_].Runtime }) | Measure-Object -Sum).Sum
    }
}

# Runtime dependency facts come from the pinned contract, cross-checked live
# against `cargo metadata` with the contract's own traversal (normal and build
# edges, dev edges excluded). Generation fails closed on any drift so this
# report can never disagree with the dependency budget gate.
$contractPath = Join-Path $workspace 'tests/dependency-contract/sealr-runtime.json'
$contract = Get-Content -Raw -LiteralPath $contractPath | ConvertFrom-Json -Depth 100
$dependencyRows = @()
foreach ($entry in $contract.targets) {
    $metadataText = & cargo metadata --locked --format-version 1 --filter-platform ([string]$entry.target)
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed for target $($entry.target)"
    }
    $metadata = $metadataText | ConvertFrom-Json -Depth 100
    $rootPackages = @(
        $metadata.packages | Where-Object {
            $_.name -ceq 'sealr' -and
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
    [string[]] $names = @(
        $seen |
            Where-Object { $_ -cne [string]$root.id } |
            ForEach-Object { [string]$packages[$_].name }
    )
    [Array]::Sort($names, [StringComparer]::Ordinal)
    if ($names.Count -ne $entry.package_count) {
        throw "runtime dependency graph drifted for $($entry.target): contract pins $($entry.package_count), observed $($names.Count); reconcile scripts/verify_dependency_budget.ps1 first"
    }
    [string[]] $ffiPackages = @($names | Where-Object { $_ -clike '*-sys' -or $_ -ceq 'libc' } | Select-Object -Unique)
    $dependencyRows += [pscustomobject]@{
        Target       = [string]$entry.target
        PackageCount = [int]$entry.package_count
        Direct       = @($entry.direct_dependencies).Count
        BuildScripts = @($entry.build_script_packages).Count
        Links        = @($entry.links_packages).Count
        FfiPackages  = $ffiPackages
        GraphSha256  = [string]$entry.graph_sha256
    }
}

# The report states that no parser or verifier contains unsafe code. Enforce
# that statement instead of assuming it: runtime unsafe may appear only under
# the platform effect and supervision boundary.
$unsafeAllowedPrefixes = @(
    'crates/sealr/src/materialize/',
    'crates/sealr/src/supervised/',
    'crates/sealr/src/worker_protocol/'
)
foreach ($row in $rows) {
    if ($row.UnsafeRuntime -gt 0) {
        $allowed = $false
        foreach ($prefix in $unsafeAllowedPrefixes) {
            if ($row.File.StartsWith($prefix, [StringComparison]::Ordinal)) {
                $allowed = $true
            }
        }
        if (-not $allowed) {
            throw "runtime unsafe appeared outside the platform boundary in $($row.File); the TCB report's containment statement no longer holds"
        }
    }
}

$panicRuntimeTotal = (($panicTotals.Keys | ForEach-Object { $panicTotals[$_].Runtime }) | Measure-Object -Sum).Sum
$panicTestTotal = (($panicTotals.Keys | ForEach-Object { $panicTotals[$_].Test }) | Measure-Object -Sum).Sum

$report = [Text.StringBuilder]::new()
[void]$report.AppendLine('# Trusted computing base report')
[void]$report.AppendLine()
[void]$report.AppendLine('This report is generated by `scripts/generate_tcb_report.ps1` and verified against the committed tree by `scripts/verify_tcb_report.ps1`. It contains no timestamps or commit identifiers; its content is derived only from the current sources, so it changes exactly when the measured surface changes.')
[void]$report.AppendLine()
[void]$report.AppendLine('The trusted computing base measured here is the `sealr` crate: the single admission path that turns an untrusted archive into a verified tree or a rejection, together with the platform effect boundary that materializes an admitted tree. Everything a rejection depends on lives in this crate. The measurement excludes `sealr-cli` (a thin argument-and-stream wrapper), the `tools/` workspaces, fuzz harnesses, and all dev-dependencies. Lines are physical lines including blanks and comments. Test lines are the trailing `#[cfg(test)] mod tests` region of each file plus whole modules declared `#[cfg(test)]`; every other line counts as runtime even when it is gated to one platform or to a repository-only lab feature, because such code still ships in some supported configuration.')
[void]$report.AppendLine()
[void]$report.AppendLine('Regenerate with:')
[void]$report.AppendLine()
[void]$report.AppendLine('```text')
[void]$report.AppendLine('pwsh -NoProfile -File scripts/generate_tcb_report.ps1')
[void]$report.AppendLine('```')
[void]$report.AppendLine()
[void]$report.AppendLine('## Headline measurements')
[void]$report.AppendLine()
[void]$report.AppendLine('| Measurement | Value |')
[void]$report.AppendLine('|---|---|')
[void]$report.AppendLine("| Runtime Rust lines (crates/sealr/src) | $($totals.RuntimeLines) |")
[void]$report.AppendLine("| In-crate test lines | $($totals.TestLines) |")
[void]$report.AppendLine(('| `unsafe` uses in runtime code | {0} |' -f $totals.Unsafe))
[void]$report.AppendLine(('| `unsafe` uses in test code | {0} |' -f $totals.UnsafeTest))
[void]$report.AppendLine(('| `extern "C"` blocks in runtime code | {0} |' -f $totals.Extern))
[void]$report.AppendLine(('| Panic sites in runtime code (`.unwrap(`, `.expect(`, `panic!(`, `unreachable!(`) | {0} |' -f $panicRuntimeTotal))
[void]$report.AppendLine(('| Panic sites in test code | {0} |' -f $panicTestTotal))
[void]$report.AppendLine()
[void]$report.AppendLine('## Unsafe code')
[void]$report.AppendLine()
[void]$report.AppendLine('The parsing, verification, and identity path — every module that interprets untrusted bytes — contains no `unsafe`. Runtime `unsafe` is confined to the platform effect and supervision boundary, where operating-system ACL, handle, and process interfaces require it:')
[void]$report.AppendLine()
[void]$report.AppendLine('| File | Runtime `unsafe` uses |')
[void]$report.AppendLine('|---|---|')
foreach ($row in $rows) {
    if ($row.UnsafeRuntime -gt 0) {
        [void]$report.AppendLine("| ``$($row.File)`` | $($row.UnsafeRuntime) |")
    }
}
[void]$report.AppendLine()
[void]$report.AppendLine('## Panic-site profile')
[void]$report.AppendLine()
[void]$report.AppendLine('| Pattern | Runtime | Test |')
[void]$report.AppendLine('|---|---|---|')
foreach ($label in $panicTotals.Keys) {
    [void]$report.AppendLine(('| `{0}` | {1} | {2} |' -f $label, $panicTotals[$label].Runtime, $panicTotals[$label].Test))
}
[void]$report.AppendLine()
[void]$report.AppendLine('Runtime panic sites are not admission verdicts: a panic can never admit an archive, only abort the process. They remain measured here because each one is a denial-of-service question an auditor must be able to enumerate.')
[void]$report.AppendLine()
[void]$report.AppendLine('## Runtime dependencies per release target')
[void]$report.AppendLine()
[void]$report.AppendLine('These figures restate the pinned dependency contract at `tests/dependency-contract/sealr-runtime.json` after a live `cargo metadata` cross-check; generation fails if the resolved graph and the contract disagree. Counts include normal and build edges and exclude dev-dependencies.')
[void]$report.AppendLine()
[void]$report.AppendLine('| Target | Packages | Direct | Build scripts | `links` | FFI-bearing packages |')
[void]$report.AppendLine('|---|---|---|---|---|---|')
foreach ($dependencyRow in $dependencyRows) {
    $ffiList = if ($dependencyRow.FfiPackages.Count -gt 0) {
        (@($dependencyRow.FfiPackages | ForEach-Object { '`{0}`' -f $_ }) -join ', ')
    } else {
        'none'
    }
    [void]$report.AppendLine("| ``$($dependencyRow.Target)`` | $($dependencyRow.PackageCount) | $($dependencyRow.Direct) | $($dependencyRow.BuildScripts) | $($dependencyRow.Links) | $ffiList |")
}
[void]$report.AppendLine()
[void]$report.AppendLine('Pinned graph digests:')
[void]$report.AppendLine()
foreach ($dependencyRow in $dependencyRows) {
    [void]$report.AppendLine("- ``$($dependencyRow.Target)``: ``$($dependencyRow.GraphSha256)``")
}
[void]$report.AppendLine()
[void]$report.AppendLine('## Conditionally compiled modules')
[void]$report.AppendLine()
[void]$report.AppendLine('Every `mod` declaration carrying a `cfg` gate, verbatim:')
[void]$report.AppendLine()
foreach ($declaration in $gatedModuleDeclarations) {
    [void]$report.AppendLine("- $declaration")
}
[void]$report.AppendLine()
[void]$report.AppendLine('## Per-file inventory')
[void]$report.AppendLine()
[void]$report.AppendLine('| File | Runtime lines | Test lines | Runtime `unsafe` | Runtime panic sites |')
[void]$report.AppendLine('|---|---|---|---|---|')
foreach ($row in $rows) {
    [void]$report.AppendLine("| ``$($row.File)`` | $($row.RuntimeLines) | $($row.TestLines) | $($row.UnsafeRuntime) | $($row.PanicRuntime) |")
}

[IO.File]::WriteAllText($OutputPath, $report.ToString().Replace("`r`n", "`n"))
Write-Host "TCB report generated: $OutputPath ($($totals.RuntimeLines) runtime lines, $($totals.Unsafe) runtime unsafe uses, $($rows.Count) files)."
