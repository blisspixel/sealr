[CmdletBinding()]
param(
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$Workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$OutputRoot = Join-Path $Workspace 'target/readme-walkthrough'
$FixtureRoot = Join-Path $OutputRoot 'fixtures'
$RawRoot = Join-Path $OutputRoot 'raw'
$TranscriptRoot = Join-Path $OutputRoot 'transcripts'
$ToolRoot = Join-Path $OutputRoot 'tools'
$Materialized = Join-Path $OutputRoot 'materialized'
$Blocked = Join-Path $OutputRoot 'blocked'
$Outside = Join-Path $OutputRoot 'outside.txt'

$AllowedDigest = '580606f3b53229ab60ff1d786bac90c91f75c054269c11142cd971f380d3fc25'
$RejectedDigest = '5039cccff40a5df0d0b61a2734b5dafeb8224f914603cae870f1638990f58140'

function Assert-Equal {
    param(
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Expected -ne $Actual) {
        throw "$Label expected '$Expected' but got '$Actual'"
    }
}

function Assert-False {
    param(
        [Parameter(Mandatory)][bool]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Value) {
        throw "$Label must be false"
    }
}

function Reset-ExactDirectory {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $expectedParent = [System.IO.Path]::GetFullPath($OutputRoot).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $actualParent = [System.IO.Path]::GetDirectoryName($fullPath).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    if (-not [string]::Equals($actualParent, $expectedParent, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to reset directory outside the walkthrough root: $fullPath"
    }
    if ([System.IO.File]::Exists($fullPath)) {
        throw "expected a directory path but found a file: $fullPath"
    }
    if ([System.IO.Directory]::Exists($fullPath)) {
        [System.IO.Directory]::Delete($fullPath, $true)
    }
}

function Invoke-Sealr {
    param([Parameter(Mandatory)][string[]]$CliArguments)

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:SealrBinary
    $startInfo.WorkingDirectory = $Workspace
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $CliArguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'sealr failed to start'
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
    $process.Dispose()

    [pscustomobject]@{
        ExitCode = $exitCode
        Stdout = $stdout
        Stderr = $stderr
    }
}

function Write-RawScenario {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Result
    )

    [System.IO.File]::WriteAllText(
        (Join-Path $RawRoot "$Name-view.json"),
        $Result.Stdout,
        $Utf8NoBom
    )
    [System.IO.File]::WriteAllText(
        (Join-Path $RawRoot "$Name-receipt.json"),
        $Result.Stderr,
        $Utf8NoBom
    )
}

function Write-Transcript {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $text = ($Lines -join "`n") + "`n"
    [System.IO.File]::WriteAllText((Join-Path $TranscriptRoot "$Name.txt"), $text, $Utf8NoBom)
}

New-Item -ItemType Directory -Force -Path $OutputRoot, $FixtureRoot, $RawRoot, $TranscriptRoot, $ToolRoot | Out-Null

Push-Location $Workspace
try {
    if (-not $SkipBuild) {
        & cargo build --locked --release -p sealr-cli
        if ($LASTEXITCODE -ne 0) {
            throw "release build failed with exit code $LASTEXITCODE"
        }
    }

    $executableSuffix = if ([System.OperatingSystem]::IsWindows()) { '.exe' } else { '' }
    $script:SealrBinary = Join-Path $Workspace "target/release/sealr$executableSuffix"
    if (-not [System.IO.File]::Exists($script:SealrBinary)) {
        throw "release binary is missing: $script:SealrBinary"
    }

    $fixtureTool = Join-Path $ToolRoot "walkthrough-fixtures$executableSuffix"
    & rustc --edition=2021 scripts/walkthrough_fixtures.rs -o $fixtureTool
    if ($LASTEXITCODE -ne 0) {
        throw "fixture tool build failed with exit code $LASTEXITCODE"
    }
    & $fixtureTool 'target/readme-walkthrough/fixtures'
    if ($LASTEXITCODE -ne 0) {
        throw "fixture generation failed with exit code $LASTEXITCODE"
    }

    $allowedPath = Join-Path $FixtureRoot 'allowed.zip'
    $rejectedPath = Join-Path $FixtureRoot 'rejected-parent-path.zip'
    $allowedHash = (Get-FileHash -LiteralPath $allowedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $rejectedHash = (Get-FileHash -LiteralPath $rejectedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-Equal -Expected $AllowedDigest -Actual $allowedHash -Label 'allowed fixture digest'
    Assert-Equal -Expected $RejectedDigest -Actual $rejectedHash -Label 'rejected fixture digest'

    Reset-ExactDirectory -Path $Materialized
    Reset-ExactDirectory -Path $Blocked
    Assert-False -Value ([System.IO.File]::Exists($Outside)) -Label 'outside file before walkthrough'

    $allowedRelative = 'target/readme-walkthrough/fixtures/allowed.zip'
    $rejectedRelative = 'target/readme-walkthrough/fixtures/rejected-parent-path.zip'
    $materializedRelative = 'target/readme-walkthrough/materialized'
    $blockedRelative = 'target/readme-walkthrough/blocked'
    $displayBinary = "target/release/sealr$executableSuffix"
    $displayPrompt = if ([System.OperatingSystem]::IsWindows()) { 'PS>' } else { '$' }
    $displayContinuation = if ([System.OperatingSystem]::IsWindows()) { '`' } else { '\' }
    $continuationPrompt = if ([System.OperatingSystem]::IsWindows()) { '>>' } else { '>' }

    $inspect = Invoke-Sealr -CliArguments ([string[]]@($allowedRelative))
    Write-RawScenario -Name 'inspect' -Result $inspect
    Assert-Equal -Expected 0 -Actual $inspect.ExitCode -Label 'inspect exit code'
    $inspectView = $inspect.Stdout | ConvertFrom-Json
    $inspectReceipt = $inspect.Stderr | ConvertFrom-Json
    Assert-Equal -Expected 'allowed' -Actual $inspectView.verdict -Label 'inspect verdict'
    Assert-Equal -Expected $false -Actual $inspectView.wrote -Label 'inspect wrote'
    Assert-Equal -Expected 2 -Actual @($inspectView.members).Count -Label 'inspect member count'
    Assert-Equal -Expected $AllowedDigest -Actual $inspectReceipt.source.sha256 -Label 'inspect source digest'
    Assert-False -Value ([System.IO.Directory]::Exists($Materialized)) -Label 'inspect destination'

    $reject = Invoke-Sealr -CliArguments ([string[]]@($rejectedRelative, '--dest', $blockedRelative))
    Write-RawScenario -Name 'reject' -Result $reject
    Assert-Equal -Expected 2 -Actual $reject.ExitCode -Label 'reject exit code'
    $rejectView = $reject.Stdout | ConvertFrom-Json
    $rejectReceipt = $reject.Stderr | ConvertFrom-Json
    Assert-Equal -Expected 'rejected' -Actual $rejectView.verdict -Label 'reject verdict'
    Assert-Equal -Expected $false -Actual $rejectView.wrote -Label 'reject wrote'
    Assert-Equal -Expected 1 -Actual @($rejectView.findings).Count -Label 'reject finding count'
    Assert-Equal -Expected 'path.dotdot' -Actual $rejectView.findings[0].code -Label 'reject finding code'
    Assert-Equal -Expected '../outside.txt' -Actual $rejectView.findings[0].member -Label 'reject member'
    Assert-Equal -Expected $RejectedDigest -Actual $rejectReceipt.source.sha256 -Label 'reject source digest'
    Assert-False -Value ([System.IO.Directory]::Exists($Blocked)) -Label 'blocked destination'
    Assert-False -Value ([System.IO.File]::Exists($Outside)) -Label 'outside file after rejection'

    $materialize = Invoke-Sealr -CliArguments ([string[]]@($allowedRelative, '--dest', $materializedRelative))
    Write-RawScenario -Name 'materialize' -Result $materialize
    Assert-Equal -Expected 0 -Actual $materialize.ExitCode -Label 'materialize exit code'
    $materializedView = $materialize.Stdout | ConvertFrom-Json
    $materializedReceipt = $materialize.Stderr | ConvertFrom-Json
    Assert-Equal -Expected 'allowed' -Actual $materializedView.verdict -Label 'materialize verdict'
    Assert-Equal -Expected $true -Actual $materializedView.wrote -Label 'materialize wrote'
    Assert-Equal -Expected $AllowedDigest -Actual $materializedReceipt.source.sha256 -Label 'materialize source digest'
    Assert-Equal -Expected ($inspectView.members | ConvertTo-Json -Compress) -Actual ($materializedView.members | ConvertTo-Json -Compress) -Label 'inspect and materialize members'
    Assert-Equal -Expected '{"safe":true}' -Actual ([System.IO.File]::ReadAllText((Join-Path $Materialized 'bundle/config.json')).TrimEnd("`r", "`n")) -Label 'materialized config'
    Assert-Equal -Expected 'hello from sealr' -Actual ([System.IO.File]::ReadAllText((Join-Path $Materialized 'bundle/hello.txt')).TrimEnd("`r", "`n")) -Label 'materialized hello'

    $stages = @(Get-ChildItem -LiteralPath $OutputRoot -Directory -Filter '.sealr-stage-*')
    Assert-Equal -Expected 0 -Actual $stages.Count -Label 'stale stage count'

    $inspectLines = @(
        "$displayPrompt $displayBinary $allowedRelative",
        "exit: $($inspect.ExitCode)",
        "verdict: $($inspectView.verdict)",
        "wrote: $($inspectView.wrote.ToString().ToLowerInvariant())",
        'members:'
    )
    foreach ($member in $inspectView.members) {
        $inspectLines += "  $($member.path)  $($member.method)  $($member.uncomp_bytes) bytes  sha256 $($member.sha256.Substring(0, 16))..."
    }
    $inspectLines += @(
        'receipt:',
        "  source sha256: $($inspectReceipt.source.sha256)",
        "  policy sha256: $($inspectReceipt.policy.digest.sha256)",
        "  view sha256:   $($inspectReceipt.view_digest.sha256)",
        "  signed: $($inspectReceipt.signed.ToString().ToLowerInvariant())"
    )
    Write-Transcript -Name '01-inspect-allowed' -Lines $inspectLines

    $rejectLines = @(
        "$displayPrompt $displayBinary $rejectedRelative $displayContinuation",
        "$continuationPrompt  --dest $blockedRelative",
        "exit: $($reject.ExitCode)",
        "verdict: $($rejectView.verdict)",
        "wrote: $($rejectView.wrote.ToString().ToLowerInvariant())",
        'finding:',
        "  $($rejectView.findings[0].code) | $($rejectView.findings[0].severity) | $($rejectView.findings[0].member)",
        "  $($rejectView.findings[0].detail)",
        "destination exists: $([System.IO.Directory]::Exists($Blocked).ToString().ToLowerInvariant())",
        "outside file exists: $([System.IO.File]::Exists($Outside).ToString().ToLowerInvariant())"
    )
    Write-Transcript -Name '02-reject-parent-path' -Lines $rejectLines

    $materializeLines = @(
        "$displayPrompt $displayBinary $allowedRelative $displayContinuation",
        "$continuationPrompt  --dest $materializedRelative",
        "exit: $($materialize.ExitCode)",
        "verdict: $($materializedView.verdict)",
        "wrote: $($materializedView.wrote.ToString().ToLowerInvariant())",
        'files:'
    )
    foreach ($member in $materializedView.members) {
        $fileExists = [System.IO.File]::Exists((Join-Path $Materialized $member.path))
        $materializeLines += "  $($member.path)  $($member.uncomp_bytes) bytes  exists $($fileExists.ToString().ToLowerInvariant())"
    }
    $materializeLines += "receipt view sha256: $($materializedReceipt.view_digest.sha256)"
    Write-Transcript -Name '03-materialize-allowed' -Lines $materializeLines

    $manifest = [ordered]@{
        schema = 'sealr.walkthrough.v1'
        tool_version = [string]$inspectReceipt.tool.version
        fixtures = [ordered]@{
            allowed = [ordered]@{ path = $allowedRelative; sha256 = $AllowedDigest }
            rejected = [ordered]@{ path = $rejectedRelative; sha256 = $RejectedDigest }
        }
        scenarios = [ordered]@{
            inspect = [ordered]@{ exit = 0; verdict = 'allowed'; wrote = $false; members = 2 }
            reject = [ordered]@{ exit = 2; verdict = 'rejected'; wrote = $false; finding = 'path.dotdot' }
            materialize = [ordered]@{ exit = 0; verdict = 'allowed'; wrote = $true; members = 2 }
        }
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $OutputRoot 'manifest.json'),
        (($manifest | ConvertTo-Json -Depth 8) + "`n"),
        $Utf8NoBom
    )

    Write-Host "walkthrough verified: $OutputRoot"
    Write-Host "transcripts: $TranscriptRoot"
}
finally {
    Pop-Location
}
