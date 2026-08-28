[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Publish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repository = 'blisspixel/sealr'
$DefaultBranch = 'main'
$Version = '0.1.0-alpha.11'
$ReleaseTag = "v$Version"
$ReleaseTitle = "sealr ${Version}: restricted POSIX PAX"
$CiWorkflow = '.github/workflows/ci.yml'
$ReleaseWorkflow = '.github/workflows/release.yml'
$GithubActionsAppId = 15368
$ReleaseNotesRelativePath = "docs/releases/$ReleaseTag.md"
$ApiVersion = '2026-03-10'
$FuzzWorkflow = '.github/workflows/fuzz.yml'
$ExpectedFuzzJobs = @(
    'Bounded worker protocol'
    'Bounded semantic records'
    'Bounded raw POSIX ustar'
    'Bounded raw POSIX PAX'
    'Bounded raw GNU long-name TAR'
    'Bounded RFC 1952 gzip'
    'Bounded public TAR gzip ustar'
    'Bounded strict ZIP64'
    'Bounded gzip-wrapped restricted PAX TAR'
    'Bounded gzip-wrapped GNU long-name TAR'
    'Bounded zstd-wrapped portable ustar TAR'
    'Bounded xz-wrapped portable ustar TAR'
)
$ExpectedCiJobs = @(
    'Format, lint, test, and docs'
    'Test on windows-2022'
    'Test on macos-15'
    'ZipDiff 14-class gate'
    'Supply chain'
    'Real-kernel Landlock ABI 2 floor'
)
$ExpectedChecks = @('Required CI')
$ExpectedReleaseJobs = @(
    'Validate release tag'
    'Build and test on ubuntu-24.04'
    'Build and test on windows-2022'
    'Build and test on macos-15'
    'Attest and stage prerelease draft'
)
$Workspace = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$TemporaryRoot = $null

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [switch]$AllowFailure
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.WorkingDirectory = $PWD.Path
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        Assert-True -Condition $process.Start() -Message "could not start $FilePath"
        $standardOutputTask = $process.StandardOutput.ReadToEndAsync()
        $standardErrorTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $standardOutput = $standardOutputTask.GetAwaiter().GetResult()
        $standardError = $standardErrorTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
    }
    finally {
        $process.Dispose()
    }

    if (-not $AllowFailure -and $exitCode -ne 0) {
        throw "$FilePath failed with exit code $exitCode`nstdout:`n$standardOutput`nstderr:`n$standardError"
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        Text = $standardOutput
        StandardError = $standardError
    }
}

function Invoke-GhApiJson {
    param([Parameter(Mandatory)][string[]]$ApiArguments)

    $arguments = @(
        'api'
        '-H'
        'Accept: application/vnd.github+json'
        '-H'
        "X-GitHub-Api-Version: $ApiVersion"
    ) + $ApiArguments
    $result = Invoke-NativeCommand -FilePath 'gh' -Arguments $arguments
    if ([string]::IsNullOrWhiteSpace($result.Text)) {
        throw "GitHub API returned an empty response for: $($ApiArguments -join ' ')"
    }
    $result.Text | ConvertFrom-Json -Depth 100
}

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Equal {
    param(
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Expected -ne $Actual) {
        throw "$Label expected '$Expected' but got '$Actual'"
    }
}

function Assert-ExactSet {
    param(
        [Parameter(Mandatory)][string[]]$Expected,
        [Parameter(Mandatory)][string[]]$Actual,
        [Parameter(Mandatory)][string]$Label
    )

    $expectedSorted = @($Expected | Sort-Object -Unique)
    $actualSorted = @($Actual | Sort-Object -Unique)
    $difference = @(Compare-Object -ReferenceObject $expectedSorted -DifferenceObject $actualSorted)
    if ($difference.Count -ne 0 -or $expectedSorted.Count -ne $actualSorted.Count) {
        throw "$Label differs from the expected set. Expected: $($expectedSorted -join ', '). Actual: $($actualSorted -join ', ')"
    }
}

function Normalize-ReleaseText {
    param([AllowNull()][string]$Text)

    if ($null -eq $Text) {
        return ''
    }
    return ($Text -replace "`r`n", "`n").TrimEnd("`r", "`n") + "`n"
}

function Get-RemoteMainCommit {
    $reference = Invoke-GhApiJson -ApiArguments @("repos/$Repository/git/ref/heads/$DefaultBranch")
    Assert-Equal -Expected 'commit' -Actual ([string]$reference.object.type) -Label 'remote main object type'
    return ([string]$reference.object.sha).ToLowerInvariant()
}

function Get-RemoteTagCommit {
    $encodedTag = [System.Uri]::EscapeDataString($ReleaseTag)
    $reference = Invoke-GhApiJson -ApiArguments @("repos/$Repository/git/ref/tags/$encodedTag")
    $objectType = [string]$reference.object.type
    $objectSha = ([string]$reference.object.sha).ToLowerInvariant()
    Assert-Equal -Expected 'tag' -Actual $objectType -Label 'release tag object type'

    for ($depth = 0; $depth -lt 4; $depth++) {
        if ($objectType -eq 'commit') {
            return $objectSha
        }
        if ($objectType -ne 'tag') {
            throw "release tag resolves to unsupported Git object type '$objectType'"
        }
        $tagObject = Invoke-GhApiJson -ApiArguments @("repos/$Repository/git/tags/$objectSha")
        $objectType = [string]$tagObject.object.type
        $objectSha = ([string]$tagObject.object.sha).ToLowerInvariant()
    }

    throw 'release tag indirection exceeds the allowed depth'
}

function Assert-LocalReleaseSource {
    $rootResult = Invoke-NativeCommand -FilePath 'git' -Arguments @('rev-parse', '--show-toplevel')
    $resolvedRoot = [System.IO.Path]::GetFullPath($rootResult.Text.Trim())
    Assert-True -Condition ([string]::Equals($Workspace, $resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) -Message "script must run from the sealr checkout at $Workspace"

    $status = Invoke-NativeCommand -FilePath 'git' -Arguments @('status', '--porcelain=v1', '--untracked-files=all')
    Assert-True -Condition ([string]::IsNullOrWhiteSpace($status.Text)) -Message 'release promotion requires a clean worktree'

    $branch = (Invoke-NativeCommand -FilePath 'git' -Arguments @('branch', '--show-current')).Text.Trim()
    Assert-Equal -Expected $DefaultBranch -Actual $branch -Label 'local branch'

    $localCommit = (Invoke-NativeCommand -FilePath 'git' -Arguments @('rev-parse', 'HEAD')).Text.Trim().ToLowerInvariant()
    $remoteMain = Get-RemoteMainCommit
    $remoteTag = Get-RemoteTagCommit
    Assert-Equal -Expected $remoteMain -Actual $localCommit -Label 'local HEAD versus remote main'
    Assert-Equal -Expected $remoteMain -Actual $remoteTag -Label 'release tag versus remote main'

    $metadataText = (Invoke-NativeCommand -FilePath 'cargo' -Arguments @('metadata', '--locked', '--no-deps', '--format-version', '1')).Text
    $metadata = $metadataText | ConvertFrom-Json -Depth 100
    $versions = @($metadata.packages | ForEach-Object { [string]$_.version } | Sort-Object -Unique)
    Assert-Equal -Expected 1 -Actual $versions.Count -Label 'workspace version count'
    Assert-Equal -Expected $Version -Actual $versions[0] -Label 'workspace version'

    $notesPath = Join-Path $Workspace $ReleaseNotesRelativePath
    Assert-True -Condition ([System.IO.File]::Exists($notesPath)) -Message "release notes are missing: $notesPath"

    [pscustomobject]@{
        Commit = $localCommit
        Notes = [System.IO.File]::ReadAllText($notesPath, [System.Text.Encoding]::UTF8)
    }
}

function Get-BranchProtection {
    Invoke-GhApiJson -ApiArguments @("repos/$Repository/branches/$DefaultBranch/protection")
}

function Assert-BranchProtection {
    param([Parameter(Mandatory)]$Protection)

    Assert-True -Condition ($null -ne $Protection.required_status_checks) -Message 'main must require status checks'
    Assert-True -Condition ([bool]$Protection.required_status_checks.strict) -Message 'main required status checks must use strict mode'
    Assert-True -Condition ($null -ne $Protection.enforce_admins -and [bool]$Protection.enforce_admins.enabled) -Message 'main protection must apply to administrators'
    Assert-True -Condition ($null -ne $Protection.required_pull_request_reviews) -Message 'main must require pull requests'
    Assert-True -Condition ($null -ne $Protection.required_linear_history -and [bool]$Protection.required_linear_history.enabled) -Message 'main must require linear history'
    Assert-True -Condition ($null -ne $Protection.required_conversation_resolution -and [bool]$Protection.required_conversation_resolution.enabled) -Message 'main must require conversation resolution'
    Assert-True -Condition ($null -ne $Protection.allow_force_pushes -and -not [bool]$Protection.allow_force_pushes.enabled) -Message 'main must forbid force pushes'
    Assert-True -Condition ($null -ne $Protection.allow_deletions -and -not [bool]$Protection.allow_deletions.enabled) -Message 'main must forbid deletion'

    $checks = @($Protection.required_status_checks.checks)
    Assert-Equal -Expected $ExpectedChecks.Count -Actual $checks.Count -Label 'required status check count'
    Assert-ExactSet -Expected $ExpectedChecks -Actual @($checks | ForEach-Object { [string]$_.context }) -Label 'required status checks'
    foreach ($check in $checks) {
        Assert-Equal -Expected $GithubActionsAppId -Actual ([int64]$check.app_id) -Label "required check app for $($check.context)"
    }

    return $checks
}

function Get-WorkflowRuns {
    param(
        [Parameter(Mandatory)][string]$Workflow,
        [Parameter(Mandatory)][string]$Commit,
        [string]$Event = 'push'
    )

    $workflowFileName = [System.IO.Path]::GetFileName($Workflow)
    $encodedWorkflow = [System.Uri]::EscapeDataString($workflowFileName)
    $response = Invoke-GhApiJson -ApiArguments @(
        '--method', 'GET',
        "repos/$Repository/actions/workflows/$encodedWorkflow/runs",
        '-f', "head_sha=$Commit",
        '-f', "event=$Event",
        '-f', 'per_page=20'
    )
    return @($response.workflow_runs)
}

function Get-ExactFuzzState {
    param([Parameter(Mandatory)][string]$Commit)

    $matches = @(
        Get-WorkflowRuns -Workflow $FuzzWorkflow -Commit $Commit -Event 'workflow_dispatch' |
            Where-Object {
                ([string]$_.head_sha).ToLowerInvariant() -eq $Commit -and
                [string]$_.head_branch -eq $DefaultBranch -and
                [string]$_.event -eq 'workflow_dispatch' -and
                (([string]$_.path -split '@')[0]) -eq $FuzzWorkflow
            } |
            Sort-Object @{ Expression = { [System.DateTimeOffset]$_.run_started_at } }, @{ Expression = { [int]$_.run_attempt } }, @{ Expression = { [int64]$_.id } }
    )
    Assert-True -Condition ($matches.Count -gt 0) -Message 'no exact on-demand fuzz run exists for the release commit'
    $run = $matches[-1]
    Assert-Equal -Expected 'completed' -Actual ([string]$run.status) -Label 'on-demand fuzz workflow status'
    Assert-Equal -Expected 'success' -Actual ([string]$run.conclusion) -Label 'on-demand fuzz workflow conclusion'

    $jobsResponse = Invoke-GhApiJson -ApiArguments @(
        '--method', 'GET',
        "repos/$Repository/actions/runs/$($run.id)/attempts/$($run.run_attempt)/jobs",
        '-f', 'per_page=100'
    )
    foreach ($expectedFuzzJob in $ExpectedFuzzJobs) {
        $jobs = @($jobsResponse.jobs | Where-Object { [string]$_.name -eq $expectedFuzzJob })
        Assert-Equal -Expected 1 -Actual $jobs.Count -Label "on-demand fuzz job count for $expectedFuzzJob"
        Assert-Equal -Expected 'completed' -Actual ([string]$jobs[0].status) -Label "on-demand fuzz job status for $expectedFuzzJob"
        Assert-Equal -Expected 'success' -Actual ([string]$jobs[0].conclusion) -Label "on-demand fuzz job conclusion for $expectedFuzzJob"
        Assert-Equal -Expected $Commit -Actual (([string]$jobs[0].head_sha).ToLowerInvariant()) -Label "on-demand fuzz job commit for $expectedFuzzJob"
    }

    [pscustomobject]@{
        Id = [int64]$run.id
        Attempt = [int]$run.run_attempt
        Url = [string]$run.html_url
    }
}

function Get-ExactCiState {
    param(
        [Parameter(Mandatory)][string]$Commit,
        [Parameter(Mandatory)]$RequiredChecks,
        [switch]$Wait
    )

    $deadline = if ($Wait) { [System.DateTimeOffset]::UtcNow.AddMinutes(30) } else { [System.DateTimeOffset]::UtcNow }
    $run = $null
    while ($true) {
        $matches = @(
            Get-WorkflowRuns -Workflow $CiWorkflow -Commit $Commit |
                Where-Object {
                    ([string]$_.head_sha).ToLowerInvariant() -eq $Commit -and
                    [string]$_.head_branch -eq $DefaultBranch -and
                    [string]$_.event -eq 'push' -and
                    (([string]$_.path -split '@')[0]) -eq $CiWorkflow
                } |
                Sort-Object @{ Expression = { [System.DateTimeOffset]$_.run_started_at } }, @{ Expression = { [int]$_.run_attempt } }, @{ Expression = { [int64]$_.id } }
        )
        if ($matches.Count -gt 0) {
            $run = $matches[-1]
            if ([string]$run.status -eq 'completed') {
                Assert-Equal -Expected 'success' -Actual ([string]$run.conclusion) -Label 'exact main CI conclusion'
                break
            }
        }
        if (-not $Wait -or [System.DateTimeOffset]::UtcNow -ge $deadline) {
            throw "exact main CI did not complete successfully for $Commit"
        }
        Start-Sleep -Seconds 10
    }

    $jobsResponse = Invoke-GhApiJson -ApiArguments @(
        '--method', 'GET',
        "repos/$Repository/actions/runs/$($run.id)/attempts/$($run.run_attempt)/jobs",
        '-f', 'per_page=100'
    )
    $jobs = @($jobsResponse.jobs)
    foreach ($expectedJob in $ExpectedCiJobs) {
        $matchingJobs = @($jobs | Where-Object { [string]$_.name -eq $expectedJob })
        Assert-Equal -Expected 1 -Actual $matchingJobs.Count -Label "CI job count for $expectedJob"
        Assert-Equal -Expected 'completed' -Actual ([string]$matchingJobs[0].status) -Label "CI job status for $expectedJob"
        Assert-Equal -Expected 'success' -Actual ([string]$matchingJobs[0].conclusion) -Label "CI job conclusion for $expectedJob"
        Assert-Equal -Expected $Commit -Actual (([string]$matchingJobs[0].head_sha).ToLowerInvariant()) -Label "CI job commit for $expectedJob"
    }

    foreach ($requiredCheck in @($RequiredChecks)) {
        $response = Invoke-GhApiJson -ApiArguments @(
            '--method', 'GET',
            "repos/$Repository/commits/$Commit/check-runs",
            '-f', "check_name=$($requiredCheck.context)",
            '-f', "app_id=$($requiredCheck.app_id)",
            '-f', 'filter=latest',
            '-f', 'per_page=100'
        )
        $runs = @(
            $response.check_runs |
                Where-Object {
                    [string]$_.name -eq [string]$requiredCheck.context -and
                    [int64]$_.app.id -eq [int64]$requiredCheck.app_id -and
                    ([string]$_.head_sha).ToLowerInvariant() -eq $Commit
                } |
                Sort-Object @{ Expression = { [System.DateTimeOffset]$_.started_at } }, @{ Expression = { [int64]$_.id } }
        )
        Assert-True -Condition ($runs.Count -gt 0) -Message "required check is missing for the exact commit: $($requiredCheck.context)"
        $latest = $runs[-1]
        Assert-Equal -Expected 'completed' -Actual ([string]$latest.status) -Label "required check status for $($requiredCheck.context)"
        Assert-Equal -Expected 'success' -Actual ([string]$latest.conclusion) -Label "required check conclusion for $($requiredCheck.context)"
    }

    [pscustomobject]@{
        Id = [int64]$run.id
        Attempt = [int]$run.run_attempt
        Url = [string]$run.html_url
    }
}

function Get-ExactReleaseWorkflowState {
    param([Parameter(Mandatory)][string]$Commit)

    $matches = @(
        Get-WorkflowRuns -Workflow $ReleaseWorkflow -Commit $Commit |
            Where-Object {
                ([string]$_.head_sha).ToLowerInvariant() -eq $Commit -and
                [string]$_.head_branch -eq $ReleaseTag -and
                [string]$_.event -eq 'push' -and
                (([string]$_.path -split '@')[0]) -eq $ReleaseWorkflow
            } |
            Sort-Object @{ Expression = { [System.DateTimeOffset]$_.run_started_at } }, @{ Expression = { [int]$_.run_attempt } }, @{ Expression = { [int64]$_.id } }
    )
    Assert-True -Condition ($matches.Count -gt 0) -Message 'no exact release workflow run exists for the release tag and commit'
    $run = $matches[-1]
    Assert-Equal -Expected 'completed' -Actual ([string]$run.status) -Label 'release workflow status'
    Assert-Equal -Expected 'success' -Actual ([string]$run.conclusion) -Label 'release workflow conclusion'

    $jobsResponse = Invoke-GhApiJson -ApiArguments @(
        '--method', 'GET',
        "repos/$Repository/actions/runs/$($run.id)/attempts/$($run.run_attempt)/jobs",
        '-f', 'per_page=100'
    )
    $jobs = @($jobsResponse.jobs)
    Assert-ExactSet -Expected $ExpectedReleaseJobs -Actual @($jobs | ForEach-Object { [string]$_.name }) -Label 'release workflow jobs'
    foreach ($job in $jobs) {
        Assert-Equal -Expected 'completed' -Actual ([string]$job.status) -Label "release workflow job status for $($job.name)"
        Assert-Equal -Expected 'success' -Actual ([string]$job.conclusion) -Label "release workflow job conclusion for $($job.name)"
        Assert-Equal -Expected $Commit -Actual (([string]$job.head_sha).ToLowerInvariant()) -Label "release workflow job commit for $($job.name)"
    }

    [pscustomobject]@{
        Id = [int64]$run.id
        Attempt = [int]$run.run_attempt
        Url = [string]$run.html_url
    }
}

function Assert-ImmutableReleaseSetting {
    $settings = Invoke-GhApiJson -ApiArguments @("repos/$Repository/immutable-releases")
    Assert-True -Condition ([bool]$settings.enabled) -Message 'GitHub release immutability must be enabled before promotion'
    return $settings
}

function Get-ReleaseById {
    param([Parameter(Mandatory)][int64]$ReleaseId)

    Assert-True -Condition ($ReleaseId -gt 0) -Message 'release ID must be positive'
    $release = Invoke-GhApiJson -ApiArguments @(
        '--method', 'GET',
        "repos/$Repository/releases/$ReleaseId"
    )
    Assert-Equal -Expected $ReleaseId -Actual ([int64]$release.id) -Label 'numeric release ID'
    Assert-Equal -Expected $ReleaseTag -Actual ([string]$release.tag_name) -Label 'numeric release tag'
    return $release
}

function Get-ExactReleaseForTag {
    param([int64]$ExpectedReleaseId = 0)

    $arguments = @(
        'api'
        '-H'
        'Accept: application/vnd.github+json'
        '-H'
        "X-GitHub-Api-Version: $ApiVersion"
        '--method'
        'GET'
        '--paginate'
        '--slurp'
        "repos/$Repository/releases?per_page=100"
    )
    $result = Invoke-NativeCommand -FilePath 'gh' -Arguments $arguments
    Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($result.Text)) -Message 'GitHub release list returned an empty response'
    $pages = ConvertFrom-Json -InputObject $result.Text -Depth 100 -NoEnumerate
    Assert-True -Condition ($pages -is [System.Array]) -Message 'paginated release response must be an array of pages'

    $matches = @(
        foreach ($page in $pages) {
            Assert-True -Condition ($page -is [System.Array]) -Message 'each paginated release page must be an array'
            foreach ($candidate in $page) {
                if ([string]$candidate.tag_name -eq $ReleaseTag) {
                    $candidate
                }
            }
        }
    )
    Assert-Equal -Expected 1 -Actual $matches.Count -Label "release count for $ReleaseTag"
    $releaseId = [int64]$matches[0].id
    Assert-True -Condition ($releaseId -gt 0) -Message 'discovered release ID must be positive'
    if ($ExpectedReleaseId -gt 0) {
        Assert-Equal -Expected $ExpectedReleaseId -Actual $releaseId -Label 'pinned release ID'
    }
    return Get-ReleaseById -ReleaseId $releaseId
}

function Get-ArchiveAssetNames {
    param([Parameter(Mandatory)]$Release)

    $assetNames = @($Release.assets | ForEach-Object { [string]$_.name })
    $archiveNames = @($assetNames | Where-Object { $_ -ne 'SHA256SUMS' })
    $expectedArchiveNames = @(
        "sealr-$Version-aarch64-apple-darwin.tar.gz"
        "sealr-$Version-x86_64-pc-windows-msvc.zip"
        "sealr-$Version-x86_64-unknown-linux-gnu.tar.gz"
    )
    Assert-ExactSet -Expected $expectedArchiveNames -Actual $archiveNames -Label 'native archives'
    foreach ($name in $archiveNames) {
        Assert-True -Condition (-not $name.Contains('..') -and [System.IO.Path]::GetFileName($name) -eq $name) -Message "unsafe native archive name: $name"
    }
    return $archiveNames
}

function Assert-ReleaseContract {
    param(
        [Parameter(Mandatory)]$Release,
        [Parameter(Mandatory)][string]$ExpectedNotes,
        [Parameter(Mandatory)][ValidateSet('draft', 'published')][string]$State
    )

    Assert-Equal -Expected $ReleaseTag -Actual ([string]$Release.tag_name) -Label 'release tag'
    Assert-Equal -Expected $ReleaseTitle -Actual ([string]$Release.name) -Label 'release title'
    Assert-True -Condition ([bool]$Release.prerelease) -Message 'release must remain a prerelease'
    Assert-Equal -Expected (Normalize-ReleaseText -Text $ExpectedNotes) -Actual (Normalize-ReleaseText -Text ([string]$Release.body)) -Label 'release notes'
    Assert-Equal -Expected 'github-actions[bot]' -Actual ([string]$Release.author.login) -Label 'release author'
    Assert-True -Condition ([int64]$Release.id -gt 0) -Message 'release ID must be positive'

    if ($State -eq 'draft') {
        Assert-True -Condition ([bool]$Release.draft) -Message 'release must be a draft before promotion'
        Assert-True -Condition (-not [bool]$Release.immutable) -Message 'a draft release must not claim to be immutable'
    } else {
        Assert-True -Condition (-not [bool]$Release.draft) -Message 'published release must not be a draft'
        Assert-True -Condition ([bool]$Release.immutable) -Message 'published release must be immutable'
        Assert-True -Condition ($null -ne $Release.published_at -and -not [string]::IsNullOrWhiteSpace([string]$Release.published_at)) -Message 'published release must have a publication time'
    }

    $assets = @($Release.assets)
    Assert-Equal -Expected 4 -Actual $assets.Count -Label 'release asset count'
    Assert-ExactSet -Expected (@('SHA256SUMS') + @(Get-ArchiveAssetNames -Release $Release)) -Actual @($assets | ForEach-Object { [string]$_.name }) -Label 'release assets'
    Assert-Equal -Expected $assets.Count -Actual @($assets | ForEach-Object { [int64]$_.id } | Sort-Object -Unique).Count -Label 'unique release asset IDs'

    foreach ($asset in $assets) {
        $name = [string]$asset.name
        Assert-Equal -Expected 'uploaded' -Actual ([string]$asset.state) -Label "asset state for $name"
        Assert-Equal -Expected 'github-actions[bot]' -Actual ([string]$asset.uploader.login) -Label "asset uploader for $name"
        Assert-True -Condition ([int64]$asset.size -gt 0) -Message "release asset is empty: $name"
        Assert-True -Condition ([string]$asset.digest -match '^sha256:[0-9a-f]{64}$') -Message "release asset has no valid SHA-256 API digest: $name"
        if ($name -eq 'SHA256SUMS') {
            Assert-True -Condition ([int64]$asset.size -le 64KB) -Message 'SHA256SUMS exceeds the allowed size'
        } else {
            Assert-True -Condition ([int64]$asset.size -le 128MB) -Message "release archive exceeds the allowed size: $name"
        }
    }
}

function New-ReleaseSnapshot {
    param([Parameter(Mandatory)]$Release)

    $assets = [ordered]@{}
    foreach ($asset in @($Release.assets)) {
        $assets[[string]$asset.name] = [pscustomobject]@{
            Id = [int64]$asset.id
            Size = [int64]$asset.size
            Digest = [string]$asset.digest
            State = [string]$asset.state
            Uploader = [string]$asset.uploader.login
            CreatedAt = [string]$asset.created_at
            UpdatedAt = [string]$asset.updated_at
        }
    }

    [pscustomobject]@{
        ReleaseId = [int64]$Release.id
        Tag = [string]$Release.tag_name
        Title = [string]$Release.name
        Body = Normalize-ReleaseText -Text ([string]$Release.body)
        Assets = $assets
    }
}

function Assert-ReleaseMatchesSnapshot {
    param(
        [Parameter(Mandatory)]$Release,
        [Parameter(Mandatory)]$Snapshot
    )

    Assert-Equal -Expected $Snapshot.ReleaseId -Actual ([int64]$Release.id) -Label 'release ID snapshot'
    Assert-Equal -Expected $Snapshot.Tag -Actual ([string]$Release.tag_name) -Label 'release tag snapshot'
    Assert-Equal -Expected $Snapshot.Title -Actual ([string]$Release.name) -Label 'release title snapshot'
    Assert-Equal -Expected $Snapshot.Body -Actual (Normalize-ReleaseText -Text ([string]$Release.body)) -Label 'release body snapshot'
    Assert-ExactSet -Expected @($Snapshot.Assets.Keys) -Actual @($Release.assets | ForEach-Object { [string]$_.name }) -Label 'release asset snapshot'

    foreach ($asset in @($Release.assets)) {
        $expected = $Snapshot.Assets[[string]$asset.name]
        Assert-Equal -Expected $expected.Id -Actual ([int64]$asset.id) -Label "asset ID snapshot for $($asset.name)"
        Assert-Equal -Expected $expected.Size -Actual ([int64]$asset.size) -Label "asset size snapshot for $($asset.name)"
        Assert-Equal -Expected $expected.Digest -Actual ([string]$asset.digest) -Label "asset digest snapshot for $($asset.name)"
        Assert-Equal -Expected $expected.State -Actual ([string]$asset.state) -Label "asset state snapshot for $($asset.name)"
        Assert-Equal -Expected $expected.Uploader -Actual ([string]$asset.uploader.login) -Label "asset uploader snapshot for $($asset.name)"
        Assert-Equal -Expected $expected.CreatedAt -Actual ([string]$asset.created_at) -Label "asset creation snapshot for $($asset.name)"
        Assert-Equal -Expected $expected.UpdatedAt -Actual ([string]$asset.updated_at) -Label "asset update snapshot for $($asset.name)"
    }
}

function New-ExactTemporaryRoot {
    $systemTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $path = Join-Path $systemTemp "sealr-release-promotion-$([System.Guid]::NewGuid().ToString('N'))"
    [System.IO.Directory]::CreateDirectory($path) | Out-Null
    return [System.IO.Path]::GetFullPath($path)
}

function Remove-ExactTemporaryRoot {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $systemTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $parent = [System.IO.Path]::GetDirectoryName($fullPath).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $leaf = [System.IO.Path]::GetFileName($fullPath)
    Assert-True -Condition ([string]::Equals($parent, $systemTemp, [System.StringComparison]::OrdinalIgnoreCase)) -Message "refusing to remove a temporary path outside the system temporary directory: $fullPath"
    Assert-True -Condition ($leaf -match '^sealr-release-promotion-[0-9a-f]{32}$') -Message "refusing to remove an unexpected temporary path: $fullPath"
    if ([System.IO.Directory]::Exists($fullPath)) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
}

function Download-VerifiedAssetSet {
    param(
        [Parameter(Mandatory)]$Release,
        [Parameter(Mandatory)][string]$Destination
    )

    $expectedNames = @($Release.assets | ForEach-Object { [string]$_.name } | Sort-Object)
    foreach ($name in $expectedNames) {
        Invoke-NativeCommand -FilePath 'gh' -Arguments @(
            'release', 'download', $ReleaseTag,
            '--repo', $Repository,
            '--dir', $Destination,
            '--pattern', $name
        ) | Out-Null
    }

    $downloadedFiles = @(Get-ChildItem -LiteralPath $Destination -File)
    Assert-ExactSet -Expected $expectedNames -Actual @($downloadedFiles | ForEach-Object { $_.Name }) -Label 'downloaded release assets'
    Assert-Equal -Expected 0 -Actual @(Get-ChildItem -LiteralPath $Destination -Directory).Count -Label 'downloaded release asset directory count'

    $checksumPath = Join-Path $Destination 'SHA256SUMS'
    $checksumLines = @([System.IO.File]::ReadAllLines($checksumPath) | Where-Object { $_.Length -gt 0 })
    Assert-Equal -Expected 3 -Actual $checksumLines.Count -Label 'SHA256SUMS record count'
    $checksums = [ordered]@{}
    foreach ($line in $checksumLines) {
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9_.-]+)$') {
            throw "SHA256SUMS contains an invalid record: $line"
        }
        $digest = $Matches[1]
        $name = $Matches[2]
        Assert-True -Condition (-not $checksums.Contains($name)) -Message "SHA256SUMS contains a duplicate filename: $name"
        Assert-True -Condition (-not $name.Contains('..') -and [System.IO.Path]::GetFileName($name) -eq $name) -Message "SHA256SUMS contains an unsafe filename: $name"
        $checksums[$name] = $digest
    }

    $archiveNames = @(Get-ArchiveAssetNames -Release $Release | Sort-Object)
    Assert-ExactSet -Expected $archiveNames -Actual @($checksums.Keys) -Label 'SHA256SUMS archive names'

    foreach ($asset in @($Release.assets)) {
        $path = Join-Path $Destination ([string]$asset.name)
        $actualDigest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-Equal -Expected ([string]$asset.digest).Substring(7) -Actual $actualDigest -Label "GitHub asset digest for $($asset.name)"
        if ([string]$asset.name -ne 'SHA256SUMS') {
            Assert-Equal -Expected ([string]$checksums[[string]$asset.name]) -Actual $actualDigest -Label "SHA256SUMS digest for $($asset.name)"
        }
    }

    return $archiveNames
}

function Assert-BuildProvenance {
    param(
        [Parameter(Mandatory)][string[]]$ArchiveNames,
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$Commit
    )

    $signerWorkflow = "github.com/$Repository/$ReleaseWorkflow"
    foreach ($name in $ArchiveNames) {
        $path = Join-Path $Directory $name
        $verification = Invoke-NativeCommand -FilePath 'gh' -Arguments @(
            'attestation', 'verify', $path,
            '--repo', $Repository,
            '--signer-workflow', $signerWorkflow,
            '--source-digest', $Commit,
            '--source-ref', "refs/tags/$ReleaseTag",
            '--signer-digest', $Commit,
            '--deny-self-hosted-runners',
            '--format', 'json'
        )
        $records = @($verification.Text | ConvertFrom-Json -Depth 100)
        Assert-True -Condition ($records.Count -gt 0) -Message "no valid build provenance was returned for $name"
    }
}

function Assert-ReleaseAttestation {
    $deadline = [System.DateTimeOffset]::UtcNow.AddMinutes(2)
    while ($true) {
        $result = Invoke-NativeCommand -FilePath 'gh' -Arguments @(
            'release', 'verify', $ReleaseTag,
            '--repo', $Repository,
            '--format', 'json'
        ) -AllowFailure
        if ($result.ExitCode -eq 0) {
            $records = @($result.Text | ConvertFrom-Json -Depth 100)
            Assert-True -Condition ($records.Count -gt 0) -Message 'release verification returned no attestation records'
            return
        }
        if ([System.DateTimeOffset]::UtcNow -ge $deadline) {
            throw "immutable release attestation did not verify`n$($result.Text)"
        }
        Start-Sleep -Seconds 5
    }
}

function Get-ImmutablePublishedRelease {
    param(
        [Parameter(Mandatory)][int64]$ReleaseId,
        [Parameter(Mandatory)][string]$ExpectedNotes,
        [Parameter(Mandatory)]$Snapshot
    )

    $deadline = [System.DateTimeOffset]::UtcNow.AddMinutes(1)
    while ($true) {
        $release = Get-ReleaseById -ReleaseId $ReleaseId
        if (-not [bool]$release.draft -and [bool]$release.immutable) {
            Assert-Equal -Expected $ReleaseId -Actual ([int64]$release.id) -Label 'published release ID'
            Assert-ReleaseContract -Release $release -ExpectedNotes $ExpectedNotes -State 'published'
            Assert-ReleaseMatchesSnapshot -Release $release -Snapshot $Snapshot
            return $release
        }
        if ([System.DateTimeOffset]::UtcNow -ge $deadline) {
            throw 'published release did not become immutable within one minute'
        }
        Start-Sleep -Seconds 5
    }
}

Get-Command -Name git -CommandType Application -ErrorAction Stop | Out-Null
Get-Command -Name cargo -CommandType Application -ErrorAction Stop | Out-Null
Get-Command -Name gh -CommandType Application -ErrorAction Stop | Out-Null

Push-Location $Workspace
try {
    Invoke-NativeCommand -FilePath 'gh' -Arguments @('auth', 'status', '--hostname', 'github.com') | Out-Null

    $source = Assert-LocalReleaseSource
    $initialMain = Get-RemoteMainCommit
    Assert-Equal -Expected $source.Commit -Actual $initialMain -Label 'initial remote main commit'

    $protection = Get-BranchProtection
    $requiredChecks = @(Assert-BranchProtection -Protection $protection)
    $ciState = Get-ExactCiState -Commit $source.Commit -RequiredChecks $requiredChecks -Wait
    $fuzzState = Get-ExactFuzzState -Commit $source.Commit
    $releaseWorkflowState = Get-ExactReleaseWorkflowState -Commit $source.Commit
    $immutableSettings = Assert-ImmutableReleaseSetting

    $release = Get-ExactReleaseForTag
    $state = if ([bool]$release.draft) { 'draft' } else { 'published' }
    Assert-ReleaseContract -Release $release -ExpectedNotes $source.Notes -State $state
    $snapshot = New-ReleaseSnapshot -Release $release

    $TemporaryRoot = New-ExactTemporaryRoot
    $archiveNames = @(Download-VerifiedAssetSet -Release $release -Destination $TemporaryRoot)
    Assert-BuildProvenance -ArchiveNames $archiveNames -Directory $TemporaryRoot -Commit $source.Commit

    if ($state -eq 'published') {
        Assert-ReleaseAttestation
        Assert-ImmutableReleaseSetting | Out-Null
        $finalTag = Get-RemoteTagCommit
        Assert-Equal -Expected $source.Commit -Actual $finalTag -Label 'immutable release tag commit'
        Write-Host "release already published and fully verified: https://github.com/$Repository/releases/tag/$ReleaseTag"
        [pscustomobject]@{
            repository = $Repository
            tag = $ReleaseTag
            commit = $source.Commit
            release_id = [int64]$release.id
            immutable = $true
            ci_run_id = $ciState.Id
            fuzz_run_id = $fuzzState.Id
            release_workflow_run_id = $releaseWorkflowState.Id
            assets = @($release.assets | Sort-Object name | ForEach-Object { [ordered]@{ name = $_.name; digest = $_.digest } })
        } | ConvertTo-Json -Depth 6
        return
    }

    if (-not $Publish) {
        Write-Host 'release draft passed every read-only promotion check'
        Write-Host 'rerun with -Publish to publish the verified draft as an immutable prerelease'
        return
    }

    $releaseId = [int64]$snapshot.ReleaseId
    if (-not $PSCmdlet.ShouldProcess("$Repository release $ReleaseTag with ID $releaseId", 'Publish verified draft as an immutable prerelease')) {
        return
    }

    $finalProtection = Get-BranchProtection
    $finalRequiredChecks = @(Assert-BranchProtection -Protection $finalProtection)
    $finalCiState = Get-ExactCiState -Commit $source.Commit -RequiredChecks $finalRequiredChecks
    $finalFuzzState = Get-ExactFuzzState -Commit $source.Commit
    $finalReleaseWorkflowState = Get-ExactReleaseWorkflowState -Commit $source.Commit
    Assert-ImmutableReleaseSetting | Out-Null
    $finalMain = Get-RemoteMainCommit
    $finalTag = Get-RemoteTagCommit
    Assert-Equal -Expected $source.Commit -Actual $finalMain -Label 'prepublication main commit'
    Assert-Equal -Expected $source.Commit -Actual $finalTag -Label 'prepublication tag commit'

    $finalDraft = Get-ExactReleaseForTag -ExpectedReleaseId $snapshot.ReleaseId
    Assert-ReleaseContract -Release $finalDraft -ExpectedNotes $source.Notes -State 'draft'
    Assert-ReleaseMatchesSnapshot -Release $finalDraft -Snapshot $snapshot
    Assert-Equal -Expected $releaseId -Actual ([int64]$finalDraft.id) -Label 'prepublication release ID'
    Assert-Equal -Expected $ciState.Id -Actual $finalCiState.Id -Label 'prepublication CI run ID'
    Assert-Equal -Expected $ciState.Attempt -Actual $finalCiState.Attempt -Label 'prepublication CI run attempt'
    Assert-Equal -Expected $fuzzState.Id -Actual $finalFuzzState.Id -Label 'prepublication fuzz run ID'
    Assert-Equal -Expected $fuzzState.Attempt -Actual $finalFuzzState.Attempt -Label 'prepublication fuzz run attempt'
    Assert-Equal -Expected $releaseWorkflowState.Id -Actual $finalReleaseWorkflowState.Id -Label 'prepublication release workflow run ID'
    Assert-Equal -Expected $releaseWorkflowState.Attempt -Actual $finalReleaseWorkflowState.Attempt -Label 'prepublication release workflow run attempt'

    $publication = Invoke-GhApiJson -ApiArguments @(
        '--method', 'PATCH',
        "repos/$Repository/releases/$releaseId",
        '-F', 'draft=false',
        '-F', 'prerelease=true'
    )
    Assert-Equal -Expected $releaseId -Actual ([int64]$publication.id) -Label 'publication release ID'

    $published = Get-ImmutablePublishedRelease -ReleaseId $releaseId -ExpectedNotes $source.Notes -Snapshot $snapshot
    Assert-ImmutableReleaseSetting | Out-Null
    Assert-ReleaseAttestation
    Assert-BuildProvenance -ArchiveNames $archiveNames -Directory $TemporaryRoot -Commit $source.Commit
    $publishedTag = Get-RemoteTagCommit
    Assert-Equal -Expected $source.Commit -Actual $publishedTag -Label 'postpublication tag commit'

    Write-Host "immutable prerelease published and verified: https://github.com/$Repository/releases/tag/$ReleaseTag"
    [pscustomobject]@{
        repository = $Repository
        tag = $ReleaseTag
        commit = $source.Commit
        release_id = [int64]$published.id
        immutable = [bool]$published.immutable
        ci_run_id = $finalCiState.Id
        fuzz_run_id = $finalFuzzState.Id
        release_workflow_run_id = $finalReleaseWorkflowState.Id
        assets = @($published.assets | Sort-Object name | ForEach-Object { [ordered]@{ name = $_.name; digest = $_.digest } })
    } | ConvertTo-Json -Depth 6
}
finally {
    if ($null -ne $TemporaryRoot) {
        Remove-ExactTemporaryRoot -Path $TemporaryRoot
    }
    Pop-Location
}
