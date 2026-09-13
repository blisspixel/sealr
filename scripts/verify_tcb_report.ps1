[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$committedPath = Join-Path $workspace 'docs/tcb-report.md'
if (-not (Test-Path -LiteralPath $committedPath)) {
    throw 'docs/tcb-report.md is missing; generate it with scripts/generate_tcb_report.ps1'
}

$regeneratedPath = Join-Path ([IO.Path]::GetTempPath()) "sealr-tcb-report-$([Guid]::NewGuid().ToString('N')).md"
try {
    & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'generate_tcb_report.ps1') -OutputPath $regeneratedPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'TCB report generation failed'
    }
    $committed = [IO.File]::ReadAllText($committedPath).Replace("`r`n", "`n")
    $regenerated = [IO.File]::ReadAllText($regeneratedPath)
    if ($committed -cne $regenerated) {
        throw 'docs/tcb-report.md has drifted from the measured tree; regenerate it with scripts/generate_tcb_report.ps1'
    }
} finally {
    if (Test-Path -LiteralPath $regeneratedPath) {
        Remove-Item -LiteralPath $regeneratedPath -Force
    }
}

Write-Host 'TCB report verification passed: docs/tcb-report.md matches the measured tree.'
