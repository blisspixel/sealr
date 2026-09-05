[CmdletBinding()]
param(
    [string]$Root = 'target/readme-walkthrough'
)

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$walkthroughRoot = [System.IO.Path]::GetFullPath((Join-Path $workspace $Root))
$targetRoot = [System.IO.Path]::GetFullPath((Join-Path $workspace 'target'))
if (-not $walkthroughRoot.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "walkthrough root must stay below target: $walkthroughRoot"
}

$transcriptRoot = Join-Path $walkthroughRoot 'transcripts'
$renderRoot = Join-Path $walkthroughRoot 'render'
$measured = Get-Content -Raw -LiteralPath (Join-Path $walkthroughRoot 'manifest.json') | ConvertFrom-Json
$workspaceManifest = Get-Content -Raw -LiteralPath (Join-Path $workspace 'Cargo.toml')
$version = [regex]::Match($workspaceManifest, '(?m)^version = "([^"]+)"$').Groups[1].Value
if ([string]::IsNullOrWhiteSpace($version) -or [string]$measured.tool_version -ne $version) {
    throw 'walkthrough was not measured with the current workspace version'
}
New-Item -ItemType Directory -Force -Path $renderRoot | Out-Null

$scenarios = @(
    @{ File = '01-inspect-allowed'; Label = 'Inspect without writing' },
    @{ File = '02-reject-parent-path'; Label = 'Reject parent traversal' },
    @{ File = '03-materialize-allowed'; Label = 'Materialize the approved tree' }
)

$themes = @(
    @{
        Name = 'light'
        Canvas = '#f6f8fa'
        Panel = '#ffffff'
        Border = '#d0d7de'
        Text = '#1f2328'
        Muted = '#59636e'
        Accent = '#0969da'
        Success = '#1a7f37'
        Danger = '#cf222e'
    },
    @{
        Name = 'dark'
        Canvas = '#0d1117'
        Panel = '#161b22'
        Border = '#30363d'
        Text = '#f0f6fc'
        Muted = '#9198a1'
        Accent = '#58a6ff'
        Success = '#3fb950'
        Danger = '#ff7b72'
    }
)

function Get-LineClass {
    param([Parameter(Mandatory)][string]$Line)

    if ($Line.StartsWith('PS>') -or $Line.StartsWith('>>') -or $Line.StartsWith('$ ') -or $Line.StartsWith('> ')) { return 'command' }
    if ($Line -match '^verdict: allowed$|^wrote: true$|exists true$|^destination exists: false$|^outside file exists: false$') { return 'success' }
    if ($Line -match '^verdict: rejected$|path\.dotdot') { return 'danger' }
    if ($Line -match '^receipt:|sha256:|^  signed:|^receipt view sha256:') { return 'muted' }
    return 'plain'
}

foreach ($scenario in $scenarios) {
    $transcriptPath = Join-Path $transcriptRoot "$($scenario.File).txt"
    if (-not [System.IO.File]::Exists($transcriptPath)) {
        throw "missing verified transcript: $transcriptPath"
    }
    $lines = [System.IO.File]::ReadAllLines($transcriptPath)
    $renderedLines = foreach ($line in $lines) {
        $encoded = [System.Net.WebUtility]::HtmlEncode($line)
        $class = Get-LineClass -Line $line
        "<span class=`"$class`">$encoded</span>"
    }
    $content = $renderedLines -join "`n"

    foreach ($theme in $themes) {
        $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sealr walkthrough: $($scenario.Label)</title>
<style>
* { box-sizing: border-box; }
html, body { margin: 0; width: 1000px; height: 560px; overflow: hidden; }
body {
  display: flex;
  align-items: center;
  justify-content: center;
  background: $($theme.Canvas);
  color: $($theme.Text);
  font-family: "Cascadia Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
}
main {
  width: 936px;
  height: 496px;
  border: 1px solid $($theme.Border);
  border-radius: 12px;
  background: $($theme.Panel);
  box-shadow: 0 8px 28px rgba(0, 0, 0, 0.12);
  overflow: hidden;
}
header {
  height: 62px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 28px;
  border-bottom: 1px solid $($theme.Border);
}
header strong { color: $($theme.Accent); font-size: 20px; letter-spacing: 0.02em; }
header small { color: $($theme.Muted); font-size: 14px; font-weight: normal; margin-left: 12px; }
header span { color: $($theme.Muted); font-size: 16px; }
pre {
  margin: 0;
  padding: 25px 28px;
  font: 17px/1.55 "Cascadia Mono", "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  white-space: pre-wrap;
  tab-size: 2;
}
pre span { display: inline; }
.plain { color: $($theme.Text); }
.muted { color: $($theme.Muted); }
.command { color: $($theme.Accent); font-weight: 650; }
.success { color: $($theme.Success); font-weight: 650; }
.danger { color: $($theme.Danger); font-weight: 650; }
</style>
</head>
<body>
<main aria-label="sealr terminal walkthrough">
  <header><strong>sealr <small>$version</small></strong><span>$($scenario.Label)</span></header>
  <pre>$content</pre>
</main>
</body>
</html>
"@
        $outputPath = Join-Path $renderRoot "$($scenario.File)-$($theme.Name).html"
        [System.IO.File]::WriteAllText($outputPath, $html, [System.Text.UTF8Encoding]::new($false))
    }
}

Write-Host "walkthrough renders: $renderRoot"
