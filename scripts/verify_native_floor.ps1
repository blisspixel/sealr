[CmdletBinding()]
param(
    [ValidateSet('x86_64-unknown-linux-gnu', 'aarch64-apple-darwin', 'x86_64-pc-windows-msvc')]
    [string]$ExpectedTarget,

    [switch]$ContractOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$contractPath = Join-Path $workspace 'tests/package-contract/native.json'
$contract = Get-Content -Raw -LiteralPath $contractPath | ConvertFrom-Json
$expected = [ordered]@{
    'x86_64-unknown-linux-gnu' = [ordered]@{
        runner = 'ubuntu-24.04'
        operating_system = 'Ubuntu 24.04'
        architecture = 'x86_64'
        abi = 'glibc 2.39'
        kernel = 'Linux 6.8 or later; supervised mode additionally requires Landlock ABI 3 and x86_64 seccomp'
    }
    'aarch64-apple-darwin' = [ordered]@{
        runner = 'macos-15'
        operating_system = 'macOS 15'
        architecture = 'arm64'
        abi = 'Darwin 24 with MACOSX_DEPLOYMENT_TARGET=15.0'
        kernel = 'Darwin 24'
    }
    'x86_64-pc-windows-msvc' = [ordered]@{
        runner = 'windows-2022'
        operating_system = 'Windows Server 2022 build 20348'
        architecture = 'x64'
        abi = 'MSVC'
        kernel = 'Windows NT 10.0 build 20348'
    }
}

if ($contract.schema -ne 'sealr.native-package-floor.v1') {
    throw 'native package floor contract uses an unknown schema'
}
$actualTargets = @($contract.targets)
if ($actualTargets.Count -ne $expected.Count) {
    throw "native package floor contract has $($actualTargets.Count) targets; expected $($expected.Count)"
}
$actualNames = @($actualTargets.target | Sort-Object)
if (Compare-Object -ReferenceObject @($expected.Keys | Sort-Object) -DifferenceObject $actualNames) {
    throw 'native package floor contract has missing or unknown targets'
}
foreach ($target in $actualTargets) {
    $name = [string]$target.target
    $expectedFields = @('target', 'runner', 'operating_system', 'architecture', 'abi', 'kernel')
    $actualFields = @($target.PSObject.Properties.Name | Sort-Object)
    if (Compare-Object -ReferenceObject @($expectedFields | Sort-Object) -DifferenceObject $actualFields) {
        throw "native package floor entry $name has missing or unknown fields"
    }
    foreach ($field in @('runner', 'operating_system', 'architecture', 'abi', 'kernel')) {
        if ([string]$target.$field -ne [string]$expected[$name][$field]) {
            throw "native package floor $name field $field drifted"
        }
    }
}

if ($ContractOnly) {
    Write-Host 'Verified the exact three-target native package floor declaration.'
    return
}
if ([string]::IsNullOrWhiteSpace($ExpectedTarget)) {
    throw 'ExpectedTarget is required unless ContractOnly is selected'
}

$hostLine = rustc -vV | Select-String -Pattern '^host: '
if ($null -eq $hostLine) {
    throw 'rustc did not report its host target'
}
$actualTarget = $hostLine.Line.Substring(6).Trim()
if ($actualTarget -ne $ExpectedTarget) {
    throw "native floor target drift: expected $ExpectedTarget, observed $actualTarget"
}

switch ($ExpectedTarget) {
    'x86_64-unknown-linux-gnu' {
        $osRelease = @{}
        Get-Content -LiteralPath /etc/os-release | ForEach-Object {
            if ($_ -match '^(?<key>[A-Z_]+)=(?<value>.*)$') {
                $osRelease[$Matches.key] = $Matches.value.Trim('"')
            }
        }
        if ($osRelease.ID -ne 'ubuntu' -or $osRelease.VERSION_ID -ne '24.04') {
            throw "Linux floor requires Ubuntu 24.04, observed $($osRelease.ID) $($osRelease.VERSION_ID)"
        }
        $libc = (& getconf GNU_LIBC_VERSION | Out-String).Trim()
        if ($libc -ne 'glibc 2.39') {
            throw "Linux floor requires glibc 2.39 build userspace, observed $libc"
        }
        if ((& uname -m | Out-String).Trim() -ne 'x86_64') {
            throw 'Linux floor requires x86_64 hardware'
        }
        $kernelText = (& uname -r | Out-String).Trim()
        if ($kernelText -notmatch '^(?<major>[0-9]+)\.(?<minor>[0-9]+)') {
            throw "Linux floor could not parse the kernel release: $kernelText"
        }
        $kernelMajor = [int]$Matches.major
        $kernelMinor = [int]$Matches.minor
        if ($kernelMajor -lt 6 -or ($kernelMajor -eq 6 -and $kernelMinor -lt 8)) {
            throw "Linux floor requires kernel 6.8 or later, observed $kernelText"
        }
        Write-Host "Verified Ubuntu 24.04 x86_64 with glibc 2.39 and Linux $kernelText; supervised tests separately require Landlock ABI 3."
    }
    'aarch64-apple-darwin' {
        $version = (& sw_vers -productVersion | Out-String).Trim()
        if (-not $version.StartsWith('15.', [StringComparison]::Ordinal)) {
            throw "macOS floor requires major version 15, observed $version"
        }
        if ((& uname -m | Out-String).Trim() -ne 'arm64') {
            throw 'macOS floor requires arm64 hardware'
        }
        $darwin = (& uname -r | Out-String).Trim()
        if (-not $darwin.StartsWith('24.', [StringComparison]::Ordinal)) {
            throw "macOS 15 floor requires Darwin 24, observed $darwin"
        }
        if ($env:MACOSX_DEPLOYMENT_TARGET -ne '15.0') {
            throw "macOS package build requires MACOSX_DEPLOYMENT_TARGET=15.0, observed $env:MACOSX_DEPLOYMENT_TARGET"
        }
        Write-Host "Verified macOS $version on arm64 with Darwin $darwin and deployment target 15.0."
    }
    'x86_64-pc-windows-msvc' {
        $version = [Environment]::OSVersion.Version
        if ($version.Major -ne 10 -or $version.Build -ne 20348) {
            throw "Windows floor requires Server 2022 build 20348, observed $version"
        }
        if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
            [Runtime.InteropServices.Architecture]::X64) {
            throw 'Windows floor requires x64 hardware'
        }
        Write-Host "Verified Windows Server 2022 build $($version.Build) on x64."
    }
}
