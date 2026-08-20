$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$savedDryRun = $env:PENTECT_INSTALL_DRY_RUN
$savedSkipPath = $env:PENTECT_INSTALL_SKIP_PATH
$savedInstallDir = $env:PENTECT_INSTALL_DIR
try {
    $env:PENTECT_INSTALL_DRY_RUN = '1'
    $env:PENTECT_INSTALL_SKIP_PATH = '1'
    $env:PENTECT_INSTALL_DIR = Join-Path ([System.IO.Path]::GetTempPath()) 'pentect-installer-test'
    . (Join-Path $PSScriptRoot 'install.ps1') | Out-Null

    $missingRuntimeProperty = { throw 'OSArchitecture property is unavailable' }
    $x64 = Get-PentectOsArchitecture $missingRuntimeProperty 'x86' 'AMD64'
    if ($x64 -ne 'X64') {
        throw "expected X64 from PROCESSOR_ARCHITEW6432, received $x64"
    }

    $nativeX64 = Get-PentectOsArchitecture $missingRuntimeProperty 'AMD64' ''
    if ($nativeX64 -ne 'X64') {
        throw "expected X64 from PROCESSOR_ARCHITECTURE, received $nativeX64"
    }

    $arm64 = Get-PentectOsArchitecture $missingRuntimeProperty 'x86' 'ARM64'
    if ($arm64 -ne 'Arm64') {
        throw "expected Arm64 fallback result, received $arm64"
    }
} finally {
    $env:PENTECT_INSTALL_DRY_RUN = $savedDryRun
    $env:PENTECT_INSTALL_SKIP_PATH = $savedSkipPath
    $env:PENTECT_INSTALL_DIR = $savedInstallDir
}
