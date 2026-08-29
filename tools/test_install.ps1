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

    $marker = Join-Path ([System.IO.Path]::GetTempPath()) ("pentect-marker-test-" + [guid]::NewGuid() + '.json')
    try {
        Write-PentectManagedInstallMarker -Path $marker -PathAdded $true
        $bytes = [System.IO.File]::ReadAllBytes($marker)
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            throw 'managed installation marker contains a UTF-8 BOM'
        }
        $decoded = Get-Content -Raw -LiteralPath $marker | ConvertFrom-Json
        if ($decoded.manager -ne 'pentect' -or -not [bool]$decoded.path_added) {
            throw 'managed installation marker has unexpected contents'
        }
    } finally {
        if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force }
    }
} finally {
    $env:PENTECT_INSTALL_DRY_RUN = $savedDryRun
    $env:PENTECT_INSTALL_SKIP_PATH = $savedSkipPath
    $env:PENTECT_INSTALL_DIR = $savedInstallDir
}
