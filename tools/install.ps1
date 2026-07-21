param([string]$Version = $env:PENTECT_VERSION)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

$repository = 'EdamAme-x/pentect'
$requestedVersion = $Version
if ($requestedVersion) {
    $requestedVersion = $requestedVersion.TrimStart('v')
    if ($requestedVersion -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
        throw "pentect: invalid version: $requestedVersion"
    }
    $releaseTag = "v$requestedVersion"
    $baseUrl = "https://github.com/$repository/releases/download/$releaseTag"
} else {
    $releaseTag = 'latest'
    $baseUrl = "https://github.com/$repository/releases/latest/download"
}
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($architecture -ne 'X64') {
    throw "pentect: unsupported Windows architecture: $architecture"
}
$asset = 'pentect-windows-x86_64.exe'

$installDir = if ($env:PENTECT_INSTALL_DIR) {
    $env:PENTECT_INSTALL_DIR
} else {
    Join-Path $env:LOCALAPPDATA 'Pentect\bin'
}
$destination = Join-Path $installDir 'pentect.exe'
$marker = Join-Path $installDir '.pentect-managed-install.json'

if ($env:PENTECT_INSTALL_DRY_RUN -eq '1') {
    Write-Output "asset=$asset"
    Write-Output "version=$releaseTag"
    Write-Output "install=$destination"
    return
}

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("pentect-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tempDir | Out-Null
try {
    Write-Output 'Pentect installer'
    Write-Output "  Platform : Windows x64"
    Write-Output "  Version  : $releaseTag"
    Write-Output "  Install  : $destination"
    Write-Output ''
    $binaryPath = Join-Path $tempDir $asset
    $checksumPath = "$binaryPath.sha256"
    Write-Output "[1/4] Downloading $releaseTag..."
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$asset" -OutFile $binaryPath
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$asset.sha256" -OutFile $checksumPath

    Write-Output '[2/4] Verifying SHA-256...'
    $expected = ((Get-Content -Raw -LiteralPath $checksumPath) -split '\s+')[0].ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{64}$') {
        throw 'pentect: release checksum is invalid'
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $binaryPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "pentect: release checksum mismatch (expected $expected, received $actual)"
    }

    Write-Output '[3/4] Installing binary...'
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    $staged = Join-Path $installDir 'pentect.install.exe'
    Copy-Item -LiteralPath $binaryPath -Destination $staged -Force
    if (Test-Path -LiteralPath $destination) {
        $backup = Join-Path $installDir 'pentect.previous.exe'
        Copy-Item -LiteralPath $destination -Destination $backup -Force
    }
    Move-Item -LiteralPath $staged -Destination $destination -Force

    $pathAdded = $false
    if (Test-Path -LiteralPath $marker) {
        try { $pathAdded = [bool]((Get-Content -Raw -LiteralPath $marker | ConvertFrom-Json).path_added) } catch {}
    }
    $pathStatus = 'skipped by configuration'
    if ($env:PENTECT_INSTALL_SKIP_PATH -ne '1') {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $pathParts = @($userPath -split ';' | Where-Object { $_ })
        if (-not ($pathParts | Where-Object { $_.TrimEnd('\') -ieq $installDir.TrimEnd('\') })) {
            $nextPath = (@($pathParts) + $installDir) -join ';'
            [Environment]::SetEnvironmentVariable('Path', $nextPath, 'User')
            $pathAdded = $true
            $pathStatus = 'added to user PATH'
        } else {
            $pathStatus = 'already on user PATH'
        }
        if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $installDir.TrimEnd('\') })) {
            $env:Path = "$installDir;$env:Path"
        }
    }
    Write-Output "[4/4] PATH: $pathStatus"
    @{ version = 1; path_added = $pathAdded } | ConvertTo-Json -Compress | Set-Content -Encoding utf8 -LiteralPath $marker
    Write-Output ''
    Write-Output "Installed Pentect $releaseTag"
    Write-Output 'Next: pentect doctor'
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}
