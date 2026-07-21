$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = 'EdamAme-x/pentect'
$baseUrl = "https://github.com/$repository/releases/latest/download"
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

if ($env:PENTECT_INSTALL_DRY_RUN -eq '1') {
    Write-Output "asset=$asset"
    Write-Output "install=$destination"
    return
}

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("pentect-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tempDir | Out-Null
try {
    $binaryPath = Join-Path $tempDir $asset
    $checksumPath = "$binaryPath.sha256"
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$asset" -OutFile $binaryPath
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$asset.sha256" -OutFile $checksumPath

    $expected = ((Get-Content -Raw -LiteralPath $checksumPath) -split '\s+')[0].ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{64}$') {
        throw 'pentect: release checksum is invalid'
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $binaryPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "pentect: release checksum mismatch (expected $expected, received $actual)"
    }

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    $staged = Join-Path $installDir 'pentect.install.exe'
    Copy-Item -LiteralPath $binaryPath -Destination $staged -Force
    if (Test-Path -LiteralPath $destination) {
        $backup = Join-Path $installDir 'pentect.previous.exe'
        Copy-Item -LiteralPath $destination -Destination $backup -Force
    }
    Move-Item -LiteralPath $staged -Destination $destination -Force

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $pathParts = @($userPath -split ';' | Where-Object { $_ })
    if (-not ($pathParts | Where-Object { $_.TrimEnd('\') -ieq $installDir.TrimEnd('\') })) {
        $nextPath = (@($pathParts) + $installDir) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $nextPath, 'User')
    }
    if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $installDir.TrimEnd('\') })) {
        $env:Path = "$installDir;$env:Path"
    }
    Write-Output "pentect: installed $destination"
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}
