param([string]$Version = $env:PENTECT_VERSION)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

function ConvertTo-PentectArchitecture {
    param([Parameter(Mandatory = $true)][string]$Value)

    switch ($Value.Trim().ToUpperInvariant()) {
        { $_ -in @('X64', 'AMD64', 'X86_64') } { return 'X64' }
        { $_ -in @('ARM64', 'AARCH64') } { return 'Arm64' }
        { $_ -in @('X86', 'I386', 'I486', 'I586', 'I686') } { return 'X86' }
        default { return $Value.Trim() }
    }
}

function Get-PentectOsArchitecture {
    param(
        [scriptblock]$RuntimeArchitecture = { [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() },
        [AllowEmptyString()][string]$ProcessorArchitecture = $env:PROCESSOR_ARCHITECTURE,
        [AllowEmptyString()][string]$ProcessorArchitectureW6432 = $env:PROCESSOR_ARCHITEW6432
    )

    try {
        $runtimeValue = & $RuntimeArchitecture
        if (-not [string]::IsNullOrWhiteSpace([string]$runtimeValue)) {
            return ConvertTo-PentectArchitecture ([string]$runtimeValue)
        }
    } catch {
        # Windows PowerShell 5.1 can expose RuntimeInformation without the
        # OSArchitecture property. Fall back to the native process variables.
    }

    $environmentValue = if (-not [string]::IsNullOrWhiteSpace($ProcessorArchitectureW6432)) {
        $ProcessorArchitectureW6432
    } else {
        $ProcessorArchitecture
    }
    if ([string]::IsNullOrWhiteSpace($environmentValue)) {
        throw 'pentect: could not determine Windows architecture'
    }
    return ConvertTo-PentectArchitecture $environmentValue
}

function Invoke-PentectDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [switch]$AllowNotFound
    )

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile
            return $true
        } catch {
            $response = $_.Exception.Response
            if ($AllowNotFound -and $null -ne $response -and [int]$response.StatusCode -eq 404) {
                return $false
            }
            if ($attempt -eq 3) {
                throw "pentect: could not download '$Uri' after 3 attempts: $($_.Exception.Message)"
            }
            Start-Sleep -Seconds $attempt
        }
    }
}

function Expand-PentectGzip {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $inputStream = [System.IO.File]::OpenRead($Source)
    try {
        $outputStream = [System.IO.File]::Create($Destination)
        try {
            $gzipStream = [System.IO.Compression.GzipStream]::new(
                $inputStream,
                [System.IO.Compression.CompressionMode]::Decompress
            )
            try {
                $gzipStream.CopyTo($outputStream)
            } finally {
                $gzipStream.Dispose()
            }
        } finally {
            $outputStream.Dispose()
        }
    } finally {
        $inputStream.Dispose()
    }
}

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
$architecture = Get-PentectOsArchitecture
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
    try {
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {}
    Write-Output 'Pentect installer'
    Write-Output "  Platform : Windows x64"
    Write-Output "  Version  : $releaseTag"
    Write-Output "  Install  : $destination"
    Write-Output ''
    $binaryPath = Join-Path $tempDir $asset
    $compressedPath = "$binaryPath.gz"
    $checksumPath = "$binaryPath.sha256"
    Write-Output "[1/4] Downloading $releaseTag..."
    if (Invoke-PentectDownload -Uri "$baseUrl/$asset.gz" -OutFile $compressedPath -AllowNotFound) {
        Expand-PentectGzip -Source $compressedPath -Destination $binaryPath
    } else {
        Invoke-PentectDownload -Uri "$baseUrl/$asset" -OutFile $binaryPath | Out-Null
    }
    Invoke-PentectDownload -Uri "$baseUrl/$asset.sha256" -OutFile $checksumPath | Out-Null

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
        $pathKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
        if ($null -eq $pathKey) { throw 'Could not open HKCU\Environment' }
        try {
            try { $pathKind = $pathKey.GetValueKind('Path') } catch { $pathKind = [Microsoft.Win32.RegistryValueKind]::ExpandString }
            $userPath = $pathKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $pathParts = if ($userPath -is [string[]]) { @($userPath) } else { @(([string]$userPath) -split ';' | Where-Object { $_ }) }
            if (-not ($pathParts | Where-Object { $_.TrimEnd('\') -ieq $installDir.TrimEnd('\') })) {
                $pathParts = @($pathParts) + $installDir
                $nextPath = if ($pathKind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) { [string[]]$pathParts } else { $pathParts -join ';' }
                $pathKey.SetValue('Path', $nextPath, $pathKind)
                $pathAdded = $true
                $pathStatus = 'added to user PATH'
            } else {
                $pathStatus = 'already on user PATH'
            }
        } finally {
            $pathKey.Dispose()
        }
        if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $installDir.TrimEnd('\') })) {
            $env:Path = "$installDir;$env:Path"
        }
    }
    Write-Output "[4/4] PATH: $pathStatus"
    @{ version = 1; manager = 'pentect'; path_added = $pathAdded } | ConvertTo-Json -Compress | Set-Content -Encoding utf8 -LiteralPath $marker
    Write-Output ''
    Write-Output "Installed Pentect $releaseTag"
    Write-Output 'Next: pentect doctor'
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}
