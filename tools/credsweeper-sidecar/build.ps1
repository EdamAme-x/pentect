param(
    [string]$OutputDir = "",
    [string]$Python = "python",
    [string]$WorkDir = ""
)

$ErrorActionPreference = "Stop"

function Assert-LastExit {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$VendorRoot = Join-Path $RepoRoot "crates\pentect-core\vendors\CredSweeper"
$PatchFile = Join-Path $ScriptDir "patches\lazy-imports.patch"
$Sidecar = Join-Path $ScriptDir "sidecar.py"
$Requirements = Join-Path $ScriptDir "requirements.txt"

if ($OutputDir -eq "") {
    $OutputDir = Join-Path $RepoRoot "target\credsweeper-sidecar"
}
if ($WorkDir -eq "") {
    $WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) "pentect-credsweeper-sidecar-build"
}

$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
$WorkDir = [System.IO.Path]::GetFullPath($WorkDir)
$SourceRoot = Join-Path $WorkDir "CredSweeper"
$Venv = Join-Path $WorkDir ".venv"
$VenvPython = Join-Path $Venv "Scripts\python.exe"
$TarPath = Join-Path $WorkDir "credsweeper.tar"

Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
New-Item -ItemType Directory -Force -Path $SourceRoot | Out-Null

& git -C $VendorRoot archive --format=tar -o $TarPath HEAD
Assert-LastExit "git archive CredSweeper"
& tar -xf $TarPath -C $SourceRoot
Assert-LastExit "extract CredSweeper archive"
& git -C $SourceRoot apply $PatchFile
Assert-LastExit "apply CredSweeper patch"

& $Python -m venv $Venv
Assert-LastExit "create venv"
& $VenvPython -m pip install --disable-pip-version-check --quiet --upgrade pip
Assert-LastExit "upgrade pip"
& $VenvPython -m pip install --disable-pip-version-check --quiet -r $Requirements
Assert-LastExit "install sidecar requirements"

$CredSweeperPackage = Join-Path $SourceRoot "credsweeper"
$BuildDir = Join-Path $WorkDir "pyinstaller-build"
$SpecDir = Join-Path $WorkDir "spec"
Remove-Item -LiteralPath $OutputDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
New-Item -ItemType Directory -Force -Path $SpecDir | Out-Null

& $VenvPython -m PyInstaller `
    --noconfirm `
    --clean `
    --onedir `
    --name pentect-credsweeper-sidecar `
    --paths $SourceRoot `
    --distpath $OutputDir `
    --workpath $BuildDir `
    --specpath $SpecDir `
    --add-data "$CredSweeperPackage\common\keyword_checklist.txt;credsweeper\common" `
    --add-data "$CredSweeperPackage\common\morpheme_checklist.txt;credsweeper\common" `
    --add-data "$CredSweeperPackage\rules\config.yaml;credsweeper\rules" `
    --add-data "$CredSweeperPackage\secret\config.json;credsweeper\secret" `
    --add-data "$CredSweeperPackage\ml_model\ml_config.json;credsweeper\ml_model" `
    --add-data "$CredSweeperPackage\ml_model\ml_model.onnx;credsweeper\ml_model" `
    --exclude-module pandas `
    --exclude-module IPython `
    --exclude-module matplotlib `
    --exclude-module pytest `
    --exclude-module tests `
    $Sidecar
Assert-LastExit "build sidecar"

$Exe = Join-Path $OutputDir "pentect-credsweeper-sidecar\pentect-credsweeper-sidecar.exe"
Write-Output $Exe
