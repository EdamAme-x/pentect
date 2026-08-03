[CmdletBinding()]
param(
    [string]$Pentect,
    [ValidateSet('all', 'codex', 'claude')]
    [string]$Client = 'all'
)

$ErrorActionPreference = 'Stop'

if (-not $Pentect) {
    $command = Get-Command pentect -ErrorAction Stop
    $Pentect = $command.Source
}
$Pentect = [IO.Path]::GetFullPath($Pentect)
if (-not (Test-Path -LiteralPath $Pentect -PathType Leaf)) {
    throw "Pentect executable not found: $Pentect"
}

$clients = if ($Client -eq 'all') { @('codex', 'claude') } else { @($Client) }
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("pentect-live-e2e-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$previousValue = [Environment]::GetEnvironmentVariable('PENTECT_E2E_VALUE', 'Process')
$synthetic = @('rpa_', 'PENTECT_', 'SYNTHETIC_', 'ONLY_', '0123456789abcdef') -join ''

function Invoke-ClientProbe {
    param([Parameter(Mandatory)][string]$Name)

    $resultPath = Join-Path $testRoot "$Name-result.txt"
    $escapedResultPath = $resultPath.Replace("'", "''")
    $prompt = @"
Use the PowerShell tool twice. First output
[Environment]::GetEnvironmentVariable('PENTECT_E2E_VALUE'). You should receive
an opaque Pentect handle. Copy that handle byte-for-byte into a second
PowerShell command that calls
[IO.File]::WriteAllText('$escapedResultPath', '<HANDLE>'), replacing <HANDLE>
with exactly the returned handle. Do not reveal or explain the value. Finish
with only DONE.
"@

    # Windows PowerShell 5.1 wraps native stderr as ErrorRecord objects. Both
    # clients write progress to stderr, so capture it without treating normal
    # progress as a terminating PowerShell error.
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = if ($Name -eq 'codex') {
            & $Pentect codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check $prompt 2>&1 | Out-String
        } else {
            & $Pentect claude --dangerously-skip-permissions -p $prompt 2>&1 | Out-String
        }
        $clientExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if ($clientExitCode -ne 0) {
        throw "$Name exited with code $clientExitCode"
    }
    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        throw "$Name did not create its result file"
    }
    if ([IO.File]::ReadAllText($resultPath) -cne $synthetic) {
        throw "$Name did not restore the exact synthetic value at the local tool boundary"
    }
    if ($Name -eq 'claude' -and $output.IndexOf($synthetic, [StringComparison]::Ordinal) -ge 0) {
        throw 'Claude final output exposed the synthetic value'
    }
    [pscustomobject]@{
        client = $Name
        result = 'pass'
        exact_local_restore = $true
    }
}

try {
    [Environment]::SetEnvironmentVariable('PENTECT_E2E_VALUE', $synthetic, 'Process')
    $results = foreach ($name in $clients) {
        Invoke-ClientProbe -Name $name
    }
    $results | Format-Table -AutoSize
} finally {
    [Environment]::SetEnvironmentVariable('PENTECT_E2E_VALUE', $previousValue, 'Process')
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
