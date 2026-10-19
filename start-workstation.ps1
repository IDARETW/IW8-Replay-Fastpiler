param(
    [int]$Port = 8126,
    [switch]$External,
    [switch]$UPnP,
    [string]$GameRoot = '',
    [string]$SQLite = '',
    [string]$CacheRoot = '',
    [string]$Acts = '',
    [string]$Credentials = '',
    [string]$Python = ''
)
$ErrorActionPreference = 'Stop'
$configPath = Join-Path $PSScriptRoot 'replay-project.local.json'
$config = if (Test-Path -LiteralPath $configPath) { Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json } else { $null }
if ($config -and $config.schema -ne 1) { throw 'Unsupported local workstation configuration schema.' }
if (-not $GameRoot) { $GameRoot = if ($config.game) { $config.game } else { 'E:\IW8\Builds\1.20-replay' } }
if (-not $SQLite -and $config.sqlite -and $GameRoot -eq $config.game) { $SQLite = $config.sqlite }
if (-not $CacheRoot) { $CacheRoot = if ($config.cache) { $config.cache } else { Join-Path $env:LOCALAPPDATA 'ReplayCompilerWorkstation' } }
if (-not $SQLite) { $SQLite = Join-Path $GameRoot 'game_dx12_ship_replay.exe.sqlite' }
if (-not $Acts) { $Acts = if ($env:REPLAY_ACTS) { $env:REPLAY_ACTS } elseif ($config.acts) { $config.acts } else { '' } }
$venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not $Python) {
    $Python = if ($config.workstation_python) { $config.workstation_python } elseif (Test-Path -LiteralPath $venvPython) { $venvPython } else { (Get-Command python).Source }
}
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw "Workstation Python does not exist: $Python" }
$dependencyRoot = $config.python_dependency_root
if ($dependencyRoot -and -not (Test-Path -LiteralPath $dependencyRoot -PathType Container)) { throw "Workstation Python dependencies do not exist: $dependencyRoot" }
$arguments = @('-B', '-u', (Join-Path $PSScriptRoot 'workstation\server.py'), '--game', $GameRoot, '--sqlite', $SQLite, '--cache', $CacheRoot, '--port', [string]$Port)
if ($UPnP -and -not $External) { throw '-UPnP requires -External and HTTP credentials.' }
if ($Acts) { $arguments += @('--acts', $Acts) }
if ($External) {
    if (-not $Credentials) { $Credentials = Join-Path $env:LOCALAPPDATA 'ReplayFrontendPreview\credentials.json' }
    if (-not (Test-Path -LiteralPath $Credentials -PathType Leaf)) { throw 'External access needs a private credentials JSON with username and password.' }
    $arguments += @('--host','0.0.0.0','--credentials',$Credentials)
    if ($UPnP) { $arguments += '--upnp' }
}
$previousPythonPath = $env:PYTHONPATH
$previousPythonUtf8 = $env:PYTHONUTF8
try {
    if ($dependencyRoot) {
        $env:PYTHONPATH = if ($previousPythonPath) { "$dependencyRoot$([IO.Path]::PathSeparator)$previousPythonPath" } else { $dependencyRoot }
    }
    $env:PYTHONUTF8 = '1'
    & $Python @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Replay workstation stopped with an error.' }
} finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYTHONUTF8 = $previousPythonUtf8
}
