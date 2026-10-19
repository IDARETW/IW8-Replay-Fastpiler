param(
    [ValidateRange(1, 65535)]
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
$serverPath = Join-Path $PSScriptRoot 'workstation\server.py'
$serverPattern = '(?:^|[\s"])' + [regex]::Escape($serverPath) + '(?=[\s"]|$)'
$listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
$workstationIds = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)

# Validate every owner before stopping anything; a port alone does not identify the app.
foreach ($workstationId in $workstationIds) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $workstationId"
    if (-not $process -or $process.Name -notmatch '^python(w)?\.exe$' -or
        $process.CommandLine -notmatch $serverPattern) {
        throw "Port $Port belongs to another process ($workstationId); it was left running."
    }
}
foreach ($workstationId in $workstationIds) {
    Write-Host "Stopping Replay Workstation ($workstationId)."
    Stop-Process -Id $workstationId -ErrorAction Stop
    Wait-Process -Id $workstationId -Timeout 15 -ErrorAction SilentlyContinue
}

# Windows may report the listener briefly after its owning process exits.
$deadline = [DateTime]::UtcNow.AddSeconds(15)
while (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    if ([DateTime]::UtcNow -ge $deadline) { throw "Port $Port did not become free; restart stopped." }
    Start-Sleep -Milliseconds 200
}
Write-Host "Port $Port is free. Starting Replay Workstation."
& (Join-Path $PSScriptRoot 'start-workstation.ps1') @PSBoundParameters
