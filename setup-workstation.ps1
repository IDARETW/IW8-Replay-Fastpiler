param(
    [Parameter(Mandatory)]
    [string]$GameRoot,
    [string]$SQLite = '',
    [string]$Acts = '',
    [string]$LuaActs = '',
    [string]$SabGenerator = '',
    [string]$ZoneToolSource = '',
    [string]$ScriptSourcePack = '',
    [string]$ScriptStringDecryptor = '',
    [string]$ProxySource = '',
    [switch]$UseLegacyPublicDxbc,
    [switch]$SkipAssetTools,
    [switch]$Start
)
$ErrorActionPreference = 'Stop'
$GameRoot = (Resolve-Path -LiteralPath $GameRoot).Path
if (-not (Test-Path -LiteralPath $GameRoot -PathType Container)) { throw "Replay game directory not found: $GameRoot" }
if ($SkipAssetTools -and $UseLegacyPublicDxbc) {
    throw '-UseLegacyPublicDxbc requires asset-tool setup; omit -SkipAssetTools.'
}
if (-not $SQLite) { $SQLite = Join-Path $GameRoot 'game_dx12_ship_replay.exe.sqlite' }
$SQLite = (Resolve-Path -LiteralPath $SQLite).Path
foreach ($path in (Join-Path $GameRoot 'game_dx12_ship_replay.exe'), $SQLite) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required Replay input missing: $path" }
}
if ($LuaActs) {
    $LuaActs = (Resolve-Path -LiteralPath $LuaActs).Path
    if (-not (Test-Path -LiteralPath $LuaActs -PathType Leaf)) { throw "Lua compiler not found: $LuaActs" }
}
$venvRoot = Join-Path $PSScriptRoot '.venv'
$venvPython = Join-Path $venvRoot 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    & python -m venv $venvRoot
    if ($LASTEXITCODE -ne 0) { throw 'Python virtual environment setup failed.' }
}
& $venvPython -m pip install -r (Join-Path $PSScriptRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Replay compiler dependency installation failed.' }
& $venvPython (Join-Path $PSScriptRoot 'tools\setup_workstation_ui.py')
if ($LASTEXITCODE -ne 0) { throw 'Workstation editor installation failed.' }
$prepareArguments = @((Join-Path $PSScriptRoot 'tools\prepare_workstation.py'), '--game', $GameRoot, '--sqlite', $SQLite)
if ($ProxySource) { $prepareArguments += @('--proxy-source', (Resolve-Path -LiteralPath $ProxySource).Path) }
& $venvPython @prepareArguments
if ($LASTEXITCODE -ne 0) { throw 'Pinned Replay analysis preparation failed.' }
& $venvPython (Join-Path $PSScriptRoot 'tools\workstation_preflight.py') --game $GameRoot --sqlite $SQLite
if ($LASTEXITCODE -ne 0) { throw 'Resolve the listed compiler prerequisites before starting the workstation.' }
$configuration = [ordered]@{ schema=1; game=$GameRoot; sqlite=$SQLite; cache=(Join-Path $env:LOCALAPPDATA 'ReplayCompilerWorkstation') }
if ($ProxySource) { $configuration.proxy_source = (Resolve-Path -LiteralPath $ProxySource).Path }
if (-not $SkipAssetTools) {
    & $venvPython (Join-Path $PSScriptRoot 'tools\setup_workstation_tools.py') --root $PSScriptRoot --install-public
    if ($LASTEXITCODE -ne 0) { throw 'Pinned codec tool installation failed.' }
    if (-not $Acts) {
        $actsSource = Join-Path $PSScriptRoot '.toolchains\acts'
        & $venvPython (Join-Path $PSScriptRoot 'tools\bootstrap_workstation_acts.py') $actsSource --build
        if ($LASTEXITCODE -ne 0) { throw 'Native Replay ACTS source build failed.' }
        $actsReceipt = Get-Content -Raw -LiteralPath (Join-Path $actsSource 'replay-workstation-bootstrap.json') | ConvertFrom-Json
        $Acts = $actsReceipt.build.executable
    }
    $LuaCompiler = if ($LuaActs) { $LuaActs } else { (Resolve-Path -LiteralPath $Acts).Path }
    $configuration.lua_acts = $LuaCompiler
    $luaSource = Join-Path $PSScriptRoot '.toolchains\luajit-decompiler-v2'
    & $venvPython (Join-Path $PSScriptRoot 'tools\bootstrap_workstation_lua.py') $luaSource
    if ($LASTEXITCODE -ne 0) { throw 'Replay Lua decompiler source build failed.' }
    $luaReceipt = Get-Content -Raw -LiteralPath (Join-Path $luaSource 'replay-workstation-lua-bootstrap.json') | ConvertFrom-Json
    $setupCache = Join-Path $configuration.cache 'setup'
    New-Item -ItemType Directory -Path $setupCache -Force | Out-Null
    $ownerConfig = Join-Path $setupCache 'owner-inputs.json'
    [ordered]@{ replay_executable=(Join-Path $GameRoot 'game_dx12_ship_replay.exe'); replay_sqlite=$SQLite } |
        ConvertTo-Json | Set-Content -LiteralPath $ownerConfig -Encoding utf8
    & $venvPython (Join-Path $PSScriptRoot 'tools\setup_workstation_tools.py') --owner-config $ownerConfig --acts $LuaCompiler --generate-lua-profile --receipt (Join-Path $setupCache 'asset-toolchain.json')
    if ($LASTEXITCODE -ne 0) { throw 'Target-bound Replay Lua compiler profile generation failed.' }
    & $venvPython (Join-Path $PSScriptRoot 'tools\verify_replay_lua_native_compile.py') --acts $LuaCompiler --replay-exe (Join-Path $GameRoot 'game_dx12_ship_replay.exe') --profile (Join-Path (Split-Path -Parent $LuaCompiler) 'replay120_lua_native.json') --output-dir (Join-Path $setupCache 'lua-native-validation') --receipt (Join-Path $setupCache 'lua-native-validation.json')
    if ($LASTEXITCODE -ne 0) { throw 'Selected Lua compiler failed native Replay compile validation, including the allocator-growth reproducer.' }
    $dxbcSelectionReceiptPath = Join-Path $setupCache 'dxbc-tool-selection.json'
    if (-not $UseLegacyPublicDxbc) {
        $dxbcSource = Join-Path $PSScriptRoot '.toolchains\dxbc-compute-v1'
        $dxbcBootstrapArguments = @((Join-Path $PSScriptRoot 'tools\bootstrap_workstation_dxbc.py'),
            '--destination', $dxbcSource)
        & $venvPython @dxbcBootstrapArguments
        if ($LASTEXITCODE -ne 0) { throw 'Pinned source-built DXBC CLI build or verification failed.' }
    }
    $dxbcSelectionArguments = @((Join-Path $PSScriptRoot 'tools\setup_workstation_tools.py'), '--root', $PSScriptRoot,
        '--select-dxbc', '--receipt', $dxbcSelectionReceiptPath)
    if ($UseLegacyPublicDxbc) { $dxbcSelectionArguments += '--use-public-dxbc' }
    & $venvPython @dxbcSelectionArguments
    if ($LASTEXITCODE -ne 0) { throw 'Selected DXBC CLI failed toolchain receipt and binary hash validation.' }
    $dxbcSelection = (Get-Content -Raw -LiteralPath $dxbcSelectionReceiptPath | ConvertFrom-Json).dxbc_selection
    $toolManifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'tools\workstation_toolchain_manifest.json') | ConvertFrom-Json
    $gscTool = $toolManifest.tools | Where-Object id -eq 'gsc_tool'
    $dxbcTool = $toolManifest.tools | Where-Object id -eq 'dxbc_decompiler'
    $textureTool = $toolManifest.tools | Where-Object id -eq 'texconv'
    $configuration.tools = [ordered]@{
        gsc=@{path=$gscTool.install_path; sha256=$gscTool.member_sha256}
        dxbc=@{path=$dxbcSelection.path; sha256=$dxbcSelection.sha256}
        texconv=@{path=$textureTool.install_path; sha256=$textureTool.sha256}
        luajit_decompiler=@{path=$luaReceipt.executable; sha256=$luaReceipt.sha256}
    }
}
if ($Acts) { $configuration.acts = (Resolve-Path -LiteralPath $Acts).Path }
if ($LuaActs) { $configuration.lua_acts = $LuaActs }
if ($SabGenerator) {
    $sabPath = (Resolve-Path -LiteralPath $SabGenerator).Path
    if (-not $configuration.Contains('tools')) { $configuration.tools = [ordered]@{} }
    $configuration.tools.sab_generator = @{path=$sabPath; sha256=(Get-FileHash -LiteralPath $sabPath -Algorithm SHA256).Hash.ToLowerInvariant()}
}
if ($ZoneToolSource) {
    $zoneSourcePath = (Resolve-Path -LiteralPath $ZoneToolSource).Path
    if (-not (Test-Path -LiteralPath (Join-Path $zoneSourcePath 'src\zonetool\iw8\iw8_zone.cpp') -PathType Leaf)) {
        throw 'The selected ZoneTool source has no native IW8 writer.'
    }
    if (-not $configuration.Contains('tools')) { $configuration.tools = [ordered]@{} }
    $configuration.tools.zonetool_source = @{path=$zoneSourcePath}
}
if ($ScriptSourcePack) {
    $packPath = (Resolve-Path -LiteralPath $ScriptSourcePack).Path
    if (-not $ScriptStringDecryptor) {
        $ScriptStringDecryptor = Join-Path $PSScriptRoot '.toolchains\script-string-decryptor'
        & $venvPython (Join-Path $PSScriptRoot 'tools\bootstrap_workstation_string_decryptor.py') $ScriptStringDecryptor
        if ($LASTEXITCODE -ne 0) { throw 'Pinned script string transform preparation failed.' }
    }
    if (-not $configuration.Contains('tools')) { $configuration.tools = [ordered]@{} }
    $configuration.tools.script_source_pack = @{path=$packPath; sha256=(Get-FileHash -LiteralPath $packPath -Algorithm SHA256).Hash.ToLowerInvariant()}
    $configuration.tools.script_string_decryptor = @{path=(Resolve-Path -LiteralPath $ScriptStringDecryptor).Path}
} elseif ($ScriptStringDecryptor) {
    throw '-ScriptStringDecryptor requires -ScriptSourcePack.'
}

$configuration | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'replay-project.local.json') -Encoding utf8
if ($Start) { & (Join-Path $PSScriptRoot 'start-workstation.ps1') -GameRoot $GameRoot -SQLite $SQLite }
