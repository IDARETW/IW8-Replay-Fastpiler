param(
    [switch]$CppOnly,
    [switch]$NoDeploy,
    [switch]$NoProxy,
    [switch]$Grow,
    [switch]$DeployPreparedSiblings,
    [switch]$DeployOnly,
    [ValidatePattern('^build(-[a-z0-9-]+)?$')]
    [string]$BuildDirectory = 'build',
    [string]$CompilerProxy,
    [string]$ProxySource = '',
    [string]$GameRoot = ''
)

$ErrorActionPreference = 'Stop'

$localConfiguration = @{}
$localConfigurationPath = Join-Path $PSScriptRoot 'replay-project.local.json'
if (Test-Path -LiteralPath $localConfigurationPath) {
    $localConfiguration = Get-Content -LiteralPath $localConfigurationPath -Raw | ConvertFrom-Json -AsHashtable
}
if (-not $GameRoot) { $GameRoot = $env:REPLAY_GAME_ROOT }
if (-not $GameRoot) { $GameRoot = $localConfiguration.game }
if (-not $GameRoot) { throw 'Set -GameRoot or run setup-workstation.ps1 first.' }
$gameFolder = (Resolve-Path -LiteralPath $GameRoot).Path
if (-not $ProxySource) { $ProxySource = $env:REPLAY_PROXY_SOURCE }
if (-not $ProxySource) { $ProxySource = $localConfiguration.proxy_source }
if ($ProxySource) {
    $ProxySource = (Resolve-Path -LiteralPath $ProxySource).Path
    $env:REPLAY_PROXY_SOURCE = $ProxySource
} elseif (-not $NoProxy -and -not $CompilerProxy) {
    throw 'Set -ProxySource, supply -CompilerProxy, or select -NoProxy.'
}
$env:REPLAY_GAME_ROOT = $gameFolder
if ($localConfiguration.sqlite -and -not $env:REPLAY_SQLITE) { $env:REPLAY_SQLITE = $localConfiguration.sqlite }
$outputFolder = Join-Path $PSScriptRoot $BuildDirectory
foreach ($test in 'backend_tests.py', 'layout_tests.py', 'image_reference_tests.py', 'source_provenance_tests.py') {
    & python (Join-Path $PSScriptRoot "tools\$test")
    if ($LASTEXITCODE -ne 0) { throw "Replay checks failed: $test" }
}
if (-not $DeployOnly) {
    $buildArguments = @((Join-Path $PSScriptRoot 'tools\build.py'), '--output', $BuildDirectory)
    if ($CppOnly) { $buildArguments += '--skip-assembly' }
    if ($Grow) { $buildArguments += '--grow' }
    & python @buildArguments
    if ($LASTEXITCODE -ne 0) { throw 'Replay source build failed.' }
    & python (Join-Path $PSScriptRoot 'tools\verify.py') --build $outputFolder
    if ($LASTEXITCODE -ne 0) { throw 'Replay verification failed; nothing was deployed.' }
    & python (Join-Path $PSScriptRoot 'tools\audit_relocations.py') --build $outputFolder
    if ($LASTEXITCODE -ne 0) { throw 'Replay relocation audit failed; nothing was deployed.' }

}

$artifact = Join-Path $outputFolder 'game_dx12_ship_replay_recompiled.exe'
$report = Get-Content -LiteralPath (Join-Path $outputFolder 'build-report.json') -Raw | ConvertFrom-Json -AsHashtable
& python (Join-Path $PSScriptRoot 'tools\source_provenance.py') --build $outputFolder
if ($LASTEXITCODE -ne 0) { throw 'Prepared compilation inputs changed; rebuild before deployment.' }
if ($DeployOnly) {
    $verified = Get-Content -Raw -LiteralPath (Join-Path $outputFolder 'verification-report.json') | ConvertFrom-Json -AsHashtable
    $audited = Get-Content -Raw -LiteralPath (Join-Path $outputFolder 'relocation-audit.json') | ConvertFrom-Json -AsHashtable
    if ($verified.sha256 -ne $report.sha256 -or $verified.unresolved_symbols -ne 0 -or
        -not $audited.passed -or $audited.sha256 -ne $report.sha256 -or
        (Get-FileHash -LiteralPath $artifact).Hash -ne $report.sha256) { throw 'Prepared executable has no matching successful verification and relocation audit.' }
    foreach ($source in @($report.cpp) + @($report.assembly) + @($report.native_assembly)) {
        if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $source.source)).Hash -ne $source.source_sha256 -or
            (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $source.object)).Hash -ne $source.object_sha256) {
            throw 'Prepared source/object hashes changed; rebuild before deployment.'
        }
    }
}
$proxyHash = $null
$builtProxy = $false
if (-not $NoProxy) {
    if (-not $CompilerProxy) {
        # The linker regenerated replay_patterns.inc for this executable.
        # Build the owner proxy from those signatures before deployment.
        Push-Location -LiteralPath $ProxySource
        $priorLinkOptions = $env:_LINK_
        try {
            $env:_LINK_ = '/DEBUG:NONE /INCREMENTAL:NO'
            & xmake f -m debug -a x64 --replay_compiler_keep_crash_markers=n -y
            if ($LASTEXITCODE -ne 0) { throw 'Proxy configuration failed.' }
            foreach ($target in 'mw120rproxy', 'replay-pattern-tests', 'replay-compiler-target-tests') {
                & xmake build $target
                if ($LASTEXITCODE -ne 0) { throw "Proxy build failed: $target" }
            }
            & xmake run replay-pattern-tests
            if ($LASTEXITCODE -ne 0) { throw 'Proxy scanner/cache checks failed.' }
            & xmake run replay-compiler-target-tests $artifact
            if ($LASTEXITCODE -ne 0) { throw 'Proxy compiled-image checks failed.' }
        } finally {
            $env:_LINK_ = $priorLinkOptions
            Pop-Location
        }
        $CompilerProxy = Join-Path $ProxySource 'xmake-out\x64\Debug\XInput9_1_0.dll'
        $builtProxy = $true
    }
    $proxyHash = (Get-FileHash -LiteralPath $CompilerProxy -Algorithm SHA256).Hash.ToLowerInvariant()
}
if ($NoDeploy) { return }

# Both deployed EXEs share the root proxy. Validate any still-current sibling
# before changing that DLL, then refresh its recorded proxy hash as well.
$compatibleDeployments = @()
if ($builtProxy) {
    Push-Location -LiteralPath $ProxySource
    try {
        foreach ($directory in Get-ChildItem -LiteralPath $PSScriptRoot -Directory -Filter 'build*') {
            if ($directory.FullName -eq $outputFolder) { continue }
            $file = Join-Path $directory.FullName 'deployment.json'
            if (-not (Test-Path -LiteralPath $file)) { continue }
            $previous = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
            if (-not $previous.ProxySha256 -or
                (Split-Path -Parent $previous.Executable) -ne $gameFolder -or
                -not (Test-Path -LiteralPath $previous.Executable) -or
                (Get-FileHash -LiteralPath $previous.Executable).Hash -ne $previous.Sha256) { continue }
            $selectedArtifact = $previous.Executable
            if ($DeployPreparedSiblings) {
                $candidate = Join-Path $directory.FullName 'game_dx12_ship_replay_recompiled.exe'
                $candidateReport = Join-Path $directory.FullName 'build-report.json'
                $candidateVerification = Join-Path $directory.FullName 'verification-report.json'
                $candidateAudit = Join-Path $directory.FullName 'relocation-audit.json'
                if (-not (Test-Path -LiteralPath $candidateReport) -or
                    -not (Test-Path -LiteralPath $candidateVerification) -or
                    -not (Test-Path -LiteralPath $candidateAudit) -or
                    -not (Test-Path -LiteralPath $candidate)) { throw 'Prepared sibling has no verified build.' }
                $candidateBuild = Get-Content -Raw -LiteralPath $candidateReport | ConvertFrom-Json -AsHashtable
                $verification = Get-Content -Raw -LiteralPath $candidateVerification | ConvertFrom-Json -AsHashtable
                $audit = Get-Content -Raw -LiteralPath $candidateAudit | ConvertFrom-Json -AsHashtable
                if ($candidateBuild.sha256 -ne $verification.sha256 -or
                    -not $audit.passed -or $audit.sha256 -ne $candidateBuild.sha256 -or
                    (Get-FileHash -LiteralPath $candidate).Hash -ne $candidateBuild.sha256 -or
                    $verification.unresolved_symbols -ne 0) { throw 'Prepared sibling build/verification hashes disagree.' }
                foreach ($source in @($candidateBuild.cpp) + @($candidateBuild.assembly) + @($candidateBuild.native_assembly)) {
                    $sourcePath = Join-Path $PSScriptRoot $source.source
                    if ((Get-FileHash -LiteralPath $sourcePath).Hash -ne $source.source_sha256 -or
                        (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $source.object)).Hash -ne $source.object_sha256) {
                        throw 'Prepared sibling source/object changed; rebuild it before deployment.'
                    }
                }
                $selectedArtifact = $candidate
                $previous.Sha256 = $candidateBuild.sha256
            }
            & xmake run replay-compiler-target-tests $selectedArtifact
            if ($LASTEXITCODE -ne 0) { throw 'New proxy does not support the existing sibling Replay deployment.' }
            $compatibleDeployments += [pscustomobject]@{ File = $file; Record = $previous; Source = $selectedArtifact }
        }
    } finally { Pop-Location }
}

# A loaded EXE/DLL prevents atomic replacement on Windows. Finish source and
# compatibility checks first, then refuse a mixed deployment while a game runs.
foreach ($running in Get-CimInstance Win32_Process -Filter "Name LIKE 'game_dx12_ship_replay%'") {
    if ($running.ExecutablePath -and $running.ExecutablePath.StartsWith($gameFolder + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Replay is running from the game installation; close it before deployment.'
    }
}

function Install-Artifact([string]$Source, [string]$Destination) {
    $expected = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
    $temporary = $Destination + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        Copy-Item -LiteralPath $Source -Destination $temporary
        if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ne $expected) {
            throw "Artifact copy hash mismatch: $Destination"
        }
        # Replace the directory entry, preserving old runtime hard links.
        [System.IO.File]::Move($temporary, $Destination, $true)
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
    }
    if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -ne $expected) {
        throw "Artifact deployment hash mismatch: $Destination"
    }
}

$name = if ($BuildDirectory -eq 'build') { 'game_dx12_ship_replay_recompiled.exe' } else { 'game_dx12_ship_replay_recompiled_shifted.exe' }
$destination = Join-Path $gameFolder $name
Install-Artifact $artifact $destination
if ($NoProxy) {
    # Windows loads a local DLL from the executable directory regardless of cwd.
    # Keep a proxy-free launch separate from the installation's normal DLL.
    $runDirectoryName = 'replay-compiler-native-' + $report.sha256.Substring(0, 12)
    & (Join-Path $PSScriptRoot 'prepare-run.ps1') -RunDirectoryName $runDirectoryName -BuildDirectory $BuildDirectory -NoProxy
    $destination = Join-Path (Join-Path $gameFolder $runDirectoryName) 'game_dx12_ship_replay.exe'
} else {
    $proxyDestination = Join-Path $gameFolder 'XInput9_1_0.dll'
    $backup = Join-Path $PSScriptRoot 'evidence\original-XInput9_1_0.dll'
    New-Item -ItemType Directory -Path (Split-Path -Parent $backup) -Force | Out-Null
    if ((Test-Path -LiteralPath $proxyDestination) -and -not (Test-Path -LiteralPath $backup)) {
        Copy-Item -LiteralPath $proxyDestination -Destination $backup
    }
    # All siblings were validated against this proxy before replacing any of
    # their artifacts. Deploy prepared C++ updates as one supported cohort.
    foreach ($sibling in $compatibleDeployments) {
        if ($sibling.Source -ne $sibling.Record.Executable) {
            Install-Artifact $sibling.Source $sibling.Record.Executable
        }
    }
    Install-Artifact $CompilerProxy $proxyDestination
    foreach ($sibling in $compatibleDeployments) {
        if ((Get-FileHash -LiteralPath $sibling.Record.Executable).Hash -eq $sibling.Record.Sha256) {
            $sibling.Record.ProxySha256 = $proxyHash
            $sibling.Record | ConvertTo-Json | Set-Content -LiteralPath $sibling.File -Encoding utf8
        }
    }
}
[pscustomobject]@{
    Executable = $destination
    Sha256 = $report.sha256
    ProxySha256 = $proxyHash
    WorkingDirectory = $gameFolder
    BuildDirectory = $BuildDirectory
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outputFolder 'deployment.json') -Encoding utf8
Write-Output "Deployed $destination"
Write-Output "SHA256 $($report.sha256)"
if ($proxyHash) { Write-Output "Proxy SHA256 $proxyHash" }
