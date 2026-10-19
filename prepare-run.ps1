param(
    [ValidatePattern('^replay-compiler-[a-z0-9-]+$')]
    [string]$RunDirectoryName = 'replay-compiler-run',
    [string]$GameRoot,
    [string]$TestProxy,
    [switch]$NoProxy,
    [ValidatePattern('^replay-compiler-frontend-[a-z0-9-]+$')]
    [string]$FrontendInputsFrom,
    [string]$FrontendShaderSource,
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$FrontendShaderSha256,
    [string]$FrontendZoneManifest,
    [string[]]$FrontendMeshManifest,
    [switch]$FrontendNoPso,
    [switch]$EnableCustomMaps,
    [ValidatePattern('^build(-[a-z0-9-]+)?$')]
    [string]$BuildDirectory = 'build'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'tools\prepare_run_custom_maps.ps1')
if ($NoProxy -and $TestProxy) { throw '-NoProxy and -TestProxy are mutually exclusive.' }
if ($EnableCustomMaps -and $NoProxy) { throw '-EnableCustomMaps requires the Replay proxy; it cannot be combined with -NoProxy.' }
if ([bool]$FrontendShaderSource -ne [bool]$FrontendShaderSha256) {
    throw '-FrontendShaderSource and -FrontendShaderSha256 must be supplied together.'
}
if ($FrontendShaderSource -and -not $FrontendInputsFrom) {
    throw 'An alternate frontend shader bundle requires -FrontendInputsFrom.'
}
if ($FrontendZoneManifest -and -not $FrontendInputsFrom) {
    throw 'Frontend zone overrides require -FrontendInputsFrom.'
}
if ($FrontendMeshManifest -and -not $FrontendInputsFrom) {
    throw 'Converted mesh dependencies require an isolated frontend input directory.'
}
if ($FrontendNoPso -and -not $FrontendInputsFrom) {
    throw 'An isolated frontend PSO-free test requires -FrontendInputsFrom.'
}
$meshDirectoryName = $null
if ($FrontendMeshManifest) {
    foreach ($meshManifestPath in $FrontendMeshManifest) {
        $meshManifest = Get-Content -Raw -LiteralPath $meshManifestPath | ConvertFrom-Json
        if ($meshManifest.schema -ne 2 -or [string]$meshManifest.source_version -notmatch '^[1-9][0-9]{0,9}$') {
            throw 'Invalid converted mesh manifest identity.'
        }
        $directoryName = 'replay_mesh_' + [string]$meshManifest.source_version
        if ($meshDirectoryName -and $meshDirectoryName -ne $directoryName) {
            throw 'Converted mesh manifests must share a serialized version.'
        }
        $meshDirectoryName = $directoryName
    }
}
$zoneOverrides = @{}
if ($FrontendZoneManifest) {
    $manifest = Get-Content -Raw -LiteralPath $FrontendZoneManifest | ConvertFrom-Json
    foreach ($entry in $manifest.Files) {
        $name = [string]$entry.Name
        $source = (Resolve-Path -LiteralPath ([string]$entry.Source)).Path
        $hash = [string]$entry.Sha256
        $subdirectory = [string]$entry.Subdirectory
        if ($subdirectory -and $subdirectory -notmatch '^[a-z][a-z0-9_]*$') {
            throw "Unsafe frontend zone subdirectory: $subdirectory"
        }
        $relativeName = if ($subdirectory) { $subdirectory + '/' + $name } else { $name }
        if ($name -notmatch '^[a-z0-9_]+\.(ff|fp|fc|xpak)$' -or
            (Split-Path -Leaf $source) -ne $name -or
            $hash -notmatch '^[0-9a-fA-F]{64}$' -or
            $zoneOverrides.ContainsKey($relativeName) -or
            (Get-FileHash -LiteralPath $source).Hash -ne $hash) {
            throw "Invalid or changed frontend zone override: $name"
        }
        $zoneOverrides[$relativeName] = [pscustomobject]@{Source=$source;Sha256=$hash}
    }
}
if ($FrontendShaderSource) {
    $FrontendShaderSource = (Resolve-Path -LiteralPath $FrontendShaderSource).Path
    if ((Split-Path -Leaf $FrontendShaderSource) -ne 'techsets_replay_frontend_131.ff' -or
        (Get-FileHash -LiteralPath $FrontendShaderSource).Hash -ne $FrontendShaderSha256) {
        throw 'The alternate frontend shader bundle name or hash differs.'
    }
}
$localConfiguration = Join-Path $PSScriptRoot 'replay-project.local.json'
if (-not $GameRoot) { $GameRoot = $env:REPLAY_GAME_ROOT }
if (-not $GameRoot -and (Test-Path -LiteralPath $localConfiguration -PathType Leaf)) {
    $GameRoot = [string](Get-Content -Raw -LiteralPath $localConfiguration | ConvertFrom-Json).game
}
if (-not $GameRoot) { throw 'Select -GameRoot or run setup-workstation.ps1 first.' }
$gameFolder = (Resolve-Path -LiteralPath $GameRoot).Path
if (-not (Test-Path -LiteralPath $gameFolder -PathType Container)) { throw 'GameRoot must be a directory.' }
$runFolder = Join-Path $gameFolder $RunDirectoryName
$artifact = Join-Path (Join-Path $PSScriptRoot $BuildDirectory) 'game_dx12_ship_replay_recompiled.exe'
$report = Get-Content -Raw -LiteralPath (Join-Path (Join-Path $PSScriptRoot $BuildDirectory) 'build-report.json') | ConvertFrom-Json -AsHashtable
if ($FrontendInputsFrom) {
    if (-not $report.frontend_probe -or (Test-Path -LiteralPath $runFolder)) {
        throw 'Frontend input reuse requires a probe build and a fresh runtime directory.'
    }
    $frontendInputs = Join-Path $gameFolder $FrontendInputsFrom
    if (-not (Test-Path -LiteralPath (Join-Path $frontendInputs 'zone') -PathType Container)) {
        throw 'The selected frontend input directory has no staged zone data.'
    }
    foreach ($runtimeName in 'D3D12.dll','D3D12Core.dll','D3D12SDKLayers.dll') {
        if (-not (Test-Path -LiteralPath (Join-Path $frontendInputs $runtimeName) -PathType Leaf)) {
            throw "The selected frontend input directory lacks $runtimeName"
        }
    }
    if (-not $NoProxy -and -not $TestProxy) {
        $frontendProxySource = Join-Path $frontendInputs 'XInput9_1_0.dll'
        if (-not (Test-Path -LiteralPath $frontendProxySource -PathType Leaf)) {
            throw 'The selected frontend input directory lacks XInput9_1_0.dll; supply -TestProxy or use -NoProxy.'
        }
    }
}
if ($report.frontend_probe -and $RunDirectoryName -notlike 'replay-compiler-frontend-*') {
    throw 'A frontend format probe requires an isolated replay-compiler-frontend-* runtime folder.'
}
& python (Join-Path $PSScriptRoot 'tools\source_provenance.py') --build (Join-Path $PSScriptRoot $BuildDirectory)
if ($LASTEXITCODE -ne 0) { throw 'Prepared compilation inputs changed; rebuild before preparing a runtime folder.' }
if ((Get-FileHash -LiteralPath $artifact).Hash -ne $report.sha256) { throw 'Prepared executable hash changed.' }
New-Item -ItemType Directory -Path $runFolder -Force | Out-Null

# Keep the canonical filename used by Replay's startup and proxy target checks.
# Asset directories remain in the game installation through junctions.
foreach ($directory in Get-ChildItem -LiteralPath $gameFolder -Directory) {
    if ($directory.FullName -eq $runFolder -or $directory.Name -like 'replay-compiler-*') { continue }
    if ($directory.Name -eq '.proxy') { continue }
    $destination = Join-Path $runFolder $directory.Name
    if ($FrontendNoPso -and $directory.Name -eq 'main') {
        New-Item -ItemType Directory -Path $destination | Out-Null
        foreach ($input in Get-ChildItem -LiteralPath $directory.FullName) {
            if ($input.PSIsContainer) {
                New-Item -ItemType Junction -Path (Join-Path $destination $input.Name) -Target $input.FullName | Out-Null
            } elseif ($input.Extension -ne '.psob') {
                New-Item -ItemType HardLink -Path (Join-Path $destination $input.Name) -Target $input.FullName | Out-Null
            }
        }
        continue
    }
    if ($FrontendInputsFrom -and $directory.Name -eq 'zone') {
        New-Item -ItemType Directory -Path $destination | Out-Null
        foreach ($input in Get-ChildItem -LiteralPath (Join-Path $frontendInputs 'zone')) {
            # An explicit mesh manifest stages a verified local copy below.
            # Do not first inherit a junction to an older cache of that version.
            if ($input.PSIsContainer -and $input.Name -eq $meshDirectoryName) { continue }
            $inputDestination = Join-Path $destination $input.Name
            if ($input.PSIsContainer) {
                $prefix = $input.Name + '/'
                $hasOverrides = @($zoneOverrides.Keys | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) }).Count -ne 0
                if ($hasOverrides) {
                    # Localized overrides need a private folder. Never copy
                    # them through a junction into the source game install.
                    New-Item -ItemType Directory -Path $inputDestination | Out-Null
                    foreach ($localized in Get-ChildItem -LiteralPath $input.FullName) {
                        $localizedDestination = Join-Path $inputDestination $localized.Name
                        $key = $prefix + $localized.Name
                        if ($localized.PSIsContainer) {
                            New-Item -ItemType Junction -Path $localizedDestination -Target $localized.FullName | Out-Null
                        } elseif ($zoneOverrides.ContainsKey($key)) {
                            Copy-Item -LiteralPath $zoneOverrides[$key].Source -Destination $localizedDestination
                            if ((Get-FileHash -LiteralPath $localizedDestination).Hash -ne $zoneOverrides[$key].Sha256) {
                                throw "Localized frontend copy failed: $key"
                            }
                        } else {
                            New-Item -ItemType HardLink -Path $localizedDestination -Target $localized.FullName | Out-Null
                        }
                    }
                } else {
                    New-Item -ItemType Junction -Path $inputDestination -Target $input.FullName | Out-Null
                }
            } elseif ($zoneOverrides.ContainsKey($input.Name)) {
                Copy-Item -LiteralPath $zoneOverrides[$input.Name].Source -Destination $inputDestination
                if ((Get-FileHash -LiteralPath $inputDestination).Hash -ne $zoneOverrides[$input.Name].Sha256) {
                    throw "Frontend zone override copy failed: $($input.Name)"
                }
            } elseif ($FrontendShaderSource -and $input.Name -eq 'techsets_replay_frontend_131.ff') {
                Copy-Item -LiteralPath $FrontendShaderSource -Destination $inputDestination
                if ((Get-FileHash -LiteralPath $inputDestination).Hash -ne $FrontendShaderSha256) {
                    throw 'Alternate frontend shader bundle copy verification failed.'
                }
            } else {
                New-Item -ItemType HardLink -Path $inputDestination -Target $input.FullName | Out-Null
            }
        }
        foreach ($name in $zoneOverrides.Keys) {
            $overrideDestination = Join-Path $destination $name
            if (-not (Test-Path -LiteralPath $overrideDestination)) {
                $overrideParent = Split-Path -Parent $overrideDestination
                if (-not (Test-Path -LiteralPath $overrideParent)) {
                    New-Item -ItemType Directory -Path $overrideParent | Out-Null
                }
                if ((Get-Item -LiteralPath $overrideParent).LinkType) {
                    throw "Frontend overrides require a private directory: $overrideParent"
                }
                Copy-Item -LiteralPath $zoneOverrides[$name].Source -Destination $overrideDestination
                if ((Get-FileHash -LiteralPath $overrideDestination).Hash -ne $zoneOverrides[$name].Sha256) {
                    throw "Frontend zone override copy failed: $name"
                }
            }
        }
        continue
    }
    if (-not (Test-Path -LiteralPath $destination)) {
        New-Item -ItemType Junction -Path $destination -Target $directory.FullName | Out-Null
    } else {
        $existing = Get-Item -LiteralPath $destination
        if ($existing.LinkType -ne 'Junction' -or $existing.Target -ne $directory.FullName) {
            throw "Existing runtime directory is not the expected junction: $destination"
        }
    }
}
# Keep test requests independent of any control request for the original game.
$controlFolder = Join-Path $runFolder '.proxy'
if (Test-Path -LiteralPath $controlFolder) {
    $existing = Get-Item -LiteralPath $controlFolder
    if ($existing.LinkType) {
        if ($existing.LinkType -ne 'Junction' -or
            $existing.Target -ne (Join-Path $gameFolder '.proxy') -or
            $existing.FullName -ne $controlFolder) {
            throw "Unexpected control directory link: $controlFolder"
        }
        Remove-Item -LiteralPath $controlFolder -Force
    }
}
New-Item -ItemType Directory -Path $controlFolder -Force | Out-Null
foreach ($file in Get-ChildItem -LiteralPath $gameFolder -File) {
    if ($file.Name -like 'game_dx12_ship_replay*' -or
        $file.Name -match '\.(log|pdb|i64|id0|id1|id2|nam|til|sqlite|sqlite-shm|sqlite-wal|json|csv|md|bak)$') {
        continue
    }
    if (($FrontendInputsFrom -or $TestProxy -or $NoProxy) -and $file.Name -ieq 'XInput9_1_0.dll') { continue }
    if ($FrontendInputsFrom -and $file.Name -in @('D3D12.dll','D3D12Core.dll','D3D12SDKLayers.dll')) { continue }
    $destination = Join-Path $runFolder $file.Name
    if (-not (Test-Path -LiteralPath $destination)) {
        if ($file.Extension -eq '.ini') {
            $iniSource = if ($FrontendInputsFrom -and $file.Name -eq 'mw120rproxy.ini') {
                Join-Path $frontendInputs $file.Name
            } else { $file.FullName }
            Copy-Item -LiteralPath $iniSource -Destination $destination
        } else {
            New-Item -ItemType HardLink -Path $destination -Target $file.FullName | Out-Null
        }
    }
}
if ($FrontendInputsFrom) {
    foreach ($runtimeName in 'D3D12.dll','D3D12Core.dll','D3D12SDKLayers.dll') {
        $input = Join-Path $frontendInputs $runtimeName
        $destination = Join-Path $runFolder $runtimeName
        Copy-Item -LiteralPath $input -Destination $destination
        if ((Get-FileHash -LiteralPath $input).Hash -ne (Get-FileHash -LiteralPath $destination).Hash) {
            throw 'Frontend graphics runtime copy verification failed.'
        }
    }
    if (-not $NoProxy -and -not $TestProxy) {
        $proxyDestination = Join-Path $runFolder 'XInput9_1_0.dll'
        $expectedProxyHash = (Get-FileHash -LiteralPath $frontendProxySource -Algorithm SHA256).Hash
        Copy-Item -LiteralPath $frontendProxySource -Destination $proxyDestination
        if ((Get-FileHash -LiteralPath $frontendProxySource -Algorithm SHA256).Hash -ne $expectedProxyHash -or
            (Get-FileHash -LiteralPath $proxyDestination -Algorithm SHA256).Hash -ne $expectedProxyHash) {
            throw 'Frontend proxy copy verification failed.'
        }
    }
}
if ($NoProxy -and (Test-Path -LiteralPath (Join-Path $runFolder 'XInput9_1_0.dll'))) {
    throw 'A proxy-free launch requires a fresh runtime folder without XInput9_1_0.dll.'
}
if ($TestProxy) {
    $proxyDestination = Join-Path $runFolder 'XInput9_1_0.dll'
    if (Test-Path -LiteralPath $proxyDestination) {
        if ((Get-FileHash -LiteralPath $proxyDestination -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $TestProxy -Algorithm SHA256).Hash) {
            throw 'A different test proxy requires a fresh runtime folder.'
        }
    } else {
        $expectedProxyHash = (Get-FileHash -LiteralPath $TestProxy -Algorithm SHA256).Hash
        Copy-Item -LiteralPath $TestProxy -Destination $proxyDestination
        if ((Get-FileHash -LiteralPath $TestProxy -Algorithm SHA256).Hash -ne $expectedProxyHash -or
            (Get-FileHash -LiteralPath $proxyDestination -Algorithm SHA256).Hash -ne $expectedProxyHash) {
            throw 'Test proxy copy verification failed.'
        }
    }
}
$canonical = Join-Path $runFolder 'game_dx12_ship_replay.exe'
if ($FrontendMeshManifest) {
    & python (Join-Path $PSScriptRoot 'tools\stage_frontend_meshes.py') --manifest $FrontendMeshManifest --run-folder $runFolder --hardlink
    if ($LASTEXITCODE -ne 0) { throw 'Converted frontend mesh staging failed.' }
}
Copy-Item -LiteralPath $artifact -Destination $canonical
$expected = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash
if ((Get-FileHash -LiteralPath $canonical -Algorithm SHA256).Hash -ne $expected) {
    throw 'Canonical runtime executable hash mismatch.'
}
if ($EnableCustomMaps) {
    $iniPath = Join-Path $runFolder 'mw120rproxy.ini'
    $validPackageCount = Enable-CustomMapHandoff -IniPath $iniPath -GameFolder $gameFolder -RunFolder $runFolder
    $stagedMapRoot = Join-Path $runFolder 'mods\mw120r\maps'
    Write-Output "Custom maps enabled for the F6 browser: $validPackageCount five-zone package(s) at $stagedMapRoot; selection is available in Multiplayer > Local Play."
}
Write-Output "Prepared $canonical"
