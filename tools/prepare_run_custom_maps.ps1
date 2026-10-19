function Set-PrivateIniSetting {
    param(
        [Parameter(Mandatory)][ref]$Lines,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Value
    )
    $lineList = $Lines.Value
    $sectionPattern = '^\s*\[' + [regex]::Escape($Section) + '\]\s*$'
    $sectionMatches = @()
    for ($i = 0; $i -lt $lineList.Count; ++$i) {
        if ($lineList[$i] -match $sectionPattern) { $sectionMatches += $i }
    }
    if ($sectionMatches.Count -gt 1) { throw "Staged proxy INI has duplicate [$Section] sections." }
    if ($sectionMatches.Count -eq 0) {
        if ($lineList.Count -and $lineList[$lineList.Count - 1].Trim()) { $lineList.Add('') }
        $lineList.Add("[$Section]")
        $sectionStart = $lineList.Count - 1
    } else {
        $sectionStart = $sectionMatches[0]
    }
    $sectionEnd = $lineList.Count
    for ($i = $sectionStart + 1; $i -lt $lineList.Count; ++$i) {
        if ($lineList[$i] -match '^\s*\[[^\]]+\]\s*$') { $sectionEnd = $i; break }
    }
    $keyPattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $keyMatches = @()
    for ($i = $sectionStart + 1; $i -lt $sectionEnd; ++$i) {
        if ($lineList[$i] -match $keyPattern) { $keyMatches += $i }
    }
    if ($keyMatches.Count) {
        $lineList[$keyMatches[0]] = $Key + '=' + $Value
        for ($i = $keyMatches.Count - 1; $i -ge 1; --$i) {
            $lineList.RemoveAt($keyMatches[$i])
        }
    } else {
        $lineList.Insert($sectionEnd, $Key + '=' + $Value)
    }
}

function Enable-CustomMapHandoff {
    param(
        [Parameter(Mandatory)][string]$IniPath,
        [Parameter(Mandatory)][string]$GameFolder,
        [Parameter(Mandatory)][string]$RunFolder
    )
    $iniItem = Get-Item -LiteralPath $IniPath -Force -ErrorAction Stop
    if (($iniItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Custom-map settings require a private staged mw120rproxy.ini file.'
    }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.AddRange([string[]][IO.File]::ReadAllLines($IniPath))
    Set-PrivateIniSetting -Lines ([ref]$lines) -Section 'mw120rproxy' -Key 'custom_map_loader' -Value '1'
    Set-PrivateIniSetting -Lines ([ref]$lines) -Section 'mw120rproxy' -Key 'developer_ui' -Value '1'

    # Write a new inode and rename it into place. Even if a staged INI was
    # accidentally hard-linked, this cannot change the source game's config.
    $temporaryIni = $IniPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllLines($temporaryIni, $lines.ToArray(), [Text.Encoding]::Default)
        Move-Item -LiteralPath $temporaryIni -Destination $IniPath -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryIni) { Remove-Item -LiteralPath $temporaryIni -Force }
    }
    $settings = [IO.File]::ReadAllText($IniPath)
    foreach ($key in 'custom_map_loader', 'developer_ui') {
        $keyPattern = '^\s*' + [regex]::Escape($key) + '\s*=\s*1\s*$'
        $sectionText = [regex]::Match($settings, '(?ims)^\s*\[mw120rproxy\]\s*(.*?)(?=^\s*\[|\z)').Groups[1].Value
        if ($sectionText -notmatch ('(?im)' + $keyPattern)) {
            throw "Failed to enable $key in the staged proxy INI."
        }
    }

    $modsSource = Join-Path $GameFolder 'mods'
    $modsStaged = Join-Path $RunFolder 'mods'
    $modsItem = Get-Item -LiteralPath $modsStaged -Force -ErrorAction Stop
    $modsTarget = [string]$modsItem.Target
    if ($modsItem.LinkType -ne 'Junction' -or
        -not [string]::Equals($modsTarget.TrimEnd('\'), $modsSource.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Custom maps require the staged mods junction to target the game mods directory: $modsStaged"
    }

    $sourceMapRoot = Join-Path $modsSource 'mw120r\maps'
    $stagedMapRoot = Join-Path $modsStaged 'mw120r\maps'
    if (-not (Test-Path -LiteralPath $sourceMapRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $stagedMapRoot -PathType Container)) {
        throw 'Custom map selection requires <game>\mods\mw120r\maps and its staged junction path.'
    }
    # The exact junction target was checked above. Resolve-Path does not
    # canonicalize junctions consistently across Windows PowerShell versions,
    # so confirm both concrete child paths exist under that verified link.

    # Match the proxy's package ID and required zone-family contract. The
    # proxy still performs full Replay-header validation before it lists a map.
    $validPackageCount = 0
    foreach ($package in Get-ChildItem -LiteralPath $sourceMapRoot -Directory) {
        $id = $package.Name
        if ($id -notmatch '^mp_[a-z0-9_]{1,12}$') { continue }
        $zones = @($id, ('srv_' + $id), ('eng_' + $id), ('ww_' + $id), ('techsets_' + $id))
        $complete = $true
        foreach ($zone in $zones) {
            if (-not (Test-Path -LiteralPath (Join-Path $package.FullName ($zone + '.ff')) -PathType Leaf)) {
                $complete = $false
                break
            }
        }
        if ($complete) { ++$validPackageCount }
    }
    if (-not $validPackageCount) {
        throw "No custom map package with all five native zone files is available to select under $sourceMapRoot."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $RunFolder 'XInput9_1_0.dll') -PathType Leaf)) {
        throw 'Custom-map selection requires the staged Replay proxy XInput9_1_0.dll.'
    }
    return $validPackageCount
}

