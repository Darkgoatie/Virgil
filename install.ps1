[CmdletBinding()]
param(
    [string[]]$Agent = @("auto"),

    [ValidateSet("global", "project")]
    [string]$Scope = "global",

    [string]$TargetRepo = (Get-Location).Path,

    [switch]$Link,
    [switch]$DryRun,
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SkillName = "virgil"
$RepoRoot = $PSScriptRoot
$SourceDir = Join-Path $RepoRoot "skills\$SkillName"
$SourceSkillMd = Join-Path $SourceDir "SKILL.md"

if (-not (Test-Path -LiteralPath $SourceSkillMd -PathType Leaf)) {
    throw "Source skill not found at: $SourceSkillMd"
}

$ValidAgents = @("claude", "gemini", "antigravity", "hermes", "codex", "cursor", "agents")
$HomeDir = [Environment]::GetFolderPath("UserProfile")

function Get-AgentTargetPath {
    param(
        [string]$AgentKey,
        [string]$TargetScope,
        [string]$ProjectRoot
    )
    if ($TargetScope -eq "global") {
        switch ($AgentKey) {
            "claude"      { return Join-Path $HomeDir ".claude\skills\$SkillName" }
            "gemini"      { return Join-Path $HomeDir ".gemini\skills\$SkillName" }
            "antigravity" { return Join-Path $HomeDir ".gemini\config\skills\$SkillName" }
            "hermes"      { return Join-Path $HomeDir ".hermes\skills\$SkillName" }
            "codex"       { return Join-Path $HomeDir ".codex\skills\$SkillName" }
            "cursor"      { return Join-Path $HomeDir ".cursor\skills\$SkillName" }
            "agents"      { return Join-Path $HomeDir ".agents\skills\$SkillName" }
        }
    } else {
        switch ($AgentKey) {
            "claude"      { return Join-Path $ProjectRoot ".claude\skills\$SkillName" }
            "gemini"      { return Join-Path $ProjectRoot ".gemini\skills\$SkillName" }
            "antigravity" { return Join-Path $ProjectRoot ".agents\skills\$SkillName" }
            "hermes"      { return Join-Path $ProjectRoot ".hermes\skills\$SkillName" }
            "codex"       { return Join-Path $ProjectRoot ".codex\skills\$SkillName" }
            "cursor"      { return Join-Path $ProjectRoot ".cursor\skills\$SkillName" }
            "agents"      { return Join-Path $ProjectRoot ".agents\skills\$SkillName" }
        }
    }
    throw "Unsupported agent key: $AgentKey"
}

function Resolve-AutoAgents {
    param(
        [string]$TargetScope,
        [string]$ProjectRoot
    )
    $selected = [System.Collections.Generic.List[string]]::new()
    if ($TargetScope -eq "global") {
        $checks = @(
            @{ key = "claude";      dir = (Join-Path $HomeDir ".claude") },
            @{ key = "gemini";      dir = (Join-Path $HomeDir ".gemini") },
            @{ key = "antigravity"; dir = (Join-Path $HomeDir ".gemini\config") },
            @{ key = "hermes";      dir = (Join-Path $HomeDir ".hermes") },
            @{ key = "codex";       dir = (Join-Path $HomeDir ".codex") },
            @{ key = "cursor";      dir = (Join-Path $HomeDir ".cursor") },
            @{ key = "agents";      dir = (Join-Path $HomeDir ".agents") }
        )
        foreach ($c in $checks) {
            if (Test-Path -LiteralPath $c.dir -PathType Container) {
                $selected.Add($c.key)
            }
        }
        if ($selected.Count -eq 0) {
            $selected.Add("agents")
        }
    } else {
        $selected.Add("agents")
        $checks = @(
            @{ key = "claude"; dir = (Join-Path $ProjectRoot ".claude") },
            @{ key = "gemini"; dir = (Join-Path $ProjectRoot ".gemini") },
            @{ key = "hermes"; dir = (Join-Path $ProjectRoot ".hermes") },
            @{ key = "codex";  dir = (Join-Path $ProjectRoot ".codex") },
            @{ key = "cursor"; dir = (Join-Path $ProjectRoot ".cursor") }
        )
        foreach ($c in $checks) {
            if (Test-Path -LiteralPath $c.dir -PathType Container) {
                $selected.Add($c.key)
            }
        }
    }
    return $selected.ToArray()
}

if ($Scope -eq "project") {
    if (-not (Test-Path -LiteralPath $TargetRepo -PathType Container)) {
        throw "Target project directory does not exist: $TargetRepo"
    }
    $TargetRepo = (Resolve-Path -LiteralPath $TargetRepo).Path
}

$RawTokens = [System.Collections.Generic.List[string]]::new()
foreach ($item in $Agent) {
    foreach ($part in ($item -split ",")) {
        $trimmed = $part.Trim().ToLowerInvariant()
        if ($trimmed) { $RawTokens.Add($trimmed) }
    }
}

$RequestedAgents = [System.Collections.Generic.List[string]]::new()
foreach ($tok in $RawTokens) {
    if ($tok -eq "all") {
        foreach ($a in $ValidAgents) {
            if (-not $RequestedAgents.Contains($a)) { $RequestedAgents.Add($a) }
        }
    } elseif ($tok -eq "auto") {
        foreach ($a in (Resolve-AutoAgents -TargetScope $Scope -ProjectRoot $TargetRepo)) {
            if (-not $RequestedAgents.Contains($a)) { $RequestedAgents.Add($a) }
        }
    } elseif ($ValidAgents -contains $tok) {
        if (-not $RequestedAgents.Contains($tok)) { $RequestedAgents.Add($tok) }
    } else {
        throw "Unknown agent '$tok'. Valid options: auto, all, $($ValidAgents -join ', ')"
    }
}

$SeenTargets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$Targets = [System.Collections.Generic.List[object]]::new()
foreach ($a in $RequestedAgents) {
    $dest = Get-AgentTargetPath -AgentKey $a -TargetScope $Scope -ProjectRoot $TargetRepo
    $norm = [System.IO.Path]::GetFullPath($dest)
    if ($SeenTargets.Add($norm)) {
        $Targets.Add([pscustomobject]@{
            agent = $a
            path  = $norm
        })
    } else {
        $existing = $Targets | Where-Object { $_.path -eq $norm } | Select-Object -First 1
        if ($existing) {
            $existing.agent = "$($existing.agent),$a"
        }
    }
}

function Remove-ExistingTarget {
    param([string]$TargetPath)
    $item = Get-Item -LiteralPath $TargetPath -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $false }
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        [System.IO.Directory]::Delete($TargetPath, $false)
    } else {
        Remove-Item -LiteralPath $TargetPath -Recurse -Force
    }
    return $true
}

Write-Output "Skill source: $SourceDir"
Write-Output "Scope: $Scope"

foreach ($t in $Targets) {
    $dest = $t.path
    if ($Uninstall) {
        if ($DryRun) {
            Write-Output "[dry-run] uninstall ($($t.agent)): $dest"
            continue
        }
        $removed = Remove-ExistingTarget -TargetPath $dest
        if ($removed) {
            Write-Output "[removed] ($($t.agent)) $dest"
        } else {
            Write-Output "[absent]  ($($t.agent)) $dest"
        }
        continue
    }

    $parent = Split-Path -Parent $dest
    if ($DryRun) {
        $mode = if ($Link) { "link" } else { "copy" }
        Write-Output "[dry-run] $mode ($($t.agent)): $dest"
        continue
    }

    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $parent -Force)
    }
    [void](Remove-ExistingTarget -TargetPath $dest)

    if ($Link) {
        try {
            [void](New-Item -ItemType SymbolicLink -Path $dest -Target $SourceDir -ErrorAction Stop)
            Write-Output "[linked]  ($($t.agent)) $dest -> $SourceDir"
            continue
        } catch {
            try {
                [void](New-Item -ItemType Junction -Path $dest -Target $SourceDir -ErrorAction Stop)
                Write-Output "[linked]  ($($t.agent)) $dest -> $SourceDir (junction)"
                continue
            } catch {
                Write-Warning "Could not link '$dest' ($($_.Exception.Message)); falling back to copy."
            }
        }
    }

    Copy-Item -LiteralPath $SourceDir -Destination $dest -Recurse -Force
    Write-Output "[copied]  ($($t.agent)) $dest"
}
