[CmdletBinding()]
param(
    [ValidateSet("text", "json")]
    [string]$Format = "text"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Repo = "Darkgoatie/Virgil"
$Branch = "main"
$CommitApiUrl = "https://api.github.com/repos/$Repo/commits/$Branch"
$VersionRawUrl = "https://raw.githubusercontent.com/$Repo/$Branch/skills/virgil/VERSION"
$TimeoutSec = 4
$UserAgent = "virgil-skill-update-check"

$SkillDir = Split-Path -Parent $PSScriptRoot

$LocalVer = "unknown"
$VerPath = Join-Path $SkillDir "VERSION"
if (Test-Path -LiteralPath $VerPath -PathType Leaf) {
    $rawVer = (Get-Content -LiteralPath $VerPath -Raw).Trim()
    if ($rawVer) { $LocalVer = $rawVer }
}

$LocalSha = ""
$MarkerPath = Join-Path $SkillDir ".installed-commit"
if (Test-Path -LiteralPath $MarkerPath -PathType Leaf) {
    $rawMarker = (Get-Content -LiteralPath $MarkerPath -Raw).Trim()
    if ($rawMarker) { $LocalSha = $rawMarker }
}
if (-not $LocalSha) {
    try {
        $gitCmd = Get-Command git -ErrorAction SilentlyContinue
        if ($gitCmd) {
            $gitOut = & git -C $SkillDir rev-parse HEAD 2>$null
            if ($LASTEXITCODE -eq 0 -and $gitOut) {
                $LocalSha = "$gitOut".Trim()
            }
        }
    } catch {
        $LocalSha = ""
    }
}

$RemoteSha = ""
$RemoteVer = "unknown"
$Status = "skipped"
$Message = ""

try {
    $headers = @{
        "User-Agent" = $UserAgent
        "Accept"     = "application/vnd.github+json"
    }
    $commitResp = Invoke-RestMethod -Uri $CommitApiUrl -Headers $headers -TimeoutSec $TimeoutSec -Method Get
    $RemoteSha = "$($commitResp.sha)".Trim()
    if (-not $RemoteSha) {
        throw "Missing commit sha in GitHub response"
    }

    try {
        $verResp = Invoke-RestMethod -Uri $VersionRawUrl -Headers @{ "User-Agent" = $UserAgent } -TimeoutSec $TimeoutSec -Method Get
        $verTrim = "$verResp".Trim()
        if ($verTrim) { $RemoteVer = $verTrim }
    } catch {
        $RemoteVer = "unknown"
    }

    $ShortRemote = $RemoteSha.Substring(0, [Math]::Min(7, $RemoteSha.Length))
    if ($LocalSha) {
        $ShortLocal = $LocalSha.Substring(0, [Math]::Min(7, $LocalSha.Length))
        if ($LocalSha -eq $RemoteSha) {
            $Status = "up_to_date"
            $Message = "[UP TO DATE] virgil v$LocalVer ($ShortLocal) matches $Repo@$Branch."
        } else {
            $Status = "update_available"
            $Message = "[UPDATE AVAILABLE] virgil local=v$LocalVer ($ShortLocal) vs remote=v$RemoteVer ($ShortRemote). Update from the Virgil clone with: git pull && .\install.ps1 (or ./install.sh)"
        }
    } elseif ($RemoteVer -ne "unknown" -and $LocalVer -ne $RemoteVer) {
        $Status = "update_available"
        $Message = "[UPDATE AVAILABLE] virgil local=v$LocalVer vs remote=v$RemoteVer ($ShortRemote). Update from the Virgil clone with: git pull && .\install.ps1 (or ./install.sh)"
    } elseif ($RemoteVer -ne "unknown") {
        $Status = "up_to_date"
        $Message = "[UP TO DATE] virgil v$LocalVer matches $Repo@$Branch ($ShortRemote)."
    } else {
        $Status = "skipped"
        $Message = "[UPDATE CHECK SKIPPED] Local commit unknown and remote VERSION unavailable."
    }
} catch {
    $Status = "skipped"
    $Message = "[UPDATE CHECK SKIPPED] Could not reach GitHub ($($_.Exception.GetType().Name)). Continuing offline."
}

if ($Format -eq "json") {
    $payload = [ordered]@{
        status         = $Status
        repo           = $Repo
        branch         = $Branch
        local_version  = $LocalVer
        remote_version = $RemoteVer
        local_commit   = $(if ($LocalSha) { $LocalSha } else { $null })
        remote_commit  = $(if ($RemoteSha) { $RemoteSha } else { $null })
        message        = $Message
    }
    $payload | ConvertTo-Json -Depth 4
} else {
    Write-Output $Message
}

exit 0
