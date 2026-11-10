#Requires -Version 7.2
<#
.SYNOPSIS
    Pulls Microsoft Secure Score and the per-control breakdown for the tenant.

.DESCRIPTION
    Secure Score is the one number leadership understands, but the useful part is the
    per-control table: what is not implemented, and what it would buy you.
    Exports:
      securescore-summary.txt   current vs max, overall percentage
      securescore-by-category.csv  Identity / Data / Device / Apps / Infrastructure
      securescore-controls.csv    every control with its score and remediation text
      securescore-raw.json        untouched API response

.NOTES
    Read-only. Requires Global Reader (or equivalent read roles) in the target tenant.
    Run in its own session — do not load ScubaGear here (version-pinned Graph Auth).
#>
[CmdletBinding()]
param(
    [string] $OutDir = (Join-Path $PSScriptRoot 'reports'),

    [string] $TenantId = '3177c971-05c9-4b7b-93a1-0edf6fd7237d'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (-not (Get-MgContext)) {
    Connect-MgGraph -TenantId $TenantId -UseDeviceAuthentication -NoWelcome -Scopes @(
        'SecurityEvents.Read.All'   # Secure Score + control profiles (SecurityConfiguration.Read.All is NOT a valid scope)
        'Reports.Read.All'
        'Directory.Read.All'
    )
}

$org = Get-MgOrganization | Select-Object -First 1
Write-Host "Tenant: $($org.DisplayName) ($($org.Id))" -ForegroundColor Cyan

# --- current score ---------------------------------------------------------
$score = Get-MgSecuritySecureScore -Top 1
if (-not $score) { throw 'No Secure Score returned — is this tenant licensed for Microsoft 365 Defender / E5?' }

$pct = if ($score.MaxScore -gt 0) { [math]::Round(100 * $score.CurrentScore / $score.MaxScore, 1) } else { 0 }
$summary = @(
    "Tenant          : $($org.DisplayName) ($($org.Id))"
    "Captured (UTC)  : $((Get-Date).ToUniversalTime().ToString('u'))"
    "Current score   : $($score.CurrentScore)"
    "Max score       : $($score.MaxScore)"
    "Percent         : $pct %"
) -join "`n"

$summary | Set-Content (Join-Path $OutDir 'securescore-summary.txt')
Write-Host $summary -ForegroundColor Green

# --- per-control profiles --------------------------------------------------
$profiles = Get-MgSecuritySecureScoreControlProfile -All
$profiles | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutDir 'securescore-raw.json')

$profiles |
    Select-Object Id, Title, ControlCategory, Service, MaxScore, Tier, ActionType, UserImpact, ImplementationCost, Remediation |
    Sort-Object ControlCategory, Title |
    Export-Csv (Join-Path $OutDir 'securescore-controls.csv') -NoTypeInformation

# --- score by category -----------------------------------------------------
# Only controls present in ControlScores are licensed for this tenant. Iterating
# over the full profile list instead would count unlicensed controls as 0/max and
# make every category look catastrophic (Device 0/1310 etc.).
$byControl = @{}
foreach ($p in $profiles) { $byControl[$p.Id] = $p }

$rows = foreach ($cs in $score.ControlScores) {
    $p = $byControl[$cs.ControlName]
    [pscustomobject]@{
        Category = if ($cs.ControlCategory) { $cs.ControlCategory } else { 'Uncategorised' }
        Control  = if ($p) { $p.Title } else { $cs.ControlName }
        Current  = [double]$cs.Score
        Max      = if ($p) { [double]$p.MaxScore } else { [double]$cs.Score }
    }
}

$rows |
    Group-Object Category |
    ForEach-Object {
        $cur = ($_.Group | Measure-Object Current -Sum).Sum
        $max = ($_.Group | Measure-Object Max -Sum).Sum
        [pscustomobject]@{
            Category  = $_.Name
            Controls  = $_.Count
            Current   = [math]::Round($cur, 1)
            Max       = [math]::Round($max, 1)
            Percent   = if ($max -gt 0) { [math]::Round(100 * $cur / $max, 1) } else { 0 }
        }
    } |
    Sort-Object Percent |
    Export-Csv (Join-Path $OutDir 'securescore-by-category.csv') -NoTypeInformation

Write-Host ''
Write-Host "Written to $OutDir" -ForegroundColor Green
Get-ChildItem $OutDir -Filter 'securescore-*' | Select-Object Name, Length
