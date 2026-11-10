#Requires -Version 7.2
<#
.SYNOPSIS
    Finishing analysis for the ARTEX-era M365 posture report.

.DESCRIPTION
    Closes the three gaps the first pass left open:
      A. Resolves every Conditional Access exclusion GUID to a user/group/role, and
         expands group membership — this decides whether the *enabled* MFA policies
         actually cover the admins who have no MFA registered.
      B. Recomputes Secure Score by category using only controls present in
         $score.ControlScores (i.e. licensed ones). The first-pass category CSV is
         invalid: it summed max scores for unlicensed controls.
      C. Cross-references privileged roles against MFA registration.

    Requires an active Graph session — run .\0-Connect-DeviceCode.ps1 first in the
    same window.

.EXAMPLE
    .\4-Analyze.ps1
#>
[CmdletBinding()]
param(
    [string] $OutDir = (Join-Path $PSScriptRoot 'reports')
)

$ErrorActionPreference = 'Stop'

if (-not (Get-MgContext)) {
    throw 'No Graph session. Run .\0-Connect-DeviceCode.ps1 first, in this same window.'
}

$md = [System.Collections.Generic.List[string]]::new()
function Add-Md { param([string[]] $Lines) $md.AddRange($Lines) }

# ==========================================================================
# A. Conditional Access exclusions
# ==========================================================================
Write-Host '[A] Resolving CA exclusions...' -ForegroundColor Cyan

$policies = Get-MgIdentityConditionalAccessPolicy -All
$excludedIds = $policies |
    ForEach-Object { $_.Conditions.Users.ExcludeUsers } |
    Where-Object { $_ } |
    Sort-Object -Unique

$resolved = foreach ($id in $excludedIds) {
    $type = 'unknown'; $name = '(unresolved)'
    try {
        $u = Get-MgUser -UserId $id -ErrorAction Stop
        $type = 'user'; $name = $u.UserPrincipalName
    }
    catch {
        try {
            $g = Get-MgGroup -GroupId $id -ErrorAction Stop
            $type = 'group'; $name = "$($g.DisplayName) [$($g.Id)]"
        }
        catch { }
    }
    [pscustomobject]@{ Id = $id; Type = $type; Name = $name }
}
$resolved | Export-Csv (Join-Path $OutDir 'entra-ca-exclusions.csv') -NoTypeInformation

# Expand group membership so we can see WHO is carved out of protection.
$members = foreach ($g in $resolved | Where-Object Type -eq 'group') {
    try {
        foreach ($m in Get-MgGroupMember -GroupId $g.Id -All) {
            [pscustomobject]@{
                Group = $g.Name
                Who   = $m.AdditionalProperties['userPrincipalName']
                Name  = $m.AdditionalProperties['displayName']
                Type  = $m.AdditionalProperties['@odata.type']
            }
        }
    }
    catch { Write-Host "    could not expand $($g.Name): $($_.Exception.Message)" -ForegroundColor Yellow }
}
$members | Export-Csv (Join-Path $OutDir 'entra-ca-exclusion-members.csv') -NoTypeInformation

# Per-policy view: is an exclusion a group that holds admins?
$byId = @{}
foreach ($r in $resolved) { $byId[$r.Id] = $r }

Add-Md '# Analysis appendix', ''
Add-Md '## A. Conditional Access exclusions (resolved)', ''
Add-Md '| Policy | State | Excludes | Type | Name |'
Add-Md '| --- | --- | --- | --- | --- |'
foreach ($p in $policies | Sort-Object State, DisplayName) {
    $ex = $p.Conditions.Users.ExcludeUsers
    if (-not $ex) { $ex = @('(none)') }
    foreach ($e in $ex) {
        $r = $byId[$e]
        Add-Md ("| {0} | {1} | {2} | {3} | {4} |" -f $p.DisplayName, $p.State, $e, $(if ($r) { $r.Type } else { '-' }), $(if ($r) { $r.Name } else { '-' }))
    }
}

if ($members) {
    Add-Md ''
    Add-Md '### Members of excluded groups'
    Add-Md ''
    Add-Md '| Group | UPN | Display name |'
    Add-Md '| --- | --- | --- |'
    foreach ($m in $members) { Add-Md ("| {0} | {1} | {2} |" -f $m.Group, $m.Who, $m.Name) }
}

# ==========================================================================
# B. Secure Score — licensed controls only
# ==========================================================================
Write-Host '[B] Recomputing Secure Score by category...' -ForegroundColor Cyan

$score    = Get-MgSecuritySecureScore -Top 1
$profiles = Get-MgSecuritySecureScoreControlProfile -All
$byControl = @{}
foreach ($p in $profiles) { $byControl[$p.Id] = $p }

$gaps = foreach ($c in $score.ControlScores) {
    $p = $byControl[$c.ControlName]
    $max = if ($p) { [double]$p.MaxScore } else { [double]$c.Score }
    [pscustomobject]@{
        Control  = if ($p) { $p.Title } else { $c.ControlName }
        Category = if ($c.ControlCategory) { $c.ControlCategory } else { if ($p) { $p.ControlCategory } else { 'Uncategorised' } }
        Current  = [double]$c.Score
        Max      = $max
        Gap      = [math]::Round($max - [double]$c.Score, 1)
        Remediation = if ($p) { $p.Remediation } else { '' }
    }
}

$gaps | Sort-Object Gap -Descending | Export-Csv (Join-Path $OutDir 'securescore-gaps.csv') -NoTypeInformation

$catRows = $gaps | Group-Object Category | ForEach-Object {
    $cur = ($_.Group | Measure-Object Current -Sum).Sum
    $max = ($_.Group | Measure-Object Max -Sum).Sum
    [pscustomobject]@{
        Category = $_.Name
        Controls = $_.Count
        Current  = [math]::Round($cur, 1)
        Max      = [math]::Round($max, 1)
        Percent  = if ($max -gt 0) { [math]::Round(100 * $cur / $max, 1) } else { 0 }
    }
}
# Overwrite the invalid first-pass file.
$catRows | Sort-Object Percent | Export-Csv (Join-Path $OutDir 'securescore-by-category.csv') -NoTypeInformation

$totCur = ($gaps | Measure-Object Current -Sum).Sum
$totMax = ($gaps | Measure-Object Max -Sum).Sum

Add-Md ''
Add-Md '## B. Secure Score by category (licensed controls only)', ''
Add-Md ("Total: **{0} / {1}** ({2}%)" -f [math]::Round($totCur, 1), [math]::Round($totMax, 1), [math]::Round(100 * $totCur / $totMax, 1))
Add-Md ''
Add-Md '| Category | Controls | Current | Max | Percent |'
Add-Md '| --- | --- | --- | --- | --- |'
foreach ($r in $catRows | Sort-Object Percent) { Add-Md ("| {0} | {1} | {2} | {3} | {4}% |" -f $r.Category, $r.Controls, $r.Current, $r.Max, $r.Percent) }

Add-Md ''
Add-Md '### Top 15 controls by points available'
Add-Md ''
Add-Md '| Control | Category | Now | Max | Gap |'
Add-Md '| --- | --- | --- | --- | --- |'
foreach ($g in $gaps | Sort-Object Gap -Descending | Select-Object -First 15) {
    Add-Md ("| {0} | {1} | {2} | {3} | {4} |" -f $g.Control, $g.Category, $g.Current, $g.Max, $g.Gap)
}

# ==========================================================================
# C. Privileged roles vs MFA
# ==========================================================================
Write-Host '[C] Cross-referencing admin roles with MFA...' -ForegroundColor Cyan

$adminRows = Import-Csv (Join-Path $OutDir 'entra-admin-roles.csv')
$mfaRows   = Import-Csv (Join-Path $OutDir 'entra-mfa-registration.csv')
$mfaByUpn  = @{}
foreach ($m in $mfaRows) { $mfaByUpn[$m.UserPrincipalName.ToLower()] = $m }

$adminMfa = foreach ($a in $adminRows) {
    $upn = if ($a.UPN) { $a.UPN.ToLower() } else { '' }
    $m = $mfaByUpn[$upn]
    [pscustomobject]@{
        Role        = $a.Role
        Name        = $a.Name
        UPN         = $a.UPN
        Type        = $a.Type
        MfaRegistered = if ($m) { $m.IsMfaRegistered } else { 'unknown' }
        Passwordless  = if ($m) { $m.IsPasswordlessCapable } else { 'unknown' }
    }
}
$adminMfa | Export-Csv (Join-Path $OutDir 'entra-admin-mfa.csv') -NoTypeInformation

$privWithoutMfa = $adminMfa | Where-Object { $_.Type -eq '#microsoft.graph.user' -and $_.MfaRegistered -eq 'False' }

Add-Md ''
Add-Md '## C. Privileged accounts vs MFA', ''
Add-Md '| Role | Account | MFA registered | Passwordless capable |'
Add-Md '| --- | --- | --- | --- |'
foreach ($a in $adminMfa | Sort-Object Role, Name) {
    Add-Md ("| {0} | {1} | {2} | {3} |" -f $a.Role, $a.Name, $a.MfaRegistered, $a.Passwordless)
}
Add-Md ''
Add-Md ("**$($privWithoutMfa.Count) privileged user account(s) have no MFA registered.**")

# ==========================================================================
$outFile = Join-Path $OutDir 'analysis-summary.md'
$md | Set-Content $outFile -Encoding utf8

Write-Host ''
Write-Host "Written: $outFile" -ForegroundColor Green
Get-ChildItem $OutDir -Filter '*.csv' | Select-Object Name, Length
