#Requires -Version 7.2
<#
.SYNOPSIS
    SharePoint / OneDrive sharing posture, and the Copilot oversharing exposure
    that follows from it.

.DESCRIPTION
    Copilot answers with whatever the signed-in user can already read. It does not
    invent access, but it does *surface* it: a site shared with "Everyone" has been
    a quiet problem for years and becomes a loud one the day Copilot summarises it.
    That makes sharing settings the real Copilot security control.

    Connects to the SharePoint admin endpoint — run in its own window.

.NOTES
    Read-only. Requires SharePoint Administrator (or Global Administrator).
    Install the module if missing:
      Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
.EXAMPLE
    .\8-Get-SharingPosture.ps1
#>
[CmdletBinding()]
param(
    [string] $OutDir    = (Join-Path $PSScriptRoot 'reports'),
    [string] $AdminUrl  = 'https://newporthighptsa-admin.sharepoint.com'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop
# -UseSystemBrowser: sign in through the normal browser rather than the embedded webview,
# which fails on this machine. The SPO module has no device-code switch.
try {
    Connect-SPOService -Url $AdminUrl -UseSystemBrowser:$true
}
catch {
    # A failed connect is a coverage gap. Record it so the report says so instead of
    # reading the missing CSVs as "not yet collected".
    $marker = Join-Path $OutDir 'skipped-SharePoint-sharing.txt'
    "not measured: SharePoint sharing (8-Get-SharingPosture.ps1)`nreason: Connect-SPOService failed: $($_.Exception.Message)" |
        Set-Content $marker -Encoding utf8
    Write-Host "SharePoint sign-in failed - recorded as a coverage gap in $marker" -ForegroundColor Yellow
    return
}

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param([string] $Setting, $Value, [string] $Verdict)
    $findings.Add([pscustomobject]@{ Setting = $Setting; Value = $Value; Verdict = $Verdict })
}

# --- tenant-level sharing --------------------------------------------------
Write-Host '[1/2] Tenant sharing settings' -ForegroundColor Cyan
$t = Get-SPOTenant

# 0 = Disabled, 1 = ExistingExternalUserSharingOnly, 2 = ExternalUserSharingOnly,
# 3 = ExternalUserAndGuestSharing (most permissive)
$sharingLabel = switch ($t.SharingCapability) {
    0 { 'Disabled' }
    1 { 'Existing external users only' }
    2 { 'New and existing external users' }
    3 { 'Anyone (most permissive)' }
    default { "$($t.SharingCapability)" }
}

Add-Finding 'SharingCapability'            $sharingLabel      $(if ($t.SharingCapability -ge 3) { 'GAP' } else { 'ok' })
Add-Finding 'DefaultSharingLinkType'       $t.DefaultSharingLinkType      $(if ("$($t.DefaultSharingLinkType)" -eq 'AnonymousAccess') { 'GAP - Anyone links default' } else { 'ok' })
Add-Finding 'DefaultLinkPermission'        $t.DefaultLinkPermission       $(if ("$($t.DefaultLinkPermission)" -eq 'Edit') { 'REVIEW - edit by default' } else { 'ok' })
Add-Finding 'RequireAnonymousLinksExpire'  $t.RequireAnonymousLinksExpireInDays $(if ($t.RequireAnonymousLinksExpireInDays -gt 0) { 'ok' } else { 'GAP - no expiry' })
Add-Finding 'ExternalUserExpirationRequired' $t.ExternalUserExpirationRequired $(if ($t.ExternalUserExpirationRequired) { 'ok' } else { 'REVIEW' })
Add-Finding 'PreventExternalUsersFromResharing' $t.PreventExternalUsersFromResharing $(if ($t.PreventExternalUsersFromResharing) { 'ok' } else { 'REVIEW' })
Add-Finding 'SharingDomainRestrictionMode' $t.SharingDomainRestrictionMode 'info'

$t | Select-Object SharingCapability, DefaultSharingLinkType, DefaultLinkPermission,
        RequireAnonymousLinksExpireInDays, ExternalUserExpirationRequired,
        PreventExternalUsersFromResharing, SharingDomainRestrictionMode, AllowedDomainList |
    Format-List | Out-String | Set-Content (Join-Path $OutDir 'spo-tenant-settings.txt')

# --- per-site --------------------------------------------------------------
Write-Host '[2/2] Sites' -ForegroundColor Cyan
$sites = Get-SPOSite -Limit All -ErrorAction Stop

$siteRows = foreach ($s in $sites) {
    [pscustomobject]@{
        Url                 = $s.Url
        SharingCapability   = switch ($s.SharingCapability) { 0 { 'Disabled' } 1 { 'ExistingOnly' } 2 { 'NewAndExisting' } 3 { 'Anyone' } default { "$($s.SharingCapability)" } }
        SensitivityLabel    = $s.SensitivityLabel
        ConditionalAccess   = $s.ConditionalAccessPolicy
        LockState           = $s.LockState
        Template            = $s.Template
        StorageUsedGB       = [math]::Round($s.StorageUsageCurrent / 1024, 2)
        LastModified        = $s.LastContentModifiedDate
    }
}
$siteRows | Sort-Object SharingCapability, Url | Export-Csv (Join-Path $OutDir 'spo-sites.csv') -NoTypeInformation

# Copilot exposure heuristic: readable by everyone, or externally shared, or unlabelled.
$anyone    = @($siteRows | Where-Object SharingCapability -eq 'Anyone')
$external  = @($siteRows | Where-Object SharingCapability -in @('Anyone', 'NewAndExisting'))
$unlabelled = @($siteRows | Where-Object { -not $_.SensitivityLabel })

Write-Host ''
Write-Host ("Sites                          : {0}" -f $siteRows.Count)
Write-Host ("Shared with Anyone             : {0}" -f $anyone.Count)     -ForegroundColor $(if ($anyone.Count) { 'Red' } else { 'Green' })
Write-Host ("Externally shareable           : {0}" -f $external.Count)   -ForegroundColor $(if ($external.Count) { 'Yellow' } else { 'Green' })
Write-Host ("Sites with no sensitivity label: {0}" -f $unlabelled.Count) -ForegroundColor $(if ($unlabelled.Count) { 'Yellow' } else { 'Green' })
Write-Host ''
Write-Host 'Copilot reads what the user can already read. Sites above are what it will surface first.' -ForegroundColor DarkGray

$findings | Export-Csv (Join-Path $OutDir 'spo-findings.csv') -NoTypeInformation
Write-Host "Written to $OutDir" -ForegroundColor Green
