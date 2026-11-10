#Requires -Version 7.2
<#
.SYNOPSIS
    App registration & service principal hygiene: credential expiry, ownership,
    redirect URIs, legacy Azure AD Graph grants.

.DESCRIPTION
    Closes the "no app credential lifecycle" finding. A high-privilege app whose
    secret never expires is a permanent backdoor; one whose secret already expired
    is an outage waiting for Monday. Both show up here.

    Answers:
      - Which secrets/certs are expired or expiring within N days?
      - Which apps have no owner? (nobody gets the expiry warning)
      - Which apps accept redirect URIs over http:// or with wildcards?
      - Which apps are multi-tenant when they should be single?
      - Which apps still hold Azure AD Graph (00000002) permissions?

.NOTES
    Read-only. Requires an active Graph session (run 0-Connect-DeviceCode.ps1 first).
#>
[CmdletBinding()]
param(
    [string] $OutDir = (Join-Path $PSScriptRoot 'reports'),
    [int]    $ExpiryWarnDays = 30
)

$ErrorActionPreference = 'Stop'
if (-not (Get-MgContext)) { throw 'No Graph session. Run .\0-Connect-DeviceCode.ps1 first, in this same window.' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$now     = Get-Date
$warnBy  = $now.AddDays($ExpiryWarnDays)
$legacyResource = '00000002-0000-0000-c000-000000000000'

Write-Host 'Enumerating applications...' -ForegroundColor Cyan
$apps = Get-MgApplication -All

$creds = foreach ($a in $apps) {
    $owners = try { @(Get-MgApplicationOwner -ApplicationId $a.Id -All) } catch { @() }

    foreach ($p in $a.PasswordCredentials) {
        $state = if ($p.EndDateTime -lt $now) { 'EXPIRED' }
                 elseif ($p.EndDateTime -lt $warnBy) { 'EXPIRING' }
                 else { 'ok' }
        [pscustomobject]@{
            App             = $a.DisplayName
            AppId           = $a.AppId
            Type            = 'secret'
            Name            = $p.DisplayName
            Starts          = $p.StartDateTime
            Expires         = $p.EndDateTime
            DaysLeft        = [math]::Round(($p.EndDateTime - $now).TotalDays)
            State           = $state
            Owners          = $owners.Count
        }
    }
    foreach ($k in $a.KeyCredentials) {
        $state = if ($k.EndDateTime -lt $now) { 'EXPIRED' }
                 elseif ($k.EndDateTime -lt $warnBy) { 'EXPIRING' }
                 else { 'ok' }
        [pscustomobject]@{
            App             = $a.DisplayName
            AppId           = $a.AppId
            Type            = 'certificate'
            Name            = $k.DisplayName
            Starts          = $k.StartDateTime
            Expires         = $k.EndDateTime
            DaysLeft        = [math]::Round(($k.EndDateTime - $now).TotalDays)
            State           = $state
            Owners          = $owners.Count
        }
    }
}
$creds | Sort-Object DaysLeft | Export-Csv (Join-Path $OutDir 'entra-app-credentials.csv') -NoTypeInformation

# --- risks ----------------------------------------------------------------
$risks = foreach ($a in $apps) {
    $owners = try { @(Get-MgApplicationOwner -ApplicationId $a.Id -All) } catch { @() }
    $legacy = @($a.RequiredResourceAccess | Where-Object { $_.ResourceAppId -eq $legacyResource })
    $badUris = @($a.Web.RedirectUris | Where-Object { $_ -match '^http://' -or $_ -match '\*' })

    if ($owners.Count -eq 0) {
        [pscustomobject]@{ App = $a.DisplayName; AppId = $a.AppId; Risk = 'No owner'; Detail = 'expiry warnings go nowhere' }
    }
    if ($legacy.Count -gt 0) {
        [pscustomobject]@{ App = $a.DisplayName; AppId = $a.AppId; Risk = 'Azure AD Graph permission'; Detail = 'retired API (00000002)' }
    }
    if ($badUris.Count -gt 0) {
        [pscustomobject]@{ App = $a.DisplayName; AppId = $a.AppId; Risk = 'Weak redirect URI'; Detail = ($badUris -join ' ') }
    }
    if ($a.SignInAudience -eq 'AzureADMultipleOrgs' -or $a.SignInAudience -eq 'AzureADandPersonalMicrosoftAccount') {
        [pscustomobject]@{ App = $a.DisplayName; AppId = $a.AppId; Risk = 'Multi-tenant'; Detail = $a.SignInAudience }
    }
}
$risks | Sort-Object Risk, App | Export-Csv (Join-Path $OutDir 'entra-app-risks.csv') -NoTypeInformation

# --- summary --------------------------------------------------------------
$expired  = @($creds | Where-Object State -eq 'EXPIRED')
$expiring = @($creds | Where-Object State -eq 'EXPIRING')
$noOwner  = @($risks | Where-Object Risk -eq 'No owner')

Write-Host ''
Write-Host ("Applications            : {0}" -f $apps.Count)
Write-Host ("Credentials tracked     : {0}" -f $creds.Count)
Write-Host ("Expired                 : {0}" -f $expired.Count) -ForegroundColor $(if ($expired.Count) { 'Red' } else { 'Green' })
Write-Host ("Expiring within {0,-3} days: {1}" -f $ExpiryWarnDays, $expiring.Count) -ForegroundColor $(if ($expiring.Count) { 'Yellow' } else { 'Green' })
Write-Host ("Apps with no owner      : {0}" -f $noOwner.Count) -ForegroundColor $(if ($noOwner.Count) { 'Yellow' } else { 'Green' })
Write-Host ''

$creds | Sort-Object DaysLeft | Select-Object -First 12 App, Type, Name, DaysLeft, State, Owners | Format-Table -AutoSize
Write-Host "Written to $OutDir" -ForegroundColor Green
