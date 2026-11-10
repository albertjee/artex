#Requires -Version 7.2
<#
.SYNOPSIS
    Connects to Graph with no browser, using the refresh token seeded by 0-.

.DESCRIPTION
    0- signs in once and seals the refresh token to your Windows account with DPAPI.
    This script spends it: one HTTPS round trip to Entra, a fresh access token, and a
    rotated refresh token written back for next time. No browser, no device code, no
    window to babysit.

    It is the difference between "run the assessment" and "run the assessment from a
    script, in a loop, while you do something else".

    If the refresh token is missing, expired or revoked, it says so and points at 0-.

.NOTES
    The refresh token is encrypted to the current Windows user, so it does not work
    for another account or another machine, and it is not valid if copied elsewhere.

.EXAMPLE
    .\0r-Refresh-Token.ps1
    .\0r-Refresh-Token.ps1 -Run 3,5,6
    .\0r-Refresh-Token.ps1 -Run 9
#>
[CmdletBinding()]
param(
    [string] $TenantId = '3177c971-05c9-4b7b-93a1-0edf6fd7237d',

    [string] $ClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e',

    [string[]] $Scopes = @(
        'Policy.Read.All'
        'Policy.Read.ConditionalAccess'
        'Application.Read.All'
        'Directory.Read.All'
        'AuditLog.Read.All'
        'SecurityEvents.Read.All'
        'Reports.Read.All'
        'RoleManagement.Read.Directory'
        'Group.Read.All'
        'Organization.Read.All'
        'User.Read.All'
        'UserAuthenticationMethod.Read.All'
        'IdentityRiskEvent.Read.All'
        'IdentityRiskyUser.Read.All'
        'IdentityRiskyServicePrincipal.Read.All'
        'PrivilegedAccess.Read.AzureAD'
        'RoleEligibilitySchedule.Read.Directory'
        'RoleAssignmentSchedule.Read.Directory'
    ),

    # Script numbers to run after connecting, e.g. -Run 3,5,6,9
    # Accepts -Run 3,5,6 and -Run 3 5 6. Under `pwsh -File` a comma list arrives as one
    # string, so it is split by hand; an [int[]] parameter would read "6,9" as 69.
    [string[]] $Run = @()
)

$Run = @($Run | ForEach-Object { $_ -split ',' } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

$stateDir  = Join-Path $PSScriptRoot 'state'
$statePath = Join-Path $stateDir 'refresh.dat'
$authority = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0"

if (-not (Test-Path $statePath)) {
    throw "No saved refresh token at $statePath. Run .\0-Connect-DeviceCode.ps1 once to seed it."
}

# --- 1. unseal ------------------------------------------------------------
try {
    $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
        [IO.File]::ReadAllBytes($statePath),
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    $refreshToken = [Text.Encoding]::UTF8.GetString($plain)
}
catch {
    throw "Could not unseal $statePath - it belongs to a different Windows account or is corrupt. Re-run .\0-Connect-DeviceCode.ps1."
}

# --- 2. redeem ------------------------------------------------------------
Write-Host 'Refreshing Graph session (headless)...' -ForegroundColor Cyan

try {
    $tok = Invoke-RestMethod -Method Post -Uri "$authority/token" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body @{
        grant_type    = 'refresh_token'
        client_id     = $ClientId
        refresh_token = $refreshToken
        scope         = ((@('offline_access', 'openid', 'profile') + $Scopes) -join ' ')
    }
}
catch {
    $detail = ''
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
        try {
            $payload = $_.ErrorDetails.Message | ConvertFrom-Json
            $detail = "$($payload.error): $($payload.error_description)"
        }
        catch { $detail = $_.ErrorDetails.Message }
    }
    throw @"
Refresh failed - the saved token is expired or revoked.
  $detail

Fix: run .\0-Connect-DeviceCode.ps1 once (browser, ~20 seconds) to re-seed.
"@
}

# --- 3. rotate: the endpoint returns a new refresh token ------------------
if ($tok.refresh_token) {
    try {
        $sealed = [System.Security.Cryptography.ProtectedData]::Protect(
            [Text.Encoding]::UTF8.GetBytes($tok.refresh_token),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes($statePath, $sealed)
    }
    catch {
        Write-Host "  (warning: could not store rotated token: $($_.Exception.Message))" -ForegroundColor DarkYellow
    }
}

Connect-MgGraph -AccessToken (ConvertTo-SecureString -String $tok.access_token -AsPlainText -Force) -NoWelcome

$ctx = Get-MgContext
Write-Host ("  Session : {0}" -f $ctx.Account) -ForegroundColor Green
Write-Host ("  Tenant  : {0}" -f $ctx.TenantId)
Write-Host ("  Expires : ~{0} min" -f [math]::Round($tok.expires_in / 60))
Write-Host ''

# --- 4. optionally chain scripts in this same session --------------------
if ($Run.Count -gt 0) {
    foreach ($n in $Run) {
        # Not named $script: scripts use the $script: scope modifier, and a caller-side
        # $script variable collides with it (9-Build-Report.ps1 failed only when chained).
        $childScript = Get-ChildItem -Path $PSScriptRoot -Filter "$n-*.ps1" -File |
            Where-Object { $_.Name -match "^$n-" } | Select-Object -First 1
        if (-not $childScript) {
            Write-Host "  ! no script numbered $n" -ForegroundColor Yellow
            continue
        }
        Write-Host ("=== {0} ===" -f $childScript.Name) -ForegroundColor Cyan
        & $childScript.FullName
        Write-Host ''
    }
}
