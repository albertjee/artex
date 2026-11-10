#Requires -Version 7.2
<#
.SYNOPSIS
    Device-code sign-in with a full 15-minute window, bypassing the Graph SDK's
    hard-coded 120-second inactivity timeout.

.DESCRIPTION
    Connect-MgGraph ends the device-code flow after 120s of inactivity (that limit
    lives in Azure.Identity.dll and is not exposed as a parameter). This script runs
    the same OAuth device-code flow directly against Entra, which honours the code's
    own lifetime (~900s), then hands the resulting access token to Connect-MgGraph.

    After it finishes, scripts 2 and 3 reuse the session with no further prompts.

.NOTES
    ClientId 14d82eec-204b-4c2f-b7e8-296a70dab67e is "Microsoft Graph PowerShell" —
    the same public client the SDK itself uses, so the consent you grant here is
    identical to what Connect-MgGraph would have requested.

.EXAMPLE
    .\0-Connect-DeviceCode.ps1
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

    [switch] $NoBrowser,

    # Sealing the refresh token locally is what makes every later run headless.
    [switch] $NoSaveToken
)

$ErrorActionPreference = 'Stop'

$scopeString = (@('offline_access', 'openid', 'profile') + $Scopes) -join ' '
$authority   = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0"

# --- 1. request a device code ---------------------------------------------
Write-Host "Requesting device code for tenant $TenantId ..." -ForegroundColor Cyan
$dc = Invoke-RestMethod -Method Post -Uri "$authority/devicecode" -ContentType 'application/x-www-form-urlencoded' -Body @{
    client_id = $ClientId
    scope     = $scopeString
}

$minutes = [math]::Round($dc.expires_in / 60)

Write-Host ''
Write-Host ('=' * 62) -ForegroundColor DarkGray
Write-Host "  Open : $($dc.verification_uri)" -ForegroundColor Yellow
Write-Host "  Code : $($dc.user_code)" -ForegroundColor Green
Write-Host ('=' * 62) -ForegroundColor DarkGray
Write-Host "  Valid for ~$minutes minutes. Signing in as a member of NewportHighPTSA." -ForegroundColor DarkGray
Write-Host ''

if (-not $NoBrowser) {
    try { Start-Process $dc.verification_uri | Out-Null; Write-Host '  (browser opened)' -ForegroundColor DarkGray }
    catch { Write-Host '  (could not open a browser — use the URL above)' -ForegroundColor DarkGray }
}

# --- 2. poll for the token ------------------------------------------------
$interval = [int]$dc.interval
$deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
$token    = $null
$expires  = 0
$lastMsg  = ''

Write-Host '  Waiting for sign-in...' -ForegroundColor DarkGray

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $interval

    try {
        $tok = Invoke-RestMethod -Method Post -Uri "$authority/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
            grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
            client_id   = $ClientId
            device_code = $dc.device_code
        }
        $token   = $tok.access_token
        $refresh = $tok.refresh_token
        $expires = $tok.expires_in
        break
    }
    catch {
        $payload = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try { $payload = $_.ErrorDetails.Message | ConvertFrom-Json } catch { }
        }
        $err = if ($payload) { $payload.error } else { '' }

        if ($err -eq 'authorization_pending') { continue }
        elseif ($err -eq 'slow_down') { $interval += 5; continue }
        elseif ($err -eq 'expired_token') {
            throw "Device code expired before sign-in completed (~$minutes min). Re-run the script to get a fresh code."
        }
        elseif ($err -eq 'authorization_declined') {
            throw 'Sign-in was declined in the browser.'
        }
        elseif ($err) {
            throw "Authentication failed: $err — $(if ($payload) { $payload.error_description })"
        }
        else {
            if ($_.Exception.Message -ne $lastMsg) { $lastMsg = $_.Exception.Message; Write-Host "    retrying: $lastMsg" -ForegroundColor DarkGray }
            continue
        }
    }
}

if (-not $token) { throw 'Timed out waiting for sign-in. Re-run the script for a fresh code.' }

# --- 3. hand the token to the Graph SDK ----------------------------------
Connect-MgGraph -AccessToken (ConvertTo-SecureString -String $token -AsPlainText -Force) -NoWelcome

# --- 3b. seal the refresh token so later runs need no browser ------------
if (-not $NoSaveToken -and $refresh) {
    try {
        Add-Type -AssemblyName System.Security
        $stateDir = Join-Path $PSScriptRoot 'state'
        New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
        $sealed = [System.Security.Cryptography.ProtectedData]::Protect(
            [Text.Encoding]::UTF8.GetBytes($refresh),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes((Join-Path $stateDir 'refresh.dat'), $sealed)
        Write-Host '  Refresh token sealed for this Windows user (DPAPI).' -ForegroundColor DarkGray
        Write-Host '  From now on: .\0r-Refresh-Token.ps1   - no browser, no code.' -ForegroundColor DarkGray
    }
    catch {
        Write-Host "  (could not save refresh token: $($_.Exception.Message))" -ForegroundColor DarkYellow
    }
}

$ctx = Get-MgContext
$org = $null
try { $org = Get-MgOrganization | Select-Object -First 1 } catch { }

Write-Host ''
Write-Host '  Signed in.' -ForegroundColor Green
Write-Host "  Tenant   : $(if ($org) { $org.DisplayName } else { '(unknown)' }) ($($ctx.TenantId))"
Write-Host "  Account  : $($ctx.Account)"
Write-Host "  Expires  : in ~$([math]::Round($expires / 60)) min"
Write-Host "  Scopes   : $($ctx.Scopes -join ', ')"
Write-Host ''
Write-Host '  Next, in this same window:' -ForegroundColor Cyan
Write-Host '    .\2-Get-SecureScore.ps1'
Write-Host '    .\3-Get-EntraPosture.ps1'
