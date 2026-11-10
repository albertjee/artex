#Requires -Version 7.2
<#
.SYNOPSIS
    Inventories the Entra ID attack surface that matters most: Conditional Access
    coverage, app consent / OAuth grants, MFA registration, guest posture, admin roles.

.DESCRIPTION
    Complements ScubaGear's AAD baseline with the four findings that actually decide
    whether a tenant is compromisable:
      1. Conditional Access — policies that are disabled or report-only are not enforced.
      2. App consent — over-permissioned enterprise apps and user-consent settings
         (the illicit-consent-grant path).
      3. MFA — users not registered, and privileged accounts not registered.
      4. Guests + admins — who can invite, and who holds what role.

    Everything here is read-only.

.NOTES
    Requires Global Reader in the target tenant (Directory.Read.All + Policy.Read.All).
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
        'Policy.Read.All'
        'Application.Read.All'
        'Directory.Read.All'
        'AuditLog.Read.All'
    )
}

# App permissions that amount to full tenant or data compromise if granted to the wrong app.
$highRiskAppRoles = @(
    'Directory.ReadWrite.All'
    'RoleManagement.ReadWrite.Directory'
    'Application.ReadWrite.All'
    'AppRoleAssignment.ReadWrite.All'
    'Mail.ReadWrite'
    'Mail.Send'
    'Files.ReadWrite.All'
    'Sites.FullControl.All'
    'User.ReadWrite.All'
    'Group.ReadWrite.All'
    'full_access_as_app'
)

function Try-Step {
    param([string] $Name, [scriptblock] $Block)
    Write-Host "  -> $Name" -ForegroundColor Cyan
    try { & $Block }
    catch { Write-Host "     skipped: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# --- 1. Conditional Access ------------------------------------------------
Try-Step 'Conditional Access policies' {
    $policies = Get-MgIdentityConditionalAccessPolicy -All

    # Role template IDs are GUIDs nobody can read. Resolve them once so the CSV says
    # "Global Administrator" instead of 62e90394-...
    $roleNames = @{}
    try {
        Get-MgDirectoryRoleTemplate -All | ForEach-Object { $roleNames[$_.Id] = $_.DisplayName }
    }
    catch {
        Write-Host "     (role template names unavailable: $($_.Exception.Message))" -ForegroundColor DarkYellow
    }
    $resolveRoles = {
        param($ids)
        if (-not $ids) { return '' }
        @($ids | ForEach-Object { if ($roleNames.ContainsKey($_)) { $roleNames[$_] } else { $_ } }) -join ','
    }

    # Named locations are GUIDs too. "exclude=14730dce-..." tells you nothing;
    # "exclude=United States" tells you what the policy actually does.
    $locNames = @{}
    try {
        Get-MgIdentityConditionalAccessNamedLocation -All | ForEach-Object { $locNames[$_.Id] = $_.DisplayName }
    }
    catch {
        Write-Host "     (named locations unavailable: $($_.Exception.Message))" -ForegroundColor DarkYellow
    }
    $resolveLocs = {
        param($ids)
        if (-not $ids) { return '' }
        @($ids | ForEach-Object {
                if ($_ -eq 'All') { 'All' }
                elseif ($_ -eq 'AllTrusted') { 'All trusted locations' }
                elseif ($locNames.ContainsKey($_)) { $locNames[$_] }
                else { $_ }
            }) -join '|'
    }

    # A session control counts only if it carries a value. The objects exist on every
    # policy with empty properties, so testing the object itself makes every policy look
    # protected - which is how "requires nothing" turns into a false negative.
    $sessionText = {
        param($p)
        $sc = $p.SessionControls
        if (-not $sc) { return '' }
        $parts = @()
        if ($sc.SignInFrequency -and ($sc.SignInFrequency.Value -or $sc.SignInFrequency.Type)) {
            $parts += ('signInFrequency={0}{1}' -f $sc.SignInFrequency.Value, $sc.SignInFrequency.Type)
        }
        if ($sc.PersistentBrowser -and $sc.PersistentBrowser.Mode) {
            $parts += ('persistentBrowser={0}' -f $sc.PersistentBrowser.Mode)
        }
        if ($sc.CloudAppSecurity -and $sc.CloudAppSecurity.CloudAppSecurityType) {
            $parts += ('cloudAppSecurity={0}' -f $sc.CloudAppSecurity.CloudAppSecurityType)
        }
        if ($sc.ContinuousAccessEvaluation -and $sc.ContinuousAccessEvaluation.Mode) {
            $parts += ('CAE={0}' -f $sc.ContinuousAccessEvaluation.Mode)
        }
        if ($sc.DisableResilienceDefaults) { $parts += 'resilienceDefaults=disabled' }
        $parts -join '; '
    }

    $policies |
        Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime,
            @{ n = 'GrantControls'; e = { ($_.GrantControls.BuiltInControls -join ',') } },
            @{ n = 'AuthStrength';  e = { $_.GrantControls.AuthenticationStrength.DisplayName } },
            @{ n = 'IncludeUsers';  e = { ($_.Conditions.Users.IncludeUsers -join ',') } },
            @{ n = 'IncludeGroups'; e = { ($_.Conditions.Users.IncludeGroups -join ',') } },
            @{ n = 'IncludeRoles';  e = { & $resolveRoles $_.Conditions.Users.IncludeRoles } },
            @{ n = 'ExcludeUsers';  e = { ($_.Conditions.Users.ExcludeUsers -join ',') } },
            @{ n = 'ExcludeGroups'; e = { ($_.Conditions.Users.ExcludeGroups -join ',') } },
            @{ n = 'ExcludeRoles';  e = { & $resolveRoles $_.Conditions.Users.ExcludeRoles } },
            @{ n = 'Apps';          e = { ($_.Conditions.Applications.IncludeApplications -join ',') } },
            @{ n = 'ClientAppTypes'; e = { ($_.Conditions.ClientAppTypes -join ',') } },
            # Locations decide whether "block high-risk countries" actually names any country.
            @{ n = 'Locations'; e = {
                    $loc = $_.Conditions.Locations
                    if (-not $loc) { return '' }
                    $bits = @()
                    if ($loc.IncludeLocations) { $bits += 'include=' + (& $resolveLocs $loc.IncludeLocations) }
                    if ($loc.ExcludeLocations) { $bits += 'exclude=' + (& $resolveLocs $loc.ExcludeLocations) }
                    if ($bits.Count -eq 0) { $bits += 'any' }
                    $bits -join '; '
                } },
            @{ n = 'SessionControls'; e = { & $sessionText $_ } },
            # The one place the "this policy does nothing" rule is decided, so the report
            # never has to infer it from a field it did not capture.
            @{ n = 'RequiresNothing'; e = {
                    $grants   = @($_.GrantControls.BuiltInControls)
                    $strength = $_.GrantControls.AuthenticationStrength
                    $session  = & $sessionText $_
                    if ($grants.Count -eq 0 -and -not $strength -and -not $session) { 'YES' } else { '' }
                } } |
        Sort-Object State, DisplayName |
        Export-Csv (Join-Path $OutDir 'entra-ca-policies.csv') -NoTypeInformation

    $notEnforced = $policies | Where-Object { $_.State -ne 'enabled' }
    if ($notEnforced) {
        Write-Host "     $($notEnforced.Count) of $($policies.Count) policies are NOT enforcing (disabled/report-only)" -ForegroundColor Yellow
    }
    if (-not $policies) { Write-Host '     no CA policies at all — this is the single biggest gap' -ForegroundColor Red }
}

# --- 2. App consent / OAuth grants ---------------------------------------
Try-Step 'App consent settings and high-risk grants' {
    $auth = Get-MgPolicyAuthorizationPolicy
    [pscustomobject]@{
        AllowUserConsentForRiskyApps  = $auth.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned -join ','
        AllowedToCreateApps           = $auth.DefaultUserRolePermissions.AllowedToCreateApps
        GuestUserRoleId               = $auth.GuestUserRoleId
        AllowInvitesFrom              = $auth.AllowInvitesFrom
        AllowEmailVerifiedUsersToJoin = $auth.AllowEmailVerifiedUsersToJoinOrganization
    } | Format-List | Out-String | Set-Content (Join-Path $OutDir 'entra-consent-settings.txt')

    $granted = foreach ($sp in Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, AppRoles) {
        $assigned = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
        if (-not $assigned) { continue }
        $lookup = @{}
        foreach ($r in $sp.AppRoles) { $lookup[$r.Id] = $r.Value }
        foreach ($a in $assigned) {
            [pscustomobject]@{
                Resource      = $sp.DisplayName
                ResourceAppId = $sp.AppId
                Permission    = $lookup[$a.AppRoleId]
                GrantedTo     = $a.PrincipalDisplayName
                GrantedToType = $a.PrincipalType
            }
        }
    }

    $granted | Sort-Object Resource, Permission |
        Export-Csv (Join-Path $OutDir 'entra-app-permissions.csv') -NoTypeInformation

    $risky = $granted | Where-Object { $_.Permission -in $highRiskAppRoles -and $_.GrantedToType -eq 'ServicePrincipal' }
    $risky | Sort-Object Permission |
        Export-Csv (Join-Path $OutDir 'entra-high-risk-grants.csv') -NoTypeInformation

    if ($risky) {
        Write-Host "     $($risky.Count) app-to-app grants use high-risk permissions" -ForegroundColor Yellow
    }
}

# --- 3. MFA registration --------------------------------------------------
Try-Step 'MFA registration status' {
    $reg = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
    $reg | Select-Object UserPrincipalName, UserDisplayName, IsMfaRegistered, IsMfaCapable,
            IsPasswordlessCapable, MethodsRegistered |
        Export-Csv (Join-Path $OutDir 'entra-mfa-registration.csv') -NoTypeInformation

    $noMfa = $reg | Where-Object { -not $_.IsMfaRegistered }
    Write-Host "     $($noMfa.Count) of $($reg.Count) users have no MFA method registered" -ForegroundColor $(if ($noMfa.Count) { 'Yellow' } else { 'Green' })
}

# --- 4. Admins and guests -------------------------------------------------
Try-Step 'Directory role membership' {
    $rows = foreach ($role in Get-MgDirectoryRole -All) {
        foreach ($m in Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All) {
            [pscustomobject]@{
                Role  = $role.DisplayName
                Name  = $m.AdditionalProperties['displayName']
                UPN   = $m.AdditionalProperties['userPrincipalName']
                Type  = $m.AdditionalProperties['@odata.type']
            }
        }
    }
    $rows | Sort-Object Role, Name | Export-Csv (Join-Path $OutDir 'entra-admin-roles.csv') -NoTypeInformation
    Write-Host "     $($rows.Count) role assignments across $((Get-MgDirectoryRole -All).Count) roles"
}

Try-Step 'Guest accounts' {
    $guests = Get-MgUser -Filter "userType eq 'Guest'" -All -Property Id, DisplayName, UserPrincipalName, CreatedDateTime, AccountEnabled
    $guests | Select-Object DisplayName, UserPrincipalName, AccountEnabled, CreatedDateTime |
        Export-Csv (Join-Path $OutDir 'entra-guests.csv') -NoTypeInformation
    Write-Host "     $($guests.Count) guest accounts"
}

Write-Host ''
Write-Host "Written to $OutDir" -ForegroundColor Green
Get-ChildItem $OutDir -Filter 'entra-*' | Select-Object Name, Length
