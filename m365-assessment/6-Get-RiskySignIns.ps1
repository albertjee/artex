#Requires -Version 7.2
<#
.SYNOPSIS
    Identity Protection + sign-in analysis: risky users, risk detections, failed
    sign-ins, legacy-auth attempts, MFA denials.

.DESCRIPTION
    Where the config scripts describe what *could* happen, this describes what has
    actually been attempted against the tenant. It is also the only way to tell
    whether a report-only CA policy would have fired.

    Requires Entra ID P1 (risky users / risk detections) — E5 covers it. If the
    tenant lacks it, the risky-* sections skip and the sign-in section still runs.

.NOTES
    Read-only. Requires an active Graph session (run 0-Connect-DeviceCode.ps1 first).
    Sign-in logs retain 30 days; the default window is 7.
#>
[CmdletBinding()]
param(
    [string] $OutDir = (Join-Path $PSScriptRoot 'reports'),
    [int]    $Days   = 7,
    [int]    $MaxSignIns = 5000
)

$ErrorActionPreference = 'Stop'
if (-not (Get-MgContext)) { throw 'No Graph session. Run .\0-Connect-DeviceCode.ps1 first, in this same window.' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$since = (Get-Date).AddDays(-$Days).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

function Try-Step {
    param([string] $Name, [scriptblock] $Block)
    Write-Host "  -> $Name" -ForegroundColor Cyan
    $marker = Join-Path $OutDir ('skipped-{0}.txt' -f ($Name -replace '[^\w\-]', '-'))
    try {
        & $Block
        if (Test-Path $marker) { Remove-Item $marker -Force }
    }
    catch {
        $msg = $_.Exception.Message
        Write-Host "     skipped: $msg" -ForegroundColor Yellow
        # A zero-row CSV is indistinguishable from "nothing found". A marker file is not.
        "not measured: $Name`nreason: $msg" | Set-Content $marker -Encoding utf8
    }
}

# --- risky users ----------------------------------------------------------
Try-Step 'Risky users' {
    $risky = @(Get-MgRiskyUser -All -ErrorAction Stop)
    $risky | Select-Object UserPrincipalName, UserDisplayName, RiskLevel, RiskState,
            RiskDetail, RiskLastUpdatedDateTime, IsDeleted |
        Export-Csv (Join-Path $OutDir 'entra-risky-users.csv') -NoTypeInformation
    $high = @($risky | Where-Object { $_.RiskLevel -in @('high', 'medium') -and $_.RiskState -ne 'remediated' })
    Write-Host ("     {0} risky users, {1} unremediated at medium/high" -f $risky.Count, $high.Count) -ForegroundColor $(if ($high.Count) { 'Yellow' } else { 'Green' })
}

# --- risk detections ------------------------------------------------------
Try-Step 'Risk detections' {
    $det = @(Get-MgRiskDetection -All -ErrorAction Stop -Filter "detectedDateTime ge $since")
    $det | Select-Object DetectedDateTime, RiskEventType, RiskLevel, RiskState,
            UserPrincipalName, IpAddress, Location, DetectionTimingType |
        Export-Csv (Join-Path $OutDir 'entra-risk-detections.csv') -NoTypeInformation
    $det | Group-Object RiskEventType | Sort-Object Count -Descending |
        Select-Object Count, Name | Format-Table -AutoSize
}

# --- sign-ins -------------------------------------------------------------
Try-Step 'Sign-in log' {
    $signIns = @(Get-MgAuditLogSignIn -All -ErrorAction Stop -Filter "createdDateTime ge $since" -Top $MaxSignIns)

    $signIns |
        Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, ClientAppUsed,
            IsInteractive, Status, IpAddress, Location, ConditionalAccessStatus,
            @{ n = 'FailureReason'; e = { $_.Status.FailureReason } },
            @{ n = 'MfaResult';     e = { ($_.AuthenticationRequirement) } } |
        Export-Csv (Join-Path $OutDir 'entra-signins.csv') -NoTypeInformation

    # The assessor's own auth attempts land in the same log. Left in place they read
    # as 66 failed sign-ins and invent an incident, so they are split out first.
    $toolingPattern = 'Microsoft Graph Command Line Tools|Microsoft Azure CLI|Exchange Online PowerShell|SharePoint Online Management Shell|Microsoft Teams PowerShell|Graph PowerShell|PnP PowerShell'
    $tooling = @($signIns | Where-Object { $_.AppDisplayName -match $toolingPattern })
    $human   = @($signIns | Where-Object { $_.AppDisplayName -notmatch $toolingPattern })

    if ($tooling.Count) {
        $tooling | Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, IpAddress,
                @{ n = 'FailureReason'; e = { $_.Status.FailureReason } } |
            Export-Csv (Join-Path $OutDir 'entra-signins-tooling.csv') -NoTypeInformation
    }

    # Failure summary — who is being sprayed, and is it working?
    $human |
        Where-Object { $_.Status.Error -ne 0 } |
        Group-Object { $_.Status.FailureReason } |
        Sort-Object Count -Descending |
        Select-Object Count, Name |
        Export-Csv (Join-Path $OutDir 'entra-signin-failures.csv') -NoTypeInformation

    # Legacy auth still being attempted?
    $legacy = @($human | Where-Object { $_.ClientAppUsed -in @('Other clients', 'IMAP4', 'POP3', 'SMTP', 'Exchange ActiveSync') })
    $legacy | Group-Object ClientAppUsed |
        Select-Object Count, Name |
        Export-Csv (Join-Path $OutDir 'entra-legacy-auth-attempts.csv') -NoTypeInformation

    # CA would-have-fired: report-only policies show up as 'notApplied' + reportOnlyFailure
    $reportOnly = @($human | Where-Object {
            $_.ConditionalAccessStatus -eq 'notApplied' -and
            ($_.AdditionalProperties['conditionalAccessPolicies'] | Where-Object { $_.Result -eq 'reportOnlyFailure' })
        })

    $failedHuman = @($human | Where-Object { $_.Status.Error -ne 0 }).Count
    Write-Host ("     {0} sign-ins in {1} days  ({2} from assessor tooling, excluded)" -f $signIns.Count, $Days, $tooling.Count)
    Write-Host ("     {0} assessor-independent sign-ins" -f $human.Count)
    Write-Host ("     {0} failed" -f $failedHuman) -ForegroundColor $(if ($failedHuman) { 'Yellow' } else { 'Green' })
    Write-Host ("     {0} legacy-auth attempts" -f $legacy.Count) -ForegroundColor $(if ($legacy.Count) { 'Yellow' } else { 'Green' })
    Write-Host ("     {0} sign-ins would have been blocked by a report-only policy" -f $reportOnly.Count) -ForegroundColor Yellow
}

Write-Host ''
Write-Host "Written to $OutDir" -ForegroundColor Green
Get-ChildItem $OutDir -Filter 'entra-*' | Where-Object LastWriteTime -gt (Get-Date).AddMinutes(-5) |
    Select-Object Name, Length

