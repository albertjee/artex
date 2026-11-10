#Requires -Version 7.2
<#
.SYNOPSIS
    Email security posture: anti-phishing, Safe Links, Safe Attachments, forwarding,
    SPF/DKIM/DMARC, SMTP AUTH, mailbox auditing.

.DESCRIPTION
    This is where the Secure Score gaps actually live (Safe Links 9 pts, Safe
    Attachments 8+5 pts, DLP 5 pts). Conditional Access protects the door; these
    controls stop the phish before anyone clicks.

    Connects to Exchange Online interactively — run in its own window.

.NOTES
    Read-only. Requires Exchange Administrator or Global Reader (View-Only Configuration).
.EXAMPLE
    .\7-Get-EmailPosture.ps1
    .\7-Get-EmailPosture.ps1 -Domains newportptsa.org,NewportHighPTSA.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [string]   $OutDir  = (Join-Path $PSScriptRoot 'reports'),
    [string[]] $Domains = @('newportptsa.org', 'NewportHighPTSA.onmicrosoft.com'),

    # DNS authentication records need no tenant session - run this anywhere.
    [switch]   $DnsOnly
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# ---- DNS: SPF / DMARC / DKIM ---------------------------------------------
Write-Host '[1/2] DNS authentication records' -ForegroundColor Cyan
$dns = foreach ($d in $Domains) {
    $spf = $null; $dmarc = $null; $dkim1 = $null; $dkim2 = $null
    try { $spf   = ((Resolve-DnsName $d -Type TXT -ErrorAction Stop).Strings | Where-Object { $_ -match '^v=spf1' } | Select-Object -First 1) } catch { }
    try { $dmarc = ((Resolve-DnsName "_dmarc.$d" -Type TXT -ErrorAction Stop).Strings | Where-Object { $_ -match '^v=DMARC1' } | Select-Object -First 1) } catch { }
    try { $dkim1 = ((Resolve-DnsName "selector1._domainkey.$d" -Type CNAME -ErrorAction Stop).NameHost) } catch {
        try { $dkim1 = ((Resolve-DnsName "selector1._domainkey.$d" -Type TXT -ErrorAction Stop).Strings -join '') } catch { }
    }
    try { $dkim2 = ((Resolve-DnsName "selector2._domainkey.$d" -Type CNAME -ErrorAction Stop).NameHost) } catch { }

    $dmarcPolicy = if ($dmarc -match 'p=(\w+)') { $matches[1] } else { 'none' }

    [pscustomobject]@{
        Domain       = $d
        SPF          = if ($spf) { $spf } else { 'MISSING' }
        SPFStrict    = if ($spf -match '-all') { 'yes (-all)' } elseif ($spf -match '~all') { 'soft (~all)' } else { 'no' }
        DMARC        = if ($dmarc) { $dmarc } else { 'MISSING' }
        DMARCPolicy  = $dmarcPolicy
        DKIMselector1 = if ($dkim1) { 'present' } else { 'MISSING' }
        DKIMselector2 = if ($dkim2) { 'present' } else { 'MISSING' }
    }
}
$dns | Export-Csv (Join-Path $OutDir 'email-dns-auth.csv') -NoTypeInformation
$dns | Format-Table -AutoSize

if ($DnsOnly) {
    Write-Host 'DNS-only run: skipping Exchange Online (needs interactive sign-in).' -ForegroundColor DarkGray
    Write-Host "Written to $OutDir" -ForegroundColor Green
    return
}

# ---- Exchange Online ------------------------------------------------------
Write-Host '[2/2] Exchange Online policies' -ForegroundColor Cyan
Import-Module ExchangeOnlineManagement -ErrorAction Stop
# -Device: sign-in code + microsoft.com/devicelogin, no embedded browser. The default
# interactive path fails on this machine (MSAL "embedded webview" error).
Connect-ExchangeOnline -Device -ShowBanner:$false

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param([string] $Area, [string] $Setting, $Value, [string] $Verdict)
    $findings.Add([pscustomobject]@{ Area = $Area; Setting = $Setting; Value = $Value; Verdict = $Verdict })
}
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
        # Console-only "skipped" reads as silence in the report. The marker makes it a gap.
        "not measured: $Name`nreason: $msg" | Set-Content $marker -Encoding utf8
    }
}

# Safe Links and Safe Attachments live in Security & Compliance (IPPS), not in the Exchange
# Online session. Connect there only when those cmdlets are missing. -DisableWAM skips the
# Windows account broker, the layer in front of the sign-in window that fails on this machine.
function Ensure-Ipps {
    if (Get-Command Get-SafeLinksPolicy -ErrorAction SilentlyContinue) { return }
    Connect-IPPSSession -DisableWAM -ShowBanner:$false
}

Try-Step 'Anti-phishing policy' {
    Get-AntiPhishPolicy | Select-Object Name, Enabled, IsDefault,
        EnableMailboxIntelligence, EnableMailboxIntelligenceProtection,
        EnableSpoofIntelligence, EnableTargetedUserProtection, EnableTargetedDomainsProtection,
        TargetedUserProtectionAction, TargetedDomainProtectionAction, PhishThresholdLevel, HonorDmarcPolicy |
        Export-Csv (Join-Path $OutDir 'email-antiphish.csv') -NoTypeInformation

    $d = Get-AntiPhishPolicy | Where-Object IsDefault | Select-Object -First 1
    if ($d) {
        Add-Finding 'Anti-phish' 'Impersonation protection (users)' $d.EnableTargetedUserProtection $(if ($d.EnableTargetedUserProtection) { 'ok' } else { 'GAP' })
        Add-Finding 'Anti-phish' 'Domain impersonation protection'  $d.EnableTargetedDomainsProtection $(if ($d.EnableTargetedDomainsProtection) { 'ok' } else { 'GAP' })
        Add-Finding 'Anti-phish' 'Mailbox intelligence'             $d.EnableMailboxIntelligence $(if ($d.EnableMailboxIntelligence) { 'ok' } else { 'GAP' })
        Add-Finding 'Anti-phish' 'Honor DMARC policy'               $d.HonorDmarcPolicy $(if ("$($d.HonorDmarcPolicy)" -ne 'False') { 'ok' } else { 'GAP' })
        Add-Finding 'Anti-phish' 'Phish threshold'                  $d.PhishThresholdLevel 'info'
    }
}

Try-Step 'Safe Links' {
    Ensure-Ipps
    Get-SafeLinksPolicy | Select-Object Name, Enabled, IsDefault,
        EnableSafeLinksForEmail, EnableSafeLinksForTeams, EnableSafeLinksForOffice,
        TrackClicks, AllowClickThrough, ScanUrls, EnableForInternalSenders, DeliverMessageAfterScan |
        Export-Csv (Join-Path $OutDir 'email-safelinks.csv') -NoTypeInformation

    $p = Get-SafeLinksPolicy | Where-Object IsDefault | Select-Object -First 1
    if ($p) {
        Add-Finding 'Safe Links' 'Enabled'          $p.Enabled $(if ($p.Enabled) { 'ok' } else { 'GAP' })
        Add-Finding 'Safe Links' 'Email scanning'   $p.EnableSafeLinksForEmail $(if ($p.EnableSafeLinksForEmail) { 'ok' } else { 'GAP' })
        Add-Finding 'Safe Links' 'Teams scanning'   $p.EnableSafeLinksForTeams $(if ($p.EnableSafeLinksForTeams) { 'ok' } else { 'GAP' })
        Add-Finding 'Safe Links' 'Office apps'      $p.EnableSafeLinksForOffice $(if ($p.EnableSafeLinksForOffice) { 'ok' } else { 'GAP' })
        Add-Finding 'Safe Links' 'Click tracking'   $p.TrackClicks $(if ($p.TrackClicks) { 'ok' } else { 'info' })
    } else { Add-Finding 'Safe Links' 'Policy' 'none' 'GAP' }
}

Try-Step 'Safe Attachments' {
    Ensure-Ipps
    Get-SafeAttachmentPolicy | Select-Object Name, Enabled, Action, QuarantineTag, Redirect, Enable |
        Export-Csv (Join-Path $OutDir 'email-safeattachments.csv') -NoTypeInformation
    $p = Get-SafeAttachmentPolicy | Select-Object -First 1
    if ($p) {
        Add-Finding 'Safe Attachments' 'Enabled' $p.Enable $(if ($p.Enable) { 'ok' } else { 'GAP' })
        Add-Finding 'Safe Attachments' 'Action'  $p.Action $(if ($p.Action -eq 'Block') { 'ok' } else { 'GAP - not block mode' })
    } else { Add-Finding 'Safe Attachments' 'Policy' 'none' 'GAP' }
}

Try-Step 'External forwarding' {
    $out = Get-HostedOutboundSpamFilterPolicy | Select-Object -First 1
    Add-Finding 'Forwarding' 'AutoForwardingMode' $out.AutoForwardingMode $(if ("$($out.AutoForwardingMode)" -eq 'On') { 'GAP - unrestricted' } else { 'ok' })

    $fwd = Get-TransportRule | Where-Object {
        $_.RedirectMessageTo -or $_.BlindCopyTo -or ($_.Actions -join ',' -match 'Redirect|Bcc')
    }
    $fwd | Select-Object Name, State, RedirectMessageTo, BlindCopyTo |
        Export-Csv (Join-Path $OutDir 'email-forwarding-rules.csv') -NoTypeInformation
    Add-Finding 'Forwarding' 'Mail flow rules forwarding' @($fwd).Count $(if (@($fwd).Count) { 'REVIEW' } else { 'ok' })
}

Try-Step 'Organization config' {
    $oc = Get-OrganizationConfig
    Add-Finding 'SMTP AUTH'  'SmtpClientAuthenticationDisabled' $oc.SmtpClientAuthenticationDisabled $(if ("$($oc.SmtpClientAuthenticationDisabled)" -eq 'True') { 'ok' } else { 'GAP - basic auth available' })
    Add-Finding 'Auditing'   'AuditDisabled'                    $oc.AuditDisabled $(if ("$($oc.AuditDisabled)" -eq 'False') { 'ok' } else { 'GAP - mailbox auditing off' })
    Add-Finding 'Auditing'   'AuditLogAgeLimit'                 $oc.AuditLogAgeLimit 'info'
}

Try-Step 'External sender identification' {
    $ext = Get-ExternalInOutlook -ErrorAction Stop
    Add-Finding 'External tag' 'ExternalInOutlookEnabled' $ext.Enabled $(if ($ext.Enabled) { 'ok' } else { 'GAP - no external sender banner' })
}

$findings | Export-Csv (Join-Path $OutDir 'email-posture.csv') -NoTypeInformation
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue

Write-Host ''
$findings | Where-Object Verdict -match 'GAP|REVIEW' | Format-Table Area, Setting, Value, Verdict -AutoSize
Write-Host ("{0} settings checked, {1} gaps" -f $findings.Count, @($findings | Where-Object Verdict -match 'GAP|REVIEW').Count) -ForegroundColor Yellow
Write-Host "Written to $OutDir" -ForegroundColor Green
