#Requires -Version 7.2
<#
.SYNOPSIS
    Aggregates every collected artifact into a single REPORT.md + REPORT.html.

.DESCRIPTION
    Pure local post-processing: reads the CSVs the other scripts wrote and derives
    findings from them. No tenant session required, so it can be re-run as many
    times as you like while you work through the remediation list.

    Findings are severity-ranked and mapped to MITRE ATT&CK, because the question
    "how bad is this really" is best answered by "which technique does it enable".

.NOTES
    Run last:  .\9-Build-Report.ps1
.EXAMPLE
    .\9-Build-Report.ps1
    .\9-Build-Report.ps1 -OutDir .\reports -Open
#>
[CmdletBinding()]
param(
    [string] $OutDir   = (Join-Path $PSScriptRoot 'reports'),
    [string] $Tenant   = 'NewportHighPTSA',
    [string] $TenantId = '3177c971-05c9-4b7b-93a1-0edf6fd7237d',
    [switch] $Open,

    # Domains held for branding/redirect only. They do not carry mail, so missing SPF/DKIM
    # is not a deliverability problem - but an unprotected brand domain is still spoofable.
    [string[]] $VanityDomains = @('newportptsa.org')
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
function Read-Data {
    param([string] $Name)
    $p = Join-Path $OutDir $Name
    if (-not (Test-Path $p)) { return $null }
    try { return @(Import-Csv $p) } catch { return $null }
}

function Col {
    param($Row, [string[]] $Names)
    if ($null -eq $Row) { return $null }
    $props = $Row.PSObject.Properties.Name
    foreach ($n in $Names) { if ($props -contains $n) { return $Row.$n } }
    return $null
}

$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    param(
        [string] $Id,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')] [string] $Severity,
        [string] $Domain,
        [string] $Title,
        [string] $Detail,
        [string] $Evidence
    )
    $checks.Add([pscustomobject]@{
            Id       = $Id
            Severity = $Severity
            Domain   = $Domain
            Title    = $Title
            Detail   = $Detail
            Evidence = $Evidence
        })
}

$missing = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------------------
# data
# ---------------------------------------------------------------------------
$caPolicies = Read-Data 'entra-ca-policies.csv'
$caExcl     = Read-Data 'entra-ca-exclusions.csv'
$adminMfa   = Read-Data 'entra-admin-mfa.csv'
$adminRoles = Read-Data 'entra-admin-roles.csv'
$hiGrants   = Read-Data 'entra-high-risk-grants.csv'
$scoreCat   = Read-Data 'securescore-by-category.csv'
$scoreGaps  = Read-Data 'securescore-gaps.csv'
$appCreds   = Read-Data 'entra-app-credentials.csv'
$appRisks   = Read-Data 'entra-app-risks.csv'
$riskyUsers = Read-Data 'entra-risky-users.csv'
$legacyAuth = Read-Data 'entra-legacy-auth-attempts.csv'
$emailDns   = Read-Data 'email-dns-auth.csv'
$emailPost  = Read-Data 'email-posture.csv'
$spoSites   = Read-Data 'spo-sites.csv'
$spoFind    = Read-Data 'spo-findings.csv'

$consentPath = Join-Path $OutDir 'entra-consent-settings.txt'
$consentText = if (Test-Path $consentPath) { Get-Content $consentPath -Raw } else { $null }
if (-not $consentText) { $missing.Add('entra-consent-settings.txt (3-Get-EntraPosture.ps1)') }

foreach ($n in @('entra-ca-policies.csv', 'entra-ca-exclusions.csv', 'entra-admin-mfa.csv', 'entra-admin-roles.csv', 'entra-high-risk-grants.csv', 'securescore-by-category.csv', 'securescore-gaps.csv')) {
    if (-not (Test-Path (Join-Path $OutDir $n))) { $missing.Add("$n (2-/3-Get-*.ps1)") }
}

# ---------------------------------------------------------------------------
# Conditional Access
# ---------------------------------------------------------------------------
if ($caPolicies) {
    $enabled    = @($caPolicies | Where-Object { (Col $_ @('State')) -eq 'enabled' })
    $reportOnly = @($caPolicies | Where-Object { (Col $_ @('State')) -eq 'enabledForReportingButNotEnforced' })
    $disabled   = @($caPolicies | Where-Object { (Col $_ @('State')) -eq 'disabled' })

    # enabled but with no grant control: targets users, enforces nothing
    $emptyGrant = @($enabled | Where-Object {
            [string]::IsNullOrWhiteSpace((Col $_ @('GrantControls'))) -and
            [string]::IsNullOrWhiteSpace((Col $_ @('AuthStrength')))
        })
    foreach ($p in $emptyGrant) {
        Add-Check -Id 'CA-EMPTY' -Severity 'High' -Domain 'Conditional Access' `
            -Title ("Enabled policy with no grant control: {0}" -f (Col $p @('DisplayName'))) `
            -Detail 'Policy targets users but has neither built-in controls nor an authentication strength, so it enforces nothing.' `
            -Evidence 'entra-ca-policies.csv'
    }

    $exclIds = @()
    if ($caExcl) { $exclIds = @($caExcl | ForEach-Object { Col $_ @('Id') } | Where-Object { $_ }) }

    if ($exclIds.Count -gt 0) {
        $adminSet = @()
        if ($adminRoles) {
            $adminSet = @($adminRoles | Where-Object { (Col $_ @('Name')) -notmatch 'Synchronization' } | ForEach-Object { Col $_ @('UPN') })
        }

        # Collapse to one finding per excluded identity: six rows all saying "Albert is
        # exempt from something" bury the one that matters.
        $byIdentity = @{}
        foreach ($p in $enabled) {
            $excl = @()
            foreach ($n in @('ExcludeUsers', 'Excluded')) {
                $v = Col $p @($n)
                if ($v) { $excl += ($v -split ',' | ForEach-Object { $_.Trim() }) }
            }
            foreach ($id in ($excl | Where-Object { $exclIds -contains $_ })) {
                if (-not $byIdentity.ContainsKey($id)) { $byIdentity[$id] = [System.Collections.Generic.List[string]]::new() }
                $pol = Col $p @('DisplayName')
                if (-not $byIdentity[$id].Contains($pol)) { $byIdentity[$id].Add($pol) }
            }
        }

        foreach ($id in $byIdentity.Keys) {
            $row = $caExcl | Where-Object { (Col $_ @('Id')) -eq $id } | Select-Object -First 1
            $upn = if ($row) { Col $row @('Name') } else { $id }
            $pols = @($byIdentity[$id])

            $isAdmin = $adminSet -contains $upn
            $mfaRow = if ($adminMfa -and $isAdmin) { $adminMfa | Where-Object { (Col $_ @('UPN')) -eq $upn } | Select-Object -First 1 } else { $null }
            $hasMfa = ($mfaRow -and (Col $mfaRow @('MfaRegistered')) -eq 'True')

            $sev = if ($isAdmin -and -not $hasMfa) { 'Critical' } elseif ($isAdmin) { 'High' } else { 'Medium' }
            $detail = if ($isAdmin -and -not $hasMfa) {
                'Privileged account, excluded from enforcement, and no MFA method registered. Password alone is sufficient.'
            } elseif ($isAdmin) {
                'Privileged account excluded from enforcement. MFA is registered but now self-managed, not policy-required.'
            } else {
                'Account excluded from enforcement.'
            }

            Add-Check -Id 'CA-EXCL' -Severity $sev -Domain 'Conditional Access' `
                -Title ("{0} is excluded from {1} policy/policies" -f $upn, $pols.Count) `
                -Detail ("{0} Policies: {1}." -f $detail, ($pols -join '; ')) `
                -Evidence 'entra-ca-exclusions.csv'
        }
    }

    $ratioSev = if ($reportOnly.Count -gt $enabled.Count) { 'Medium' } else { 'Info' }
    Add-Check -Id 'CA-RATIO' -Severity $ratioSev -Domain 'Conditional Access' `
        -Title ("{0} enabled, {1} report-only, {2} disabled" -f $enabled.Count, $reportOnly.Count, $disabled.Count) `
        -Detail 'Report-only policies block nothing. Each one is a decision that has not yet been made.' `
        -Evidence 'entra-ca-policies.csv'
}

# ---------------------------------------------------------------------------
# privileged accounts without MFA
# ---------------------------------------------------------------------------
if ($adminMfa) {
    $noMfa = @($adminMfa | Where-Object {
            (Col $_ @('MfaRegistered')) -eq 'False' -and
            (Col $_ @('Name')) -notmatch 'Synchronization' -and
            (Col $_ @('UPN')) -notmatch '^ADToAAD'
        })
    foreach ($u in $noMfa) {
        $nm = Col $u @('Name')
        $detail = "Role: {0}. A password alone satisfies this account." -f (Col $u @('Role'))
        if ($nm -match 'glass|emergency|break') {
            $detail += ' If this is a deliberate break-glass account, give it a phishing-resistant credential held offline rather than no second factor at all.'
        }
        Add-Check -Id 'ADMIN-NOMFA' -Severity 'Critical' -Domain 'Identity' `
            -Title ("Privileged account without MFA: {0}" -f $nm) `
            -Detail $detail `
            -Evidence 'entra-admin-mfa.csv'
    }
    if ($noMfa.Count -eq 0) {
        Add-Check -Id 'ADMIN-MFA-OK' -Severity 'Info' -Domain 'Identity' `
            -Title 'All human privileged accounts have MFA registered' `
            -Detail 'The directory-synchronisation service account is excluded as expected.' `
            -Evidence 'entra-admin-mfa.csv'
    }
}

# ---------------------------------------------------------------------------
# application consent
# ---------------------------------------------------------------------------
if ($hiGrants) {
    $appOnly = @($hiGrants | Where-Object { (Col $_ @('GrantedToType')) -eq 'ServicePrincipal' })
    $to = @($appOnly | ForEach-Object { Col $_ @('GrantedTo') } | Sort-Object -Unique)
    Add-Check -Id 'APP-GRANTS' -Severity 'High' -Domain 'Applications' `
        -Title ("{0} high-risk app-to-app permission grants" -f $appOnly.Count) `
        -Detail ("Granted to: {0}. These are standing permissions with no user in the loop." -f ($to -join ', ')) `
        -Evidence 'entra-high-risk-grants.csv'
}

if ($consentText -match 'AllowEmailVerifiedUsersToJoinOrganization\s*:\s*True') {
    Add-Check -Id 'CONSENT-EMAILVERIFIED' -Severity 'Medium' -Domain 'Identity' `
        -Title 'Email-verified users may join the tenant as guests' `
        -Detail 'Anyone who can verify an email address can be added as a guest without an invitation being approved.' `
        -Evidence 'entra-consent-settings.txt'
}
if ($consentText -match 'AllowedToCreateApps\s*:\s*True') {
    Add-Check -Id 'CONSENT-USERAPPS' -Severity 'Medium' -Domain 'Applications' `
        -Title 'Users can register applications' `
        -Detail 'Application registration plus user consent is the standard consent-phishing path.' `
        -Evidence 'entra-consent-settings.txt'
}

# ---------------------------------------------------------------------------
# app credential lifecycle
# ---------------------------------------------------------------------------
if ($appCreds) {
    $expired = @($appCreds | Where-Object { (Col $_ @('State')) -eq 'EXPIRED' })
    $expiring = @($appCreds | Where-Object { (Col $_ @('State')) -eq 'EXPIRING' })
    if ($expired.Count -gt 0) {
        $names = @($expired | ForEach-Object { Col $_ @('App') } | Sort-Object -Unique)
        Add-Check -Id 'APPCRED-EXPIRED' -Severity 'Medium' -Domain 'Applications' `
            -Title ("{0} expired app credential(s)" -f $expired.Count) `
            -Detail ("Affected: {0}. Expired secrets cause outages; if the app still authenticates, a second credential exists." -f ($names -join ', ')) `
            -Evidence 'entra-app-credentials.csv'
    }
    if ($expiring.Count -gt 0) {
        $list = @($expiring | ForEach-Object { '{0} ({1}d)' -f (Col $_ @('App')), (Col $_ @('DaysLeft')) })
        Add-Check -Id 'APPCRED-EXPIRING' -Severity 'Low' -Domain 'Applications' `
            -Title ("{0} app credential(s) expiring within 30 days" -f $expiring.Count) `
            -Detail ($list -join ', ') `
            -Evidence 'entra-app-credentials.csv'
    }
}
if ($appRisks) {
    $noOwner = @($appRisks | Where-Object { (Col $_ @('Risk')) -eq 'No owner' })
    if ($noOwner.Count -gt 0) {
        Add-Check -Id 'APP-NOOWNER' -Severity 'Medium' -Domain 'Applications' `
            -Title ("{0} application(s) have no owner" -f $noOwner.Count) `
            -Detail 'Nobody receives the credential-expiry warning, so the secret becomes permanent by neglect.' `
            -Evidence 'entra-app-risks.csv'
    }
}

# ---------------------------------------------------------------------------
# identity risk / sign-ins
# ---------------------------------------------------------------------------
if ($riskyUsers) {
    # Not $open: PowerShell variables are case-insensitive, so that would overwrite the
    # [switch] $Open parameter and break the -Open flag at the end of the script.
    $unremediated = @($riskyUsers | Where-Object {
            (Col $_ @('RiskLevel')) -in @('high', 'medium') -and (Col $_ @('RiskState')) -ne 'remediated'
        })
    if ($unremediated.Count -gt 0) {
        Add-Check -Id 'IDP-RISKY' -Severity 'High' -Domain 'Identity' `
            -Title ("{0} unremediated risky user(s) at medium/high" -f $unremediated.Count) `
            -Detail 'Risk was detected and never closed. Remediate the session or dismiss with a documented reason.' `
            -Evidence 'entra-risky-users.csv'
    }
}
if ($legacyAuth) {
    $total = ($legacyAuth | ForEach-Object { [int](Col $_ @('Count')) } | Measure-Object -Sum).Sum
    if ($total -gt 0) {
        Add-Check -Id 'AUTH-LEGACY' -Severity 'High' -Domain 'Identity' `
            -Title ("{0} legacy-auth sign-in attempt(s) in the sample window" -f $total) `
            -Detail 'Legacy protocols bypass MFA by design. Blocking them in Conditional Access is the highest-value single change.' `
            -Evidence 'entra-legacy-auth-attempts.csv'
    }
}

# ---------------------------------------------------------------------------
# email
# ---------------------------------------------------------------------------
if ($emailDns) {
    foreach ($d in $emailDns) {
        $dom = Col $d @('Domain')

        # The tenant's initial *.onmicrosoft.com domain is platform-managed: its SPF/DKIM/DMARC
        # are not customer-configurable, so flagging them would be noise, not a finding.
        if ($dom -match '\.onmicrosoft\.com$') { continue }

        # A vanity domain that sends no mail does not need DKIM or a mail-flow SPF.
        # It still should not be spoofable, but that is a two-record fix, not an outage.
        if ($VanityDomains -contains $dom) {
            $gaps = @()
            if ((Col $d @('SPF')) -eq 'MISSING') { $gaps += 'no SPF' }
            if ((Col $d @('DMARCPolicy')) -eq 'none') { $gaps += 'DMARC p=none' }
            if ($gaps.Count -gt 0) {
                Add-Check -Id 'EMAIL-BRAND-DOMAIN' -Severity 'Low' -Domain 'Email' `
                    -Title ("Brand domain {0} is spoofable ({1})" -f $dom, ($gaps -join ', ')) `
                    -Detail 'Not used for mail, so this is not a deliverability issue - but a sender can still forge it, and the PTSA name is the asset. Fix: publish `v=spf1 -all` and `v=DMARC1; p=reject;`. No DKIM needed if it never sends.' `
                    -Evidence 'email-dns-auth.csv'
            }
            continue
        }

        if ((Col $d @('SPF')) -eq 'MISSING') {
            Add-Check -Id 'EMAIL-SPF' -Severity 'High' -Domain 'Email' `
                -Title ("No SPF record for {0}" -f $dom) `
                -Detail 'Without SPF any host may send mail claiming to be this domain, and receivers have no basis to reject it.' `
                -Evidence 'email-dns-auth.csv'
        }
        elseif ((Col $d @('SPFStrict')) -match 'soft') {
            Add-Check -Id 'EMAIL-SPF-SOFT' -Severity 'Medium' -Domain 'Email' `
                -Title ("SPF for {0} ends in ~all instead of -all" -f $dom) `
                -Detail 'Soft fail marks spoofed mail but does not reject it.' `
                -Evidence 'email-dns-auth.csv'
        }

        if ((Col $d @('DMARC')) -eq 'MISSING') {
            Add-Check -Id 'EMAIL-DMARC' -Severity 'High' -Domain 'Email' `
                -Title ("No DMARC record for {0}" -f $dom) `
                -Detail 'Anyone can spoof this domain, and there is no reporting to tell you it happened.' `
                -Evidence 'email-dns-auth.csv'
        }
        elseif ((Col $d @('DMARCPolicy')) -eq 'none') {
            Add-Check -Id 'EMAIL-DMARC-NONE' -Severity 'Medium' -Domain 'Email' `
                -Title ("DMARC p=none for {0}" -f $dom) `
                -Detail 'Monitoring only: spoofed mail is reported, not rejected. Pair this with a missing SPF and the domain is fully spoofable.' `
                -Evidence 'email-dns-auth.csv'
        }

        if ((Col $d @('DKIMselector1')) -eq 'MISSING') {
            Add-Check -Id 'EMAIL-DKIM' -Severity 'Medium' -Domain 'Email' `
                -Title ("No DKIM selector1 for {0}" -f $dom) `
                -Detail 'No cryptographic signing, so receivers cannot verify integrity and forwarders break alignment.' `
                -Evidence 'email-dns-auth.csv'
        }
    }
}
if ($emailPost) {
    foreach ($g in @($emailPost | Where-Object { (Col $_ @('Verdict')) -match 'GAP|REVIEW' })) {
        $sev = if ((Col $g @('Verdict')) -match 'GAP') { 'High' } else { 'Medium' }
        # Mailbox intelligence strengthens impersonation detection; it is a layer, not the
        # control itself, so off-by-default is Medium, not High.
        if ((Col $g @('Setting')) -eq 'Mailbox intelligence') { $sev = 'Medium' }
        Add-Check -Id 'EMAIL-CFG' -Severity $sev -Domain 'Email' `
            -Title ("{0}: {1}" -f (Col $g @('Area')), (Col $g @('Setting'))) `
            -Detail ("Observed {0} - {1}" -f (Col $g @('Value')), (Col $g @('Verdict'))) `
            -Evidence 'email-posture.csv'
    }
}

# ---------------------------------------------------------------------------
# sharing / Copilot exposure
# ---------------------------------------------------------------------------
if ($spoFind) {
    foreach ($g in @($spoFind | Where-Object { (Col $_ @('Verdict')) -match 'GAP|REVIEW' })) {
        $sev = if ((Col $g @('Verdict')) -match 'GAP') { 'High' } else { 'Medium' }
        Add-Check -Id 'SPO-CFG' -Severity $sev -Domain 'Data' `
            -Title ("Sharing: {0}" -f (Col $g @('Setting'))) `
            -Detail ("Observed {0} - {1}" -f (Col $g @('Value')), (Col $g @('Verdict'))) `
            -Evidence 'spo-findings.csv'
    }
}
if ($spoSites) {
    $anyone = @($spoSites | Where-Object { (Col $_ @('SharingCapability')) -eq 'Anyone' })
    $unlabelled = @($spoSites | Where-Object { -not (Col $_ @('SensitivityLabel')) })
    if ($anyone.Count -gt 0) {
        Add-Check -Id 'SPO-ANYONE' -Severity 'High' -Domain 'Data' `
            -Title ("{0} site(s) shared with Anyone" -f $anyone.Count) `
            -Detail 'Unauthenticated links. Copilot will happily summarise content sitting behind one.' `
            -Evidence 'spo-sites.csv'
    }
    if ($unlabelled.Count -gt 0) {
        Add-Check -Id 'SPO-NOLABEL' -Severity 'Medium' -Domain 'Data' `
            -Title ("{0} site(s) have no sensitivity label" -f $unlabelled.Count) `
            -Detail 'No label means no encryption, no DLP match, and no Copilot exclusion.' `
            -Evidence 'spo-sites.csv'
    }
}

if (-not $spoSites -and -not $spoFind) { $missing.Add('spo-sites.csv / spo-findings.csv (8-Get-SharingPosture.ps1)') }
if (-not $appCreds -and -not $appRisks) { $missing.Add('entra-app-credentials.csv (5-Get-AppCredentials.ps1)') }
if (-not (Test-Path (Join-Path $OutDir 'entra-signins.csv'))) { $missing.Add('sign-in logs (6-Get-RiskySignIns.ps1)') }
if (-not $emailPost -and -not $emailDns) { $missing.Add('email-posture.csv / email-dns-auth.csv (7-Get-EmailPosture.ps1)') }

# A section that failed mid-run is a coverage gap, not a pass. Surface it explicitly.
$notMeasured = @(
    Get-ChildItem $OutDir -Filter 'skipped-*.txt' -File -ErrorAction SilentlyContinue | ForEach-Object {
        $why = (Get-Content $_.FullName | Where-Object { $_ -match '^reason:' } | Select-Object -First 1) -replace '^reason:\s*', ''
        [pscustomobject]@{
            Area   = ($_.BaseName -replace '^skipped-', '') -replace '-', ' '
            Reason = if ($why) { $why } else { 'unknown' }
            Marker = $_.Name
        }
    }
)

# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------
$scorePct = $null
if ($scoreCat) {
    $cur = ($scoreCat | ForEach-Object { [double](Col $_ @('Current')) } | Measure-Object -Sum).Sum
    $max = ($scoreCat | ForEach-Object { [double](Col $_ @('Max')) } | Measure-Object -Sum).Sum
    if ($max -gt 0) { $scorePct = [math]::Round(100 * $cur / $max, 1) }
}

$sevOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }
$sorted = @($checks | Sort-Object @{ e = { $sevOrder[$_.Severity] } }, Domain, Title)
$counts = @{}
foreach ($s in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
    $counts[$s] = @($sorted | Where-Object Severity -eq $s).Count
}

# ---------------------------------------------------------------------------
# ATT&CK mapping
# ---------------------------------------------------------------------------
$attack = @(
    [pscustomobject]@{ Technique = 'T1078 - Valid Accounts'; Surface = 'Identity'; Why = 'Password-only privileged accounts are directly usable; no exploit required.' }
    [pscustomobject]@{ Technique = 'T1110 - Brute Force / Password Spray'; Surface = 'Identity'; Why = 'Accounts without MFA can be sprayed at scale.' }
    [pscustomobject]@{ Technique = 'T1556 - Modify Authentication Process'; Surface = 'Conditional Access'; Why = 'Exclusions plus report-only policies leave the enforcement path editable.' }
    [pscustomobject]@{ Technique = 'T1528 - Steal Application Access Token'; Surface = 'Applications'; Why = 'Broad standing app grants turn one stolen token into tenant-wide access.' }
    [pscustomobject]@{ Technique = 'T1098.001 - Additional Cloud Credentials'; Surface = 'Applications'; Why = 'Non-expiring app secrets are credential persistence.' }
    [pscustomobject]@{ Technique = 'T1566 - Phishing'; Surface = 'Email'; Why = 'Missing Safe Links / Safe Attachments / DMARC enforcement leaves delivery intact.' }
    [pscustomobject]@{ Technique = 'T1114.003 - Email Forwarding Rule'; Surface = 'Email'; Why = 'Unrestricted auto-forwarding exfiltrates mail silently.' }
    [pscustomobject]@{ Technique = 'T1213 - Data from Information Repositories'; Surface = 'Data'; Why = 'Anyone-links and unlabelled sites are mass-readable; Copilot indexes them.' }
    [pscustomobject]@{ Technique = 'T1557 - AiTM / Session Hijack'; Surface = 'Identity'; Why = 'No phishing-resistant MFA and no token protection means session theft wins.' }
)

# ---------------------------------------------------------------------------
# render markdown
# ---------------------------------------------------------------------------
$md = [System.Collections.Generic.List[string]]::new()
function Add-Line { param([string[]] $Lines) foreach ($x in $Lines) { $script:md.Add($x) } }

Add-Line @(
    "# Security posture assessment - $Tenant"
    ''
    "- **Tenant:** $Tenant ($TenantId)"
    "- **Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
    "- **Method:** read-only Microsoft Graph and Exchange Online queries; SharePoint and ScubaGear products only where their sign-in succeeded (see Coverage gaps)"
    "- **Scope:** identity, Conditional Access, applications, email, collaboration data"
    ''
)

Add-Line @('## Executive summary', '')
if ($null -ne $scorePct) {
    Add-Line @("- Microsoft Secure Score: **$scorePct%** of the licensed maximum.")
}
Add-Line @(
    '- Read-only assessment: no configuration was changed.'
    ''
    '| Severity | Count |'
    '| --- | --- |'
)
foreach ($s in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
    Add-Line @("| $s | $($counts[$s]) |")
}
Add-Line @('')

if ($missing.Count -gt 0) {
    $joined = (@($missing | Sort-Object -Unique) -join '; ')
    Add-Line @("> Not collected yet: $joined")
    Add-Line @('')
}

if ($notMeasured.Count -gt 0) {
    Add-Line @('### Coverage gaps - not measured', '')
    Add-Line @('These sections ran and failed. They are **not** clean results; absence of a finding here means absence of evidence.', '')
    Add-Line @('| Area | Why it was not measured |', '| --- | --- |')
    foreach ($n in $notMeasured) { Add-Line @("| $($n.Area) | $($n.Reason) |") }
    Add-Line @('')
}

if (Test-Path (Join-Path $OutDir 'entra-signins-tooling.csv')) {
    $toolRows = @(Import-Csv (Join-Path $OutDir 'entra-signins-tooling.csv')).Count
    Add-Line @("> Sign-in analysis excludes $toolRows authentication attempts made by the assessment tooling itself (see ``entra-signins-tooling.csv``), so the assessor's own failed connects are not reported as hostile activity.")
    Add-Line @('')
}

Add-Line @('## Findings', '')
foreach ($g in ($sorted | Group-Object Domain | Sort-Object Name)) {
    Add-Line @("### $($g.Name)", '')
    foreach ($c in ($g.Group | Sort-Object @{ e = { $sevOrder[$_.Severity] } })) {
        Add-Line @(
            ("**[{0}] {1}** - {2}" -f $c.Severity.ToUpper(), $c.Id, $c.Title)
            ''
            "  $($c.Detail)"
            ''
            "  evidence: ``$($c.Evidence)``"
            ''
        )
    }
}

if ($scoreCat) {
    Add-Line @('## Secure Score by category', '', '| Category | Current | Max | Percent |', '| --- | --- | --- | --- |')
    foreach ($r in $scoreCat) {
        Add-Line @("| $(Col $r @('Category')) | $(Col $r @('Current')) | $(Col $r @('Max')) | $(Col $r @('Percent'))% |")
    }
    Add-Line @('')
}

if ($scoreGaps) {
    $top = @($scoreGaps | Sort-Object { [double](Col $_ @('Gap')) } -Descending | Select-Object -First 12)
    $top = @($top | Where-Object { [double](Col $_ @('Gap')) -gt 0 })
    if ($top.Count -gt 0) {
        Add-Line @('### Largest point gaps', '', '| Control | Category | Gap |', '| --- | --- | --- |')
        foreach ($r in $top) {
            Add-Line @("| $(Col $r @('Control')) | $(Col $r @('Category')) | $(Col $r @('Gap')) |")
        }
        Add-Line @('')
    }
}

Add-Line @('## MITRE ATT&CK mapping', '', '| Technique | Surface | Why it applies here |', '| --- | --- | --- |')
foreach ($a in $attack) { Add-Line @("| $($a.Technique) | $($a.Surface) | $($a.Why) |") }
Add-Line @('')

Add-Line @(
    '## Remediation order'
    ''
    '1. **Block legacy authentication** - one Conditional Access policy removes an entire bypass class.'
    '2. **Fix the admin MFA exclusions** - an admin MFA policy that exempts the admins is decoration.'
    '3. **Register MFA on every human privileged account**, then convert the report-only policies to enabled.'
    '4. **Safe Links and Safe Attachments to Block mode** - roughly 22 Secure Score points.'
    '5. **Enforce DMARC at p=reject and publish DKIM** for each accepted domain.'
    '6. **Restrict auto-forwarding** and review mail-flow rules that redirect externally.'
    '7. **Reduce standing app permissions**, expire secrets, and give every app an owner.'
    '8. **Tighten sharing**: no Anyone links, edit-not-default, expiry on anonymous links, label sites.'
    ''
    '> Ordering rationale: each step removes a technique rather than a symptom. Steps 1-3 close the'
    '> paths that need no user action at all.'
    ''
    '## Evidence inventory'
    ''
    '| File | Rows | KB |'
    '| --- | --- | --- |'
)
foreach ($f in (Get-ChildItem $OutDir -File | Sort-Object Name)) {
    $rows = ''
    if ($f.Extension -eq '.csv') {
        try { $rows = (@(Import-Csv $f.FullName)).Count } catch { $rows = '?' }
    }
    Add-Line @("| ``$($f.Name)`` | $rows | $([math]::Round($f.Length / 1KB, 1)) |")
}
Add-Line @('')

$mdPath = Join-Path $OutDir 'REPORT.md'
$md | Set-Content $mdPath -Encoding utf8
Write-Host "Report written: $mdPath" -ForegroundColor Green

# ---------------------------------------------------------------------------
# HTML copy
# ---------------------------------------------------------------------------
function Convert-MdToHtml {
    param([string[]] $Lines)

    function Esc([string] $s) { $s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' }
    function Inline([string] $s) {
        $s = Esc $s
        $s = [regex]::Replace($s, '\*\*(.+?)\*\*', '<strong>$1</strong>')
        $s = [regex]::Replace($s, '`(.+?)`', '<code>$1</code>')
        return $s
    }

    $sb = [System.Text.StringBuilder]::new()
    $inTable = $false; $inList = $false; $inCode = $false; $tableHasHeader = $false

    foreach ($line in $Lines) {
        if ($line -match '^```') {
            if ($inCode) { [void]$sb.AppendLine('</pre>'); $inCode = $false }
            else { [void]$sb.AppendLine('<pre>'); $inCode = $true }
            continue
        }
        if ($inCode) { [void]$sb.AppendLine((Esc $line)); continue }

        if ($line -match '^\|') {
            if ($line -match '^\|[\s\-:|]+$') { continue }
            if (-not $inTable) { [void]$sb.AppendLine('<table>'); $inTable = $true; $tableHasHeader = $false }
            $cells = $line.Trim('|') -split '\|'
            $tag = if (-not $tableHasHeader) { 'th' } else { 'td' }
            [void]$sb.Append('<tr>')
            foreach ($c in $cells) { [void]$sb.Append("<$tag>$(Inline $c.Trim())</$tag>") }
            [void]$sb.AppendLine('</tr>')
            $tableHasHeader = $true
            continue
        }
        if ($inTable) { [void]$sb.AppendLine('</table>'); $inTable = $false }

        if ($line -match '^- ') {
            if (-not $inList) { [void]$sb.AppendLine('<ul>'); $inList = $true }
            [void]$sb.AppendLine("<li>$(Inline ($line -replace '^- ', ''))</li>")
            continue
        }
        if ($inList) { [void]$sb.AppendLine('</ul>'); $inList = $false }

        if ($line -match '^(#{1,6})\s+(.*)$') {
            $n = $matches[1].Length
            [void]$sb.AppendLine("<h$n>$(Inline $matches[2])</h$n>")
            continue
        }
        if ($line -match '^> (.*)$') {
            [void]$sb.AppendLine("<blockquote>$(Inline $matches[1])</blockquote>")
            continue
        }
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        if ($line -match '^  ') {
            $txt = $line.Trim()
            $cls = if ($txt -match '^evidence:') { 'evidence' } else { 'detail' }
            [void]$sb.AppendLine("<p class=`"$cls`">$(Inline $txt)</p>")
            continue
        }
        [void]$sb.AppendLine("<p>$(Inline $line)</p>")
    }
    if ($inTable) { [void]$sb.AppendLine('</table>') }
    if ($inList) { [void]$sb.AppendLine('</ul>') }
    if ($inCode) { [void]$sb.AppendLine('</pre>') }
    return $sb.ToString()
}

$body = Convert-MdToHtml -Lines $md

$html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security posture assessment - $Tenant</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.65 -apple-system, "Segoe UI", Roboto, sans-serif; max-width: 60rem; margin: 0 auto; padding: 3rem 1.5rem; color: #14171f; background: #fbfbfd; }
  h1 { font-size: 2rem; letter-spacing: -.02em; margin-bottom: .25rem; }
  h2 { margin-top: 3rem; padding-bottom: .4rem; border-bottom: 1px solid #dfe3ea; font-size: 1.4rem; }
  h3 { margin-top: 2.25rem; font-size: .82rem; text-transform: uppercase; letter-spacing: .09em; color: #5b6474; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0 1.5rem; font-size: .93rem; }
  th, td { text-align: left; padding: .5rem .65rem; border-bottom: 1px solid #e6e9ef; vertical-align: top; }
  th { background: #f1f3f7; font-weight: 600; }
  code { background: #eef1f6; padding: .1em .35em; border-radius: 4px; font-size: .88em; }
  blockquote { margin: 1.2rem 0; padding: .7rem 1rem; border-left: 3px solid #c8cfdb; background: #f4f6fa; color: #4a5262; }
  p.evidence { margin: .1rem 0 .9rem; color: #6b7385; font-size: .78rem; }
  p.detail { margin: .3rem 0 .2rem; color: #3d4453; }
  @media (prefers-color-scheme: dark) {
    body { background: #14161b; color: #e6e9f0; }
    h2 { border-color: #2c313b; } h3 { color: #9aa3b5; }
    th { background: #1d212a; } th, td { border-color: #262b35; }
    code { background: #1d212a; }
    blockquote { background: #1a1e26; border-color: #333a47; color: #a9b2c3; }
    p.detail { color: #b6becd; } p.evidence { color: #8e97a8; }
  }
</style></head><body>
$body
</body></html>
"@

$htmlPath = Join-Path $OutDir 'REPORT.html'
$html | Set-Content $htmlPath -Encoding utf8
Write-Host "HTML written:   $htmlPath" -ForegroundColor Green

# ---------------------------------------------------------------------------
# console summary
# ---------------------------------------------------------------------------
Write-Host ''
foreach ($s in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
    $colour = switch ($s) { 'Critical' { 'Red' } 'High' { 'DarkYellow' } 'Medium' { 'Yellow' } 'Low' { 'Gray' } default { 'DarkGray' } }
    Write-Host ("{0,-9} {1}" -f $s, $counts[$s]) -ForegroundColor $colour
}
if (@($sorted | Where-Object Severity -in @('Critical', 'High')).Count -gt 0) {
    $sorted | Where-Object Severity -in @('Critical', 'High') | Select-Object Severity, Id, Title | Format-Table -AutoSize
}

if ($missing.Count -gt 0) {
    Write-Host 'Not yet collected - run the listed script, then re-run this one:' -ForegroundColor Yellow
    $missing | Sort-Object -Unique | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkYellow }
}

if ($notMeasured.Count -gt 0) {
    Write-Host ''
    Write-Host 'Coverage gaps (ran, failed, NOT a pass):' -ForegroundColor Yellow
    $notMeasured | ForEach-Object { Write-Host ("  - {0}: {1}" -f $_.Area, $_.Reason) -ForegroundColor DarkYellow }
}

if ($Open) { Start-Process $htmlPath }
