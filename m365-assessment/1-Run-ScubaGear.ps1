#Requires -Version 7.2
<#
.SYNOPSIS
    Runs the CISA SCuBA baseline assessment against the tenant with ScubaGear.

.DESCRIPTION
    Produces an HTML report scoring every M365 control in the CISA SCuBA baselines
    (Entra ID, Defender, Exchange, SharePoint, Teams) as Pass / Fail / N/A / 3rd Party,
    plus the raw JSON that backs each finding.

    Interactive: you will be prompted to sign in. Run this in your OWN terminal window,
    not through an automation harness — the browser/device-code prompt needs you.

.NOTES
    Requires a Global Reader (or Global Administrator) account in the target tenant.
    Exchange, SharePoint and Teams checks additionally need the matching admin role
    (View-Only Configuration / SharePoint Administrator / Teams Administrator).
    ScubaGear pins Microsoft.Graph.Authentication 2.25.0 — do not run this script and
    the Graph posture scripts in the same PowerShell session.

.EXAMPLE
    .\1-Run-ScubaGear.ps1
    .\1-Run-ScubaGear.ps1 -Products aad,exo
#>
[CmdletBinding()]
param(
    [string]   $Organization = 'newporthighptsa.onmicrosoft.com',

    # Valid ScubaGear product names: aad, exo, securitysuite (Defender), sharepoint, teams, powerplatform, powerbi.
    # 'defender' and 'exchange' are rejected by ValidateSet; Defender is covered by 'securitysuite'.
    [string[]] $Products = @('aad', 'securitysuite', 'exo', 'sharepoint', 'teams'),

    [string]   $OutRoot = (Join-Path $PSScriptRoot 'reports')
)

$ErrorActionPreference = 'Stop'

# PowerShell loads the highest installed Graph module by default (2.38.1), which ScubaGear
# rejects. Pin the version it requires before anything else imports Graph.
Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.25.0 -ErrorAction Stop
Import-Module ScubaGear -ErrorAction Stop

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$folder = "scuba-$stamp"

Write-Host ''
Write-Host "Tenant     : $Organization"            -ForegroundColor Cyan
Write-Host "Products   : $($Products -join ', ')"  -ForegroundColor Cyan
Write-Host "Output     : $(Join-Path $OutRoot $folder)" -ForegroundColor Cyan
Write-Host ''
Write-Host 'Sign in when prompted. Expect one prompt per workload.' -ForegroundColor Yellow
Write-Host ''

Invoke-SCuBA `
    -ProductNames $Products `
    -Organization $Organization `
    -OutPath      $OutRoot `
    -OutFolderName $folder

# ScubaGear appends its own timestamp to -OutFolderName, so the folder we asked for is not
# the folder it writes to. Find the one it actually created.
$actual = Get-ChildItem -Path $OutRoot -Directory -Filter "$folder*" -ErrorAction SilentlyContinue |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1

Write-Host ''
$report = if ($actual) {
    Get-ChildItem -Path $actual.FullName -Filter 'BaselineReports.html' -ErrorAction SilentlyContinue | Select-Object -First 1
}
if ($report) {
    Write-Host "HTML report: $($report.FullName)" -ForegroundColor Green
    Write-Host 'Open it in a browser. Each control links to the policy that produced the result.'
} else {
    Write-Host "No HTML report found under $OutRoot\$folder*" -ForegroundColor Yellow
}

# A product that fails authentication is a coverage gap, not a clean pass. Say so here.
if ($actual) {
    $debugLog = Get-ChildItem -Path (Join-Path $actual.FullName 'DebugLogs') -Filter '*ErrorReport.md' -ErrorAction SilentlyContinue | Select-Object -First 1
    $failed = if ($debugLog) { Select-String -Path $debugLog.FullName -Pattern 'Some products failed authentication' -SimpleMatch -Quiet } else { $false }
    if ($failed) {
        Write-Host ''
        Write-Host 'Some products FAILED to authenticate. Their controls were not assessed - see the debug report:' -ForegroundColor Red
        Write-Host "  $($debugLog.FullName)" -ForegroundColor Red
    }
}
