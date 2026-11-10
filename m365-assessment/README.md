# M365 Posture Assessment — NewportHighPTSA

Read-only security assessment of tenant `3177c971-05c9-4b7b-93a1-0edf6fd7237d`
(`NewportHighPTSA.onmicrosoft.com`).

This is configuration assessment, not a penetration test: the tenant's attack surface *is* its
configuration. Every script reads; none changes a policy, grants consent, or sends an
authentication attempt at a user.

## The suite

```text
.\0-Connect-DeviceCode.ps1    --- sign in once, 15-min window; seals a refresh token so later runs are headless
.\0r-Refresh-Token.ps1        --- reconnect with no browser; -Run 3,5,6 chains scripts in one session
.\1-Run-ScubaGear.ps1         --- CISA SCuBA baselines: Exchange, SharePoint, Teams, Defender, Purview
.\2-Get-SecureScore.ps1       --- Secure Score total, per category, and the largest point gaps
.\3-Get-EntraPosture.ps1      --- CA policies + exclusions, roles, MFA registration, apps, grants, consent
.\4-Analyze.ps1               --- joins 2+3, resolves exclusion GUIDs to names, scores by category
.\5-Get-AppCredentials.ps1    --- secret/cert expiry, orphaned apps, weak redirect URIs, legacy graph perms
.\6-Get-RiskySignIns.ps1      --- risky users, risk detections, failed sign-ins, legacy auth
.\7-Get-EmailPosture.ps1      --- SPF/DKIM/DMARC, anti-phish, Safe Links, Safe Attachments, forwarding, SMTP AUTH
.\8-Get-SharingPosture.ps1    --- SharePoint sharing caps, Anyone links, unlabelled sites (Copilot exposure)
.\9-Build-Report.ps1          --- everything into REPORT.md + REPORT.html, severity-ranked, ATT&CK-mapped
```

## Headless workflow

Seed once, then never see a browser again:

```powershell
.\0-Connect-DeviceCode.ps1          # once: browser, ~20 seconds, seals refresh.dat with DPAPI
.\0r-Refresh-Token.ps1 -Run 2,3,5,6,9   # from now on: no interaction at all
```

`0r-` redeems the sealed refresh token, rotates it, and re-seals the new one. The token is
encrypted to your Windows account, so it does not work for anyone else or on another machine,
and `m365-assessment/state/` is gitignored.

Chain only what the session can do — `-Run 9` alone needs no Graph access at all.

## What each script needs

| Script | Needs | Can it be headless? |
| --- | --- | --- |
| 0- | Global Admin (or Global Reader) | No — it *is* the interactive step |
| 0r- | a seeded token | Yes |
| 1- | ScubaGear; interactive consent per workload | No |
| 2- | Graph `Reports.Read.All` | Yes |
| 3- | Graph `Policy.Read.All`, `RoleManagement.Read.Directory`, `Policy.Read.ConditionalAccess` | Yes |
| 4- | nothing (local) | Yes |
| 5- | Graph `Application.Read.All` | Yes |
| 6- | Graph `AuditLog.Read.All` + `IdentityRiskyUser.Read.All` | Yes |
| 7- | Exchange Online module + Exchange Administrator | No (interactive) |
| 8- | SharePoint admin endpoint + SharePoint Administrator | No (interactive) |
| 9- | nothing (local) | Yes |

An Azure CLI token (`az account get-access-token --resource https://graph.microsoft.com`) also works
for 2, 5 and the sign-in half of 6, because the Azure CLI client carries `Reports.Read.All`-adjacent
and `AuditLog.Read.All` scopes. It does **not** carry `Policy.Read*`, `RoleManagement.Read.Directory`
or the Identity Protection scopes, so 3 and the risky-user sections of 6 fail under `az`. Those
failures are recorded as `skipped-*.txt` markers, never as empty results.

## Output

Everything lands in `m365-assessment\reports\`.

| File | What it tells you |
| --- | --- |
| `REPORT.md` / `REPORT.html` | The deliverable: severity-ranked findings, ATT&CK mapping, remediation order |
| `scuba-<timestamp>\*.html` | Per-control Pass/Fail across all baselines |
| `securescore-by-category.csv` | Identity / Data / Device / Apps / Infrastructure, worst first |
| `securescore-gaps.csv` | Every unimplemented control with its remediation text |
| `entra-ca-policies.csv` | Policies with `State` — anything not `enabled` is not enforced |
| `entra-ca-exclusions.csv` | Exclusion IDs resolved to names, which is where the real story lives |
| `entra-high-risk-grants.csv` | Apps holding `Directory.ReadWrite.All`, `Mail.Send`, `full_access_as_app`, … |
| `entra-app-credentials.csv` | Every secret/certificate with days remaining and owner count |
| `entra-signins-tooling.csv` | The assessor's own auth attempts, kept out of the findings |
| `skipped-*.txt` | A section that failed. **Not a pass.** |
| `email-posture.csv`, `spo-findings.csv` | Per-setting verdicts: ok / REVIEW / GAP |

## Reading the results honestly

The tenant is a dev/test lab - 50 `lab-copilot-userNNN` accounts, `test99`, `Lab Admin`. So:

- **Configuration findings are real** and transfer directly to a production tenant. A CA policy that
  excludes its own admins is the same mistake anywhere.
- **Identity-behaviour findings are thin.** The users are fabricated; "no risky users" means nobody
  is using the tenant, not that identity protection works.
- **A coverage gap is not a pass.** Check `skipped-*.txt` and the "not measured" section of the
  report before quoting a clean result.
- Expect `N/A` rows in ScubaGear for unlicensed workloads. N/A is not a pass either.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `AADSTS70011 ... scope ... does not exist` | One invalid scope rejects the whole list. `SecurityConfiguration.Read.All` is not a delegated scope; Secure Score needs `SecurityEvents.Read.All` |
| `AADSTS500191 ... certificate authority` | The Graph PowerShell client's cached credential is unusable in this tenant. Do not try to reuse the MSAL cache; seed with `0-` |
| `Refresh failed - expired or revoked` | Re-run `0-` to re-seed |
| `Connect-MgGraph` opens no browser | Use the device-code prompt it prints, or `Connect-MgGraph -UseDeviceAuthentication` |
| ScubaGear: Graph Auth "outside acceptable range" | Expected. ScubaGear pins `Microsoft.Graph.Authentication` 2.25.0; keep it in its own window |
| SharePoint checks fail | `Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser` |
| A section reports `403 required scopes are missing` | The token lacks that scope. Use `0-`/`0r-`, not `az` |

## Second opinion: first-party tooling

- **Secure Score** in the Defender portal — same data as script 2, with history.
- **Entra ID Protection** risky users / detections — Microsoft's own view of identity risk.
- **Attack Simulation Training** (Defender) — the sanctioned way to run a phishing simulation,
  instead of sending credential attacks at your own users.
