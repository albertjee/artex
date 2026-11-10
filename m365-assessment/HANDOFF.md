# M365 posture assessment: handoff

Read-only assessment of tenant `3177c971-05c9-4b7b-93a1-0edf6fd7237d` (`NewportHighPTSA.onmicrosoft.com`), a dev/test lab. Nothing here changes tenant configuration or grants consent.

Start with `FINDINGS.md` for the narrative and `reports\REPORT.md` for the generated, severity-ranked list. `README.md` is the script index.

## Run order

| Step | Command | Sign-in | Status |
| --- | --- | --- | --- |
| Seed a refresh token | `.\0-Connect-DeviceCode.ps1` | Browser, once | Done. Token sealed to `state\refresh.dat` (DPAPI, this Windows user only) |
| Graph checks, headless | `.\0r-Refresh-Token.ps1 -Run 3,5,6,9` | None | Done. Re-runnable until the refresh token expires |
| ScubaGear baseline | `.\1-Run-ScubaGear.ps1` | Interactive, one window | Entra done. Other four products failed auth (see below) |
| Exchange configuration | `.\7-Get-EmailPosture.ps1` | Device code, then a second sign-in for Security & Compliance | Partly done (see below) |
| SharePoint sharing | `.\8-Get-SharingPosture.ps1` | System browser | Failed to connect. Re-run once to record the gap |
| Report | `.\0r-Refresh-Token.ps1 -Run 9` or `.\9-Build-Report.ps1` | None (local) | Run after any collector changes |

`0r-` accepts `-Run 3,5,6` or `-Run 3 5 6`. Scripts that need Graph run in the same process, so they inherit the session.

## Authentication: what works on this machine

- **Graph:** device code via `0-`, then headless refresh via `0r-`. Verified: the refreshed token carries the Identity Protection, Policy and RoleManagement read scopes. It also carries some write scopes (`Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Mail.Send`), which is the consent-sprawl finding in `FINDINGS.md` C1.
- **Exchange Online:** `Connect-ExchangeOnline -Device` works.
- **Security & Compliance (IPPS):** `Connect-IPPSSession -DisableWAM` connects, but the Safe Links and Safe Attachments cmdlets are not exposed in that session. Likely cause: Defender for Office 365 licence or role. Not verified.
- **ScubaGear, non-Entra products:** the interactive sign-in fails with `To enable the embedded webview on Windows`. MSAL's embedded browser path breaks in this PowerShell session. ScubaGear 2.0.0 has no device-code option.
- **SharePoint Online:** `Connect-SPOService` fails, including with `-UseSystemBrowser:$true`. The cause is not shown in the error.

## Known gaps (recorded in the report as not measured)

- ScubaGear for Exchange, Defender, SharePoint and Teams.
- Safe Links, Safe Attachments, external sender identification (Exchange).
- SharePoint sharing and Copilot oversharing.

A gap is not a pass. Each one appears in the report's "Coverage gaps" section.

## Options for the gaps

1. Rewrite script 8 on PnP.PowerShell with device-code login. Verify the current PnP syntax first. PnP can't load alongside the SPO module in this session.
2. Check Defender for Office 365 licensing and the account's roles in the admin centre. If licensed, the Safe Links cmdlets may need a role change.
3. Run ScubaGear under Windows PowerShell 5.1. Untested.

## Lessons from this run

Recorded so the next person doesn't repeat them:

- A console-only "skipped" reads as silence in a report. Every collector now writes a `skipped-*.txt` marker.
- Empty CSVs are indistinguishable from "nothing found", so markers are the only reliable signal.
- Before asserting a policy "requires nothing", check every control surface: built-in grant controls, authentication strength and session controls. The Entra export now captures all three and sets `RequiresNothing` in one place.
- Verify claims against the export, not against earlier notes. Three claims in FINDINGS.md were wrong and got corrected this way.
- A PowerShell variable named `$Open` collides with `$open` (case-insensitive), which broke script 9 once the risky-user data became non-empty.
- `pwsh -File` passes a comma list as one string, so `-Run 6,9` was read as the number 69. `0r-` now splits it.

## Files

- Collectors: `0-`, `0r-`, `1-`, `2-`, `3-`, `4-`, `5-`, `6-`, `7-`, `8-`, `9-` (see `README.md`).
- Narrative: `FINDINGS.md`. Index: `README.md`.
- Evidence: `reports\*.csv`, `reports\scuba-*\`, `reports\REPORT.md`, `reports\REPORT.html`. Gitignored.
- Secret: `state\refresh.dat`. Gitignored. Never print or commit it.

## Open items

- Re-run `.\8-Get-SharingPosture.ps1` once, so the SharePoint gap is recorded.
- Re-run `2-` and `4-` before quoting Secure Score category numbers. They were not re-verified after the last changes.
- Decide on the coverage options above.
- Commit `m365-assessment/` to git. Leave unrelated uncommitted files in the repo alone.
