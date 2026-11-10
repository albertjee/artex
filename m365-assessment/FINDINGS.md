# M365 Posture Findings — Newport High PTSA

| | |
| --- | --- |
| Tenant | Newport High PTSA · `3177c971-05c9-4b7b-93a1-0edf6fd7237d` |
| Account used | `Albert.Jee@newportptsa.org` (Global Administrator) |
| Captured | 2026-11-10 20:37 UTC |
| Method | Read-only Graph enumeration. No policy was changed, no credential was attacked. |
| Scope | Entra ID, app consent, Conditional Access, Secure Score |
| **Not yet covered** | Exchange, SharePoint, Teams, Defender — those come from ScubaGear (`1-Run-ScubaGear.ps1`), which has not been run |

**This is a lab tenant** (50 `lab-copilot-userNNN` accounts, `test99`, `Lab Admin`). Configuration findings
transfer to a production tenant. Counts of affected users do not — they describe how the sandbox was
provisioned, not how a real workforce behaves.

---

## Headline

**Secure Score: 178.1 / 267 — 66.7%.** Roughly 89 points are unclaimed.

Three findings matter more than the score:

1. **Two third-party apps hold tenant-wide write access** — including all mail, all SharePoint, and directory write.
2. **The admin MFA policy excludes the admins.** 3 of 4 Global Admins have no MFA registered (the Helpdesk
   Administrator has none either), and the two accounts `CA001` exempts are themselves Global Admins — one of them
   password-only and also excluded from the legacy-authentication block.
3. **17 of 24 Conditional Access policies are report-only** and 1 is disabled — the September baseline import
   mostly enforces nothing.

---

## Critical

### C1. Third-party apps hold tenant-wide write permissions

`reports/entra-high-risk-grants.csv`

| App | Resource | Permission |
| --- | --- | --- |
| AdminDroid Service Application | Microsoft Graph | `Directory.ReadWrite.All` |
| AdminDroid Service Application | **Windows Azure Active Directory** (legacy) | `Directory.ReadWrite.All` |
| AdminDroid Service Application | Microsoft Graph | `Mail.ReadWrite` |
| AdminDroid Service Application | Microsoft Graph | `User.ReadWrite.All` |
| AdminDroid Service Application | SharePoint Online | `Sites.FullControl.All` |
| CopilotReadiness-V1 | Microsoft Graph | `Sites.FullControl.All` |
| CopilotReadiness-V1 | SharePoint Online | `Sites.FullControl.All` |

**Why it's critical.** AdminDroid is a reporting/monitoring product. A reporting tool needs `Directory.Read.All`,
`Mail.Read`, `Sites.Read.All`. It has been granted the *write* half of every one of those scopes instead. The
practical consequences:

- `Mail.ReadWrite` = read and modify every mailbox in the tenant.
- `Sites.FullControl.All` = full control of every SharePoint site and OneDrive, including permission changes.
- `Directory.ReadWrite.All` on Graph **and** the deprecated AAD Graph endpoint (`00000002-…`) = create/modify users
  and groups. Combined with any role-assignable group, that is a path to Global Administrator.
- `User.ReadWrite.All` = reset passwords, modify authentication methods on any account.

None of this requires compromising the tenant. It requires compromising **one app credential** — which is a
secret in a vendor's database, not a password behind MFA. That is the single shortest path to full tenant
takeover in this environment.

**Fix, in order:**
1. Step down scopes to what the product actually documents it needs. Admin-consent the reduced set, then verify
   the app still works.
2. Remove the legacy AAD Graph (`00000002-0000-0000-c000-000000000000`) grant entirely — that API endpoint is retired.
3. Enforce app credential expiry (≤12 months) and alert 60 days before expiry. Unrotated secrets are how these
   grants become permanent.
4. Enable **App governance** (Defender for Cloud Apps) if licensed: it flags anomalous use of exactly these grants.

**Related: delegated consent sprawl, demonstrated by this assessment.** The Microsoft Graph PowerShell enterprise
app holds a standing delegated grant in this tenant. The token it persisted on the assessment workstation carried
`Directory.ReadWrite.All`, `User.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`,
`Policy.ReadWrite.ConditionalAccess` and `Mail.Send` alongside the read scopes actually needed. Any administrator
can therefore mint, from any machine, a token equivalent to their own identity with write access to every directory
object — no further prompt, no MFA step at the point of use.

This is a different risk class from AdminDroid: first-party, delegated, and bounded by the admin's own rights. But
the grant is permanent, wider than any single administrative task requires, and invisible during day-to-day work.
During review, treat `Directory.ReadWrite.All` and `RoleManagement.ReadWrite.Directory` delegation as findings in
their own right, and prefer scoped app registrations with certificate authentication for automation over
interactive admin sessions.

### C2. The admin MFA policy excludes the admins

`reports/entra-ca-exclusions.csv`, `reports/entra-admin-mfa.csv`, `reports/entra-admin-roles.csv`

`CA001: Require multifactor authentication for admins` is **enabled**. Its exclusion list contains two Global
Administrators:

| Excluded account | Privileged role | MFA registered | Excluded from |
| --- | --- | --- | --- |
| `Admin99@newportptsa.org` (Break The Glass) | Global Administrator | **False** | CA001, CA003 (legacy auth block) |
| `Albert.Jee@newportptsa.org` | Global Administrator | True | CA001, CA003, CA005, CA006, Block device code flow |
| `breakglass@…onmicrosoft.com` (Emergency) | Global Administrator | **False** | POL-Enforce-MFA-HighSecurity |

The exclusion GUIDs resolved to **users, not groups**: `7500f01a-…` = `Albert.Jee`, `243ea0a5-…` = `Admin99`,
`2dd703d6-…` = `breakglass@`. There is no group membership to blame.

Two consequences, of different severity:

- **`Admin99` is a password-only Global Administrator, explicitly exempted from both the admin MFA policy and the
  legacy-authentication block.** Legacy protocols skip MFA by design, so this account is reachable with a password
  over a protocol that cannot challenge it. That is the shortest identity path in the tenant.
- **`Albert.Jee` has MFA, but it is self-managed rather than policy-required**, and he is exempt from five policies
  including the device-code-flow block — the exact flow this assessment uses to sign in.

Privileged accounts with no MFA registered, excluding the directory-sync service account (a non-interactive service
identity, correctly without MFA):

| Role | Account | MFA registered |
| --- | --- | --- |
| Global Administrator | `Admin1@…onmicrosoft.com` | **False** |
| Global Administrator | `Admin99@newportptsa.org` | **False** |
| Global Administrator | `breakglass@…onmicrosoft.com` | **False** |
| Helpdesk Administrator | `t1helpdesk@…onmicrosoft.com` | **False** |
| Global Administrator | `Albert.Jee@newportptsa.org` | True |

**Include scope, verified.** `CA001` targets 15 directory roles by role template, including Global Administrator,
Security Administrator, Exchange Administrator, Conditional Access Administrator and Privileged Role Administrator
(`entra-ca-policies.csv`, `IncludeRoles`, resolved to names). Its two exclusions, `Albert.Jee` and `Admin99`, are both
Global Administrators. The policy targets the admin roles and exempts two of the Global Administrators it names.

**Fix, in order:**
1. Remove both Global Administrator exclusions from `CA001` and `CA003`. If a break-glass exemption is genuinely
   needed, keep **one** account, exclude it from nothing else, and give it a phishing-resistant credential held
   offline — not a password.
2. Register MFA on `Admin1`, `Admin99` and `t1helpdesk`, then re-enable enforcement.
3. Move admins to phishing-resistant methods (FIDO2 / Windows Hello / certificate), not SMS or voice.
4. Enable the **Registration campaign** so new accounts cannot reach their first sign-in without a method.
5. After enforcement, verify with a sign-in as an excluded account and confirm it is actually challenged.

---

## High

### H1. 17 of 24 Conditional Access policies are report-only

`reports/entra-ca-policies.csv`

Enabled and enforcing today — 6 policies:

| Policy | Control |
| --- | --- |
| CA001: Require MFA for admins | mfa |
| CA003: Block legacy authentication | block |
| CA005: Require MFA for guest access | mfa |
| CA006: Require MFA for Azure management | mfa |
| Microsoft-managed: Block device code flow | block |
| POL-Enforce-MFA-HighSecurity | mfa *(excludes the break-glass admin — see C2)* |

Report-only — 17 policies, all created 2026-09-02, none protecting anyone:

`CA-Admin-PhishingResistant-MFA`, `CA-Baseline-Block-LegacyAuthentication`, `CA-Device-Require-CompliantOrHybridJoined`,
`CA-External-B2BGuests-Require-TenantMFA`, `CA-External-CrossTenant-EnforcePartnerTrust`, `CA-Finance-RiskBased-DynamicMFA`,
`CA-Identity-Require-VerifiedID-PreHire`, `CA-Identity-Secure-SecurityInfoRegistration`,
`CA-IdentityProtection-HighUserRisk-SelfServiceRemediation`, `CA-Management-AzurePortal-PhishingResistantIsolation`,
`CA-Mobile-Require-AppProtectionPolicy-MAM`, `CA-Network-Block-HighRiskCountries`, `CA-Session-Admin-SignInFrequencyAndKMSI`,
`CA-Session-DefenderCloudApps-BlockDownload-Unmanaged`, `CA-Session-TokenProtection-M365`,
`CA901 Block usagr from outside USA`, `CA902 Session Admin Persistence`.

A 24th, `CA-Session-ContinuousAccessEvaluation-Strict`, is disabled outright.

**The phishing-resistant policy requires the right control, but is not enforcing it.** `CA-Admin-PhishingResistant-MFA`
has no built-in grant control, but it does carry an authentication strength: `Phishing-resistant MFA` (verified in
`entra-ca-policies.csv`, `AuthStrength` column). An empty `GrantControls` alone does not mean "requires nothing";
the authentication-strength property is a separate grant-control property, and this policy uses it. The policy is
correctly designed and is still report-only.

Its scope has two defects:

- **It excludes the primary administrator.** `ExcludeUsers` contains `Albert.Jee` (`7500f01a-…`) and `breakglass@`
  (`2dd703d6-…`). Albert is also a member of the include group, so he is in scope and then exempted.
- **Its include scope is small and specific.** It targets user `Alex Rivera` (`b6f8c646-…`) and group `GRP-IT-Admins`
  (`ee4d6ac4-…`, three members: Albert, Alex Rivera, Tier 1 Helpdesk). The policy protects three people on paper, and
  one of its own members is exempt.

Enabling it as-is would enforce phishing-resistant MFA for Alex and the helpdesk account only. The fix is to remove
the Albert exclusion (keeping breakglass excluded and monitored) and then enable it.

**Why it matters.** The most valuable controls — phishing-resistant MFA for admins, high-risk sign-in remediation,
device compliance, token protection, geo-blocking — exist as documents rather than enforcement. A report-only policy
looks excellent in a screenshot and stops zero attacks. The 2026-09-02 cluster suggests a baseline template was
imported and never turned on.

Also note `CA-Baseline-Block-LegacyAuthentication` (report-only) duplicates the already-enabled `CA003` — harmless,
but it signals the template was imported without reconciling against what was already there.

**Fix — enable one at a time, in this order, checking sign-in logs between each:**
1. `CA-IdentityProtection-HighUserRisk-SelfServiceRemediation`
2. `CA-Admin-PhishingResistant-MFA` — the highest-value single control in the list
3. `CA-Session-Admin-SignInFrequencyAndKMSI`
4. `CA-Device-Require-CompliantOrHybridJoined` — the only one that needs Intune readiness first
5. The rest as appetite allows

Do not bulk-enable. Policy #4 will lock out every unmanaged device on the spot.

### H2. Self-service signup accepts any email-verified user

`reports/entra-consent-settings.txt`

```
AllowEmailVerifiedUsersToJoinOrganization : True
```

Anyone who registers an address on a tenant domain and verifies it by email can join the directory as a guest,
without an invitation. With a custom domain (`newportptsa.org`) this is an onboarding path an attacker can walk.

Currently 0 guest accounts exist, so exposure today is theoretical — but the setting is a standing invitation.

**Fix:** set to `False` unless there is a documented self-service onboarding requirement
(Entra admin centre → External Identities → External collaboration settings → *Guest self-service sign-up*).

---

## Medium

### M1. Legacy AAD Graph permission still granted

The `Directory.ReadWrite.All` grant on `00000002-0000-0000-c000-000000000000` targets **Azure AD Graph**, which is
retired. It grants no capability Microsoft Graph does not already cover, but it is an additional credential surface
that no longer receives security fixes.

**Fix:** remove the grant alongside the C1 remediation.

### M2. No app credential lifecycle

Seven high-privilege app grants exist with no evidence of expiry management (the export does not capture credential
expiry — verify under Entra → App registrations → Certificates & secrets). Service principal secrets that never
rotate are the standard mechanism by which a one-time grant becomes permanent.

**Fix:** inventory secrets and certificates for AdminDroid and CopilotReadiness-V1; set expiry ≤12 months and alert.

---

## Review items (verified, need an owner's decision)

- **`CA901 Block usagr from outside USA` has a dangling location reference.** Its exclusions include
  `00000000-0000-0000-0000-000000000000`, which matches no named location in the tenant
  (`Get-MgIdentityConditionalAccessNamedLocation`). Low severity: it is hygiene, not an open door. Check in the portal
  whether that entry is a sentinel or a deleted location, then remove it. The policy's wording also has a typo
  ("usagr"), which is cosmetic.
- **`CA-Network-Block-HighRiskCountries` is an allow-list, not a block-list.** It includes all locations and excludes
  `Approved-Operating-Countries`. Its effect is "block everywhere outside the approved countries". That may be exactly
  intended, but the name says the opposite. Rename it or document it, so reviewers do not read it as a block on a
  short list of high-risk countries.
- **Risky users: one user measured, none unremediated at medium or high.** That is a real measurement from this run,
  but the tenant is a lab with fabricated users, so "one user, now remediated" says nothing about production identity
  behaviour.

## What is already good

Worth stating plainly, because these are deliberate and correct:

- **Users cannot register applications** (`AllowedToCreateApps: False`) — closes a common escalation path.
- **Guest invitations restricted to admins and guest inviters** — no casual external sharing.
- **Restricted guest role** (`GuestUserRoleId: 10dae51f-…`) — the most restrictive built-in guest role.
- **Legacy authentication is actually blocked** by enabled `CA003`, not merely planned.
- **Device code flow is blocked** by a Microsoft-managed policy — notable, since device-code phishing is the
  current favourite M365 attack and you already have an account (`0-Connect-DeviceCode.ps1`) proving it works
  when a policy permits it.
- **Two break-glass accounts exist** — the right instinct. They need hardening, not removal.

---

## Remediation sequence

Order matters — several of these can lock you out if done first.

| Step | Action | Risk if done out of order |
| --- | --- | --- |
| 1 | Confirm both break-glass accounts work; record their credentials offline | Enforcing MFA without them = permanent lockout |
| 2 | Harden break-glass: FIDO2 or long random password, no mailbox, sign-in alerting | — |
| 3 | Register MFA for the admin accounts; move to phishing-resistant methods | — |
| 4 | Resolve the C2 contradiction — fix `CA001` so its scope actually covers admins | Applying a broken scope change can exclude everyone |
| 5 | Reduce AdminDroid / CopilotReadiness permissions (C1, M1, M2) | — |
| 6 | Enable report-only policies one at a time (H1), watching sign-in logs | Bulk-enable → helpdesk outage on unmanaged devices |
| 7 | Set `AllowEmailVerifiedUsersToJoinOrganization: False` (H2) | — |
| 8 | Re-run `2-Get-SecureScore.ps1` and compare | — |

Steps 1–3 are the same afternoon. Step 6 is weeks, deliberately.

---

## Open items

| Item | How it closes |
| --- | --- |
| Whether admins are excluded from `CA001` | **Closed.** `CA001` targets 15 admin roles and excludes two Global Administrators (`Albert.Jee`, `Admin99`). |
| Risky users and risk detections | **Measured.** One risky user, none unremediated at medium or high. Lab data, so it says little about production. |
| ScubaGear, Entra (`aad`) | **Done.** 15 failing, 8 passing, 4 manual, 7 warnings. Report: `scuba-20261110-135026_…\BaselineReports.html`. |
| ScubaGear, Exchange (`exo`), Defender (`securitysuite`), SharePoint (`sharepoint`), Teams (`teams`) | **Gap.** Sign-in failed on each (MSAL embedded-browser error). Not assessed. |
| Exchange configuration (script 7) | **Partly measured.** Anti-phishing and SMTP AUTH results are in. Safe Links, Safe Attachments and external sender identification are recorded as gaps. |
| SharePoint sharing and Copilot oversharing (script 8) | **Gap.** `Connect-SPOService` failed. Re-run script 8 once so the gap is recorded in the report. |
| Secure Score category breakdown | **Not re-verified this session.** Re-run `2-` and `4-` before quoting category numbers. |

The category table in the first run is **invalid** — it summed max scores across all Graph controls including
unlicensed ones (Device 0/1310, Identity 27/915), which is why categories totalled 2613 against a tenant max of
267. `2-Get-SecureScore.ps1` has been corrected and `4-Analyze.ps1` rewrites the file.
