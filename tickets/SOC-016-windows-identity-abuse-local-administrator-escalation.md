# SOC-016 — Windows Identity Abuse & Local Administrator Escalation

## Ticket Metadata

| Field | Value |
|---|---|
| Ticket | SOC-016 |
| Status | Closed |
| Classification | True Positive — Controlled Lab |
| Severity | High |
| Asset | WIN-30JS3HVHMAB / Windows Server 2022 |
| User | WIN-30JS3HVHMAB\soccase16 |
| User SID | S-1-5-21-3382847163-1926424565-132962873-1004 |
| SIEM | Wazuh 4.14.7 |
| Endpoint Source | Windows Security Events + Sysmon |
| Final Rule | 100395 / Level 15 |

## Alert

Wazuh rule `100395` fired at Level 15 after a newly created local account was
assigned to the local Administrators group and subsequently executed a
High-Integrity process.

## Timeline — UTC

| Time | Observation |
|---|---|
| 05:05:39.732 | Rule 100365 — Event 4720 created `soccase16`, SID `S-1-5-21-3382847163-1926424565-132962873-1004` |
| 05:08:05.561 | Rule 100375 — Event 4732 correlated recent creation with local Administrators assignment |
| 05:13:17.641 | Rule 100380 — Event 4624 elevated token, Logon ID `0x452c93` |
| 05:13:17.771 | Rule 100385 — Event 4672 special privileges, same Logon ID |
| 05:17:12.140 | Rule 100395 — Sysmon High Integrity `powershell.exe`, PID 4120 |
| 05:32:58.283 | Event 4733 — identity removed from local Administrators |
| 05:33:11.960 | Event 4726 — `soccase16` deleted |

## Triage

The identity was newly created under the local Administrator account and then
assigned to `BUILTIN\Administrators`.

The `4720.targetSid` and `4732.memberSid` fields both contained:

`S-1-5-21-3382847163-1926424565-132962873-1004`

establishing that the same Windows security principal moved from account
creation into local administrative membership.

## Findings

1. Event `4720` confirmed local account creation.
2. Event `4732` confirmed assignment to `S-1-5-32-544` (Administrators).
3. Rule `100375` correlated creation followed by privilege assignment.
4. Two linked `4624` records represented UAC elevated and filtered tokens.
5. Elevated Logon ID `0x452c93` linked to filtered Logon ID
   `0x452cc0`.
6. Event `4672` assigned special privileges to `0x452c93`.
7. The endpoint showed a Medium PowerShell with Administrators deny-only.
8. User-approved UAC elevation produced a High PowerShell with Administrators
   enabled.
9. Sysmon Event ID 1 tied the High process to Logon ID
   `0x452c93`.
10. Rule `100395` generated a Level 15 final correlation.

## Assessment

**True Positive — Controlled Lab.**

The behavior demonstrates an identity-focused local administrative privilege
assignment and subsequent privileged use. The observed elevated execution was
generated through normal user-approved UAC behavior.

No malware, credential dumping, UAC bypass, exploit, or external offensive
framework was involved.

## ATT&CK

- T1136.001 — Create Account: Local Account
- T1098 — Account Manipulation (Wazuh-compatible); current granular mapping:
  T1098.007 — Additional Local or Domain Groups
- T1078 — Valid Accounts (Wazuh-compatible); current granular mapping:
  T1078.003 — Local Accounts

## Detection Logic

```text
100365 — account creation
   ↓
100370 — Administrators membership
   ↓
100375 — create → promote correlation
   ↓
100380 — elevated-token logon
   ↓
100385 — special privileges
   ↓
100390 — High Integrity process
   ↓
100395 — final Level 15 correlation
```

The final rule directly correlates `100375` with `100390`. Rules `100380` and
`100385` provide corroborating identity/session evidence and are validated
independently.

## Tuning Notes

Multiple High Integrity child processes in the same elevated session generated
additional Level 15 alerts while the `100375` timeframe remained valid.

Production tuning should consider:

- deduplication by user + Logon ID;
- shorter correlation windows;
- account allowlists;
- approved administration/change context;
- SID normalization across account-creation and group-membership fields.

## Containment and Remediation

Completed after evidence preservation:

- `soccase16` removed from local Administrators;
- Event `4733`, Record `7752`, preserved;
- `soccase16` deleted;
- Event `4726`, Record `7754`, preserved;
- Secondary Logon restored to `Stopped / Manual`;
- local Administrators membership returned to baseline.

## Evidence

- `evidence/case16/wazuh-live-alerts.jsonl`
- `evidence/case16/wazuh-live-chain.jsonl`
- `evidence/case16/case16-custom-rules.xml`
- `evidence/case16/summary.md`
- `evidence/case16/hashes.sha256`

## Closure

No additional containment is required for the controlled scenario. The test
account and local administrative membership were removed after evidence
collection, and the Wazuh detection logic was retained for defensive training
and portfolio evidence.
