# Case 16 — Windows Identity Abuse & Local Administrator Escalation Investigation & Detection Engineering

## Executive Summary

A controlled Windows Server 2022 identity-focused scenario demonstrated how
a newly created local account can be promoted into the local Administrators
group, obtain linked UAC filtered/elevated logon contexts, receive special
privileges, and execute processes at High Integrity.

The exercise focused on SOC investigation, Windows identity semantics,
cross-event correlation, and Wazuh detection engineering. No malware,
credential dumping, exploit, UAC bypass, or external offensive framework was
used.

**Final disposition:** True Positive — Controlled Lab.

## Environment

- Windows Server 2022: `WIN-30JS3HVHMAB`
- Controlled local account: `soccase16`
- Live identity SID: `S-1-5-21-3382847163-1926424565-132962873-1004`
- Wazuh agent: `002 / WINSERVER2022`
- SIEM: Wazuh 4.14.7
- Endpoint telemetry: Windows Security Events + Sysmon
- Live validation date: `2026-09-21`

## Investigation

The live validation produced a complete identity lifecycle:

```text
Local account creation
        ↓
Local Administrators assignment
        ↓
Valid interactive logon
        ↓
UAC filtered/elevated split token
        ↓
Special privileges
        ↓
High Integrity process execution
        ↓
Wazuh Level 15 correlation
```

The account was recreated after an earlier test. The historical identity ended
in RID `1003`; the live identity ended in RID `1004`. This demonstrated that
the same username does not imply the same Windows security principal.

## Identity Correlation

The live Event ID `4720` recorded:

`targetSid = S-1-5-21-3382847163-1926424565-132962873-1004`

Event ID `4732` later recorded:

`memberSid = S-1-5-21-3382847163-1926424565-132962873-1004`

This established that the newly created identity was the same principal added
to `BUILTIN\Administrators`.

## UAC Split Token

Two linked Event ID `4624` records represented the administrative account's
UAC split token:

- elevated context: `0x452c93`, `ElevatedToken = Yes`;
- filtered context: `0x452cc0`, `ElevatedToken = No`.

The filtered PowerShell ran at Medium Integrity with the Administrators group
in deny-only state. After user-approved UAC elevation, the High PowerShell had
Administrators enabled and a broader administrative privilege set.

This was legitimate UAC elevation, not a UAC bypass.

## Cross-Source Correlation

The elevated Logon ID was observed consistently across independent event
sources:

```text
4624.targetLogonId   = 0x452c93
4672.subjectLogonId  = 0x452c93
Sysmon.logonId       = 0x452c93
```

This tied authentication, special privileges, and process execution to the
same elevated logon context.

## Detection Engineering

| Rule | Level | Purpose |
|---|---:|---|
| 100365 | 8 | controlled local account creation |
| 100370 | 12 | local Administrators membership addition |
| 100375 | 13 | create → administrator assignment |
| 100380 | 10 | elevated-token logon |
| 100385 | 12 | elevated logon → special privileges |
| 100390 | 12 | High Integrity process by controlled identity |
| 100395 | 15 | final identity-escalation correlation |

Positive and negative tests confirmed ordering behavior for the correlation
rules.

The live Wazuh pipeline produced:

`100365 → 100375 → 100380 → 100385 → 100395`

## Final High-Confidence Alert

The first live Level 15 process was:

- Sysmon Record ID: `34532`
- Image: `powershell.exe`
- PID: `4120`
- Parent PID: `4440`
- User: `WIN-30JS3HVHMAB\soccase16`
- Logon ID: `0x452c93`
- Integrity Level: `High`
- Wazuh rule: `100395`
- Level: `15`

Additional High processes from the same elevated session also matched while
the correlation window remained active. This was documented as a tuning
consideration rather than treated as independent compromise evidence.

## ATT&CK Mapping

- T1136.001 — Create Account: Local Account
- T1098 — Account Manipulation (Wazuh-compatible mapping); current granular
  mapping: T1098.007 — Additional Local or Domain Groups
- T1078 — Valid Accounts (Wazuh-compatible mapping); current granular mapping
  for this local identity: T1078.003 — Local Accounts

`T1548.002` was intentionally not used because the scenario did not bypass
UAC.

## Detection Tuning

Potential production improvements:

- suppress repeated High Integrity child processes from the same elevated
  session;
- correlate newly created SID to group-member SID through normalization or
  enrichment;
- use shorter correlation windows where appropriate;
- exclude approved provisioning or administrative workflows;
- enrich account changes with change-management context.

## Remediation

After evidence preservation:

- `soccase16` was removed from local Administrators;
- the account was deleted;
- removal Event ID `4733` and deletion Event ID `4726` were preserved;
- Secondary Logon returned to `Stopped / Manual`;
- local Administrators returned to its baseline membership.

## Skills Demonstrated

- Windows SID and identity analysis
- authentication vs authorization analysis
- Windows UAC split-token interpretation
- integrity-level analysis
- Windows Security Event IDs 4720, 4732, 4624, 4672, 4733, 4726
- Sysmon Event ID 1 process analysis
- Logon ID correlation across Security Event Log and Sysmon
- Wazuh custom rule engineering
- positive and negative detection testing
- temporal correlation
- alert-tuning analysis
- evidence preservation
- controlled cleanup and remediation
- MITRE ATT&CK mapping
