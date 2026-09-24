# Case 17 — Windows Event Log Clearing & Defense Evasion Detection

## Executive Summary

A controlled Windows Server 2022 scenario validated detection of Windows Event Log clearing using Windows Event IDs `104` and `1102`, Sysmon Event ID `1`, Wazuh custom rules, and temporal correlation.

Evidence was preserved before destructive actions. The final validation correlated `wevtutil.exe cl Security` with Security Event ID `1102` and generated a Wazuh Level 15 alert.

**Final disposition:** True Positive — Controlled Lab.

## Environment

- Asset: `WIN-30JS3HVHMAB`
- Operating system: Windows Server 2022
- SIEM: Wazuh 4.14.7
- Endpoint telemetry: Windows Event Log + Sysmon
- Wazuh agent: `002 / WINSERVER2022`
- MITRE ATT&CK: `T1070.001 — Clear Windows Event Logs`

## Investigation

The exercise used two stages.

First, a dedicated `SOC-Case17` log was created, populated, exported, hashed, and cleared. System Event ID `104` confirmed the clear operation.

Second, the Windows `Security` log was exported and verified before a single controlled clearing operation. Security Event ID `1102` identified the account responsible for the action.

## Final Correlation

```text
Sysmon Event 1
Record 41784
wevtutil.exe cl Security
LogonId 0x60d4a
        |
        | ~12.97 ms
        v
Security Event 1102
Record 8097
SubjectLogonId 0x60d4a
```

The event timestamps establish that process execution preceded Event `1102`.

Wazuh received the channels in the opposite order:

```text
100420 / Level 12
Security 1102
        |
        v
Sysmon telemetry arrives
        |
        v
100427 / Level 15
reversed-ingestion correlation
```

## Key Findings

- Security evidence was exported and hashed before clearing.
- `wevtutil.exe cl Security` was attributed to an elevated Administrator PowerShell session through Sysmon.
- `Sysmon.logonId` and `1102.subjectLogonId` both contained `0x60d4a`.
- Event ID `104` was observed when the isolated `SOC-Case17` channel was cleared.
- Event ID `104` was not observed in the tested window for the Security clear.
- Wazuh native rule `63103` detected Event ID `1102`.
- Custom rule `100420` elevated the confirmed clear to Level 12.
- Custom rule `100427` generated the final Level 15 correlation.
- Symmetric correlation rules were required because cross-channel ingestion order differed from endpoint event order.

## Negative Test

`wevtutil qe Security /c:1 /rd:true /f:text` generated Sysmon Event ID `1`, Record `41861`, but did not produce a new Case 17 clear alert.

The relevant Wazuh alert counter remained `2 → 2`.

This validated that the process rule targets the `cl Security` operation rather than generic execution of `wevtutil.exe`.

## Detection Rules

| Rule | Level | Purpose |
|---|---:|---|
| 100400 | 8 | controlled log clear command |
| 100405 | 10 | Event 104 for `SOC-Case17` |
| 100410 | 13 | normal-order controlled-log correlation |
| 100412 | 13 | reversed-order controlled-log correlation |
| 100415 | 10 | `wevtutil.exe cl Security` |
| 100420 | 12 | Security Event ID 1102 |
| 100425 | 15 | normal-order Security clear correlation |
| 100427 | 15 | reversed-order Security clear correlation |

## ATT&CK

- `T1070.001 — Indicator Removal: Clear Windows Event Logs`

## Limitations

The final Wazuh correlation is temporal. It does not dynamically compare `win.eventdata.logonId` to `win.logFileCleared.subjectLogonId`; that equality was validated during investigation.

The current process detection covers `wevtutil.exe`. Additional log-clearing mechanisms require separate coverage.

## Skills Demonstrated

- Windows Event ID 104 analysis
- Windows Security Event ID 1102 analysis
- Sysmon Event ID 1 process attribution
- command-line analysis
- Logon ID correlation
- evidence preservation before destructive testing
- SHA256 integrity validation
- Wazuh custom rule engineering
- temporal correlation
- out-of-order telemetry handling
- positive and negative detection testing
- MITRE ATT&CK T1070.001 mapping
- Defense Evasion investigation
