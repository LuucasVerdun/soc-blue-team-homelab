# Case 17 — Evidence Summary

## Identificação

- **Case:** 17
- **Título:** Windows Event Log Clearing & Defense Evasion Investigation & Detection Engineering
- **Asset:** `WINSERVER2022` / `WIN-30JS3HVHMAB`
- **User:** `WIN-30JS3HVHMAB\Administrator`
- **SID:** `S-1-5-21-3382847163-1926424565-132962873-500`
- **Session Logon ID used in final correlation:** `0x60d4a`
- **SIEM:** Wazuh 4.14.7
- **Endpoint telemetry:** Windows Event Log + Sysmon
- **ATT&CK:** `T1070.001 — Clear Windows Event Logs`
- **Classification:** True Positive — Controlled Lab

## Final Security-log validation

### Sysmon

- Event ID: `1`
- Record: `41784`
- SystemTime: `2026-09-22T04:36:39.6758754Z`
- PID: `1412`
- Image: `C:\Windows\System32\wevtutil.exe`
- Command line: `"C:\Windows\system32\wevtutil.exe" cl Security`
- User: `WIN-30JS3HVHMAB\Administrator`
- Logon ID: `0x60d4a`
- Integrity: High
- Parent PID: `3112`
- Parent: PowerShell

### Security

- Event ID: `1102`
- Record: `8097`
- SystemTime: `2026-09-22T04:36:39.6888454Z`
- Subject SID: `S-1-5-21-3382847163-1926424565-132962873-500`
- Subject user: `Administrator`
- Subject domain: `WIN-30JS3HVHMAB`
- Subject Logon ID: `0x60d4a`
- Custom rule: `100420 / Level 12`

### Correlation

`Sysmon.logonId == 1102.subjectLogonId == 0x60d4a`

The Sysmon event preceded Event `1102` by approximately `12.97 ms`.

Wazuh ingested the Security event first and later received the Sysmon event, therefore the final observed correlation was `100420 → 100427 / Level 15`.

## Controlled-log validation

`SOC-Case17` was used before touching the Security log.

Observed native telemetry:

- Event ID `104`, Record `10973` — first controlled clear
- Event ID `104`, Record `11031` — detection test
- Event ID `104`, Record `11058` — correlation test
- Sysmon Record `40597` — `wevtutil.exe cl SOC-Case17`
- Rule `100412 / Level 13` — reversed-ingestion correlation

## Wazuh custom rules

| Rule | Level | Function |
|---|---:|---|
| 100400 | 8 | `wevtutil cl SOC-Case17` |
| 100405 | 10 | Event 104 for controlled log |
| 100410 | 13 | normal-order controlled-log correlation |
| 100412 | 13 | reversed-order controlled-log correlation |
| 100415 | 10 | `wevtutil cl Security` |
| 100420 | 12 | Security Event 1102 |
| 100425 | 15 | normal-order Security correlation |
| 100427 | 15 | reversed-order Security correlation |

## Native Wazuh observations

- `63104 / Level 5` materialized for Event ID `104`.
- `63103 / Level 5` materialized for Event ID `1102`.
- `60117` also exists in the installed ruleset for `1102` but did not materialize in the tested pipeline.
- Custom Case 17 rules use `T1070.001`.

## Negative test

Command: `wevtutil qe Security /c:1 /rd:true /f:text`

Sysmon Event ID `1`, Record `41861`.

Case 17 Security alert count: `2 → 2`.

No new `100415`, `100420`, `100425`, or `100427` was generated.

## EVTX preservation performed during execution

| Artifact | Records | SHA256 |
|---|---:|---|
| SOC-Case17-before-clear-20260921-194227.evtx | 3 | `945202D7CD8E9FA8206BFED70933E3D1101CD404BF06A40C31DAB31E4BB441B5` |
| SOC-Case17-before-detection-clear-20260921-203527.evtx | 3 | `0EAC8B6B6749CCCD58E5CE68768F015928493AEA3545B0345E14968D3DA5FB91` |
| SOC-Case17-before-correlation-clear-20260921-204606.evtx | 3 | `B057D32B0E84213089F21DB2E0637DB5CEAA9E04A1C6CAAAAD9D60476F8C3E4F` |
| Security-before-clear-20260921-211213.evtx | 8072 | `5857D2210035B3596723C8A163363E0C99B99B339EF5E35175C3AB44343B0139` |
| Security-before-detection-clear-20260921-213605.evtx | 11 | `DE4D9F0290364BC9BF43FC8AF503E8DE791D496F7E393A320D6D7C9FA7ED306A` |

The EVTX files were preserved locally during testing; the repository contains the selected XML event exports and Wazuh evidence needed to demonstrate the final chain.

## Repository evidence

- `case17-custom-rules.xml`
- `local_rules-active-post-case17.xml`
- `wazuh-alerts.jsonl`
- `wazuh-final-chain.jsonl`
- `supporting-events.jsonl`
- `security-8097-event1102.xml`
- `sysmon-41784-wevtutil-cl-security.xml`
- `sysmon-41861-negative-qe-security.xml`
- `summary.md`
- `hashes.sha256`

## Limitations

- Wazuh temporal rules do not dynamically compare the two Logon ID field names.
- The Logon ID equality was validated during investigation.
- Cross-channel ingestion order may differ from endpoint event order.
- The process rule covers `wevtutil.exe`; additional mechanisms require separate detections.
- Event ID `104` was not observed for Security clearing in the tested window.
- Log clearing can be legitimate administrative activity and requires context.

## Conclusion

The Case 17 evidence demonstrates process-level attribution, confirmed Windows audit-log clearing, evidence preservation before destructive actions, out-of-order SIEM correlation, a final Level 15 Wazuh alert, and a negative control that did not trigger the detection.
