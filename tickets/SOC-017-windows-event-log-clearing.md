# SOC-017 — Windows Event Log Clearing & Defense Evasion

## Ticket Metadata

| Field | Value |
|---|---|
| Ticket | SOC-017 |
| Status | Closed |
| Classification | True Positive — Controlled Lab |
| Severity | High |
| Asset | WIN-30JS3HVHMAB / Windows Server 2022 |
| User | WIN-30JS3HVHMAB\Administrator |
| User SID | S-1-5-21-3382847163-1926424565-132962873-500 |
| SIEM | Wazuh 4.14.7 |
| Endpoint Source | Windows Event Log + Sysmon |
| ATT&CK | T1070.001 — Clear Windows Event Logs |
| Final Rule | 100427 / Level 15 |

## Alert

Wazuh rule `100427` generated a Level 15 alert after a Security Event ID `1102` was temporally correlated with Sysmon telemetry showing `wevtutil.exe cl Security`.

## Timeline — UTC

| Time | Observation |
|---|---|
| 02:51:08.853 | First controlled `SOC-Case17` clear produced Event 104, Record 10973 |
| 03:36:33.119 | Sysmon Record 40329 — `wevtutil.exe cl SOC-Case17` |
| 03:36:33.130 | Event 104 Record 11031 — controlled log cleared |
| 03:47:16.448 | Sysmon Record 40597 — correlation validation |
| 03:47:16.458 | Event 104 Record 11058 — controlled log cleared |
| 03:47:21.972 | Rule 100412 / Level 13 — reversed-ingestion correlation |
| 04:16:26.952 | Sysmon Record 41279 — `wevtutil.exe cl Security` |
| 04:16:26.967 | Security 1102 Record 8086 — first controlled Security clear |
| 04:36:39.675 | Sysmon Record 41784 — final `wevtutil.exe cl Security` |
| 04:36:39.688 | Security 1102 Record 8097 — final confirmed clear |
| 04:36:44.987 | Rule 100420 / Level 12 |
| 04:36:45.259 | Rule 100427 / Level 15 |
| ~04:40:50 | Sysmon Record 41861 — negative `wevtutil qe Security` test |

## Triage

The final Security clear was executed from an elevated Administrator PowerShell session.

Sysmon recorded `wevtutil.exe`, command line `cl Security`, PID `1412`, Integrity `High`, Logon ID `0x60d4a`, and a PowerShell parent process.

Security Event ID `1102` independently recorded the `Administrator` account, SID `S-1-5-21-3382847163-1926424565-132962873-500`, and Subject Logon ID `0x60d4a`.

## Findings

1. Event ID `104` confirmed clearing of the isolated `SOC-Case17` log.
2. Wazuh native rule `63104` detected that event.
3. Cross-channel ingestion occurred in an order different from endpoint event time.
4. Rule `100412` successfully handled reversed ingestion for the isolated log.
5. The full Security log was exported and hashed before destructive testing.
6. Security Event ID `1102` confirmed audit-log clearing.
7. Wazuh native rule `63103` detected Event ID `1102`.
8. Sysmon attributed the Security clear to `wevtutil.exe`.
9. `Sysmon.logonId` matched `1102.subjectLogonId` at `0x60d4a`.
10. Rule `100420` raised the confirmed clear to Level 12.
11. Rule `100427` produced the final Level 15 correlation.
12. A `wevtutil qe Security` negative test produced no new clear alert.

## Assessment

**True Positive — Controlled Lab.**

The behavior is consistent with the ATT&CK technique for clearing Windows Event Logs. In this case it was an authorized defensive simulation performed after evidence preservation.

No malware, credential theft, persistence mechanism, or external offensive framework was involved.

## ATT&CK

- `T1070.001 — Indicator Removal: Clear Windows Event Logs`

## Detection Logic

```text
Controlled log branch:

100400 — wevtutil cl SOC-Case17
100405 — Event 104 confirmation
100410 — normal ingestion order
100412 — reversed ingestion order

Security log branch:

100415 — wevtutil cl Security
100420 — Security Event 1102
100425 — normal ingestion order
100427 — reversed ingestion order / final Level 15
```

Observed final path:

```text
100420 / Event 1102
        |
        v
Sysmon event satisfies 100415 conditions
        |
        v
100427 / Level 15
```

The final rule is temporal. Logon ID equality was verified during investigation and is not a dynamic field-to-field comparison performed by Wazuh.

## Negative Test

`wevtutil qe Security /c:1 /rd:true /f:text` generated Sysmon Record `41861`.

The Case 17 Security alert count remained `2 → 2`.

No new `100415`, `100420`, `100425`, or `100427` was produced.

## Tuning Notes

Production tuning should consider approved maintenance and troubleshooting workflows, additional log-clearing tools and APIs, host/session enrichment, normalized user/session identifiers, telemetry latency and out-of-order arrival, and approved change windows.

## Evidence Preservation

Before the first Security clear, `8072` events were exported; SHA256: `5857D2210035B3596723C8A163363E0C99B99B339EF5E35175C3AB44343B0139`.

Before the final validation, `11` Security events were exported; SHA256: `DE4D9F0290364BC9BF43FC8AF503E8DE791D496F7E393A320D6D7C9FA7ED306A`.

## Repository Evidence

- `evidence/case17/wazuh-alerts.jsonl`
- `evidence/case17/wazuh-final-chain.jsonl`
- `evidence/case17/supporting-events.jsonl`
- `evidence/case17/local_rules-active-post-case17.xml`
- `evidence/case17/case17-custom-rules.xml`
- `evidence/case17/security-8097-event1102.xml`
- `evidence/case17/sysmon-41784-wevtutil-cl-security.xml`
- `evidence/case17/sysmon-41861-negative-qe-security.xml`
- `evidence/case17/summary.md`
- `evidence/case17/hashes.sha256`

## Closure

No additional containment was required for this controlled scenario. Evidence was preserved before log clearing, the final detection was validated at Level 15, and a negative test confirmed command-line specificity.
