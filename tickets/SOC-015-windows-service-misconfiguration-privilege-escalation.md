# SOC-015 — Windows Service Misconfiguration Privilege Escalation

## Ticket Metadata

| Field | Value |
|---|---|
| Ticket | SOC-015 |
| Status | Closed |
| Classification | True Positive — Controlled Lab |
| Severity | High |
| Asset | WIN-30JS3HVHMAB / Windows Server 2022 |
| User | WIN-30JS3HVHMAB\soccase15 |
| Service | SOC_CASE15 |
| Service Account | LocalSystem |
| SIEM | Wazuh 4.14.7 |
| Endpoint Source | Sysmon 15.21 |
| Final Token | 20260916-220147 |

## Alert

The final Wazuh correlation rule `100360` fired at Level 15 after a standard
user modified and started a controlled Windows service configured to run as
`LocalSystem`, followed by observed SYSTEM process execution.

## Timeline — UTC

| Time | Observation |
|---|---|
| 05:03:09.643 | Rule 100325 — `sc.exe config SOC_CASE15` by `soccase15`, Medium Integrity |
| 05:03:09.677 | Rule 100350 — service ImagePath Registry modification correlated |
| 05:03:11.713 | Rule 100355 — `sc.exe start SOC_CASE15` correlated after modification |
| 05:03:11.767 | Rule 100345 — SYSTEM-created controlled marker |
| 05:03:13.862 | Rule 100360 — controlled SYSTEM execution correlation confirmed |

## Triage

The initiating account was validated as a non-administrative local user.
Baseline evidence showed:

- `BUILTIN\Users` membership;
- no membership in `Administrators`;
- Medium Integrity;
- limited token privileges.

`SOC_CASE15` was configured to run as `LocalSystem`. A deliberate weak ACE on
the service object permitted the lab account to change service configuration
and start the service.

## Findings

1. `sc.exe config` executed under `soccase15` and returned
   `ChangeServiceConfig SUCCESS`.
2. Sysmon Event 13 recorded `services.exe` writing the new
   `SOC_CASE15\ImagePath`.
3. `sc.exe start` executed under `soccase15` with Medium Integrity.
4. The controlled service command launched `cmd.exe` as
   `NT AUTHORITY\SYSTEM`.
5. Sysmon Event 11 recorded a controlled marker created by the SYSTEM process.
6. `whoami.exe` executed as `NT AUTHORITY\SYSTEM`, System Integrity.
7. Wazuh rule `100360` correlated the chain at Level 15.

## Assessment

**True Positive — Controlled Lab.**

The observed behavior demonstrates a local privilege-escalation path created by
intentionally weak service permissions. There is no evidence of malware,
credential dumping, persistence beyond the temporary controlled service, or
third-party compromise.

The `StartService FAILED 1053` message did not invalidate execution. The
controlled `cmd.exe` command ran, but it did not behave as a native Windows
service from the Service Control Manager's perspective.

## ATT&CK

- T1543.003 — Create or Modify System Process: Windows Service
- T1569.002 — System Services: Service Execution
- T1059.003 — Command and Scripting Interpreter: Windows Command Shell

## Detection Logic

The custom chain used:

`100325 → 100350 → 100355 → 100345 → 100360`

Supporting rules `100330`, `100335`, `100340`, and `100352` provide atomic or
correlation-prerequisite coverage.

## Containment and Remediation

Completed after evidence preservation:

- benign service ImagePath restored;
- original service SDDL restored;
- weak user-specific ACE removed;
- `SOC_CASE15` deleted;
- `soccase15` deleted;
- temporary Case 15 files removed from `C:\Users\Public`;
- Secondary Logon returned to `Stopped`;
- Sysmon restored to `sysmon-case14.xml`.

## Evidence

- `evidence/case15/wazuh-final-chain.jsonl`
- `evidence/case15/wazuh-final-telemetry.jsonl`
- `evidence/case15/case15-custom-rules.xml`
- `evidence/case15/summary.md`
- endpoint evidence hash:
  `466C805410B0F604B276371F16245C4066BFE08B72978CAF79B349A2179AA909`

## Closure

No additional containment is required for the controlled scenario. The
deliberately vulnerable service and test account were removed, the original
security state was restored, and the resulting detection logic was retained for
portfolio and detection-engineering evidence.
