# Case 15 — Windows Service Misconfiguration Privilege Escalation Investigation & Detection Engineering

## Executive Summary

A controlled Windows Server 2022 lab scenario demonstrated how weak permissions
on a service object can allow a standard user to modify a service configured to
run as `LocalSystem` and trigger privileged execution.

The exercise focused on investigation quality and detection engineering rather
than exploitation tooling. No malware, credential dumping, kernel exploit, or
third-party offensive framework was used.

**Final disposition:** True Positive — Controlled Lab.

## Environment

- Windows Server 2022: `WIN-30JS3HVHMAB`
- Standard user: `soccase15`
- Controlled service: `SOC_CASE15`
- Service account: `LocalSystem`
- Endpoint telemetry: Sysmon 15.21
- SIEM: Wazuh 4.14.7
- Final validation token: `20260916-220147`

## Initial Validation

The test account was confirmed as a standard user with:

- `BUILTIN\Users` membership;
- no `Administrators` membership;
- Medium Integrity;
- a limited privilege token.

The service was stopped, configured for demand start, and ran under
`LocalSystem`.

## Investigation

The service DACL was deliberately weakened for the controlled account. Under
the standard-user context, `sc.exe config SOC_CASE15 ...` returned
`ChangeServiceConfig SUCCESS`.

Sysmon then provided two complementary perspectives:

1. `sc.exe` showed the initiating user as `soccase15` with Medium Integrity.
2. `services.exe` showed the resulting service `ImagePath` Registry update as
   `NT AUTHORITY\SYSTEM`.

This distinction was important for attribution: the standard user initiated the
change while the Service Control Manager performed the Registry write.

## Privileged Execution

The standard user subsequently executed:

`sc.exe start SOC_CASE15`

The configured command executed under the service account context. Sysmon
recorded:

- `cmd.exe` as `NT AUTHORITY\SYSTEM`;
- System Integrity;
- a SYSTEM-owned controlled marker file;
- `whoami.exe` as `NT AUTHORITY\SYSTEM`.

`StartService` returned error 1053 because `cmd.exe` is not a native Windows
service implementation. The process telemetry demonstrated that the controlled
command still executed.

## Detection Engineering

Custom Wazuh rules covered both atomic behavior and correlated behavior:

| Rule | Level | Purpose |
|---|---:|---|
| 100325 | 8 | standard-user service configuration change |
| 100330 | 10 | controlled service ImagePath modification |
| 100335 | 10 | standard-user service start |
| 100340 | 12 | controlled SYSTEM execution |
| 100345 | 12 | SYSTEM-created marker |
| 100350 | 13 | service configuration + Registry correlation |
| 100352 | 13 | symmetric correlation fallback |
| 100355 | 14 | modification followed by service start |
| 100360 | 15 | final privilege-escalation correlation |

The final alert chain observed in Wazuh was:

`100325 → 100350 → 100355 → 100345 → 100360`

The Level 15 `100360` alert represented the complete controlled chain from a
standard-user modification to observed SYSTEM execution.

## ATT&CK Mapping

- T1543.003 — Create or Modify System Process: Windows Service
- T1569.002 — System Services: Service Execution
- T1059.003 — Command and Scripting Interpreter: Windows Command Shell

## Evidence Integrity

Key preserved hashes:

- Wazuh final chain:
  `ee33234fef161a003b434a4d18386ab5a6c76fb3f3cd7eee1b996408bed5eb4e`
- Wazuh final telemetry:
  `6b677c512754c8547823dde0cf37aa09c906c5d55e97c43802d57d962ba45a63`
- Final endpoint Sysmon evidence:
  `466C805410B0F604B276371F16245C4066BFE08B72978CAF79B349A2179AA909`

## Remediation

The controlled vulnerable state was fully removed after evidence collection:

- original service SDDL restored;
- controlled service deleted;
- standard test user deleted;
- temporary payload and marker artifacts deleted;
- Secondary Logon restored to its previous stopped state;
- Sysmon returned to the Case 14 defensive configuration.

## Skills Demonstrated

- Windows service security and access-control analysis
- Sysmon process, file, and Registry telemetry
- Wazuh custom rule engineering
- temporal alert correlation
- standard-user versus SYSTEM context validation
- evidence preservation and SHA256 verification
- controlled remediation and post-test cleanup
- MITRE ATT&CK mapping
