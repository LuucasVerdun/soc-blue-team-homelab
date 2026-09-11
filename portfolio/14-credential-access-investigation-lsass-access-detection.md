# Case 14 — Credential Access Investigation & LSASS Access Detection

## Executive Summary

This case focused on distinguishing legitimate LSASS process access from higher-risk access behavior using Sysmon and Wazuh.

After enabling Sysmon Event ID 10 specifically for `lsass.exe`, I established a baseline of legitimate process access. `VBoxService.exe` repeatedly accessed LSASS with `GrantedAccess 0x1400`, while `svchost.exe` used `0x1000`. Both binaries were validated through trusted paths, digital signatures, and SHA256 hashes.

I then generated a controlled PowerShell test that opened LSASS with access mask `0x1010` and immediately closed the handle. No process memory was read, no LSASS dump was created, and no credentials were extracted.

The test generated native and custom Wazuh detections and culminated in a Level 15 correlated alert.

## Key Findings

- Sysmon Event ID 10 successfully captured access to LSASS.
- Legitimate LSASS access existed in the baseline and would produce false positives if every Event ID 10 were treated as credential dumping.
- Native Wazuh rule `92900` identified PowerShell accessing LSASS with `0x1010`.
- PowerShell `Add-Type` caused `csc.exe` execution, detected by native rule `92006`.
- Custom rule `100310` identified the controlled PowerShell/CSC stage.
- Custom rule `100315` identified PowerShell obtaining a read-capable LSASS handle.
- Custom rule `100320` correlated the stages and generated a Level 15 alert.
- Matching process GUIDs proved the same PowerShell process was involved in both stages.

## Final Correlation

```text
PowerShell PID 1884
ProcessGuid {34dad77b-8dd1-6aa3-7101-000000001800}
        |
        v
csc.exe / Add-Type
Sysmon Event 1
        |
        v
100310 — Level 8
        |
        v
PowerShell -> lsass.exe
Sysmon Event 10
GrantedAccess 0x1010
        |
        v
100320 — Level 15
```

## Baseline vs Higher-Risk Pattern

| Source | Access | Assessment |
|---|---:|---|
| `VBoxService.exe` | `0x1400` | Observed legitimate baseline |
| `svchost.exe` | `0x1000` | Observed legitimate baseline |
| `powershell.exe` | `0x1010` | Controlled higher-risk access requiring investigation |

## Analyst Decision

**Suspicious controlled LSASS access detected; credential dumping was not performed or confirmed.**

The controlled test did not call `ReadProcessMemory`, create an LSASS memory dump, extract credentials, or use a credential-dumping utility.

## Detection Engineering Value

The case shows why an alert description is not the final incident verdict. Wazuh produced descriptions such as `possible malware drop` and `possible credential dump`; both required contextual investigation.

## Evidence Integrity

Controlled script SHA256:

```text
EBB6BECA27AA6F3B3E92EC146C82C9E0D3C7E3130B4C062B0B48D5AF3203591F
```

Final Sysmon evidence SHA256:

```text
7030F8BCDE7B97E252FCB1F17D913242189A5249708DFF917C88DDB6A9347CAA
```

## Skills Demonstrated

- Windows endpoint telemetry analysis
- Sysmon Event ID 10
- LSASS access investigation
- Wazuh rule analysis
- Detection engineering
- False-positive analysis and baselining
- Process GUID correlation
- Alert validation
- Evidence preservation
- MITRE ATT&CK-aware analysis without over-attribution
