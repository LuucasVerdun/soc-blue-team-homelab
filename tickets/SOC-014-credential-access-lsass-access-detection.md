# SOC-014 — Credential Access Investigation / LSASS Access Detection

## Ticket Summary

**Severity:** High
**Status:** Closed — Controlled Lab Activity
**Endpoint:** WINSERVER2022
**Detection Source:** Sysmon + Wazuh
**Primary Event:** Sysmon Event ID 10
**Final Custom Alert:** Wazuh Rule 100320 / Level 15

## Alert

A PowerShell process accessed `lsass.exe` with `GrantedAccess 0x1010`. Native Wazuh rule `92900` classified the behavior as possible credential dumping.

## Baseline Comparison

```text
VBoxService.exe -> lsass.exe -> 0x1400
svchost.exe     -> lsass.exe -> 0x1000
```

The PowerShell event represented a materially different access pattern.

## Investigation

The controlled PowerShell script used `Add-Type`, which invoked `csc.exe`.

Final PowerShell:

```text
PID: 1884
ProcessGuid: {34dad77b-8dd1-6aa3-7101-000000001800}
```

Sysmon Event ID 1 for `csc.exe`:

```text
ParentProcessId: 1884
ParentProcessGuid: {34dad77b-8dd1-6aa3-7101-000000001800}
```

Subsequent Sysmon Event ID 10:

```text
SourceProcessId: 1884
SourceProcessGuid: {34dad77b-8dd1-6aa3-7101-000000001800}
GrantedAccess: 0x1010
```

This confirmed that the same PowerShell process was responsible for both stages.

## Detection Chain

```text
92006 / native
PowerShell -> csc.exe
        ↓
100310 / Level 8
Controlled Add-Type compilation
        ↓
92900 / native validation
LSASS access with 0x1010
        ↓
100315 / Level 13
Read-capable LSASS handle
        ↓
100320 / Level 15
Correlated Case14 chain
```

## Analyst Assessment

The access mask justified a high-priority investigation because it included memory-read capability. However, the controlled script only opened and closed the process handle.

No evidence showed `ReadProcessMemory`, LSASS memory dumping, credential extraction, or use of a credential-dumping tool.

## Disposition

**Controlled lab activity / detection engineering validation.**

Final conclusion:

**Suspicious LSASS access was successfully detected and correlated. Credential dumping was not performed or confirmed.**

## Cleanup

- Removed all `case14-lsass-access-*.ps1` scripts.
- Retained Sysmon monitoring.
- Retained the final Sysmon evidence file.
- Synchronized final Wazuh rules with the Git repository.

## Evidence

Controlled script SHA256:

```text
EBB6BECA27AA6F3B3E92EC146C82C9E0D3C7E3130B4C062B0B48D5AF3203591F
```

Endpoint evidence SHA256:

```text
7030F8BCDE7B97E252FCB1F17D913242189A5249708DFF917C88DDB6A9347CAA
```

Repository evidence:

```text
evidence/case14/case14-custom-rules.xml
evidence/case14/wazuh-final-chain.jsonl
evidence/case14/wazuh-lsass-access-alerts.jsonl
```
