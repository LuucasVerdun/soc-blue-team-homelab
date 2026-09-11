# Case 14 — Credential Access Investigation & LSASS Access Detection

## Objective

Investigate controlled access to the Windows Local Security Authority Subsystem Service (`lsass.exe`) using Sysmon Event ID 10 and Wazuh, while distinguishing legitimate process access from higher-risk access patterns.

This lab did **not** dump LSASS memory, call `ReadProcessMemory`, extract credentials, or use credential-dumping tooling.

## Environment

- Endpoint: `WINSERVER2022`
- Wazuh agent: `002`
- Wazuh manager: `soc01`
- Sysmon: v15.21
- Sysmon configuration: `C:\Tools\Sysmon\sysmon-case14.xml`
- Wazuh native Sysmon Event 10 base rule: `61612`
- Wazuh native LSASS access rule: `92900`

## Sysmon Configuration

Sysmon ProcessAccess telemetry was enabled only for accesses targeting `lsass.exe`:

```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="end with">\lsass.exe</TargetImage>
</ProcessAccess>
```

The final Sysmon configuration preserved ProcessCreate, NetworkConnect, FileCreate and DnsQuery telemetry.

## Baseline Analysis

| Source process | Target | GrantedAccess | Observation |
|---|---|---:|---|
| `C:\Windows\System32\VBoxService.exe` | `lsass.exe` | `0x1400` | Repeated legitimate VirtualBox Guest Additions activity |
| `C:\Windows\System32\svchost.exe` | `lsass.exe` | `0x1000` | Repeated legitimate Windows activity |

### VBoxService validation

- File version: `7.2.8.173730`
- Company: `Oracle and/or its affiliates`
- Authenticode: valid, signer `Oracle America, Inc.`
- SHA256: `6C315D6DE874545EC328E3E94A8FE0881E1C6B6E4FA5C0BA1E9EFC1FE50BB4C6`

### svchost validation

- Authenticode: valid, signer `Microsoft Windows`
- SHA256: `31780FF2AAF7BC71F755BA0E4FEF1D61B060D1D2741EAFB33CBAB44D889595A0`

The baseline demonstrated that Sysmon Event ID 10 targeting LSASS must not automatically be classified as credential dumping.

## Wazuh Native Detection

Wazuh rule `61612` handles Sysmon Event ID 10 at Level 0. Wazuh rule `92900` raises Level 12 for LSASS access with `GrantedAccess` `0x1010` or `0x40` (subject to source exclusions) and maps to MITRE ATT&CK `T1003.001`.

The rule text says `possible credential dump`; this is an alert hypothesis, not proof.

## Controlled Test

A PowerShell script requested a handle to LSASS with access mask `0x1010`, then immediately closed it. It did not call `ReadProcessMemory`, create an LSASS dump, or extract credentials.

Because the script used PowerShell `Add-Type`, .NET invoked `csc.exe`.

Final script:

```text
C:\Tools\Sysmon\case14-lsass-access-20260910-221243.ps1
```

SHA256:

```text
EBB6BECA27AA6F3B3E92EC146C82C9E0D3C7E3130B4C062B0B48D5AF3203591F
```

## Final Telemetry Chain

```text
PowerShell
  PID 1884
  ProcessGuid {34dad77b-8dd1-6aa3-7101-000000001800}
        |
        +--> Add-Type
        v
csc.exe
  Sysmon Event ID 1
  ParentProcessId 1884
  ParentProcessGuid {34dad77b-8dd1-6aa3-7101-000000001800}
        |
        v
Wazuh 100310 — Level 8
        |
        v
same PowerShell process
        |
        v
lsass.exe
  Sysmon Event ID 10
  SourceProcessId 1884
  SourceProcessGuid {34dad77b-8dd1-6aa3-7101-000000001800}
  GrantedAccess 0x1010
        |
        v
Wazuh 100320 — Level 15
```

The matching ParentProcessGuid and SourceProcessGuid prove the same PowerShell process was involved in both stages.

## Custom Wazuh Rules

- `100310` Level 8: controlled PowerShell Add-Type compilation, child of native rule `92006`.
- `100315` Level 13: PowerShell opened a read-capable LSASS handle with `0x1010`, child of native rule `92900`.
- `100320` Level 15: temporal/contextual correlation of `100310` followed by `100315` within 60 seconds.

The Wazuh correlation does not dynamically compare GUID values. Exact process identity was verified from the underlying Sysmon telemetry.

## Analyst Assessment

**Suspicious controlled LSASS access detected; credential dumping was not performed or confirmed.**

The access mask justified investigation because it included memory-read capability, but the evidence did not show memory reading, a dump, or credential extraction.

## Detection Engineering Lessons

1. Sysmon Event ID 10 alone is not enough to classify LSASS access as malicious.
2. `GrantedAccess` materially changes investigative priority.
3. Legitimate software can repeatedly access LSASS.
4. Native alert descriptions require analyst validation.
5. Process GUID correlation can provide strong process-level attribution.
6. Detection confidence and incident conclusion are separate concepts.

## Evidence

Repository:

```text
evidence/case14/case14-custom-rules.xml
evidence/case14/wazuh-final-chain.jsonl
evidence/case14/wazuh-lsass-access-alerts.jsonl
```

Endpoint evidence:

```text
C:\Tools\Sysmon\case14-final-sysmon-events.txt
```

SHA256:

```text
7030F8BCDE7B97E252FCB1F17D913242189A5249708DFF917C88DDB6A9347CAA
```

## Cleanup

All `case14-lsass-access-*.ps1` scripts were removed. Sysmon remained running and `sysmon-case14.xml` was retained as a defensive monitoring configuration. Final Wazuh rules were synchronized with the repository.

## Final Status

```text
Detection engineering: VALIDATED
Custom correlation: VALIDATED
Final Wazuh rule: 100320 / Level 15
Credential dumping: NOT PERFORMED
Credential extraction: NOT OBSERVED
Cleanup: COMPLETE
```
