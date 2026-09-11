# Case 14 Evidence Summary

## Scenario

Controlled LSASS process-access investigation using Sysmon Event ID 10 and Wazuh. No LSASS dump or credential extraction was performed.

## Final Controlled Execution

Script:

```text
C:\Tools\Sysmon\case14-lsass-access-20260910-221243.ps1
```

Script SHA256:

```text
EBB6BECA27AA6F3B3E92EC146C82C9E0D3C7E3130B4C062B0B48D5AF3203591F
```

PowerShell:

```text
PID: 1884
ProcessGuid: {34dad77b-8dd1-6aa3-7101-000000001800}
```

Final Sysmon evidence SHA256:

```text
7030F8BCDE7B97E252FCB1F17D913242189A5249708DFF917C88DDB6A9347CAA
```

## Baseline

```text
VBoxService.exe -> lsass.exe -> 0x1400
svchost.exe     -> lsass.exe -> 0x1000
```

## Controlled Higher-Risk Pattern

```text
powershell.exe -> lsass.exe -> 0x1010
```

## Validated Wazuh Rules

```text
61612   Level 0   Sysmon Event 10 base rule
92006   Level 6   PowerShell/CSC native detection
92900   Level 12  Native LSASS access detection
100310  Level 8   Controlled Add-Type compilation
100315  Level 13  Read-capable LSASS handle
100320  Level 15  Correlated Case14 chain
```

## Final Alert

```text
Rule: 100320
Level: 15
Description:
SOC LAB: Controlled Case14 PowerShell execution was followed by read-capable LSASS process access.
```

Final Event ID 10:

```text
SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
SourceProcessId: 1884
SourceProcessGuid: {34dad77b-8dd1-6aa3-7101-000000001800}
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1010
```

## Assessment

```text
Suspicious controlled LSASS access detected.
Credential dumping was not performed or confirmed.
```
