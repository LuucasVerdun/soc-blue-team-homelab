# SOC-007 — Discovery Followed by Scheduled Task Persistence and Execution

## Summary

**Final detection:** Wazuh Rule `100235`, Level 15
**Endpoint:** `WIN10`
**Classification:** TRUE POSITIVE
**Payload:** BENIGN CONTROLLED MARKER
**Malicious persistence:** NOT CONFIRMED
**Host compromise:** NOT ESTABLISHED

## Alert Chain

```text
100130 / Level 12
Elevated PowerShell discovery
        ↓
100230 / Level 13
Scheduled Task registration after discovery
        ↓
100235 / Level 15
Task-driven command execution
```

## Investigation

At `13:53:09 UTC`, Wazuh detected an elevated PowerShell process spawning `cmd.exe` to execute:

```text
whoami & hostname & ipconfig & net user
```

At `13:53:45 UTC`, Task Scheduler Event ID `106` recorded registration of `\SOC-LAB-CASE07`.

Wazuh rule `100230` correlated the task registration with the preceding discovery activity.

The Scheduled Task was then executed. Sysmon recorded:

```text
svchost.exe -k netsvcs -p -s Schedule
        ↓
cmd.exe
```

The command created:

```text
C:\Users\Public\soc-case07-marker.txt
```

At `13:53:56 UTC`, Wazuh rule `100235`, Level 15, completed the correlation chain.

Task Scheduler reported `LastTaskResult = 0`, and the marker file contained the expected controlled text.

## ATT&CK Context

- `T1059.003` — Windows Command Shell
- `T1033` — System Owner/User Discovery
- `T1016` — System Network Configuration Discovery
- `T1087.001` — Local Account Discovery
- `T1053.005` — Scheduled Task/Job: Scheduled Task

## Analyst Conclusion

The discovery sequence, Scheduled Task registration, and task-driven execution were all confirmed.

The payload was benign and authorized. Therefore, malicious persistence and endpoint compromise are not established.

## Disposition

**Closed — authorized security simulation.**

A production equivalent should be escalated when task creation or execution is unexpected, unauthorized, linked to suspicious binaries or scripts, or associated with additional evidence of compromise.
