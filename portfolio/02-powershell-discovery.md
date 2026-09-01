# SOC Case 002 — PowerShell and Discovery Activity

## Case Summary

**Status:** Closed  
**Verdict:** True Positive — Authorized Security Test  
**Telemetry:** Sysmon, PowerShell Logging, Wazuh

---

## Scenario

A controlled discovery sequence was executed on a monitored Windows endpoint:

```text
PowerShell
    ↓
cmd.exe
    ↓
whoami
hostname
ipconfig
net user
```

The goal was to validate endpoint visibility and determine whether the SIEM could reconstruct a suspicious command sequence.

---

## Detection

Relevant custom rules:

```text
100110
PowerShell spawning cmd.exe

100120
whoami discovery

100130
Multi-command discovery sequence
```

---

## Investigation

### Parent / Child Process Analysis

The investigation focused on:

- parent process;
- child process;
- process GUID;
- parent process GUID;
- command line;
- user context;
- integrity level.

### Discovery Commands

The observed sequence included:

```text
whoami
hostname
ipconfig
net user
```

These commands can be legitimate administrative activity, but in sequence they can also be consistent with post-execution reconnaissance.

### Context

The commands were intentionally generated in the lab and therefore classified as an authorized true positive.

In a production SOC, the analyst should validate:

- who executed the commands;
- whether the parent process is expected;
- whether the execution came from an administrative tool;
- whether similar commands occurred on other endpoints;
- whether network connections or credential activity followed.

---

## MITRE ATT&CK

| Technique | Description |
|---|---|
| T1059.003 | Windows Command Shell |
| T1033 | System Owner/User Discovery |
| T1016 | System Network Configuration Discovery |
| T1087.001 | Local Account Discovery |

---

## Verdict

```text
TRUE POSITIVE
AUTHORIZED SECURITY TEST
```

The telemetry and detection rules correctly identified the controlled discovery sequence.

---

## Response Recommendation for Production

If unexpected:

1. validate the user and host;
2. review the parent process;
3. inspect the complete process tree;
4. review surrounding PowerShell activity;
5. identify network connections after discovery;
6. search for credential access or lateral movement;
7. escalate when execution cannot be explained by legitimate administration.

---

## Evidence

```text
cases/case-100130-discovery.txt
docs/process-tree-investigation.md
scripts/process-tree.sh
```

---

## Analyst Skills Demonstrated

- endpoint triage;
- Sysmon analysis;
- PowerShell investigation;
- process tree analysis;
- command-line analysis;
- MITRE ATT&CK mapping;
- contextual classification;
- escalation reasoning.

