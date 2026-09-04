# Case 07 — Post-Compromise Endpoint Investigation

## Executive Summary

A controlled endpoint investigation reconstructed a sequence of discovery activity followed by Scheduled Task registration and task-driven command execution on a Windows endpoint.

The scenario used existing Wazuh detections, native Windows Task Scheduler telemetry, and Sysmon process creation events. The final correlation demonstrated elevated PowerShell launching `cmd.exe`, multiple discovery commands, Scheduled Task registration, task execution by the Windows Task Scheduler service, creation of a benign marker file, and Wazuh correlation across the full sequence.

**Final classification:** TRUE POSITIVE — Discovery Followed by Scheduled Task Persistence and Execution
**Payload behavior:** BENIGN CONTROLLED MARKER
**Malicious persistence:** NOT CONFIRMED
**Host compromise:** NOT ESTABLISHED

## Controlled Scenario

The activity began from an elevated PowerShell session. A child `cmd.exe` executed:

```text
whoami
hostname
ipconfig
net user
```

A controlled Scheduled Task named:

```text
\SOC-LAB-CASE07
```

was then registered.

The task action executed:

```text
cmd.exe /c echo SOC CASE 07 CONTROLLED TASK > "C:\Users\Public\soc-case07-marker.txt"
```

The marker file was intentionally benign and existed only to prove successful task execution.

## Detection Stage 1 — Discovery

Wazuh rule `100130`, Level 12, detected multiple discovery commands executed from elevated PowerShell.

Final validation:

- Timestamp: `2026-09-04T13:53:09.356+0000`
- Agent: `WIN10`
- Event ID: `1`
- Image: `C:\Windows\System32\cmd.exe`
- Parent: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Integrity: `High`
- User: `WIN10\vboxuser`

Command line:

```text
cmd.exe /c "whoami & hostname & ipconfig & net user"
```

Relevant ATT&CK context:

- `T1059.003` — Windows Command Shell
- `T1033` — System Owner/User Discovery
- `T1016` — System Network Configuration Discovery
- `T1087.001` — Local Account Discovery

## Detection Stage 2 — Scheduled Task Registration

Windows Task Scheduler Operational Event ID `106` recorded registration of:

```text
\SOC-LAB-CASE07
```

by:

```text
WIN10\vboxuser
```

Wazuh native rule `67014` maps this event to `T1053.005 — Scheduled Task/Job: Scheduled Task`.

Custom correlation rule `100230`, Level 13, required both the native Task Scheduler registration event and a recent `100130` discovery alert.

Final validation:

- Timestamp: `2026-09-04T13:53:45.612+0000`
- Rule: `100230`
- Level: `13`
- Agent: `WIN10`
- Event ID: `106`
- Task: `\SOC-LAB-CASE07`
- User: `WIN10\vboxuser`

This establishes that the controlled Scheduled Task registration occurred after the discovery sequence.

## Detection Stage 3 — Task-Driven Execution

The Scheduled Task was manually started for validation.

Windows Task Scheduler telemetry recorded the task lifecycle, including Events `100`, `129`, `200`, `110`, `201`, and `102`.

`LastTaskResult` was `0`.

The benign marker contained:

```text
SOC CASE 07 CONTROLLED TASK
```

## Sysmon Process Evidence

Sysmon Event ID `1` recorded the task-driven command process.

Final correlated process:

- PID: `8384`
- Image: `C:\Windows\System32\cmd.exe`
- User: `WIN10\vboxuser`
- Parent image: `C:\Windows\System32\svchost.exe`

Parent command line:

```text
C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
```

Process command line:

```text
cmd.exe /c echo SOC CASE 07 CONTROLLED TASK > "C:\Users\Public\soc-case07-marker.txt"
```

The parent context shows that the command was launched through the Windows Task Scheduler service rather than directly from the original PowerShell session.

## Final Correlation — Wazuh Rule 100235

Rule `100235`, Level 15, required a recent `100230` correlation, Sysmon process creation matching task-driven execution, Task Scheduler service parent context, and the controlled command marker.

Final alert:

- Timestamp: `2026-09-04T13:53:56.260+0000`
- Rule: `100235`
- Level: `15`
- Agent: `WIN10`
- Event ID: `1`
- Image: `cmd.exe`
- PID: `8384`
- Parent: `svchost.exe -k netsvcs -p -s Schedule`

The Level 15 alert represents high-confidence correlation of the controlled sequence. It does not, by itself, establish that the endpoint was maliciously compromised.

## Timeline

```text
13:53:09 UTC
100130 / Level 12
Elevated PowerShell -> cmd.exe
whoami + hostname + ipconfig + net user
        |
        v
13:53:45 UTC
100230 / Level 13
Scheduled Task registration after discovery
\SOC-LAB-CASE07
        |
        v
13:53:53 UTC
Task executed successfully
LastTaskResult = 0
        |
        v
13:53:56 UTC
100235 / Level 15
Task Scheduler service -> cmd.exe
Benign marker created
```

## Analyst Assessment

**Discovery activity:** CONFIRMED
**Scheduled Task registration:** CONFIRMED
**Task execution:** CONFIRMED
**Payload behavior:** BENIGN CONTROLLED MARKER
**Malicious persistence:** NOT CONFIRMED
**Host compromise:** NOT ESTABLISHED

The technique resembles persistence behavior, but the task was intentionally created in an authorized laboratory. No malicious payload or unauthorized persistence mechanism was established.

## SOC N1 Decision

**Disposition:** Closed — authorized security simulation.

For an equivalent production alert, the analyst should identify the task name, author, trigger, action and execution context; review process ancestry and command lines; investigate activity immediately preceding task creation; inspect discovery, credential access, execution and network activity; determine whether the task is expected administrative activity; inspect referenced binaries, scripts, URLs and file hashes; review execution history; and escalate when the task or associated activity is unauthorized, malicious or linked to compromise.

## Key Lessons

1. A Scheduled Task registration alert is more useful when correlated with preceding endpoint behavior.
2. Native Windows telemetry can be reused instead of duplicating detections unnecessarily.
3. Sysmon process ancestry distinguishes task-driven execution from direct shell execution.
4. A successful task result confirms execution, not malicious intent.
5. High-severity correlation must remain separate from claims of confirmed compromise.
6. Building detections from observed telemetry reduces unnecessary custom rules and false-positive risk.

## Evidence

```text
cases/case-100235-discovery-persistence-execution.jsonl
evidence/case07-evidence-summary.txt
tickets/SOC-007-post-compromise-endpoint-investigation.md
endpoint/case07/case07-post-compromise-investigation-checklist.md
wazuh/rules/local_rules.xml
```

## Final Verdict

**TRUE POSITIVE — Discovery Followed by Scheduled Task Persistence and Execution**

**Discovery:** Confirmed
**Scheduled Task registration:** Confirmed
**Task execution:** Confirmed
**Payload:** Benign controlled marker
**Malicious persistence:** Not confirmed
**Host compromise:** Not established
