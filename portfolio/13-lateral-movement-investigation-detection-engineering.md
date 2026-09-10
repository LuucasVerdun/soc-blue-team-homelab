# Case 13 — Lateral Movement Investigation & Detection Engineering

## Executive Summary

This case documents a controlled lateral-movement simulation from `WIN10` (`192.168.100.20`) to `WINSERVER2022` (`192.168.100.30`) using SMB administrative shares and the Windows Service Control Manager.

The objective was to investigate the activity across endpoint, Windows audit, network, IDS, and SIEM telemetry, then engineer Wazuh detections that correlated the chain into a high-confidence multi-source alert.

No malware was used. The remote command only created a benign marker file.

**Final verdict:** True Positive — Controlled Lab Simulation

## Final Run

- Token: `20260910-030053`
- Service: `SOC_CASE13_20260910030053`
- Script: `case13-remote-20260910-030053.cmd`
- Marker: `case13-marker-20260910-030053.txt`
- SMB flow: `192.168.100.20:50227 -> 192.168.100.30:445`
- Script SHA256: `59E00E12FCC3249FCF9B0B4E71AE2B232AF38AC3E8967A58E531CDF53367409D`

## Investigation Findings

### SMB Authentication Context

Windows Security Event ID 4624 established the session with Logon Type 3, source workstation WIN10, source IP `192.168.100.20`, NTLM V2, and Administrator credentials. The session remained open and was reused by the final run.

A native Wazuh rule described the logon as possible pass-the-hash / possible RDP. The underlying evidence did not support either conclusion, so the alert description was treated as an investigation lead rather than ground truth.

### ADMIN$ File Transfer

Event ID 5145 showed `192.168.100.20:50227` writing `Temp\case13-remote-20260910-030053.cmd` through `ADMIN$` with access mask `0x2` / `WriteData (or AddFile)`.

Custom Wazuh rule `100260` elevated this controlled write to Level 8.

### Zeek SMB File Visibility

Zeek observed the same file over SMB:

- UID `C2mN2qTkFJzCj9PTj`
- FUID `FTs14p1ZkYJbJpWOr9`
- 108 bytes
- MIME `text/x-msdos-batch`
- missing bytes `0`
- SHA256 `59e00e12fcc3249fcf9b0b4e71ae2b232af38ac3e8967a58e531cdf53367409d`

The server-side artifact produced the same SHA256.

### Remote Service Creation

Windows Event ID 7045 recorded service `SOC_CASE13_20260910030053` with image path `cmd.exe /c C:\Windows\Temp\case13-remote-20260910-030053.cmd`, demand start, and LocalSystem account.

### Zeek DCE/RPC

The same SMB session showed:

- `OpenSCManager2`
- `CreateServiceW`
- `OpenServiceW`
- `StartServiceW`

Endpoint: `svcctl`
Named pipe: `\pipe\ntsvcs`

This independently corroborated remote service creation and service start behavior.

### Suricata

Suricata generated `ET INFO Command Shell Activity Over SMB - Possible Lateral Movement` for the same source/destination SMB pair. It was used as supporting evidence, not standalone proof.

### Execution Despite Service Error

`sc.exe start` returned error 1053 because `cmd.exe` is not a service executable implementing the normal SCM protocol. Events 7009 and 7000 recorded the timeout, but Sysmon proved the command still executed.

### Sysmon

Event ID 1 showed `cmd.exe /c C:\Windows\Temp\case13-remote-20260910-030053.cmd` running as `NT AUTHORITY\SYSTEM`, PID `2476`, ProcessGuid `{34dad77b-47e5-6aa2-6d02-000000001700}`.

Event ID 11 showed the same PID and ProcessGuid creating `C:\Users\Public\case13-marker-20260910-030053.txt`.

ParentImage was not populated. Parent PID 612 was later identified as `services.exe`; this is complementary evidence only.

## Detection Engineering

| Rule | Level | Detection |
|---|---:|---|
| 100260 | 8 | Case13 script written through ADMIN$ |
| 100265 | 10 | Controlled Windows service created as LocalSystem |
| 100270 | 12 | Case13 cmd.exe execution as SYSTEM |
| 100275 | 8 | Execution marker created |
| 100280 | 10 | Suricata SMB lateral-movement indication |
| 100285 | 13 | ADMIN$ transfer followed by remote service creation |
| 100290 | 15 | Transfer + service creation + SYSTEM execution |
| 100295 | 15 | Multi-source branch: endpoint first, network second |
| 100300 | 15 | Multi-source branch: network first, endpoint second |

The final controlled run triggered `100300` at Level 15.

## ATT&CK Mapping

- `T1021.002` — SMB/Windows Admin Shares
- `T1543.003` — Windows Service
- `T1569.002` — Service Execution
- `T1059.003` — Windows Command Shell

`T1569.002` is supported by the combined `CreateServiceW`, `StartServiceW`, and subsequent SYSTEM-level command execution evidence, not by Event ID 7045 alone.

## SOC Assessment

**Classification:** True Positive — Controlled Lab Simulation

In production, this combination would warrant high-priority investigation because it joins administrative-share file transfer, remote service creation, service start, SYSTEM command execution, and network IDS corroboration.

## Limitations

- Long-lived SMB session reused across tests.
- No fresh 4624 in final run.
- Sysmon did not populate ParentImage.
- PID 612 -> services.exe was validated later.
- Suricata only indicates possible lateral movement by itself.
- Final-run WIN10 source-file hash was not independently retained in the supplied output.
- Authorized lab simulation, not a real compromise.

## Cleanup

All controlled services, scripts, markers, and SMB sessions were removed after evidence preservation. Defensive telemetry and rules were retained.

## Skills Demonstrated

SOC triage, Windows authentication analysis, SMB/Admin Share investigation, Windows service analysis, Sysmon correlation, Zeek SMB/DCE-RPC analysis, Suricata validation, Wazuh rule engineering, multi-source correlation, ATT&CK mapping, false-positive/context validation, evidence preservation, and cleanup.
