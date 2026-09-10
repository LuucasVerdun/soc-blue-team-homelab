# SOC-013 — Lateral Movement via SMB Administrative Share and Remote Service

**Status:** Closed
**Severity:** High / Level 15 correlated detection
**Classification:** True Positive — Controlled Lab Simulation
**Source:** WIN10 (`192.168.100.20`)
**Destination:** WINSERVER2022 (`192.168.100.30`)
**Primary Protocol:** SMB (`445/TCP`)
**Final Wazuh Rule:** `100300`

## Alert Summary

A controlled lab simulation generated a multi-source detection consistent with lateral movement through SMB administrative shares followed by remote Windows service execution.

## Final Run Indicators

- Token: `20260910-030053`
- Service: `SOC_CASE13_20260910030053`
- Script: `case13-remote-20260910-030053.cmd`
- Marker: `case13-marker-20260910-030053.txt`
- SHA256: `59E00E12FCC3249FCF9B0B4E71AE2B232AF38AC3E8967A58E531CDF53367409D`

## Key Evidence

### Windows Security

Existing SMB authentication context:
- 4624 Logon Type 3
- WIN10 / `192.168.100.20`
- NTLM V2
- Administrator
- Logon ID `0x2C5437`

Final-run 5145:
- `192.168.100.20:50227`
- `ADMIN$`
- `Temp\case13-remote-20260910-030053.cmd`
- `WriteData (or AddFile)`
- access mask `0x2`

### Windows System

7045:
- service `SOC_CASE13_20260910030053`
- `cmd.exe /c C:\Windows\Temp\case13-remote-20260910-030053.cmd`
- LocalSystem

7009/7000 later recorded the expected service timeout / 1053 condition.

### Sysmon

Event ID 1:
- `cmd.exe`
- controlled script
- SYSTEM
- PID 2476
- ProcessGuid `{34dad77b-47e5-6aa2-6d02-000000001700}`

Event ID 11:
- same PID and ProcessGuid
- marker file created

### Zeek

SMB:
- same source/destination pair
- ADMIN$
- full 108-byte batch file observed
- SHA256 matching server copy

DCE/RPC:
- OpenSCManager2
- CreateServiceW
- OpenServiceW
- StartServiceW
- endpoint `svcctl`
- named pipe `\pipe\ntsvcs`

### Suricata

`ET INFO Command Shell Activity Over SMB - Possible Lateral Movement`

Signature ID `2027175`.

## Wazuh Detection Chain

- `100260` L8 — ADMIN$ write
- `100265` L10 — controlled service creation
- `100270` L12 — cmd.exe as SYSTEM
- `100275` L8 — execution marker
- `100280` L10 — Suricata SMB indication
- `100285` L13 — ADMIN$ + service creation
- `100290` L15 — Windows execution chain
- `100295/100300` L15 — cross-agent multi-source correlation

Final alert: `100300 — Level 15`.

## ATT&CK

- T1021.002 — SMB/Windows Admin Shares
- T1543.003 — Windows Service
- T1569.002 — Service Execution
- T1059.003 — Windows Command Shell

## Analyst Validation

A native Wazuh rule suggested possible pass-the-hash and possible RDP for the earlier NTLM network logon. Evidence showed authorized SMB/445, Logon Type 3, and NTLM V2. No pass-the-hash technique was performed and the event was not classified as RDP.

## Assessment

The behavior tested is a **True Positive**. Security impact is benign by design because the operator was authorized and the payload only created a marker.

In production, this chain would justify immediate validation of account use, source-host authorization, remote service creation, transferred files, credential exposure, further lateral movement, and persistence.

## Cleanup

- all `SOC_CASE13_*` services deleted;
- remote scripts deleted;
- markers deleted;
- WIN10 local scripts deleted;
- SMB session disconnected;
- `net use` returned no entries.

## Closure

Controlled simulation completed successfully. Evidence preserved, Level 15 correlation validated, and test artifacts removed.
