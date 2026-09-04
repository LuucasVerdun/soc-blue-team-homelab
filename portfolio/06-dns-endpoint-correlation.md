# Case 06 — DNS Investigation with Endpoint Process Attribution

## Executive Summary

A controlled DNS investigation correlated repeated DNS activity observed on the network with the endpoint process responsible for generating the query.

Final controlled FQDN:

`case06-final-011757.soc-lab-beacon.example`

Independent telemetry sources:

- Sysmon Event ID 22 on `WIN10`, attributing the query to `powershell.exe`;
- Zeek DNS telemetry on `soc01`, showing repeated A/AAAA queries from `192.168.100.20` to `192.168.100.30:53`.

Wazuh correlation chain:

- `100220` — Sysmon endpoint DNS attribution;
- `100195` — Zeek controlled suspicious DNS query;
- `100200` — repeated DNS / beacon-like pattern;
- `100225` — multi-source endpoint + network correlation.

**Final classification:** TRUE POSITIVE — Suspicious Repeated DNS Activity with Endpoint Process Attribution
**C2 activity:** NOT CONFIRMED
**Host compromise:** NOT ESTABLISHED

## Endpoint Evidence

Wazuh Rule `100220`, Level 8:

- Timestamp: `2026-09-04T04:18:50.263+0000`
- Agent: `WIN10`
- Event ID: `22`
- Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- PID: `1052`
- User: `WIN10\vboxuser`
- Query: `case06-final-011757.soc-lab-beacon.example`
- QueryStatus: `1460`

The PowerShell session `$PID` was independently confirmed as `1052`, matching the Sysmon Event 22 process ID.

## Network Evidence

Zeek observed repeated DNS traffic:

`192.168.100.20 -> 192.168.100.30:53/UDP`

for the same unique FQDN. A and AAAA queries/retries were observed within a short interval.

## Final Wazuh Correlation

Rule `100225`, Level 13:

- Timestamp: `2026-09-04T04:19:02.100+0000`
- Agent: `soc01`
- Source: `192.168.100.20`
- Destination: `192.168.100.30`
- Destination port: `53`
- Protocol: `udp`
- Query: `case06-final-011757.soc-lab-beacon.example`
- Current qtype: `A`

The alert's `previous_output` preserved repeated DNS observations, including A and AAAA activity for the same FQDN.

## Timeline

```text
04:18:50 UTC
Sysmon Event 22
PowerShell PID 1052
Wazuh 100220
        |
        v
Zeek sees repeated A / AAAA DNS activity
        |
        v
100195 / 100200 logic
        |
        v
04:19:02 UTC
Wazuh 100225 / Level 13
```

## Analyst Assessment

**Classification:** TRUE POSITIVE — Suspicious Repeated DNS Activity with Endpoint Process Attribution

**Process attribution:** CONFIRMED FOR THE CONTROLLED TEST

**C2 activity:** NOT CONFIRMED

Repeated DNS activity can be consistent with beacon-like behavior, and MITRE ATT&CK `T1071.004 — DNS` is relevant as detection context. However, the evidence does not establish a real C2 server, malicious infrastructure, tasking, data transfer, or successful command-and-control communication.

**Host compromise:** NOT ESTABLISHED

## Key Lessons

1. Zeek shows the network behavior; Sysmon Event 22 attributes the DNS activity to a process.
2. Unique lab subdomains improve repeatability and reduce ambiguity between tests.
3. Multi-source correlation increases confidence without proving C2.
4. `global_frequency` is required when correlating events from different Wazuh agents.
5. Detection context and confirmed malicious behavior must remain analytically separate.

## Final Verdict

**TRUE POSITIVE — Suspicious Repeated DNS Activity with Endpoint Process Attribution**
**Process attribution:** PowerShell PID 1052
**C2 activity:** Not confirmed
**Host compromise:** Not established
