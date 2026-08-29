# Zeek Network Monitoring

## Objective
Add protocol-aware network metadata collection to the SOC Blue Team Home Lab using Zeek in parallel with Suricata on the passive interface `enp0s9`, with ingestion and correlation in Wazuh.

## Architecture
```text
WIN10 192.168.100.20
        |
        v
VirtualBox Host-Only Network
        |
        v
SOC01 / enp0s9
   |           |
   v           v
Suricata      Zeek
   |           |
eve.json   conn.log / dns.log
   |           |
   +-----+-----+
         |
         v
       Wazuh
```

## Environment
- Zeek 8.2.2
- Ubuntu Server 24.04.4 LTS
- Monitoring interface: `enp0s9`
- Management interface: `enp0s8` / `192.168.100.10`
- Local network: `192.168.100.0/24`

## Configuration
`node.cfg`:
```text
[zeek]
type=standalone
host=localhost
interface=enp0s9
```

`networks.cfg`:
```text
192.168.100.0/24    SOC-LAB
```

JSON logging was enabled in `local.zeek`:
```text
@load policy/tuning/json-logs
```

## Service Persistence
The Zeek package did not provide an active systemd service in this environment, so a custom service was created to run `zeekctl deploy` at boot and `zeekctl stop` during shutdown.

A previous `crashed` state was investigated. The logs showed:
```text
received termination signal
TERMINATED [atexit]
```

No OOM event, segmentation fault, or core dump was present. The system journal showed a complete operating-system shutdown at the same timestamp. Conclusion: Zeek was terminated by system shutdown, not by an internal crash.

## Capture Validation
Validated capture statistics:
```text
41650 packets received
0 packets dropped
0.00% capture loss
```

Logs observed:
```text
conn.log
dns.log
known_services.log
notice.log
capture_loss.log
telemetry.log
```

## RDP Visibility
Zeek observed traffic between:
```text
WIN10          192.168.100.20
WINSERVER2022  192.168.100.30
```

Observed protocol metadata included:
```text
TCP/3389 -> service ssl
UDP/3389 -> service rdpeudp
```

This complements Suricata: Suricata focuses on alerts/signatures, while Zeek provides connection and protocol metadata.

## Wazuh Integration
Wazuh contains Zeek/OwlH-oriented rules using fields such as `bro_engine`. This lab instead ingests Zeek's native JSON logs directly.

Collected files:
```text
/opt/zeek/logs/current/conn.log
/opt/zeek/logs/current/dns.log
```

Zeek fields such as:
```text
id.orig_h
id.orig_p
id.resp_h
id.resp_p
```

are normalized by Wazuh as:
```text
data.id.orig_h
data.id.orig_p
data.id.resp_h
data.id.resp_p
```

## Detection 1 - Rule 100190
Purpose: detect Zeek connection metadata for WIN10 to WINSERVER2022 on TCP/3389.

```text
Rule ID: 100190
Level: 5
MITRE: T1021.001 - Remote Desktop Protocol
Tactic: Lateral Movement
```

Validated event:
```text
Source: 192.168.100.20:50044
Destination: 192.168.100.30:3389
Protocol: TCP
Duration: 120.073743
Connection state: RSTO
```

Detection chain:
```text
WIN10 -> enp0s9 -> Zeek -> conn.log JSON -> Wazuh -> 100190
```

This rule represents connection visibility and does not by itself prove successful RDP authentication.

## Detection 2 - Rule 100195
Controlled DNS indicator:
```text
soc-lab-beacon.example
```

Traffic:
```text
192.168.100.20 -> 192.168.100.30:53/UDP
```

Validated query types:
```text
A
AAAA
```

Rule:
```text
Rule ID: 100195
Level: 7
MITRE: T1071.004 - DNS
Tactic: Command and Control
```

Detection chain:
```text
WIN10 -> DNS/53 -> enp0s9 -> Zeek -> dns.log JSON -> Wazuh -> 100195
```

This is a controlled lab indicator. A DNS query alone does not prove Command and Control.

## Detection 3 - Rule 100200
Repeated queries to the same controlled domain were correlated.

```text
Rule ID: 100200
Level: 10
Frequency: 4
Timeframe: 15 seconds
```

Correlation:
```text
same source IP
same DNS query
```

MITRE:
```text
T1071.004 - DNS
Tactic: Command and Control
```

Validated alert:
```text
Timestamp: 2026-08-29T05:37:40.241+0000
Source: 192.168.100.20
Destination: 192.168.100.30
Query: soc-lab-beacon.example
QType: AAAA
```

Detection chain:
```text
Repeated DNS queries
  -> Zeek dns.log
  -> Wazuh 100195
  -> 4 matches / 15 seconds
  -> same source + same query
  -> Wazuh 100200
```

This rule detects beacon-like behavior in a controlled scenario; it does not independently confirm malicious C2.

## Validation Status
```text
Zeek installation             VALIDATED
Standalone configuration      VALIDATED
Passive interface enp0s9      VALIDATED
JSON logging                  VALIDATED
Capture loss 0.00%           VALIDATED
conn.log                      VALIDATED
dns.log                       VALIDATED
RDP TCP metadata              VALIDATED
RDPEUDP metadata              VALIDATED
Systemd persistence           VALIDATED
Wazuh JSON ingestion          VALIDATED
Rule 100190                   VALIDATED
Rule 100195                   VALIDATED
Rule 100200                   VALIDATED
MITRE mapping                 VALIDATED
```

## Repository Files
```text
zeek/config/node.cfg
zeek/config/networks.cfg
zeek/config/local.zeek
docs/zeek-network-monitoring.md
cases/case-100190-zeek-rdp-connection.txt
cases/case-100195-zeek-dns-query.txt
cases/case-100200-zeek-dns-beacon-like.txt
```

