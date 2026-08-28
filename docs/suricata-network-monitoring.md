# Suricata Network Monitoring

## Objective

Add network-based detection capability to the SOC Blue Team Home Lab using Suricata integrated with Wazuh.

The sensor operates passively and monitors east-west traffic between laboratory systems.

## Architecture

```text
Windows 10
192.168.100.20
      |
      | Network traffic
      v
VirtualBox Host-Only Network
      |
      v
SOC01 - enp0s9
Passive monitoring interface
      |
      v
Suricata
      |
      v
/var/log/suricata/eve.json
      |
      v
Wazuh Logcollector
      |
      v
Wazuh Analysis Engine
      |
      v
Custom SOC detections
```

## Sensor Interface

Suricata monitors the dedicated passive interface:

```text
enp0s9
```

The interface:

- has no IPv4 address
- has no IPv6 link-local address
- is dedicated to passive network monitoring
- operates with VirtualBox promiscuous mode enabled
- is not used for management traffic

Management connectivity remains on:

```text
enp0s8
192.168.100.10
```

## Suricata Configuration

Suricata version:

```text
7.0.3 RELEASE
```

Capture mode:

```text
AF_PACKET
```

HOME_NET:

```text
192.168.100.0/24
```

Monitoring interface:

```text
enp0s9
```

The sensor successfully observed bidirectional traffic between:

```text
WIN10
192.168.100.20

WINSERVER2022
192.168.100.30
```

RDP traffic on TCP/3389 was identified directly by the Suricata application-layer parser.

## Suricata Rules

The validated local rules are stored in:

```text
/var/lib/suricata/rules/local.rules
```

### RDP Detection

```text
alert tcp 192.168.100.20 any -> 192.168.100.30 3389 (msg:"SOC LAB: RDP connection attempt detected"; flags:S; flow:to_server,stateless; sid:1000001; rev:1;)
```

### TCP Port Scan Detection

```text
alert tcp 192.168.100.20 any -> 192.168.100.30 any (msg:"SOC LAB: Possible TCP port scan detected"; flags:S; flow:stateless; threshold:type threshold,track by_src,count 10,seconds 10; sid:1000002; rev:2;)
```

## Wazuh Integration

Suricata writes network telemetry to:

```text
/var/log/suricata/eve.json
```

Wazuh collects the file using JSON log collection:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

Wazuh already includes native Suricata rules in:

```text
/var/ossec/ruleset/rules/0475-suricata_rules.xml
```

The native alert rule used in this lab is:

```text
86601
Suricata: Alert - $(alert.signature)
```

Custom Wazuh rules then classify the laboratory detections.

## Detection 1 - RDP Connection

### Suricata

Signature ID:

```text
1000001
```

Signature:

```text
SOC LAB: RDP connection attempt detected
```

Traffic:

```text
192.168.100.20 -> 192.168.100.30:3389/TCP
```

Validated Suricata alert:

```text
Source:      192.168.100.20
Destination: 192.168.100.30:3389
Protocol:    TCP
SID:         1000001
Action:      allowed
```

The `allowed` action is expected because Suricata is operating as a passive IDS rather than an inline IPS.

### Wazuh

Custom Wazuh rule:

```xml
<rule id="100180" level="6">
  <if_sid>86601</if_sid>
  <field name="alert.signature_id">^1000001$</field>

  <description>SOC LAB: Suricata detected an RDP connection attempt from WIN10 to WINSERVER2022.</description>

  <group>suricata,ids,rdp,network_detection,soc_lab,</group>

  <mitre>
    <id>T1021.001</id>
  </mitre>
</rule>
```

Wazuh rule:

```text
100180
Level 6
```

MITRE ATT&CK:

```text
T1021.001 - Remote Desktop Protocol
Tactic: Lateral Movement
```

Validated detection chain:

```text
WIN10
  -> TCP SYN/3389
  -> enp0s9
  -> Suricata SID 1000001
  -> eve.json
  -> Wazuh 86601
  -> Wazuh 100180
```

Validated Wazuh alert:

```text
Rule:        100180
Level:       6
Source:      192.168.100.20
Destination: 192.168.100.30:3389
MITRE:       T1021.001
```

## Detection 2 - TCP Port Scan

### Suricata

Signature ID:

```text
1000002
Revision 2
```

Signature:

```text
SOC LAB: Possible TCP port scan detected
```

Detection threshold:

```text
10 TCP SYN attempts within 10 seconds
tracked by source IP
```

Source:

```text
192.168.100.20
```

Target:

```text
192.168.100.30
```

The controlled test generated connection attempts against multiple TCP ports on the Windows Server.

### Wazuh

Custom Wazuh rule:

```xml
<rule id="100185" level="8">
  <if_sid>86601</if_sid>
  <field name="alert.signature_id">^1000002$</field>

  <description>SOC LAB: Suricata detected a possible TCP port scan against WINSERVER2022.</description>

  <group>suricata,ids,network_scan,reconnaissance,soc_lab,</group>

  <mitre>
    <id>T1046</id>
  </mitre>
</rule>
```

Wazuh rule:

```text
100185
Level 8
```

MITRE ATT&CK:

```text
T1046 - Network Service Discovery
Tactic: Discovery
```

Validated detection chain:

```text
Multiple TCP SYN attempts
  -> enp0s9
  -> Suricata SID 1000002
  -> eve.json
  -> Wazuh 86601
  -> Wazuh 100185
```

Validated alerts included:

```text
192.168.100.20 -> 192.168.100.30:29
192.168.100.20 -> 192.168.100.30:39
```

Both generated:

```text
Rule:  100185
Level: 8
MITRE: T1046
```

## Detection Engineering Notes

The first implementation of the port scan rule used `detection_filter`.

Once the configured count was reached, subsequent qualifying SYN packets generated additional alerts, increasing alert volume.

The rule was changed to:

```text
threshold:type threshold,track by_src,count 10,seconds 10
```

With this configuration, the sensor produces approximately one alert for each group of ten qualifying connection attempts within the configured window.

This reduces unnecessary SIEM noise and provides better alert-volume control.

## Validation Status

- Passive packet capture: VALIDATED
- Dedicated monitoring interface: VALIDATED
- Promiscuous traffic visibility: VALIDATED
- AF_PACKET capture: VALIDATED
- RDP protocol visibility: VALIDATED
- Suricata custom rules: VALIDATED
- Suricata SID 1000001: VALIDATED
- Suricata SID 1000002 rev:2: VALIDATED
- EVE JSON output: VALIDATED
- fast.log alert output: VALIDATED
- Wazuh EVE JSON ingestion: VALIDATED
- Native Wazuh Suricata rule 86601: VALIDATED
- Wazuh rule 100180: VALIDATED
- Wazuh rule 100185: VALIDATED
- MITRE ATT&CK mapping: VALIDATED

## Current Network Detection Pipeline

```text
Network Traffic
      |
      v
VirtualBox Host-Only Network
      |
      v
enp0s9 - Passive Sensor
      |
      v
Suricata
      |
      v
eve.json
      |
      v
Wazuh
      |
      +---- Rule 100180 - RDP
      |
      +---- Rule 100185 - Port Scan
```

## Current SOC Visibility

The home lab now combines:

```text
Endpoint telemetry
       +
Windows authentication telemetry
       +
Network IDS telemetry
       |
       v
      Wazuh
```

This phase established passive network visibility and demonstrated the complete path from packet observation to custom SIEM detection.

