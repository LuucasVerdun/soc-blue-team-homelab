# Tri-Source RDP Correlation — Suricata + Zeek + Windows + Wazuh

## Overview

This case documents a controlled multi-source detection scenario in the SOC Home Lab. The same activity chain was observed by three independent telemetry sources and correlated in Wazuh:

- **Suricata** — network reconnaissance / TCP port scan
- **Zeek** — RDP network connection metadata
- **Windows Security Events** — repeated RDP authentication failures followed by a successful RDP logon
- **Wazuh** — correlation of the above events into a Level 15 tri-source incident

The objective was to move beyond isolated alerts and validate a realistic SOC-style investigation in which different sensors corroborate the same attack sequence.

---

## Lab Context

| System | IP | Role |
|---|---:|---|
| WIN10 | 192.168.100.20 | Source / controlled test endpoint |
| WINSERVER2022 | 192.168.100.30 | RDP target |
| soc01 | 192.168.100.10 | Wazuh Manager + Suricata + Zeek |

Suricata and Zeek monitor the dedicated passive interface `enp0s9` on the lab network `192.168.100.0/24`.

---

## Detection Chain

```text
WIN10
192.168.100.20
      |
      | Controlled TCP port scan
      v
Suricata
Rule 100185
T1046 - Network Service Discovery
      |
      | RDP connection attempts
      v
Zeek
Rule 100190
TCP/3389 metadata
T1021.001 - Remote Desktop Protocol
      |
      | Repeated authentication failures
      v
Windows Security Events / Wazuh
Rule 100170
T1110.001 - Password Guessing
T1021.001 - Remote Desktop Protocol
      |
      | Successful RDP logon
      v
Rule 100205
Suricata + Windows correlation
      |
      | Previous Zeek RDP telemetry also present
      v
Rule 100210
TRI-SOURCE CORRELATION
LEVEL 15
```

---

## Validated Timeline

The final controlled test was performed on 2026-09-01.

| Timestamp (UTC) | Rule | Source | Observation |
|---|---:|---|---|
| 02:51:57 | 100185 | Suricata | Possible TCP port scan from 192.168.100.20 to 192.168.100.30 |
| 02:51:59 | 100185 | Suricata | Additional thresholded port-scan alert |
| 02:52:45 | 100190 | Zeek | TCP connection from 192.168.100.20 to 192.168.100.30:3389 |
| 02:52:48 | 100190 | Zeek | Additional RDP network connection metadata |
| 02:52:51 | 100170 | Windows/Wazuh | Repeated RDP authentication failures against Administrator from 192.168.100.20 |
| 02:52:52 | 100190 | Zeek | Additional TCP/3389 connection |
| 02:52:57 | 100190 | Zeek | Additional TCP/3389 connection |
| 02:53:11 | 100190 | Zeek | Additional TCP/3389 connection |
| 02:53:17 | 100210 | Wazuh correlation | Tri-source correlated incident, Level 15 |

The final alert was:

```text
Rule: 100210
Level: 15
Agent: WINSERVER2022
User: Administrator
Source IP: 192.168.100.20
Description: SOC LAB: Tri-source correlation - Suricata reconnaissance, Zeek RDP network activity, and successful Windows RDP access after password guessing.
```

---

## Relevant Rules

### Rule 100185 — Suricata Port Scan

Purpose:

- Detect controlled TCP reconnaissance from WIN10 against WINSERVER2022.
- Provide network-layer evidence of service discovery.

MITRE ATT&CK:

```text
T1046 - Network Service Discovery
```

### Rule 100190 — Zeek RDP Connection Metadata

Purpose:

- Detect TCP connection metadata between WIN10 and WINSERVER2022 on destination port 3389.
- Provide independent network-session context for the RDP activity.

MITRE ATT&CK:

```text
T1021.001 - Remote Desktop Protocol
```

A Zeek TCP/3389 event proves that Zeek observed traffic to the RDP service. It does not, by itself, prove that authentication succeeded.

### Rule 100170 — Repeated RDP Authentication Failures

Purpose:

- Correlate repeated Windows authentication failures associated with RDP.
- Detect password-guessing activity against the same Windows account from the same source IP.

MITRE ATT&CK:

```text
T1021.001 - Remote Desktop Protocol
T1110.001 - Password Guessing
```

Validated account: `Administrator`

Validated source: `192.168.100.20`

### Rule 100205 — Suricata + Windows Correlation

Purpose:

- Correlate a previous Suricata port-scan alert with a successful RDP logon following password guessing.
- Bridge network reconnaissance and endpoint authentication telemetry.

Relevant logic:

```xml
<if_sid>100175</if_sid>
<if_matched_sid>100185</if_matched_sid>
<global_frequency />
```

`global_frequency` is needed because relevant events are processed under different Wazuh agents:

```text
Suricata -> agent 000 / soc01
Windows  -> agent 002 / WINSERVER2022
```

### Rule 100210 — Tri-Source Correlation

Validated rule:

```xml
<rule id="100210" level="15" timeframe="300">
  <if_sid>100205</if_sid>
  <if_matched_sid>100190</if_matched_sid>

  <global_frequency />

  <field name="win.eventdata.ipAddress">^192\.168\.100\.20$</field>

  <description>SOC LAB: Tri-source correlation - Suricata reconnaissance, Zeek RDP network activity, and successful Windows RDP access after password guessing.</description>

  <group>correlation,multi_source,suricata,zeek,windows,rdp,reconnaissance,credential_access,lateral_movement,soc_lab,</group>

  <mitre>
    <id>T1046</id>
    <id>T1110.001</id>
    <id>T1021.001</id>
    <id>T1078.003</id>
  </mitre>
</rule>
```

MITRE ATT&CK:

```text
T1046     - Network Service Discovery
T1110.001 - Password Guessing
T1021.001 - Remote Desktop Protocol
T1078.003 - Local Accounts
```

---

## Why Rule 100205 Did Not Appear Separately in the Final Test

The final tri-source run emitted Rule 100210 as the final alert for the successful RDP event.

The rule chain is:

```text
100175
  -> 100205
       -> 100210
```

The event can satisfy intermediate correlation logic and then match the more specific child rule. Therefore, absence of a separate 100205 line in the final execution does not mean the 100205 logic failed.

---

## Why This Detection Is Multi-Source

Suricata answers whether reconnaissance occurred before the RDP activity.

Zeek independently confirms that TCP connections to the RDP service were observed.

Windows Security Events provide endpoint-side evidence of authentication failures and the eventual successful RemoteInteractive/RDP logon, including account and source IP context.

Wazuh correlates these observations into a single higher-confidence incident.

---

## Detection Engineering Interpretation

The individual events have different levels of certainty:

- A TCP port scan indicates reconnaissance but does not prove compromise.
- A TCP/3389 connection indicates RDP network activity but does not prove successful authentication.
- Repeated authentication failures indicate password guessing.
- Windows Event ID 4624 with Logon Type 10 provides endpoint-side evidence of a successful RDP logon.
- Correlating the above signals increases confidence because the sequence is corroborated by independent telemetry sources.

The resulting Rule 100210 therefore represents a higher-confidence incident than any individual network alert alone.

---

## Evidence

Raw evidence:

```text
cases/case-100210-tri-source-rdp-correlation.txt
```

The evidence file contains nine JSON alert records from the final controlled test window.

---

## Result

The lab successfully demonstrated a controlled correlated incident involving:

```text
Suricata
+
Zeek
+
Windows Security Events
+
Wazuh correlation
```

Final validated alert:

```text
Rule 100210
Level 15
Tri-source correlation
```

This phase demonstrates a progression from isolated detections to a multi-source SOC investigation in which reconnaissance, network-service activity, authentication failures, and successful remote access are linked into a single incident timeline.

