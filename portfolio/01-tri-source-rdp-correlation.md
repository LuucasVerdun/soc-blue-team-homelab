# SOC Case 001 — Tri-Source RDP Correlation

## Case Summary

**Severity:** High / Level 15  
**Status:** Closed  
**Verdict:** True Positive — Authorized Security Test  
**Source Host:** WIN10  
**Source IP:** 192.168.100.20  
**Target Host:** WINSERVER2022  
**Target IP:** 192.168.100.30  
**Affected Account:** Administrator

---

## Alert

Wazuh generated Rule `100210` after correlating:

- Suricata TCP port-scan telemetry;
- Zeek TCP/3389 connection metadata;
- repeated Windows RDP authentication failures;
- a successful Windows RDP logon.

Final alert:

```text
Rule: 100210
Level: 15
Description: SOC LAB: Tri-source correlation - Suricata reconnaissance, Zeek RDP network activity, and successful Windows RDP access after password guessing.
```

---

## Timeline

| Timestamp UTC | Rule | Source | Event |
|---|---:|---|---|
| 02:51:57 | 100185 | Suricata | Port scan from 192.168.100.20 to 192.168.100.30 |
| 02:51:59 | 100185 | Suricata | Additional thresholded scan alert |
| 02:52:45 | 100190 | Zeek | TCP connection to 192.168.100.30:3389 |
| 02:52:48 | 100190 | Zeek | Additional RDP connection metadata |
| 02:52:51 | 100170 | Windows/Wazuh | Repeated RDP authentication failures |
| 02:52:52 | 100190 | Zeek | Additional TCP/3389 connection |
| 02:52:57 | 100190 | Zeek | Additional TCP/3389 connection |
| 02:53:11 | 100190 | Zeek | Additional TCP/3389 connection |
| 02:53:17 | 100210 | Wazuh | Tri-source correlated incident |

---

## Investigation

### 1. Reconnaissance

Suricata detected a controlled TCP port-scan pattern from:

```text
192.168.100.20
```

to:

```text
192.168.100.30
```

This matched Wazuh Rule `100185`.

### 2. RDP Network Activity

Zeek independently observed multiple TCP connections from the same source host to:

```text
192.168.100.30:3389
```

This matched Wazuh Rule `100190`.

This telemetry confirms network activity against the RDP service, but does not by itself prove successful authentication.

### 3. Authentication Failures

Windows Security telemetry identified repeated RDP authentication failures against:

```text
Administrator
```

from:

```text
192.168.100.20
```

This generated Rule `100170`.

### 4. Successful Authentication

A successful RDP logon was then observed through Windows Security Event ID `4624`, Logon Type `10`.

The endpoint event provides the authentication evidence that network telemetry alone cannot provide.

### 5. Correlation

Wazuh correlated:

```text
Suricata reconnaissance
+
Zeek RDP activity
+
Windows authentication failures
+
Successful RDP logon
```

and generated:

```text
Rule 100210
Level 15
```

---

## MITRE ATT&CK

| Technique | Description |
|---|---|
| T1046 | Network Service Discovery |
| T1110.001 | Password Guessing |
| T1021.001 | Remote Desktop Protocol |
| T1078.003 | Local Accounts |

---

## Verdict

```text
TRUE POSITIVE
AUTHORIZED SECURITY TEST
```

The activity was generated intentionally in the home lab.

The detection logic correctly linked independent network and endpoint telemetry into a higher-confidence incident.

---

## Response Recommendation for Production

If the same activity were unexpected in a production environment:

1. validate whether the source IP is legitimate;
2. confirm whether the account owner initiated the RDP session;
3. contain or disable the account if compromise is suspected;
4. reset credentials;
5. restrict or block the source where appropriate;
6. review endpoint telemetry after the successful logon;
7. search for additional lateral movement;
8. escalate to SOC N2 / Incident Response if compromise cannot be excluded.

---

## Evidence

```text
cases/case-100210-tri-source-rdp-correlation.txt
docs/tri-source-rdp-correlation.md
wazuh/rules/local_rules.xml
```

---

## Analyst Skills Demonstrated

- alert triage;
- authentication analysis;
- RDP investigation;
- network telemetry analysis;
- Suricata analysis;
- Zeek analysis;
- Windows Event Log analysis;
- Wazuh correlation;
- timeline reconstruction;
- MITRE ATT&CK mapping;
- escalation reasoning;
- evidence preservation.

