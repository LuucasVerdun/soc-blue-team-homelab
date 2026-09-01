# SOC Analyst N1 Portfolio

## Lucas Souza

Blue Team / SOC-focused cybersecurity professional building practical experience through a hands-on home lab centered on alert triage, Windows telemetry, network monitoring, detection engineering, MITRE ATT&CK mapping, and multi-source investigation.

This portfolio is intentionally focused on the skills expected from a junior SOC analyst:

- alert triage;
- log analysis;
- Windows authentication analysis;
- endpoint investigation;
- network investigation;
- SIEM usage;
- IOC analysis;
- MITRE ATT&CK mapping;
- incident documentation;
- escalation decisions.

---

## Core SOC Skills

### SIEM / Detection

- Wazuh
- Custom detection rules
- Correlation rules
- Alert severity tuning
- Cross-agent correlation
- Multi-source incident correlation
- JSON log analysis with `jq`

### Endpoint

- Sysmon
- Windows Security Event Log
- PowerShell Script Block Logging
- Process creation analysis
- Parent/child process relationships
- Command-line analysis
- Process tree reconstruction

### Network

- Suricata
- Zeek
- RDP traffic analysis
- Port-scan detection
- DNS monitoring
- Connection metadata analysis
- Passive network monitoring

### Investigation

- Alert validation
- Timeline reconstruction
- Authentication analysis
- Password-guessing investigation
- Successful-logon correlation
- Account lockout investigation
- Network + endpoint correlation
- True-positive classification
- Authorized-test classification
- Evidence preservation

### Frameworks

- MITRE ATT&CK
- Cyber Kill Chain concepts
- SOC triage workflow

---

# Home Lab

## Architecture

```text
Windows 11 Host
      |
      v
VirtualBox
      |
      +-------------------------------+
      |               |               |
      v               v               v
   soc01            WIN10       WINSERVER2022
Ubuntu Server    192.168.100.20 192.168.100.30
192.168.100.10
      |
      +--> Wazuh
      +--> Suricata
      +--> Zeek
```

### SOC Server

```text
Hostname: soc01
OS: Ubuntu Server 24.04.4 LTS
Management IP: 192.168.100.10
```

Main components:

- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard
- Suricata
- Zeek
- Bash
- jq

### Windows Endpoints

```text
WIN10
192.168.100.20

WINSERVER2022
192.168.100.30
```

The Windows Server is used for RDP, authentication, account-lockout, and correlation scenarios.

---

# Featured Investigations

## 01 — Tri-Source RDP Correlation

**Status:** Validated
**Severity:** Level 15
**Classification:** True Positive — Authorized Security Test

### Scenario

A controlled sequence was generated from `WIN10` against `WINSERVER2022`:

```text
TCP port scan
      ↓
RDP connection activity
      ↓
Repeated RDP authentication failures
      ↓
Successful RDP logon
      ↓
Multi-source correlation
```

### Telemetry

- Suricata
- Zeek
- Windows Security Events
- Wazuh

### Detection Chain

```text
100185
Suricata TCP port scan
      ↓
100190
Zeek RDP connection metadata
      ↓
100170
Repeated RDP authentication failures
      ↓
Successful Windows RDP logon
      ↓
100205
Suricata + Windows correlation
      ↓
100210
Tri-source correlation
Level 15
```

### MITRE ATT&CK

- `T1046` — Network Service Discovery
- `T1110.001` — Password Guessing
- `T1021.001` — Remote Desktop Protocol
- `T1078.003` — Local Accounts

### Analyst Conclusion

The network reconnaissance, repeated RDP failures, RDP connection metadata, and successful RemoteInteractive logon were temporally correlated. Independent telemetry sources corroborated the same activity chain, increasing confidence beyond any individual alert.

### Recommended Response if Unauthorized

- validate whether the source IP is expected;
- disable or contain the affected account if compromise is suspected;
- reset credentials;
- block or restrict the source where appropriate;
- review activity after the successful logon;
- escalate to SOC N2 / Incident Response when compromise cannot be ruled out.

### Evidence

```text
cases/case-100210-tri-source-rdp-correlation.txt
docs/tri-source-rdp-correlation.md
```

---

## 02 — Suspicious PowerShell and Discovery Activity

**Status:** Validated
**Classification:** True Positive — Authorized Security Test

### Scenario

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

### Telemetry

- Sysmon
- PowerShell Logging
- Wazuh
- Windows process telemetry

### Detection Chain

```text
100110
PowerShell spawning cmd.exe
      ↓
100120
whoami discovery
      ↓
100130
Multi-command discovery sequence
```

### MITRE ATT&CK

- `T1059.003` — Windows Command Shell
- `T1033` — System Owner/User Discovery
- `T1016` — System Network Configuration Discovery
- `T1087.001` — Local Account Discovery

### Investigation Focus

- parent process;
- child process;
- process GUID;
- command line;
- execution user;
- integrity level;
- sequence of discovery commands.

### Analyst Conclusion

The command sequence is consistent with local discovery activity. In this lab it was intentionally generated and classified as an authorized true positive. In a production SOC, the same sequence would require user/process validation, review of surrounding activity, and escalation when unexpected.

### Evidence

```text
cases/case-100130-discovery.txt
docs/process-tree-investigation.md
scripts/process-tree.sh
```

---

## 03 — Phishing Email Investigation

**Status:** Validated
**Verdict:** True Positive — Controlled Phishing Simulation

### Scenario

A Microsoft 365-themed phishing sample was investigated using a SOC N1 triage workflow.

### Analysis Performed

- sender analysis;
- Return-Path and Reply-To comparison;
- Received header analysis;
- SPF / DKIM / DMARC validation;
- lookalike-domain identification;
- URL extraction;
- HTML attachment inspection;
- SHA256 calculation;
- IOC extraction;
- escalation decision.

### Key Findings

```text
Sender:
security-update@micros0ft-support.example

SPF:
fail

DKIM:
none

DMARC:
fail

URL:
https://login-microsoft365.example/verify
```

The attachment was not classified as malware based on the static checks performed.

### Evidence

```text
portfolio/03-phishing-investigation.md
tickets/SOC-003-phishing-ticket.md
phishing/case03/
```

---

## 04 — Suspicious File / Malware Triage

**Status:** Validated
**Verdict:** Benign Controlled Sample with Suspicious Static Indicators

### Scenario

An unsigned PowerShell file was triaged using a SOC N1 workflow combining static analysis, Authenticode validation, controlled execution, Sysmon telemetry, PowerShell Script Block Logging, and Wazuh alerts.

### Analysis Performed

- file type and size identification;
- SHA256, SHA1, and MD5 calculation;
- Authenticode signature validation;
- static string analysis;
- controlled PowerShell execution;
- Sysmon Event ID 1 analysis;
- Sysmon Event ID 11 analysis;
- PowerShell Event ID 4104 analysis;
- Wazuh alert interpretation;
- IOC / observable classification;
- escalation decision.

### Key Findings

```text
File:
invoice_security_update.ps1

SHA256:
c931381865e91f9f323d8133feaa71799e2567c7049feef47e3c426364b96e4a

Authenticode:
NotSigned

Wazuh:
92200 - File creation
92029 - PowerShell execution
91816 - Script Block content
```

The sample contained suspicious-looking strings such as a C2-style URL, IP address, Run-key path, `rundll32.exe`, and `EncodedCommand`, but these values were located inside PowerShell comments.

The controlled execution created only a harmless marker file.

### Key Analytical Lesson

```text
STRING MATCH != BEHAVIORAL EVIDENCE
```

A SIEM search can match strings stored inside script content or logs. Analysts must validate event type and field context before concluding that network communication, process execution, or persistence actually occurred.

### MITRE ATT&CK Context

- `T1059.001` — PowerShell (directly supported by process telemetry)
- Native Wazuh mappings such as `T1105` and `T1082` were reviewed in context rather than treated as automatic proof of malicious behavior.

### Evidence

```text
portfolio/04-suspicious-file-malware-triage.md
tickets/SOC-004-malware-triage.md
evidence/case04-evidence-summary.txt
malware/case04/
```

---

## 05 — Windows Password Guessing

**Status:** Validated

### Detection

```text
4625
Failed authentication
      ↓
100135
Wrong password for existing account
      ↓
100140
Repeated password guessing
```

### MITRE ATT&CK

- `T1110.001` — Password Guessing

### Investigation Focus

- source IP;
- target account;
- failure reason;
- number of attempts;
- timeframe;
- subsequent successful authentication.

### Evidence

```text
cases/case-100140-password-guessing.txt
```

---

## 06 — Successful Logon After Password Guessing

**Status:** Validated
**Severity:** High

### Detection Chain

```text
Repeated authentication failures
      ↓
100140
Password Guessing
      ↓
Successful network logon
      ↓
100150
Success After Password Guessing
```

### Investigation Focus

- confirm same source IP;
- confirm same target user;
- identify the successful logon type;
- review subsequent endpoint activity;
- determine whether the successful authentication was expected.

### Evidence

```text
cases/case-100150-success-after-password-guessing.txt
```

---

## 07 — Account Lockout After Password Guessing

**Status:** Validated

### Detection Chain

```text
Password Guessing
      ↓
Windows Event 4740
      ↓
Account Lockout
      ↓
100155
```

### MITRE ATT&CK

- `T1110.001` — Password Guessing
- `T1531` — Account Access Removal

### Evidence

```text
cases/case-100155-account-lockout-after-password-guessing.txt
```

---

## 08 — DNS Beacon-Like Activity

**Status:** Validated in controlled lab scenario

### Scenario

Repeated DNS queries were generated for a controlled indicator:

```text
soc-lab-beacon.example
```

### Telemetry

- Zeek `dns.log`
- Wazuh

### Detection Chain

```text
100195
Controlled suspicious DNS query
      ↓
4 events / 15 seconds
same source
same query
      ↓
100200
Beacon-like DNS activity
```

### MITRE ATT&CK

- `T1071.004` — DNS

### Analyst Interpretation

Repeated DNS requests with a regular pattern can be consistent with beaconing, but the DNS pattern alone does not prove malicious command-and-control activity. Endpoint and process context are required before making that conclusion.

### Evidence

```text
cases/case-100195-zeek-dns-query.txt
cases/case-100200-zeek-dns-beacon-like.txt
docs/zeek-network-monitoring.md
```

---

# SOC Workflow Demonstrated

The investigations in this repository follow a practical SOC workflow:

```text
Alert
  ↓
Validate source
  ↓
Validate destination
  ↓
Identify affected user / host / process
  ↓
Review preceding events
  ↓
Review subsequent events
  ↓
Correlate endpoint and network telemetry
  ↓
Map behavior to MITRE ATT&CK
  ↓
Determine confidence
  ↓
Classify
  ↓
Recommend response / escalation
```

---

# Detection Coverage

| Area | Status |
|---|---|
| Windows Security Events | Validated |
| Sysmon | Validated |
| PowerShell Logging | Validated |
| Process Tree Analysis | Validated |
| Password Guessing | Validated |
| Successful Logon Correlation | Validated |
| Account Lockout | Validated |
| RDP Monitoring | Validated |
| Suricata IDS | Validated |
| Zeek NSM | Validated |
| Port Scan Detection | Validated |
| DNS Monitoring | Validated |
| Multi-Source Correlation | Validated |
| MITRE ATT&CK Mapping | Validated |
| Incident Documentation | Validated |
| Phishing Investigation | Validated |
| Malware Triage | Validated |
| Web Attack Investigation | Planned |

---

# Tools

## SIEM / Monitoring

- Wazuh
- Sysmon
- Windows Event Viewer
- PowerShell Logging

## Network

- Suricata
- Zeek
- Wireshark

## Analysis

- jq
- Bash
- PowerShell
- VirusTotal
- MITRE ATT&CK

## Infrastructure

- VirtualBox
- Ubuntu Server
- Windows 10
- Windows Server 2022

---

# Repository Navigation

For recruiters and SOC hiring managers, the recommended order is:

```text
1. PORTFOLIO.md
2. docs/tri-source-rdp-correlation.md
3. cases/case-100210-tri-source-rdp-correlation.txt
4. docs/process-tree-investigation.md
5. docs/windows-authentication-monitoring.md
6. docs/suricata-network-monitoring.md
7. docs/zeek-network-monitoring.md
```

The full `README.md` contains the detailed technical build and implementation history.

---

# Current Focus

The next portfolio scenarios are intentionally aligned with common SOC N1 responsibilities:

1. Web attack investigation
2. DNS investigation with endpoint-process correlation
3. Additional SOC ticket and escalation scenarios
4. Post-compromise endpoint investigation
5. Expand malware triage with reputation and sandbox analysis

---

# Repository

```text
https://github.com/LuucasVerdun/soc-blue-team-homelab
```

---

# Disclaimer

All activity documented in this repository was performed in a controlled and authorized lab environment for defensive cybersecurity training, detection engineering, threat hunting, and SOC practice.

