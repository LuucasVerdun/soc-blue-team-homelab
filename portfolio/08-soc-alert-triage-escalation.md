# Case 08 — SOC Alert Triage and Escalation: HTTP File Transfer + PowerShell File Creation

## Objective

Demonstrate a realistic SOC N1 workflow in which an analyst receives a correlated alert, validates endpoint and network telemetry, determines what can and cannot be concluded from the evidence, and escalates the case without overclaiming malware or host compromise.

## Scenario

A controlled PowerShell session on WIN10 downloaded a benign text artifact from an IIS server on WINSERVER2022.

The activity generated telemetry across multiple layers:

- Suricata — HTTP transaction and file metadata
- Zeek — independent HTTP observation
- Sysmon — Event ID 11 FileCreate
- Wazuh — endpoint detection, network detection, and multi-source correlation

## Environment

| Component | Value |
|---|---|
| Endpoint | WIN10 |
| Endpoint IP | 192.168.100.20 |
| HTTP Server | WINSERVER2022 |
| Server IP | 192.168.100.30 |
| Wazuh Manager | soc01 |
| Sensor Interface | enp0s9 |
| Download Path | `C:\Users\Public\case08-filecreate-131955.txt` |
| Source Resource | `/lab/case08-benign.txt` |

## Detection Engineering

### Rule 100240 — Endpoint FileCreate

Rule 100240 is a child of native Wazuh Sysmon Rule 61613 and detects PowerShell-created controlled files matching the Case 08 filename pattern.

Validated event:

- Sysmon Event ID: 11
- Image: `powershell.exe`
- Target: `C:\Users\Public\case08-filecreate-131955.txt`
- Level: 8

### Rule 100245 — Suricata HTTP Transfer

Rule 100245 is a child of native Suricata HTTP Rule 86602.

It validates the controlled HTTP transaction:

- Source: `192.168.100.20`
- Destination: `192.168.100.30:80`
- Method: `GET`
- HTTP status: `200`
- URL pattern: `/lab/case08-benign.txt?case=case08-download-*`
- Level: 7

### Rules 100250 / 100255 — Symmetric Multi-Source Correlation

Endpoint and network events were observed arriving in different orders during testing.

To avoid relying on a deterministic ingestion sequence, two symmetric correlation branches were implemented:

- **100250** — network alert already matched, endpoint event arrives next.
- **100255** — endpoint alert already matched, network event arrives next.

`global_frequency` is used because the correlated alerts originate from different Wazuh agents.

The final validated production-style test fired **Rule 100255** at Level 13.

## Final Test Timeline

| UTC Timestamp | Rule / Source | Observation |
|---|---|---|
| 16:20:32.634 | Suricata HTTP | WIN10 requested the controlled file from WINSERVER2022; HTTP 200 |
| 16:20:33.615 | Wazuh 100240 / Sysmon | PowerShell-created file detected on WIN10 |
| 16:20:34.131 | Wazuh 100255 | Multi-source network + endpoint correlation |

Suricata later emitted a `fileinfo` event at 16:22:12.687 UTC showing:

- file: `/lab/case08-benign.txt`
- size: 100 bytes
- state: CLOSED
- gaps: false

## Artifact Integrity

Source file SHA256:

`C4608BED81A785FD3E155A2225519241833D371853B64BE43FB93277F219CCD9`

Downloaded file SHA256:

`C4608BED81A785FD3E155A2225519241833D371853B64BE43FB93277F219CCD9`

The hashes matched, proving that the artifact served by IIS and the file created on WIN10 were identical.

## SOC N1 Analysis

**Confirmed**

- PowerShell initiated HTTP activity.
- An HTTP GET was sent to the controlled IIS server.
- The server returned HTTP 200.
- A 100-byte text object was transferred.
- PowerShell created a file in `C:\Users\Public`.
- Network and endpoint telemetry independently observed the activity.
- Wazuh generated a successful Level 13 multi-source correlation.
- Source and downloaded file SHA256 values matched.

**Not established**

- Malware.
- Payload execution.
- Persistence caused by the downloaded artifact.
- Credential theft.
- Lateral movement.
- Host compromise.

## N1 Escalation Decision

In a production environment, unexpected PowerShell-based HTTP file transfer into `C:\Users\Public` is sufficiently suspicious to justify SOC N2 review when no authorized business context is immediately available.

The correct N1 boundary is to escalate the behavior for deeper investigation while explicitly stating that malicious content and execution have not been established.

## Disposition

**TRUE POSITIVE DETECTION — AUTHORIZED CONTROLLED SIMULATION**

The detection was valid because the observed behavior actually occurred. The laboratory context later established that the artifact was intentionally benign.

## MITRE ATT&CK

**T1105 — Ingress Tool Transfer**

This mapping is used as a controlled behavioral simulation. The laboratory transferred a benign text artifact rather than a malicious tool, so the portfolio does not claim confirmed adversary tool transfer.

## Key Learning

This case demonstrated that multi-source SIEM correlation must account for asynchronous event ingestion.

During testing, Suricata and Sysmon events arrived in different orders. Implementing symmetric correlation branches prevented the detection logic from depending on a single ingestion sequence.

The case also demonstrates an important SOC principle: a high-confidence suspicious behavior can justify escalation without proving malware or compromise.
