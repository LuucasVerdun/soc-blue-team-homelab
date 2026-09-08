# SOC-008 — HTTP File Transfer Followed by PowerShell File Creation

## Ticket Summary

**Status:** Escalated to SOC N2
**Severity:** High
**Disposition:** True Positive Detection — Authorized Controlled Simulation
**Primary Detection:** Wazuh Rule 100255
**MITRE ATT&CK:** T1105 — Ingress Tool Transfer (behavioral simulation)
**Endpoint:** WIN10 — 192.168.100.20
**Remote Host:** WINSERVER2022 — 192.168.100.30:80
**User:** WIN10\vboxuser

## Initial Alert

Wazuh generated a Level 13 multi-source correlation alert after PowerShell file creation on WIN10 was correlated with an HTTP file transfer observed by Suricata.

Final correlation:

- Rule 100240 — Level 8 — PowerShell-created file detected through Sysmon Event ID 11.
- Rule 100245 — Level 7 — Suricata observed a controlled HTTP GET with status 200.
- Rule 100255 — Level 13 — Multi-source correlation between the endpoint and network observations.

The final validated branch was Rule 100255. A symmetric Rule 100250 was also implemented to account for the opposite ingestion order, because earlier tests demonstrated that network and endpoint events could arrive in either order.

## Timeline

### Network transfer

**2026-09-08 16:20:32.634 UTC**

Suricata observed:

- Source: `192.168.100.20:49959`
- Destination: `192.168.100.30:80`
- Method: `GET`
- URL: `/lab/case08-benign.txt?case=case08-download-131955`
- User-Agent: `WindowsPowerShell/5.1.19041.6456`
- HTTP status: `200`
- Content-Type: `text/plain`
- Length: `100` bytes

Zeek independently observed the same HTTP transfer during validation.

### Endpoint file creation

**2026-09-08 16:20:33.615 UTC**

Wazuh Rule 100240 detected Sysmon Event ID 11:

- Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Target: `C:\Users\Public\case08-filecreate-131955.txt`
- User: `WIN10\vboxuser`

### Multi-source correlation

**2026-09-08 16:20:34.131 UTC**

Wazuh Rule 100255 generated a Level 13 alert:

> Multi-source correlation - PowerShell file creation on WIN10 correlated with an HTTP transfer observed by Suricata.

## File Integrity Validation

Downloaded artifact SHA256:

`C4608BED81A785FD3E155A2225519241833D371853B64BE43FB93277F219CCD9`

IIS source artifact SHA256:

`C4608BED81A785FD3E155A2225519241833D371853B64BE43FB93277F219CCD9`

The hashes matched, confirming that the object hosted by IIS and the artifact written to the endpoint were byte-for-byte identical.

Downloaded content:

```text
SOC CASE 08 BENIGN DOWNLOAD
Controlled SOC triage and escalation simulation.
No malicious content.
```

## SOC N1 Triage

### Confirmed

- HTTP file transfer occurred.
- The HTTP request returned status 200.
- PowerShell was used as the HTTP client.
- A file was written to `C:\Users\Public`.
- Sysmon Event ID 11 recorded the file creation.
- Suricata observed the HTTP transaction.
- Zeek independently observed the HTTP transaction.
- Wazuh correlated endpoint and network telemetry.
- The downloaded file matched the IIS source artifact by SHA256.

### Not Established

- Malicious file content.
- Execution of the downloaded artifact.
- Persistence caused by the downloaded artifact.
- Credential theft.
- Lateral movement.
- Host compromise.

## N1 Decision

**Escalate to SOC N2.**

In a production environment, an unexpected PowerShell process performing an HTTP transfer and writing a file to `C:\Users\Public`, supported by independent endpoint and network telemetry, provides sufficient suspicious context for escalation even when malicious content or payload execution has not yet been confirmed.

The N1 analyst should avoid classifying the file as malware based only on the transfer behavior.

## Final Disposition

**TRUE POSITIVE DETECTION — AUTHORIZED CONTROLLED SIMULATION**

The observed behavior genuinely occurred and the alert logic correctly detected it. The activity was intentionally generated as part of the SOC laboratory.

This case does **not** establish that malware was transferred or that the endpoint was compromised.

## MITRE ATT&CK Note

Rule 100255 is mapped to **T1105 — Ingress Tool Transfer** as a behavioral simulation of remote file transfer into an endpoint.

The transferred object in this laboratory was a benign text file, not an adversary tool. Therefore, the case should not claim that a malicious tool was transferred.
