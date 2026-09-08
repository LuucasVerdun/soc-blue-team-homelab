# ESC-008 — SOC N1 to N2 Escalation Note

## Reason for Escalation

A Level 13 Wazuh multi-source correlation detected PowerShell file creation on WIN10 in temporal proximity to a successful HTTP file transfer observed by Suricata.

The behavior is suspicious enough to warrant deeper investigation because PowerShell was used as the HTTP client and wrote the transferred artifact into `C:\Users\Public`.

## Evidence Provided

- Endpoint: WIN10 / 192.168.100.20
- User: WIN10\vboxuser
- Process: `powershell.exe`
- Remote server: 192.168.100.30:80
- HTTP status: 200
- URL: `/lab/case08-benign.txt?case=case08-download-131955`
- Destination file: `C:\Users\Public\case08-filecreate-131955.txt`
- Wazuh 100240: PowerShell FileCreate
- Wazuh 100245: Suricata HTTP transfer
- Wazuh 100255: Level 13 multi-source correlation
- MITRE mapping: T1105 — Ingress Tool Transfer
- File SHA256: `C4608BED81A785FD3E155A2225519241833D371853B64BE43FB93277F219CCD9`

## What N1 Confirmed

- HTTP transfer occurred.
- HTTP response was successful.
- PowerShell was associated with the transfer.
- A file was written to the endpoint.
- Network and endpoint telemetry independently observed the behavior.
- Source and destination file hashes matched.

## What N1 Could Not Establish

- Whether the artifact is malicious.
- Whether the artifact was executed.
- Whether persistence was established.
- Whether credentials were accessed.
- Whether lateral movement occurred.
- Whether the endpoint was compromised.

## N2 Recommended Actions

1. Review PowerShell process ancestry and full command line.
2. Check whether the downloaded artifact was subsequently executed, renamed, moved, or deleted.
3. Review Sysmon ProcessCreate events around the transfer window.
4. Search for additional network connections initiated by the same PowerShell process or related processes.
5. Validate the file hash against organizational allowlists and reputation sources when applicable.
6. Review PowerShell Script Block Logging and other PowerShell Operational events.
7. Determine whether the activity was authorized by a user, administrator, automation, or change record.
8. Expand the timeline before and after the event for persistence, credential access, discovery, or lateral movement indicators.

## N1 Escalation Assessment

**Suspicious behavior confirmed; maliciousness not established. Escalation is justified based on the combination of PowerShell-based HTTP transfer, file creation in a public directory, and corroborating multi-source telemetry.**

## Lab Resolution

After escalation criteria were satisfied, the scenario was confirmed to be an authorized controlled simulation. The transferred artifact was a benign text file and no malicious execution or host compromise was established.
