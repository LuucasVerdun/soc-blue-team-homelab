# Case 08 — SOC N1 Triage & Escalation Checklist

## Alert Validation

- [x] Confirm Wazuh Rule 100240 fired from Sysmon Event ID 11.
- [x] Confirm PowerShell was the creating process.
- [x] Confirm controlled file was written to `C:\Users\Public`.
- [x] Confirm Suricata observed the HTTP GET.
- [x] Confirm HTTP status 200.
- [x] Confirm Wazuh Rule 100245 fired from native Suricata HTTP Rule 86602.
- [x] Confirm Level 13 multi-source correlation fired.
- [x] Confirm final validated correlation branch: Rule 100255.

## Network Context

- [x] Source endpoint identified as 192.168.100.20.
- [x] Destination server identified as 192.168.100.30:80.
- [x] PowerShell User-Agent observed.
- [x] Suricata HTTP telemetry reviewed.
- [x] Suricata fileinfo telemetry reviewed.
- [x] Zeek HTTP telemetry independently validated.

## Artifact Validation

- [x] Downloaded artifact located.
- [x] SHA256 calculated on WIN10.
- [x] SHA256 calculated on WINSERVER2022.
- [x] Hashes matched.
- [x] Artifact content confirmed benign in the controlled scenario.

## Analyst Boundary

- [x] Do not claim malware based solely on HTTP transfer.
- [x] Do not claim execution without ProcessCreate or equivalent evidence.
- [x] Do not claim compromise without supporting evidence.
- [x] State confirmed behavior separately from unproven impact.
- [x] Escalate suspicious behavior with evidence to N2.

## Final Disposition

- [x] N1 decision: ESCALATE TO SOC N2.
- [x] Lab disposition: TRUE POSITIVE DETECTION — AUTHORIZED CONTROLLED SIMULATION.
- [x] MITRE T1105 documented as a behavioral simulation, not confirmed adversary tool transfer.

## Detection Engineering Lesson

- [x] Confirmed that multi-source events can arrive in different orders.
- [x] Implemented symmetric correlation paths 100250 / 100255.
- [x] Validated Rule 100255 in the final run.
- [x] Documented correlation limitation: Wazuh does not directly compare the numeric token embedded in the URL against the token embedded in the endpoint filename.
