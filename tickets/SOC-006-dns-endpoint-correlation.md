# SOC-006 — Repeated DNS Activity with Endpoint Process Attribution

## Summary

**Severity:** High investigative priority
**Final detection:** Wazuh `100225`, Level 13
**Endpoint detection:** Wazuh `100220`, Level 8
**Classification:** TRUE POSITIVE
**C2:** NOT CONFIRMED
**Compromise:** NOT ESTABLISHED

## Alert Details

- Endpoint: `WIN10`
- Endpoint IP: `192.168.100.20`
- DNS destination: `192.168.100.30:53/UDP`
- Query: `case06-final-011757.soc-lab-beacon.example`
- Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- PID: `1052`
- User: `WIN10\vboxuser`
- Sysmon Event ID: `22`
- Final Wazuh rule: `100225`

## Investigation

Sysmon Event ID 22 attributed the controlled DNS query to PowerShell PID `1052`. The active PowerShell session PID was also `1052`.

Zeek independently observed repeated A and AAAA DNS queries from `192.168.100.20` to `192.168.100.30:53` for the same FQDN.

Wazuh correlated endpoint attribution and repeated network DNS activity through rule `100225`.

## Conclusion

**TRUE POSITIVE — Suspicious Repeated DNS Activity with Endpoint Process Attribution**

C2 activity was not confirmed and host compromise was not established.

## Disposition

**Closed — authorized lab simulation.**

In production, investigate the responsible process, process ancestry, domain reputation, DNS periodicity, subsequent network activity, and signs of post-exploitation before deciding whether to escalate.
