# Case 06 — DNS + Endpoint Correlation Checklist

## Validation

- [x] Sysmon Event ID 22 enabled
- [x] Wazuh agent active on WIN10
- [x] Unique lab FQDN used
- [x] PowerShell PID matched Sysmon Event 22 PID
- [x] Zeek observed same FQDN
- [x] A and AAAA DNS activity observed
- [x] Wazuh `100220` validated
- [x] Wazuh `100195` / `100200` detection logic validated
- [x] Wazuh `100225` multi-source correlation validated
- [x] Source IP confirmed
- [x] Destination IP/port confirmed
- [x] C2 not overclaimed
- [x] Host compromise not overclaimed

## Final Classification

**TRUE POSITIVE — Suspicious Repeated DNS Activity with Endpoint Process Attribution**

- Process attribution: PowerShell PID 1052
- C2 activity: NOT CONFIRMED
- Host compromise: NOT ESTABLISHED

## Repository Tasks

- [ ] Copy current Wazuh rules into repository
- [ ] Update README
- [ ] Update PORTFOLIO.md
- [ ] Add portfolio case
- [ ] Add SOC ticket
- [ ] Add evidence summary
- [ ] Run `git diff --check`
- [ ] Commit and push
