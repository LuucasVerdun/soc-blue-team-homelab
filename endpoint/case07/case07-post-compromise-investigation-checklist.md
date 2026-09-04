# Case 07 — Post-Compromise Endpoint Investigation Checklist

## Telemetry Preparation

- [x] Confirm Wazuh agent is active on WIN10
- [x] Confirm Sysmon Operational log is enabled
- [x] Confirm Sysmon Event ID 1 process creation telemetry
- [x] Enable Task Scheduler Operational log
- [x] Add Task Scheduler Operational channel to Wazuh agent collection
- [x] Confirm Wazuh agent remains active after configuration change
- [x] Identify native Wazuh Task Scheduler rule `67014`

## Controlled Activity

- [x] Start from elevated PowerShell
- [x] Execute controlled discovery commands
- [x] Register `SOC-LAB-CASE07`
- [x] Execute Scheduled Task
- [x] Create benign marker file
- [x] Confirm marker contents
- [x] Confirm `LastTaskResult = 0`

## Detection Validation

- [x] Validate `100130` / Level 12
- [x] Validate Task Scheduler Event ID 106
- [x] Validate native Wazuh `67014`
- [x] Create and validate `100230` / Level 13
- [x] Confirm Sysmon task-driven `cmd.exe`
- [x] Confirm Task Scheduler service parent context
- [x] Create and validate `100235` / Level 15
- [x] Save three-event Wazuh correlation evidence

## Analyst Assessment

- [x] Discovery activity confirmed
- [x] Scheduled Task registration confirmed
- [x] Task execution confirmed
- [x] Payload identified as benign controlled marker
- [x] Do not claim malicious persistence
- [x] Do not claim endpoint compromise
- [x] Map relevant ATT&CK techniques
- [x] Document analytical limitations

## Repository Tasks

- [ ] Add professional portfolio case
- [ ] Add SOC ticket
- [ ] Add evidence summary
- [ ] Add investigation checklist
- [x] Save raw JSONL evidence
- [ ] Sync Wazuh rules
- [ ] Update README
- [ ] Update PORTFOLIO.md
- [ ] Run `git diff --check`
- [ ] Stage reviewed files
- [ ] Commit and push
