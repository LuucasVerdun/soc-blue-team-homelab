# Case 05 — Web Attack Investigation Checklist

## Preparation

- [x] IIS installed and running on WINSERVER2022
- [x] TCP/80 listening
- [x] IIS access logging available
- [x] Static lab page created
- [x] Benign HTTP baseline generated
- [x] Baseline observed in IIS
- [x] Baseline observed in Zeek
- [x] Baseline observed in Suricata

## Suspicious Request

- [x] Controlled command-injection-like request generated
- [x] Payload used: `127.0.0.1;whoami`
- [x] Semicolon URL encoded as `%3B`
- [x] Unique case marker used

## Web Telemetry

- [x] Confirm source IP
- [x] Confirm destination IP and port
- [x] Confirm HTTP method
- [x] Confirm URI/query string
- [x] Confirm HTTP response code
- [x] Confirm user-agent
- [x] Compare encoded/raw and normalized URI representations

## Detection Engineering

- [x] Create Suricata SID `1000003`
- [x] Validate Suricata configuration with `suricata -T`
- [x] Confirm Suricata alert fires
- [x] Confirm EVE alert contains HTTP context
- [x] Confirm Wazuh ingests Suricata alert through rule `86601`
- [x] Create Wazuh rule `100215`
- [x] Confirm Wazuh level 10 alert

## Execution Validation

- [x] Check whether Sysmon telemetry is available
- [x] Check Windows Process Creation audit policy
- [x] Search available Security 4688 telemetry for `whoami.exe`
- [x] Verify target is a static HTML resource
- [x] Avoid treating missing telemetry as proof of non-execution

## Analyst Decision

- [x] Separate suspicious request from confirmed execution
- [x] Do not interpret HTTP 200 as successful exploitation
- [x] Do not interpret IDS `allowed` as successful exploitation
- [x] Classification: TRUE POSITIVE — HTTP Command Injection Attempt
- [x] Exploitation: NOT CONFIRMED
- [x] Host compromise: NOT ESTABLISHED
- [x] Document telemetry limitations

## Portfolio Deliverables

- [x] Portfolio investigation
- [x] SOC ticket
- [x] Evidence summary
- [x] Investigation checklist
- [ ] Copy current Suricata rule file into repository
- [ ] Copy current Wazuh local rule file into repository
- [ ] Update README featured cases
- [ ] Update PORTFOLIO index
- [ ] Run `git diff --check`
- [ ] Commit and push
