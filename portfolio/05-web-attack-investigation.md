# Case 05 — Web Attack Investigation

## Executive Summary

A controlled HTTP request containing a command-injection-like payload was sent from `WIN10` (`192.168.100.20`) to an IIS web server on `WINSERVER2022` (`192.168.100.30:80`).

The request contained `host=127.0.0.1;whoami`. The semicolon appeared URL-encoded as `%3B` in IIS and Suricata telemetry, while Zeek exposed the normalized URI with `;`.

The activity was detected by Suricata SID `1000003` and elevated by Wazuh custom rule `100215` at level 10.

**Final classification:** TRUE POSITIVE — HTTP Command Injection Attempt
**Exploitation status:** NOT CONFIRMED
**Host compromise:** NOT ESTABLISHED

The target was a static HTML resource. No server-side logic was configured to pass the `host` parameter to a command interpreter. Sysmon telemetry was unavailable and Windows Process Creation auditing was disabled, so the investigation does not claim definitive proof that `whoami.exe` never executed. The supported conclusion is that no evidence of server-side command execution was identified in the telemetry collected.

## Environment

| Component | Role | Address |
|---|---|---|
| WIN10 | Controlled request source | `192.168.100.20` |
| WINSERVER2022 | IIS web server | `192.168.100.30:80` |
| soc01 | Suricata, Zeek, Wazuh | `192.168.100.10` |

Target resource:

`C:\inetpub\wwwroot\lab\index.html`

Content:

`<html><body><h1>SOC Web Lab</h1><p>Controlled HTTP test page.</p></body></html>`

## Baseline Validation

A benign request was generated first:

`GET /lab/?host=127.0.0.1`

It was observed by IIS, Zeek, and Suricata with HTTP status `200`. This confirmed the monitoring path before the suspicious test.

## Suspicious Request

Controlled request:

`GET /lab/?host=127.0.0.1%3Bwhoami&case=command-injection-test03`

Decoded logical parameter:

`host=127.0.0.1;whoami`

Source: `192.168.100.20`
Destination: `192.168.100.30:80`
HTTP response: `200`

HTTP `200` means the requested resource was served successfully. It does not establish that `whoami` executed.

## IIS Evidence

IIS recorded:

- Timestamp: `2026-09-01 15:15:56 UTC`
- Server IP: `192.168.100.30`
- Method: `GET`
- URI: `/lab/`
- Query: `host=127.0.0.1%3Bwhoami&case=command-injection-test03`
- Client IP: `192.168.100.20`
- Status: `200`

Relevant record:

`2026-09-01 15:15:56 192.168.100.30 GET /lab/ host=127.0.0.1%3Bwhoami&case=command-injection-test03 80 - 192.168.100.20 ... 200 0 0 43`

This confirms that the suspicious request reached IIS.

## Zeek Evidence

Zeek recorded:

- Source: `192.168.100.20:50108`
- Destination: `192.168.100.30:80`
- Method: `GET`
- URI: `/lab/?host=127.0.0.1;whoami&case=command-injection-test03`
- Status: `200`
- User-Agent: Windows PowerShell 5.1

Normalization difference:

- IIS / Suricata: `%3Bwhoami`
- Zeek: `;whoami`

This demonstrates why analysts should understand encoded/raw and normalized HTTP representations.

## Suricata Detection

Custom signature:

```text
alert http 192.168.100.20 any -> 192.168.100.30 80 (msg:"SOC LAB: Possible HTTP command injection attempt"; flow:established,to_server; http.uri; content:"|3b|whoami"; nocase; sid:1000003; rev:1;)
```

Suricata generated:

- SID: `1000003`
- Signature: `SOC LAB: Possible HTTP command injection attempt`
- Source: `192.168.100.20:50108`
- Destination: `192.168.100.30:80`
- Method: `GET`
- Status: `200`
- Action: `allowed`

`action: allowed` means the IDS detected but did not block the request. It does not indicate exploitation success.

## Wazuh Detection

Suricata EVE alerts were ingested through Wazuh rule `86601`.

Custom rule:

```xml
<rule id="100215" level="10">
  <if_sid>86601</if_sid>
  <field name="alert.signature_id">^1000003$</field>
  <description>SOC LAB: Suricata detected a possible HTTP command injection attempt against WINSERVER2022.</description>
  <group>suricata,ids,http,web_attack,command_injection,soc_lab,</group>
</rule>
```

Final Wazuh alert:

- Rule ID: `100215`
- Level: `10`
- Agent: `000 / soc01`
- Source IP: `192.168.100.20`
- Destination IP: `192.168.100.30`
- Destination port: `80`
- Suricata SID: `1000003`
- Method: `GET`
- URL: `/lab/?host=127.0.0.1%3Bwhoami&case=command-injection-test03`
- HTTP status: `200`
- IDS action: `allowed`

## Execution Validation

Sysmon was not available on `WINSERVER2022`.

Windows audit policy:

`Process Creation    No Auditing`

A search for Security Event ID `4688` containing `whoami.exe` returned no result. Because Process Creation auditing was disabled, that absence cannot be treated as proof that the process did not execute.

The tested endpoint was a static `.html` file, and no server-side application logic was configured to consume the `host` parameter and invoke a shell.

Supported conclusion:

**No evidence of server-side command execution was identified in the telemetry collected during the investigation.**

## Analyst Assessment

**Classification:** TRUE POSITIVE — HTTP Command Injection Attempt

The request genuinely contained a command-injection-like sequence (`;whoami`), and the IDS correctly detected it.

**Exploitation:** NOT CONFIRMED

The evidence establishes an attempted injection pattern, not successful command execution.

**Compromise:** NOT ESTABLISHED

No collected evidence established shell execution, payload execution, persistence, or post-exploitation activity.

## SOC N1 Decision

**Disposition:** Closed — controlled lab simulation.

In production, validate whether the targeted endpoint passes user-controlled input to an operating-system command. Review application logs, EDR/Sysmon process creation telemetry, child processes of the web server, subsequent network connections, file activity, authentication events, and persistence indicators.

Escalate if server-side execution or post-exploitation behavior is identified.

## Key Lessons

1. A suspicious HTTP payload proves an **attempt**, not successful execution.
2. HTTP `200` does not prove command execution.
3. Suricata `action: allowed` means detection without blocking.
4. URI normalization can change how the same payload appears across telemetry sources.
5. Missing process telemetry limits confidence in negative execution findings.
6. SOC analysis must distinguish observed content, detected behavior, and confirmed execution.

## Final Verdict

**TRUE POSITIVE — HTTP Command Injection Attempt**
**Successful exploitation:** Not confirmed
**Host compromise:** Not established
