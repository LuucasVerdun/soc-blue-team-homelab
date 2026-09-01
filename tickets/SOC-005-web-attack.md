# SOC-005 — HTTP Command Injection Attempt

## Ticket Summary

**Severity:** Medium / High investigative priority
**Detection:** Wazuh Rule `100215`, Level `10`
**Source:** Suricata SID `1000003`
**Classification:** TRUE POSITIVE
**Activity:** HTTP Command Injection Attempt
**Exploitation:** NOT CONFIRMED
**Compromise:** NOT ESTABLISHED

## Alert Details

- Source IP: `192.168.100.20`
- Destination IP: `192.168.100.30`
- Destination port: `80`
- Protocol: HTTP
- Method: `GET`
- URL: `/lab/?host=127.0.0.1%3Bwhoami&case=command-injection-test03`
- Decoded payload: `host=127.0.0.1;whoami`
- HTTP response: `200`
- Suricata action: `allowed`
- Suricata signature: `SOC LAB: Possible HTTP command injection attempt`
- Wazuh rule: `100215`
- Wazuh level: `10`

## Investigation

IIS confirmed that the request reached the web server from `192.168.100.20`.

Zeek recorded the same transaction and normalized the URI to:

`/lab/?host=127.0.0.1;whoami&case=command-injection-test03`

Suricata matched the `;whoami` pattern and generated SID `1000003`.

Wazuh ingested the Suricata event and elevated it through custom rule `100215`.

The target was a static IIS resource:

`C:\inetpub\wwwroot\lab\index.html`

No server-side application logic was configured to process the `host` parameter or invoke a shell.

Sysmon telemetry was unavailable. Windows Process Creation auditing was `No Auditing`, so the absence of Event ID `4688` cannot be treated as proof that no process executed.

## Analyst Conclusion

The alert is a **true positive for an HTTP command injection attempt**.

The available evidence does **not** establish successful execution of `whoami`, successful exploitation of the server, or host compromise.

## Disposition

**Closed — controlled lab simulation.**

For a production equivalent, validate server-side process telemetry and escalate if web-server child processes, shell execution, payload delivery, persistence, or other post-exploitation behavior is identified.
