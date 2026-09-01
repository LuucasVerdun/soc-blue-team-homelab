# SOC-003 — Suspected Phishing Email

## Ticket Information

**Category:** Email Security / Phishing  
**Severity:** Medium  
**Status:** Closed  
**Verdict:** True Positive — Controlled Phishing Simulation

## Affected User

```text
employee@example.internal
```

## Alert Summary

A Microsoft 365-themed email was reported for analysis.

The message attempted to create urgency around password expiration and contained a login-themed URL.

## Key Evidence

```text
From:
security-update@micros0ft-support.example

Return-Path:
billing@mailer.example

Reply-To:
helpdesk-reset@account-security.example

Source IP:
203.0.113.77

SPF:
fail

DKIM:
none

DMARC:
fail

URL:
https://login-microsoft365.example/verify

Attachment:
Security_Update.html

SHA256:
2911bdd0e3dcc2a3e5b9a8f341febd1c8237191bb7f6b1258d19f42c092c2a30
```

## Analysis

The sender domain uses `micros0ft`, with the number zero replacing the letter `o`, which is consistent with a lookalike-domain pattern.

The `From`, `Return-Path`, and `Reply-To` fields use different domains.

The sample Authentication-Results header reports SPF failure, no DKIM signature, and DMARC failure.

The message and HTML attachment both contain the same login-themed URL.

Static inspection of the HTML attachment found the password-themed lure and hyperlink but did not identify JavaScript, PowerShell, cmd.exe, iframe, or HTML form indicators in the checks performed.

## Verdict

```text
True Positive
Controlled Phishing Simulation
```

The attachment should not be described as confirmed malware based on the evidence collected.

## Recommended Actions

If observed in production:

- quarantine the message;
- search for additional recipients;
- block the sender/domain/URL where appropriate;
- identify click activity;
- review endpoint, DNS, proxy, and authentication telemetry;
- reset credentials if credential submission is suspected;
- escalate if user interaction or compromise is confirmed.

## Closure Reason

Authorized controlled SOC training sample. No live malicious infrastructure was involved.

