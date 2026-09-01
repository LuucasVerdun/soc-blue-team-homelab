# SOC Case 03 — Phishing Email Investigation

## Case Summary

**Alert Type:** Suspected Phishing Email  
**Status:** Closed  
**Verdict:** True Positive — Controlled Phishing Simulation  
**Severity:** Medium  
**Recipient:** employee@example.internal  
**Sender Display Name:** Microsoft 365 Security  
**Sender Address:** security-update@micros0ft-support.example  
**Subject:** URGENT: Your Microsoft 365 password expires today

---

## Executive Summary

A controlled phishing-style email was analyzed as part of the SOC Analyst N1 portfolio.

The message contained multiple indicators commonly associated with phishing:

- lookalike sender domain using `micros0ft` instead of `microsoft`;
- mismatch between `From`, `Return-Path`, and `Reply-To`;
- SPF failure;
- no DKIM signature;
- DMARC failure;
- urgency-based password-expiration lure;
- link to a separate login-themed domain;
- HTML attachment containing the same link.

The attachment itself did not contain JavaScript, PowerShell, `cmd.exe`, iframe, or HTML form indicators in the performed static grep check. The observed HTML content acted as a lure that directed the user to the supplied URL.

Because the sample is intentionally controlled, all domains use reserved `.example` namespaces and the source IP is from TEST-NET-3.

---

## Email Metadata

### From

```text
Microsoft 365 Security <security-update@micros0ft-support.example>
```

### To

```text
SOC Lab User <employee@example.internal>
```

### Subject

```text
URGENT: Your Microsoft 365 password expires today
```

### Return-Path

```text
<billing@mailer.example>
```

### Reply-To

```text
helpdesk-reset@account-security.example
```

### Received

```text
from unknown-host.example (unknown-host.example [203.0.113.77])
by mail.example.internal with ESMTP id LAB20260901
for <employee@example.internal>;
Tue, 01 Sep 2026 03:10:00 +0000
```

### Authentication-Results

```text
spf=fail smtp.mailfrom=micros0ft-support.example
dkim=none
dmarc=fail header.from=micros0ft-support.example
```

---

## Header Analysis

### Sender Domain

Observed sender domain:

```text
micros0ft-support.example
```

The string `micros0ft` uses the digit `0` in place of the letter `o`.

This is consistent with a lookalike / typosquatting-style naming pattern intended to resemble Microsoft branding.

### Identity Mismatch

The message uses different domains across key identity fields:

```text
From:
micros0ft-support.example

Return-Path:
mailer.example

Reply-To:
account-security.example
```

This mismatch is a significant phishing indicator and should trigger further investigation in a production SOC.

---

## Email Authentication Analysis

### SPF

```text
spf=fail
```

Interpretation:

The message failed the SPF validation represented in the sample header.

### DKIM

```text
dkim=none
```

Interpretation:

No DKIM signature was present in the sample.

### DMARC

```text
dmarc=fail
```

Interpretation:

The message failed the DMARC result represented in the sample header.

### Analyst Assessment

The combination:

```text
SPF fail
+
DKIM none
+
DMARC fail
```

substantially increases suspicion when combined with the sender-domain lookalike and identity mismatches.

---

## Social Engineering Indicators

The subject line uses urgency:

```text
URGENT: Your Microsoft 365 password expires today
```

The message theme attempts to pressure the recipient into taking immediate action related to account access.

This is a common social-engineering pattern because password expiration and account suspension themes can cause users to act before validating the message.

---

## URL Analysis

The same URL was found in both the email and the HTML attachment:

```text
https://login-microsoft365.example/verify
```

Observed domain:

```text
login-microsoft365.example
```

The URL uses a login-themed domain intended to appear related to Microsoft 365.

In this controlled sample, `.example` is a reserved namespace and therefore no external reputation or live-site interaction is required.

---

## Attachment Analysis

Attachment:

```text
Security_Update.html
```

SHA256:

```text
2911bdd0e3dcc2a3e5b9a8f341febd1c8237191bb7f6b1258d19f42c092c2a30
```

Static content checks identified:

```text
password
href=
```

Observed HTML link:

```text
https://login-microsoft365.example/verify
```

The performed grep check did not find:

```text
<script
javascript:
powershell
cmd.exe
iframe
form
```

### Analyst Interpretation

Based on the performed static checks, the HTML attachment should not be described as an executable payload or confirmed malware.

Its observed role is to reinforce the phishing lure and direct the recipient to the suspicious login-themed URL.

---

## Indicators of Compromise / Investigation Indicators

### Email Addresses

```text
security-update@micros0ft-support.example
billing@mailer.example
helpdesk-reset@account-security.example
```

### Domains

```text
micros0ft-support.example
mailer.example
account-security.example
unknown-host.example
login-microsoft365.example
```

### IP Address

```text
203.0.113.77
```

### URL

```text
https://login-microsoft365.example/verify
```

### Attachment

```text
Security_Update.html
```

### SHA256

```text
2911bdd0e3dcc2a3e5b9a8f341febd1c8237191bb7f6b1258d19f42c092c2a30
```

---

## Investigation Timeline

```text
Email received
      |
      v
Sender / Reply-To / Return-Path reviewed
      |
      v
Lookalike sender domain identified
      |
      v
SPF fail / DKIM none / DMARC fail
      |
      v
URL extracted
      |
      v
HTML attachment analyzed
      |
      v
Attachment hash calculated
      |
      v
Phishing indicators correlated
      |
      v
Verdict: True Positive
Controlled Phishing Simulation
```

---

## Verdict

```text
TRUE POSITIVE
CONTROLLED PHISHING SIMULATION
```

The message is classified as phishing within the controlled exercise because multiple independent indicators support the conclusion:

- sender-domain impersonation pattern;
- identity-field mismatches;
- failed email-authentication results;
- urgency-based account lure;
- suspicious login-themed URL;
- HTML attachment directing the recipient to the same URL.

The attachment was not classified as malware based on the checks performed.

---

## Recommended Response in a Production SOC

If this were a real organization and the email were not authorized:

1. quarantine or remove the message from affected mailboxes;
2. block the sender and malicious domains where appropriate;
3. block the URL through email/web security controls;
4. search for additional recipients of the same campaign;
5. determine whether any users clicked the link;
6. review proxy, DNS, EDR, and browser telemetry for the URL/domain;
7. identify whether credentials were submitted;
8. reset affected credentials if credential exposure is suspected;
9. review authentication logs for suspicious access;
10. escalate to SOC N2 / Incident Response if user interaction or compromise is confirmed.

---

## Escalation Decision

### Escalate when:

- a user clicked the URL;
- credentials may have been entered;
- endpoint activity followed the interaction;
- suspicious authentication occurred after delivery;
- multiple recipients were targeted;
- the campaign appears active across the environment.

### N1 Closure May Be Appropriate When:

- the message is confirmed phishing;
- no user interaction occurred;
- the email was successfully quarantined;
- no additional indicators of compromise are identified;
- organizational procedures allow closure at N1.

---

## Analyst Skills Demonstrated

- phishing triage;
- email-header analysis;
- SPF interpretation;
- DKIM interpretation;
- DMARC interpretation;
- sender-identity comparison;
- lookalike-domain identification;
- URL extraction;
- static HTML inspection;
- hash calculation;
- IOC extraction;
- verdict formulation;
- escalation reasoning;
- incident documentation.

---

## Evidence

```text
phishing/case03/case03-phishing-sample.eml
phishing/case03/Security_Update.html
phishing/case03/case03-phishing-checklist.md
```

---

## Safety Note

This case uses a deliberately harmless training sample.

The domains use reserved `.example` namespaces and the source IP `203.0.113.77` is from TEST-NET-3. No live malicious infrastructure is used.

