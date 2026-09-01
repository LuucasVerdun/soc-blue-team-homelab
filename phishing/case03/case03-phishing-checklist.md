# Case 03 — Phishing Investigation Checklist

Controlled sample: `case03-phishing-sample.eml`

Attachment: `Security_Update.html`

## Analyst Tasks

1. Identify sender, Return-Path, Reply-To, recipient and subject.
2. Review the Received header and identify the originating IP.
3. Review SPF, DKIM and DMARC results shown in Authentication-Results.
4. Identify lookalike / suspicious sender-domain characteristics.
5. Extract all URLs and domains from the message and attachment.
6. Calculate attachment hashes and compare them with the reference values below.
7. Determine whether the attachment contains executable or script content.
8. Decide whether the message should be classified as phishing.
9. Produce a SOC ticket with verdict, evidence, IOCs and recommended actions.
10. Map relevant behavior to MITRE ATT&CK where justified.

## Reference Hashes for the Controlled Attachment

SHA256:
`2911bdd0e3dcc2a3e5b9a8f341febd1c8237191bb7f6b1258d19f42c092c2a30`

SHA1:
`72a9b4005af0d8b7fc905d905f25b7048d04fb50`

MD5:
`04650e65e2ab94cb4e445fc4ec27835a`

## Safety

The sample is intentionally harmless. IP `203.0.113.77` belongs to TEST-NET-3 and the URLs use reserved `.example` domains.
