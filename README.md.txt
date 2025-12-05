🎣 Phishing Incident Response: Header Analysis & Threat Intel

🔍 Executive Summary

This project documents the investigation of a reported phishing email masquerading as "Google Support." The analysis confirmed spoofing via header inspection and threat intelligence correlation. Additionally, a live traffic analysis was performed on a real-world marketing email to validate legitimate sender authentication.

🛠️ Investigation Tools

Header Analysis: Google Admin Toolbox Messageheader

Reputation Check: AbuseIPDB, VirusTotal

Protocol Verification: SPF, DKIM, DMARC

🔬 Investigation 1: The Phishing Attempt (Simulated)

Scenario: User received an email from "Google Support" urging a password reset.

Findings:

Spoofing Detected: Mismatch between From header (support@google.com) and Return-Path (attacker@evil-server.xyz).

Authentication Failure: SPF Hard Fail. The Source IP 192.168.56.101 is not authorized by the google.com SPF record.

Verdict: CONFIRMED PHISHING.

🔬 Investigation 2: Live Traffic Analysis (Real World)

Scenario: Validating a marketing email received in the inbox.

Findings:

Source IP: 156.70.53.174

SPF Result: PASS. The IP is authorized for the sending domain.

Reputation Check: AbuseIPDB Score: 0% (Clean).

Verdict: LEGITIMATE EMAIL.

📸 Evidence

Header Analysis (SPF Fail):

Reputation Check (AbuseIPDB/VirusTotal):

🛡️ Remediation Strategy

Blocked sender domain evil-server.xyz and Source IP at the email gateway.

Purged malicious email from user inbox to prevent credential theft.