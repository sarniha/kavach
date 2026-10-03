---
slug: phishing
title: Phishing and Initial Access
mitre_techniques:
  - T1566
  - T1566.001
  - T1566.002
tactics:
  - Initial Access
related_malware: []
---

# Phishing and Initial Access

## Description
Adversaries send deceptive communications (emails, messages) disguised as legitimate entities to entice users into clicking malicious links, opening infected attachments, or providing credentials.

## Log-Level Indicators
- **Email Gateway logs**: Incoming emails from newly registered domains or lookalike domains with high SPF/DKIM failure rates.
- **Proxy / DNS logs**: User workstation navigating to suspicious external URLs immediately after an inbound email event.
- **Endpoint logs**: Mail client (`outlook.exe`, web browser) spawning child processes like `powershell.exe`, `wscript.exe`, or MS Office macros.

## Typical Event Sequence
1. Attacker crafts spearphishing email with deceptive lure (e.g. urgent invoice, HR policy).
2. Victim opens email and clicks credential harvesting link or downloads attachment.
3. Victim submits corporate credentials on spoofed portal or attachment executes payload.
4. Immediate login attempt using stolen credentials or C2 beacon established from payload.

## Related MITRE Techniques
- T1566 (Phishing)
- T1566.001 (Spearphishing Attachment)
- T1566.002 (Spearphishing Link)

## Common False Positives
- Internal company-authorized phishing simulation exercises.
- Marketing campaigns or vendor onboarding notifications.

## Recommended Remediation Steps
1. Quarantine suspicious emails enterprise-wide.
2. Invalidate sessions and force credential rotation for victims who submitted forms.
3. Isolate workstations that executed attachments and perform malware triage.
4. Block phishing domain and sender infrastructure at mail gateway and DNS.

## Severity Guidance
- **High** if a payload was executed or credentials were entered.
- **Low** if phishing email was blocked or ignored without user interaction.
