---
slug: brute_force
title: Brute Force Authentication Attack
mitre_techniques:
  - T1110
  - T1110.001
tactics:
  - Credential Access
related_malware:
  - S0154
---

# Brute Force Authentication Attack

## Description
An adversary attempts to gain access to an account by systematically guessing passwords against a single targeted user account from one or more IP addresses until valid credentials are discovered.

## Log-Level Indicators
- **Auth logs**: Rapid burst of `auth_failure` events for the same target username from a single source IP. High failure-to-success ratio.
- **Network logs**: Sustained connection attempts on standard authentication ports (SSH: 22, RDP: 3389, Kerberos: 88, HTTP/S: 80/443).
- **Process logs**: Repeated spawns of authentication daemons (`sshd`, `lsass.exe`, `pam`).

## Typical Event Sequence
1. External or internal reconnaissance identifying a high-value account name (e.g. `admin`, `root`).
2. High-frequency login attempts with generic or dictionary passwords.
3. Eventual `auth_success` event from the same source IP.
4. Immediate interactive session launch or privilege change.

## Related MITRE Techniques
- T1110 (Brute Force)
- T1110.001 (Password Guessing)
- T1078 (Valid Accounts)

## Common False Positives
- Misconfigured automated service account or scheduled task with expired credentials.
- Users returning from leave repeatedly typing forgotten passwords.

## Recommended Remediation Steps
1. Immediately lock the compromised account and reset credentials.
2. Terminate active sessions for the user from the offending IP.
3. Block source IP at the perimeter firewall / WAF.
4. Enforce Multi-Factor Authentication (MFA) and account lockout policies.

## Severity Guidance
- **High** if authentication success follows failures.
- **Medium** if failures are blocked without any successful logon.
