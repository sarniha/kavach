---
slug: privilege_escalation
title: Privilege Escalation
mitre_techniques:
  - T1548
  - T1548.002
  - T1098
tactics:
  - Privilege Escalation
related_malware:
  - S0002
---

# Privilege Escalation

## Description
Adversaries exploit system vulnerabilities, misconfigurations, or credential manipulation mechanisms to elevate privileges from standard user to administrative or system-level access.

## Log-Level Indicators
- **Auth / Audit logs**: Explicit `privilege_change` events, addition of accounts to privileged groups (`Domain Admins`, `wheel`, `sudoers`), or SUDO authorization events.
- **Process logs**: Spawning of elevated processes (e.g., cmd.exe or bash running as `SYSTEM` or `root` with a non-privileged parent process).
- **Registry / File logs**: Modifications to UAC bypass registry keys, setuid binaries, or scheduled tasks.

## Typical Event Sequence
1. Attacker gains foothold as a low-privilege service account or standard user.
2. System enumeration for unpatched local vulnerabilities or insecure permissions.
3. Execution of exploit payload or group membership modification (`net localgroup administrators attacker /add`).
4. Re-authentication or token duplication yielding administrative rights.

## Related MITRE Techniques
- T1548 (Abuse Elevation Control Mechanism)
- T1548.002 (Bypass User Account Control)
- T1098 (Account Manipulation)

## Common False Positives
- Approved administrative elevation during software installations.
- Automated deployment scripts legitimately adding accounts during configuration management.

## Recommended Remediation Steps
1. Immediately remove unauthorized accounts from privileged groups.
2. Terminate elevated processes and revoke interactive tokens.
3. Audit recent group policy changes and revert unauthorized permissions.
4. Apply vendor security patches for local privilege escalation (LPE) vulnerabilities.

## Severity Guidance
- **Critical** if root or Domain Admin privileges were attained.
- **High** if unauthorized local administrator rights were established.
