---
slug: lateral_movement
title: Lateral Movement and Pivot
mitre_techniques:
  - T1021
  - T1021.001
  - T1021.002
  - T1078
tactics:
  - Lateral Movement
related_malware:
  - S0029
  - S0154
---

# Lateral Movement and Pivot

## Description
Adversaries use compromised credentials, remote administrative protocols, or legitimate administrative utilities to extend access from an initial beachhead system to internal hosts and servers.

## Log-Level Indicators
- **Auth logs**: The same user account authenticating sequentially or concurrently across multiple distinct internal hosts (`dst_ip`/`host`).
- **Network logs**: Internal traffic over SMB (445), RDP (3389), SSH (22), or WinRM (5985/5986) originating from non-administrative endpoints.
- **Process logs**: Execution of `psexec`, `wmic process call create`, `powershell.exe -EncodedCommand`, or remote service creation (`sc.exe`).

## Typical Event Sequence
1. Initial compromise and local credential extraction on workstation A.
2. Internal port scanning or network reconnaissance targeting workstation B and server C.
3. Remote authentication to server C using harvested credentials.
4. Process spawning on server C followed by privilege elevation.

## Related MITRE Techniques
- T1021 (Remote Services)
- T1021.001 (Remote Desktop Protocol)
- T1021.002 (SMB/Windows Admin Shares)
- T1078 (Valid Accounts)

## Common False Positives
- System administrators performing routine patch deployment or maintenance across servers.
- Automated vulnerability scanning software operating with approved credentials.

## Recommended Remediation Steps
1. Isolate the source workstation and all destination hosts involved in the pivot.
2. Revoke active Kerberos tickets and reset passwords for affected accounts.
3. Restrict internal East-West traffic using host-based firewalls and network microsegmentation.
4. Disable unnecessary remote management protocols on endpoints.

## Severity Guidance
- **Critical** when moving towards domain controllers or sensitive database servers.
- **High** for any unexpected workstation-to-workstation pivot.
