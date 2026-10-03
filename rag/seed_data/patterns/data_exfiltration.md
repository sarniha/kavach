---
slug: data_exfiltration
title: Data Exfiltration
mitre_techniques:
  - T1041
  - T1048
tactics:
  - Exfiltration
related_malware:
  - S0154
---

# Data Exfiltration

## Description
Adversaries steal sensitive, confidential, or operational data from enterprise networks using encrypted channels, cloud storage providers, or alternative protocols.

## Log-Level Indicators
- **Network logs**: Spike in outbound data volume transferred to rare or unclassified external IP addresses. High ratio of outbound to inbound bytes.
- **Process logs**: Archive utilities (`7z.exe`, `tar`, `rar.exe`) executing against sensitive directories, followed by file transfer tools (`curl.exe`, `scp`, `rclone`).
- **Cloud logs**: Large downloads from S3, Azure Blob, or Google Drive via non-standard APIs or outside of business hours.

## Typical Event Sequence
1. Internal discovery and staging: compressing files into encrypted ZIP/RAR archives.
2. Channel establishment: outbound connection to command-and-control (C2) server or public file sharing service.
3. Burst or throttled exfiltration of archived data.
4. Deletion of staging archives to remove forensic artifacts.

## Related MITRE Techniques
- T1041 (Exfiltration Over C2 Channel)
- T1048 (Exfiltration Over Alternative Protocol)
- T1560 (Archive Collected Data)

## Common False Positives
- Scheduled off-site database backups to secondary cloud data centers.
- Large legitimate user uploads to corporate cloud storage.

## Recommended Remediation Steps
1. Block destination external IP/domain at network perimeter and DNS resolver.
2. Revoke compromised cloud access keys and session tokens.
3. Identify exact files accessed from staging logs and evaluate regulatory notification requirements.
4. Inspect internal host for remaining staged data and exfiltration scripts.

## Severity Guidance
- **Critical** when proprietary source code, customer PII, or credentials are confirmed exfiltrated.
- **High** for unconfirmed large outbound volume to untrusted external infrastructure.
