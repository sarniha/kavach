---
slug: credential_stuffing
title: Credential Stuffing
mitre_techniques:
  - T1110
  - T1110.004
tactics:
  - Credential Access
related_malware: []
---

# Credential Stuffing

## Description
Adversaries leverage automated tools and lists of compromised username/password pairs leaked from external breaches to gain unauthorized access to target enterprise systems.

## Log-Level Indicators
- **Auth logs**: High volume of distinct username/password combinations tried against login portals. Geographically distributed source IPs (often residential proxies).
- **Network logs**: Requests featuring spoofed User-Agents or high concurrency across authentication endpoints.
- **Application logs**: High failure rates interspersed with occasional valid logins.

## Typical Event Sequence
1. Ingestion of third-party breach database credentials into automated bot runner.
2. Rapid replay of credential pairs against target login endpoint.
3. Verification of successful authentication tokens and subsequent account takeover.

## Related MITRE Techniques
- T1110.004 (Credential Stuffing)
- T1078 (Valid Accounts)

## Common False Positives
- Internal load testing of authentication services without synthetic test accounts.

## Recommended Remediation Steps
1. Require immediate password resets on accounts with successful logons.
2. Deploy CAPTCHA or bot-management challenges on login endpoints.
3. Implement dark-web breach monitoring to proactively notify users of compromised passwords.

## Severity Guidance
- **High** if account takeovers are verified.
- **Medium** for automated stuffing traffic actively blocked by security controls.
