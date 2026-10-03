---
slug: password_spraying
title: Password Spraying Attack
mitre_techniques:
  - T1110.003
tactics:
  - Credential Access
related_malware:
  - S0154
---

# Password Spraying Attack

## Description
An adversary attempts a small number of commonly used passwords against many different user accounts to avoid account lockout thresholds and evade rate-based detection.

## Log-Level Indicators
- **Auth logs**: Multiple `auth_failure` events across distinct usernames originating from a single source IP or small IP subnet within a bounded timeframe.
- **Network logs**: Distributed authentication requests across identity endpoints (SSO, Active Directory, Okta, VPN).
- **Process logs**: Low volume per account, preventing typical single-account threshold alerts.

## Typical Event Sequence
1. Target account enumeration (harvesting emails/usernames via OSINT or directory search).
2. Systematic attempt of a single password (e.g., `SeasonYear!`) across all discovered accounts.
3. Isolated `auth_success` on one or more accounts.
4. Post-authentication discovery and enumeration from the successful account.

## Related MITRE Techniques
- T1110.003 (Password Spraying)
- T1078 (Valid Accounts)

## Common False Positives
- Enterprise-wide password audit tools operated by internal security or IT.
- Automated system integration tool attempting connectivity across multiple services.

## Recommended Remediation Steps
1. Identify all accounts targeted and reset passwords for any account that logged a success.
2. Add the source IP/range to defensive deny lists.
3. Require MFA for all remote access portals.
4. Implement smart lockout mechanisms based on IP reputation and anomaly scoring.

## Severity Guidance
- **High** if any targeted account experiences an `auth_success`.
- **Medium** if widespread failures are observed without successful logons.
