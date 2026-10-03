"""
sentinelai/agents/auth.py
─────────────────────────
Auth Agent (Section 7.2).

Investigates authentication activity:
- Repeated failed logins & brute force (T1110)
- Password spraying (T1110.003)
- Success-after-failure & valid accounts (T1078)
- Off-hours / unusual login times
- Privilege changes & elevation (T1548)
"""
from __future__ import annotations

from sentinelai.agents.base import BaseInvestigationAgent


class AuthAgent(BaseInvestigationAgent):
    """
    SOC Tier 2 Agent specializing in authentication analysis.
    """

    agent_name: str = "auth"
    prompt_version: str = "auth_v1"
