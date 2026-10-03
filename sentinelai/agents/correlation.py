"""
sentinelai/agents/correlation.py
────────────────────────────────
Correlation Agent (Section 7.4).

Connects related IPs, users, hosts, and events to uncover multi-host pivots,
lateral movement, and shared attack infrastructure.
"""
from __future__ import annotations

from sentinelai.agents.base import BaseInvestigationAgent


class CorrelationAgent(BaseInvestigationAgent):
    """
    SOC Tier 2 Agent specializing in entity relationship correlation.
    """

    agent_name: str = "correlation"
    prompt_version: str = "correlation_v1"
