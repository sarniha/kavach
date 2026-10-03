"""
sentinelai/agents/timeline.py
─────────────────────────────
Timeline Agent (Section 7.3).

Reconstructs chronological attack sequences, maps events to kill-chain phases,
and generates structured TimelineEntry items and cited Findings.
"""
from __future__ import annotations

from sentinelai.agents.base import BaseInvestigationAgent


class TimelineAgent(BaseInvestigationAgent):
    """
    SOC Tier 2 Agent specializing in chronological timeline reconstruction.
    """

    agent_name: str = "timeline"
    prompt_version: str = "timeline_v1"
