"""
sentinelai/agents/__init__.py
─────────────────────────────
Investigation agents package for SentinelAI.
"""
from __future__ import annotations

from sentinelai.agents.auth import AuthAgent
from sentinelai.agents.base import BaseInvestigationAgent
from sentinelai.agents.correlation import CorrelationAgent
from sentinelai.agents.schemas import AgentAction, FindingDraft, ToolCall
from sentinelai.agents.timeline import TimelineAgent

__all__ = [
    "BaseInvestigationAgent",
    "AuthAgent",
    "TimelineAgent",
    "CorrelationAgent",
    "ToolCall",
    "FindingDraft",
    "AgentAction",
]
