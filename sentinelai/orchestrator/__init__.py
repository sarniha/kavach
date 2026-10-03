"""
sentinelai/orchestrator/__init__.py
───────────────────────────────────
Orchestrator package for SentinelAI multi-agent investigation workflow.
"""
from __future__ import annotations

from sentinelai.orchestrator.graph import build_investigation_graph
from sentinelai.orchestrator.nodes import (
    archive_node,
    merge_node,
    plan_node,
    run_auth_node,
    run_correlation_node,
    run_timeline_node,
)
from sentinelai.orchestrator.routing import plan_investigation
from sentinelai.orchestrator.state import InvestigationState

__all__ = [
    "InvestigationState",
    "plan_investigation",
    "build_investigation_graph",
    "plan_node",
    "archive_node",
    "run_auth_node",
    "run_timeline_node",
    "run_correlation_node",
    "merge_node",
]
