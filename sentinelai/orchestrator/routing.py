"""
sentinelai/orchestrator/routing.py
──────────────────────────────────
Deterministic routing logic mapping incident risk level and RL strategy to agent fan-out.
"""
from __future__ import annotations

from typing import Any
from sentinelai.schemas import IncidentInput, RiskLevel


VALID_INVESTIGATION_AGENTS = {"auth", "timeline", "correlation"}


def plan_investigation(incident: IncidentInput) -> dict[str, Any]:
    """
    Build the deterministic investigation plan based on risk level and RL metadata.

    Rules (Section 7.1 & Section 12):
    - IGNORE / LOW -> route to archive_node (no LLM calls).
    - MEDIUM -> 2 agents (auth, timeline).
    - HIGH / CRITICAL -> 3 agents (auth, timeline, correlation).
    - Override via rl_metadata['selected_strategy'] if provided.
    """
    risk = incident.risk_level

    # Check for RL engine strategy override
    rl_strategy = incident.rl_metadata.get("selected_strategy")
    if isinstance(rl_strategy, list) and all(a in VALID_INVESTIGATION_AGENTS for a in rl_strategy):
        selected_agents = list(rl_strategy)
        route = "fan_out" if selected_agents else "archive"
        return {
            "risk_level": risk.value,
            "route": route,
            "selected_agents": selected_agents,
            "source": "rl_override",
        }

    if risk in (RiskLevel.IGNORE, RiskLevel.LOW):
        return {
            "risk_level": risk.value,
            "route": "archive",
            "selected_agents": [],
            "source": "deterministic_risk",
        }

    if risk == RiskLevel.MEDIUM:
        return {
            "risk_level": risk.value,
            "route": "fan_out",
            "selected_agents": ["auth", "timeline"],
            "source": "deterministic_risk",
        }

    # HIGH or CRITICAL
    return {
        "risk_level": risk.value,
        "route": "fan_out",
        "selected_agents": ["auth", "timeline", "correlation"],
        "source": "deterministic_risk",
    }
