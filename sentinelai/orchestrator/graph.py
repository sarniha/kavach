"""
sentinelai/orchestrator/graph.py
────────────────────────────────
LangGraph StateGraph workflow for SentinelAI investigation tier (Section 4 & Section 12).

Node topology (Phase 6d update):
  plan_node → fan-out → merge_node → threat_intel_node → validate_node → END
                ↳ archive_node (low/ignore)         ↑
  follow_up_dispatch ─────────────────────────────────
"""
from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from sentinelai.config import settings as global_settings
from sentinelai.llm.protocol import LLMClient
from sentinelai.orchestrator.nodes import (
    archive_node,
    follow_up_dispatch,
    merge_node,
    plan_node,
    run_auth_node,
    run_correlation_node,
    run_report_node,
    run_threat_intel_node,
    run_timeline_node,
    validate_node,
)
from sentinelai.orchestrator.state import InvestigationState
from sentinelai.report.generator import ReportGenerator
from sentinelai.threat_intel.retriever import ThreatIntelRetriever
from sentinelai.tools.registry import ToolRegistry


def build_investigation_graph(
    registry: ToolRegistry,
    llm_client: LLMClient,
    max_validation_loops: int | None = None,
    retriever: ThreatIntelRetriever | None = None,
    report_generator: ReportGenerator | None = None,
) -> CompiledStateGraph:
    """
    Construct and compile the multi-agent investigation workflow graph with validation loop.

    Graph topology (updated with Phase 6d & Phase 7):
    - START -> plan_node
    - plan_node -> archive_node [if risk in {IGNORE, LOW}]
    - plan_node -> parallel fan-out [if risk in {MEDIUM, HIGH, CRITICAL}]
        - MEDIUM: [auth_node, timeline_node]
        - HIGH/CRITICAL: [auth_node, timeline_node, correlation_node]
    - [fan-out agents] -> merge_node (join)
    - archive_node -> END
    - merge_node -> threat_intel_node (if retriever provided) OR validate_node (no RAG)
    - threat_intel_node -> validate_node
    - validate_node -> follow_up_dispatch [if sufficient=False and loop_count < max_loops]
    - validate_node -> report_node (if report_generator) OR END [if sufficient=True or loop_count >= max_loops]
    - report_node -> END
    - follow_up_dispatch -> merge_node
    """
    loop_limit = (
        max_validation_loops
        if max_validation_loops is not None
        else global_settings.max_validation_loops
    )

    workflow = StateGraph(InvestigationState)

    # 1. Register nodes
    workflow.add_node("plan_node", plan_node)
    workflow.add_node("archive_node", archive_node)
    workflow.add_node(
        "auth_node",
        lambda state: run_auth_node(state, registry, llm_client),
    )
    workflow.add_node(
        "timeline_node",
        lambda state: run_timeline_node(state, registry, llm_client),
    )
    workflow.add_node(
        "correlation_node",
        lambda state: run_correlation_node(state, registry, llm_client),
    )
    workflow.add_node("merge_node", merge_node)

    # Threat Intel node (Phase 6d) – only registered when a retriever is provided
    if retriever is not None:
        workflow.add_node(
            "threat_intel_node",
            lambda state: run_threat_intel_node(state, retriever, llm_client),
        )

    workflow.add_node(
        "validate_node",
        lambda state: validate_node(state, registry, llm_client),
    )
    workflow.add_node(
        "follow_up_dispatch",
        lambda state: follow_up_dispatch(state, registry, llm_client, retriever),
    )

    if report_generator is not None:
        workflow.add_node(
            "report_node",
            lambda state: run_report_node(state, report_generator),
        )

    # 2. Add edges
    workflow.add_edge(START, "plan_node")

    def route_plan(state: InvestigationState) -> list[str] | str:
        plan = state.get("plan", {})
        if plan.get("route") == "archive":
            return "archive_node"
        agents = plan.get("selected_agents", ["auth", "timeline"])
        return [f"{a}_node" for a in agents]

    workflow.add_conditional_edges(
        "plan_node",
        route_plan,
        ["archive_node", "auth_node", "timeline_node", "correlation_node"],
    )

    workflow.add_edge("archive_node", END)
    workflow.add_edge("auth_node", "merge_node")
    workflow.add_edge("timeline_node", "merge_node")
    workflow.add_edge("correlation_node", "merge_node")

    # merge_node routes to threat_intel_node (if RAG available) or straight to validate
    if retriever is not None:
        workflow.add_edge("merge_node", "threat_intel_node")
        workflow.add_edge("threat_intel_node", "validate_node")
    else:
        workflow.add_edge("merge_node", "validate_node")

    def route_validation(state: InvestigationState) -> str:
        val = state.get("validation")
        loops = state.get("loop_count", 0)
        if val is not None and not val.sufficient and loops < loop_limit:
            return "follow_up_dispatch"
        if report_generator is not None:
            return "report_node"
        return END

    val_destinations: dict[str, Any] = {"follow_up_dispatch": "follow_up_dispatch"}
    if report_generator is not None:
        val_destinations["report_node"] = "report_node"
        workflow.add_edge("report_node", END)
    else:
        val_destinations[END] = END

    workflow.add_conditional_edges(
        "validate_node",
        route_validation,
        val_destinations,
    )

    # follow_up_dispatch re-enters at merge (which then routes to TI if applicable)
    workflow.add_edge("follow_up_dispatch", "merge_node")

    return workflow.compile()
