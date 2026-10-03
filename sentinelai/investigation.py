"""
sentinelai/investigation.py
────────────────────────────
Main public entrypoint for SentinelAI multi-agent investigation tier (Section 9 & Section 12 Phase 8).

Defines:
- investigate(incident: IncidentInput, ...) -> InvestigationReport
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from sentinelai.config import settings
from sentinelai.llm import create_llm_client
from sentinelai.llm.protocol import LLMClient
from sentinelai.orchestrator.graph import build_investigation_graph
from sentinelai.report.generator import ReportGenerator
from sentinelai.schemas import (
    IncidentInput,
    InvestigationReport,
    TimelineEntry,
)
from sentinelai.store.log_store import LogStore
from sentinelai.threat_intel.retriever import MockThreatIntelRetriever, ThreatIntelRetriever
from sentinelai.tools import create_default_registry
from sentinelai.tracing.local_trace import LocalTraceManager


def investigate(
    incident: IncidentInput,
    llm_client: LLMClient | None = None,
    retriever: ThreatIntelRetriever | None = None,
    out_dir: str | Path | None = None,
    max_validation_loops: int | None = None,
) -> InvestigationReport:
    """
    Main public API for SentinelAI (Section 9).
    Autonomously investigates an incident, correlates evidence, checks threat intel,
    validates findings, and synthesizes a structured investigation report.

    Parameters
    ----------
    incident:
        The normalized incident input from the detection/RL tier.
    llm_client:
        Optional LLM client (defaults to configured client via settings).
    retriever:
        Optional ThreatIntelRetriever (defaults to MockThreatIntelRetriever).
    out_dir:
        Optional directory to persist report.md and trace.json.
    max_validation_loops:
        Optional cap on validation loops (defaults to settings.max_validation_loops = 2).
    """
    start_time = time.monotonic()
    client = llm_client or create_llm_client()
    intel_retriever = retriever or MockThreatIntelRetriever()

    # 1. Setup store & tools
    store = LogStore()
    store.load_incident(incident)
    registry = create_default_registry(store)

    # 2. Setup report generator
    report_gen = ReportGenerator(client)

    # 3. Build & compile workflow graph
    graph = build_investigation_graph(
        registry=registry,
        llm_client=client,
        max_validation_loops=max_validation_loops,
        retriever=intel_retriever,
        report_generator=report_gen,
    )

    # 4. Execute workflow
    result = graph.invoke({"incident": incident})
    duration = time.monotonic() - start_time

    # 5. Extract or assemble report
    report: InvestigationReport | None = result.get("report")

    if report is None:
        # Handle low/ignore risk incidents routed to archive
        archive_dec = result.get("archive_decision")
        reason = archive_dec.reason if archive_dec else "Archived per low risk level."
        report = InvestigationReport(
            incident_id=incident.incident_id,
            executive_summary=f"Incident {incident.incident_id} was triaged as low risk and archived without full multi-agent investigation. Reason: {reason}",
            root_cause="Benign or low-priority event requiring no active escalation.",
            mitre_mapping=[],
            timeline=[
                TimelineEntry(
                    timestamp=incident.events[0].timestamp if incident.events else incident.created_at,
                    description=reason,
                    event_ids=[incident.events[0].event_id] if incident.events else [],
                )
            ],
            findings=[],
            recommendations=["No containment necessary; maintain routine monitoring."],
            overall_confidence=1.0,
            limitations=["Triaged to archive_node with zero LLM agent execution."],
            trace_summary={"agents_run": [], "loops_used": 0, "tool_calls": 0, "duration_seconds": round(duration, 3), "total_tokens": 0},
        )

    # 6. Trace & file exports
    if out_dir is not None:
        out_path = Path(out_dir)
        incident_dir = out_path / incident.incident_id
        incident_dir.mkdir(parents=True, exist_ok=True)

        # Export Markdown
        report_gen.export_markdown(
            report=report,
            out_path=incident_dir / "report.md",
            risk_level=incident.risk_level.value if hasattr(incident.risk_level, "value") else str(incident.risk_level),
        )

        # Export Trace
        trace = result.get("trace", {})
        val = result.get("validation")
        val_verdicts = [
            {
                "finding_id": f.finding_id,
                "claim": f.claim,
                "verdict": f.verdict.value,
                "confidence": f.confidence,
            }
            for f in (val.findings if val else [])
        ]

        trace_mgr = LocalTraceManager(base_dir=out_path)
        trace_mgr.export_trace(
            incident_id=incident.incident_id,
            risk_level=incident.risk_level.value if hasattr(incident.risk_level, "value") else str(incident.risk_level),
            agents_executed=list(trace.get("agents", {}).keys()),
            tool_calls_per_agent={
                agent: len(info.get("tool_calls", []))
                for agent, info in trace.get("agents", {}).items()
                if isinstance(info, dict)
            },
            loops_used=result.get("loop_count", 0),
            tokens=sum(result.get("token_usage", {}).values()),
            estimated_cost=0.0,
            wall_clock_time=duration,
            overall_confidence=report.overall_confidence,
            validator_verdicts=val_verdicts,
            raw_trace=trace,
            report=report,
        )

    store.close()
    return report
