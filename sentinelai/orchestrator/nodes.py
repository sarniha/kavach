"""
sentinelai/orchestrator/nodes.py
────────────────────────────────
LangGraph workflow nodes for SentinelAI investigation tier.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sentinelai.agents.auth import AuthAgent
from sentinelai.agents.correlation import CorrelationAgent
from sentinelai.agents.threat_intel import ThreatIntelAgent
from sentinelai.agents.timeline import TimelineAgent
from sentinelai.llm.protocol import LLMClient
from sentinelai.orchestrator.routing import plan_investigation
from sentinelai.orchestrator.state import InvestigationState
from sentinelai.report.generator import ReportGenerator
from sentinelai.schemas import ArchiveDecision, Entities, Finding
from sentinelai.threat_intel.retriever import ThreatIntelRetriever
from sentinelai.tools.registry import ToolRegistry


def plan_node(state: InvestigationState) -> dict[str, Any]:
    """
    Build investigation plan from incident risk level and RL metadata.
    Deterministic routing without required LLM calls.
    """
    incident = state["incident"]
    plan = plan_investigation(incident)

    return {
        "plan": plan,
        "loop_count": 0,
        "findings": [],
        "timeline_entries": [],
        "threat_findings": [],
        "limitations": [],
        "token_usage": {},
        "trace": {
            "incident_id": incident.incident_id,
            "plan": plan,
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def archive_node(state: InvestigationState) -> dict[str, Any]:
    """
    Handle IGNORE / LOW incidents without agent execution or LLM calls.
    """
    incident = state["incident"]
    decision = ArchiveDecision(
        incident_id=incident.incident_id,
        risk_level=incident.risk_level,
        reason=f"Incident risk {incident.risk_level.value} archived without deep investigation.",
        archived_at=datetime.now(timezone.utc),
    )
    return {
        "archive_decision": decision,
        "trace": {
            "archived": True,
            "archived_at": decision.archived_at.isoformat(),
        },
    }


def run_auth_node(
    state: InvestigationState,
    registry: ToolRegistry,
    llm_client: LLMClient,
) -> dict[str, Any]:
    """Execute the Auth Agent."""
    incident = state["incident"]
    agent = AuthAgent(
        llm_client=llm_client,
        registry=registry,
        incident=incident,
    )
    findings = agent.run()
    return {
        "findings": findings,
        "trace": {"agents": {"auth": agent.trace}},
        "limitations": agent.trace.get("limitations", []),
    }


def run_timeline_node(
    state: InvestigationState,
    registry: ToolRegistry,
    llm_client: LLMClient,
) -> dict[str, Any]:
    """Execute the Timeline Agent."""
    incident = state["incident"]
    agent = TimelineAgent(
        llm_client=llm_client,
        registry=registry,
        incident=incident,
    )
    findings = agent.run()
    return {
        "findings": findings,
        "timeline_entries": agent.timeline_entries,
        "trace": {"agents": {"timeline": agent.trace}},
        "limitations": agent.trace.get("limitations", []),
    }


def run_correlation_node(
    state: InvestigationState,
    registry: ToolRegistry,
    llm_client: LLMClient,
) -> dict[str, Any]:
    """Execute the Correlation Agent."""
    incident = state["incident"]
    agent = CorrelationAgent(
        llm_client=llm_client,
        registry=registry,
        incident=incident,
    )
    findings = agent.run()
    return {
        "findings": findings,
        "trace": {"agents": {"correlation": agent.trace}},
        "limitations": agent.trace.get("limitations", []),
    }


def merge_node(state: InvestigationState) -> dict[str, Any]:
    """
    Join and deduplicate findings across parallel agents, index entities,
    and update trace metadata.
    """
    raw_findings = state.get("findings", [])
    timeline_entries = state.get("timeline_entries", [])

    # Deduplicate findings by claim and evidence event IDs
    seen_keys: set[tuple[str, str]] = set()
    deduped_findings: list[Finding] = []

    for f in raw_findings:
        key = (f.claim.strip().lower(), ",".join(sorted(f.evidence_event_ids)))
        if key not in seen_keys:
            seen_keys.add(key)
            deduped_findings.append(f)

    # Aggregate entities into entities_index
    combined_entities = Entities()
    for f in deduped_findings:
        combined_entities = combined_entities.merge(f.entities)

    return {
        "entities_index": combined_entities,
        "trace": {
            "merge": {
                "total_findings_received": len(raw_findings),
                "deduplicated_findings_count": len(deduped_findings),
                "entities_indexed": combined_entities.model_dump(),
                "timeline_count": len(timeline_entries),
            }
        },
    }


def run_threat_intel_node(
    state: InvestigationState,
    retriever: ThreatIntelRetriever,
    llm_client: LLMClient,
) -> dict[str, Any]:
    """
    Execute the Threat Intel Agent (Section 7.5).
    Receives entities + hints from entities_index, runs RAG retrieval,
    and produces threat_findings.
    """
    incident = state["incident"]
    entities = state.get("entities_index", Entities())

    # Extract MITRE hints from existing findings
    hints: list[str] = []
    claims: list[str] = []
    for f in state.get("findings", []):
        if f.mitre_hint:
            hints.append(f.mitre_hint)
        if f.claim:
            claims.append(f.claim)

    agent = ThreatIntelAgent(
        llm_client=llm_client,
        retriever=retriever,
        incident=incident,
    )
    threat_findings = agent.run(
        entities=entities,
        hints=list(set(hints)),
        claims=claims,
    )
    return {
        "threat_findings": threat_findings,
        "findings": threat_findings,  # Also feed into main findings for validator
        "trace": {"agents": {"threat_intel": agent.trace}},
        "limitations": agent.trace.get("limitations", []),
    }


def validate_node(
    state: InvestigationState,
    registry: ToolRegistry,
    llm_client: LLMClient,
) -> dict[str, Any]:
    """
    Evidence Validator node executing Stage 1 deterministic rules and
    Stage 2 LLM-as-judge checks.
    """
    from sentinelai.validator import EvidenceValidator

    store = registry.store
    if store is None:
        raise ValueError("EvidenceValidator requires a LogStore in ToolRegistry.")

    validator = EvidenceValidator(store=store, llm_client=llm_client)
    findings = state.get("findings", [])
    incident = state["incident"]

    result = validator.validate(findings, incident)

    return {
        "validation": result,
        "follow_ups": result.follow_ups,
        "limitations": result.limitations,
        "trace": {
            "validation": {
                "sufficient": result.sufficient,
                "overall_confidence": result.overall_confidence,
                "follow_ups_count": len(result.follow_ups),
                "rejected_count": len([vf for vf in result.findings if vf.verdict.value in ("unsupported", "contradicted")]),
            }
        },
    }


def follow_up_dispatch(
    state: InvestigationState,
    registry: ToolRegistry,
    llm_client: LLMClient,
    retriever: ThreatIntelRetriever | None = None,
) -> dict[str, Any]:
    """
    Re-dispatch targeted agents with specific follow-up questions from the validator.
    Increments loop_count and feeds findings back into merge_node.
    Supports: auth, timeline, correlation, threat_intel.
    """
    follow_ups = state.get("follow_ups", [])
    current_loops = state.get("loop_count", 0) + 1
    incident = state["incident"]

    new_findings: list[Finding] = []
    limitations: list[str] = [f"Validation loop {current_loops} initiated."]

    for fu in follow_ups:
        target = fu.target_agent.lower().strip()
        if target == "auth":
            agent = AuthAgent(llm_client=llm_client, registry=registry, incident=incident)
            new_findings.extend(agent.run(follow_up_question=fu.question))
        elif target == "timeline":
            agent = TimelineAgent(llm_client=llm_client, registry=registry, incident=incident)
            new_findings.extend(agent.run(follow_up_question=fu.question))
        elif target == "correlation":
            agent = CorrelationAgent(llm_client=llm_client, registry=registry, incident=incident)
            new_findings.extend(agent.run(follow_up_question=fu.question))
        elif target == "threat_intel" and retriever is not None:
            entities = state.get("entities_index", Entities())
            ti_agent = ThreatIntelAgent(
                llm_client=llm_client,
                retriever=retriever,
                incident=incident,
            )
            new_findings.extend(
                ti_agent.run(
                    entities=entities,
                    hints=[],
                    claims=[],
                    follow_up_question=fu.question,
                )
            )

    return {
        "loop_count": current_loops,
        "findings": new_findings,
        "limitations": limitations,
        "trace": {
            f"loop_{current_loops}": {
                "targeted_agents": [fu.target_agent for fu in follow_ups],
                "new_findings_count": len(new_findings),
            }
        },
    }


def run_report_node(
    state: InvestigationState,
    report_generator: ReportGenerator,
) -> dict[str, Any]:
    """
    Synthesize the final InvestigationReport from validated findings (Phase 7).
    Only SUPPORTED and WEAK findings enter the report narrative.
    """
    incident = state["incident"]
    validation = state.get("validation")
    validated_findings = validation.findings if validation is not None else []
    timeline = state.get("timeline_entries", [])
    limitations = state.get("limitations", [])
    trace = state.get("trace", {})

    trace_summary = {
        "agents_run": list(trace.get("agents", {}).keys()),
        "loops_used": state.get("loop_count", 0),
        "tool_calls": sum(
            len(a.get("tool_calls", []))
            for a in trace.get("agents", {}).values()
            if isinstance(a, dict)
        ),
        "duration_seconds": 0.0,
        "total_tokens": sum(state.get("token_usage", {}).values()),
    }

    report = report_generator.generate(
        incident_id=incident.incident_id,
        validated_findings=validated_findings,
        timeline_entries=timeline,
        validation_result=validation,
        trace_summary=trace_summary,
        existing_limitations=limitations,
        risk_level=incident.risk_level.value if hasattr(incident.risk_level, "value") else str(incident.risk_level),
    )

    return {"report": report}

