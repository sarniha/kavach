"""
sentinelai/orchestrator/state.py
────────────────────────────────
InvestigationState TypedDict with LangGraph reducers for parallel fan-out.
"""
from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from sentinelai.schemas import (
    ArchiveDecision,
    Entities,
    Finding,
    FollowUpRequest,
    IncidentInput,
    InvestigationReport,
    TimelineEntry,
    ValidationResult,
    _merge_findings,
    _merge_token_usage,
    _merge_trace,
)


class InvestigationState(TypedDict, total=False):
    """
    Central LangGraph state passed through the investigation workflow.
    
    Fields with Annotated[..., reducer] safely combine results from
    concurrent parallel agent nodes (Auth, Timeline, Correlation).
    """

    incident: IncidentInput
    plan: dict[str, Any]

    # Parallel fan-out reducers (append-only with deduplication)
    findings: Annotated[list[Finding], _merge_findings]
    timeline_entries: Annotated[list[TimelineEntry], operator.add]
    threat_findings: Annotated[list[Finding], operator.add]
    limitations: Annotated[list[str], operator.add]

    # Merged dictionaries
    token_usage: Annotated[dict[str, int], _merge_token_usage]
    trace: Annotated[dict[str, Any], _merge_trace]

    # Replace semantics
    entities_index: Entities
    validation: ValidationResult | None
    follow_ups: list[FollowUpRequest]
    loop_count: int
    report: InvestigationReport | None
    archive_decision: ArchiveDecision | None
