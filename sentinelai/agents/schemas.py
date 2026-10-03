"""
sentinelai/agents/schemas.py
────────────────────────────
Structured output models for agent planning, tool invocation, and findings.
"""
from __future__ import annotations

import uuid
from typing import Any
from pydantic import BaseModel, Field

from sentinelai.schemas import Entities, Finding, TimelineEntry


class ToolCall(BaseModel):
    """A tool invocation request issued by an agent."""
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    reasoning: str = ""


class FindingDraft(BaseModel):
    """A draft finding produced by an LLM before validation and normalization."""
    finding_id: str | None = None
    agent: str | None = None
    claim: str
    evidence_event_ids: list[str] = Field(default_factory=list)
    entities: Entities = Field(default_factory=Entities)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    mitre_hint: str | None = None
    reasoning: str = ""

    def to_finding(self, agent_name: str) -> Finding:
        """Convert draft to a validated Finding."""
        return Finding(
            finding_id=self.finding_id or str(uuid.uuid4()),
            agent=self.agent or agent_name,
            claim=self.claim,
            evidence_event_ids=self.evidence_event_ids,
            entities=self.entities,
            confidence=self.confidence,
            mitre_hint=self.mitre_hint,
            reasoning=self.reasoning,
        )


class AgentAction(BaseModel):
    """Structured decision returned by an agent in each investigation turn."""
    thought: str = Field(default="", description="Internal reasoning for this step")
    tool_calls: list[ToolCall] = Field(
        default_factory=list,
        description="Tools to invoke, if more evidence is needed.",
    )
    findings: list[FindingDraft] = Field(
        default_factory=list,
        description="Findings established so far or at conclusion.",
    )
    timeline_entries: list[TimelineEntry] = Field(
        default_factory=list,
        description="Chronological attack steps (primarily for Timeline Agent).",
    )
    is_complete: bool = Field(
        default=False,
        description="True if the agent has gathered sufficient evidence and completed.",
    )
